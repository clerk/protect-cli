package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/clerk/protect-cli/internal/api"
	"github.com/clerk/protect-cli/internal/httperr"
)

// Virtual tables: the lookup data a rule reads through in_table. A table has
// typed columns; a row holds, per column, a list of entries — literal values,
// or matchers (CIDR, prefix, suffix, wildcard, regex, range, set) on a
// matchable column.

type tableColumn struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Matchable bool   `json:"matchable,omitempty"`
	Required  bool   `json:"required,omitempty"`
}

type tableInfo struct {
	Name        string        `json:"name"`
	Description string        `json:"description,omitempty"`
	Columns     []tableColumn `json:"columns"`
	RowCount    int32         `json:"row_count,omitempty"`
	IntelRef    string        `json:"intel_ref,omitempty"`
}

type tableEntry struct {
	Kind  string `json:"kind,omitempty"`
	Value string `json:"value"`
}

type tableRow struct {
	ID        string                  `json:"id"`
	Fields    map[string][]tableEntry `json:"fields"`
	ExpiresAt string                  `json:"expires_at,omitempty"`
	AddedAt   string                  `json:"added_at,omitempty"`
	Note      string                  `json:"note,omitempty"`
	Reference string                  `json:"reference,omitempty"`
}

// columnTypes are the types a column may have; entryKinds the matchers an
// entry on a matchable column may be. Kept to validate flags early and to say
// what is allowed in --help, never to decide what the server accepts.
var (
	columnTypes = []string{"STRING", "INTEGER", "IP", "DOMAIN", "ASN"}
	entryKinds  = []string{"LITERAL", "WILDCARD", "REGEX", "PREFIX", "SUFFIX", "RANGE", "CIDR", "SET"}
)

func (a *app) tablesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tables",
		Short: "Manage the lookup tables your rules read with in_table, and their rows",
	}
	cmd.AddCommand(
		a.tablesListCmd(),
		a.tablesGetCmd(),
		a.tablesCreateCmd(),
		a.tablesUpdateCmd(),
		a.tablesDeleteCmd(),
		a.tableRowsCmd(),
	)
	return cmd
}

func (a *app) tablesListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List this instance's tables",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, _, err := a.client()
			if err != nil {
				return err
			}
			if a.jsonOut {
				return a.rawGet(cmd, c, api.Path("tables"), nil)
			}
			var list struct {
				Tables []tableInfo `json:"tables"`
			}
			if err := c.JSON(ctxOf(cmd), http.MethodGet, api.Path("tables"), nil, nil, &list); err != nil {
				return err
			}
			if len(list.Tables) == 0 {
				a.printf("No tables yet. `clerk-protect tables create` makes one.\n")
				return nil
			}
			tw := a.table()
			tw.Header("NAME", "ROWS", "COLUMNS", "DESCRIPTION")
			tw.Style(0, a.out.ID)
			for _, t := range list.Tables {
				tw.Row(t.Name, strconv.Itoa(int(t.RowCount)), columnSummary(t.Columns), t.Description)
			}
			return tw.Flush()
		},
	}
}

func (a *app) tablesGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <table>",
		Short: "Show a table's columns",
		Args:  exactArgs(1, "a table name"),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, _, err := a.client()
			if err != nil {
				return err
			}
			if a.jsonOut {
				return a.rawGet(cmd, c, api.Path("tables", args[0]), nil)
			}
			var t tableInfo
			if err := c.JSON(ctxOf(cmd), http.MethodGet, api.Path("tables", args[0]), nil, nil, &t); err != nil {
				return err
			}
			a.printf("%s — %d rows\n", a.out.ID(t.Name), t.RowCount)
			if t.Description != "" {
				a.printf("%s\n", t.Description)
			}
			if t.IntelRef != "" {
				a.printf("%s\n", a.out.Warn("An indicator set curated by Clerk: read-only here."))
			}
			a.printf("\n")
			tw := a.table()
			tw.Header("COLUMN", "TYPE", "MATCHABLE", "REQUIRED")
			tw.Style(0, a.out.Emphasis)
			for _, col := range t.Columns {
				tw.Row(col.Name, col.Type, yesNo(col.Matchable), yesNo(col.Required))
			}
			return tw.Flush()
		},
	}
}

func (a *app) tablesCreateCmd() *cobra.Command {
	var columns []string
	var description string
	cmd := &cobra.Command{
		Use:   "create <table> --column NAME:TYPE[:matchable][:required] ...",
		Short: "Create a table",
		Long: "Create a table. Each --column is NAME:TYPE, optionally followed by :matchable (rows may hold " +
			"matchers — CIDR, prefix, wildcard… — that rules match values against) and :required.\n\n" +
			"Types: " + strings.Join(columnTypes, ", ") + ".\n\n" +
			"  clerk-protect tables create blocked_networks --column network:IP:matchable:required --column reason:STRING",
		Args: exactArgs(1, "a table name"),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(columns) == 0 {
				return usageError("give at least one --column NAME:TYPE")
			}
			cols := make([]tableColumn, 0, len(columns))
			for _, spec := range columns {
				col, err := parseColumn(spec)
				if err != nil {
					return err
				}
				cols = append(cols, col)
			}
			if err := a.requireConsent(); err != nil {
				return err
			}
			c, _, err := a.client()
			if err != nil {
				return err
			}
			if err := a.confirm("Create table " + args[0]); err != nil {
				return err
			}
			body := map[string]any{"name": args[0], "description": description, "columns": cols}
			resp, err := c.Do(ctxOf(cmd), http.MethodPost, api.Path("tables"), nil, body)
			if err != nil {
				return err
			}
			return a.reportTable(resp, "Created table", args[0])
		},
	}
	cmd.Flags().StringArrayVar(&columns, "column", nil, "A column, NAME:TYPE[:matchable][:required] (repeatable)")
	cmd.Flags().StringVar(&description, "description", "", "What the table holds")
	return cmd
}

func (a *app) tablesUpdateCmd() *cobra.Command {
	var add, update, remove, rename []string
	var description string
	cmd := &cobra.Command{
		Use:   "update <table>",
		Short: "Change a table's description or columns",
		Long: "Change a table's description or columns. --add-column and --update-column take " +
			"NAME:TYPE[:matchable][:required]; --rename-column takes OLD=NEW; --remove-column a name. " +
			"Removing a column removes its values from every row.",
		Args: exactArgs(1, "a table name"),
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]any{}
			if cmd.Flags().Changed("description") {
				body["description"] = description
			}
			for _, pair := range []struct {
				key   string
				specs []string
			}{{"add", add}, {"update", update}} {
				if len(pair.specs) == 0 {
					continue
				}
				cols := make([]tableColumn, 0, len(pair.specs))
				for _, spec := range pair.specs {
					col, err := parseColumn(spec)
					if err != nil {
						return err
					}
					cols = append(cols, col)
				}
				body[pair.key] = cols
			}
			if len(remove) > 0 {
				body["remove"] = remove
			}
			if len(rename) > 0 {
				m := map[string]string{}
				for _, r := range rename {
					from, to, ok := strings.Cut(r, "=")
					if !ok || from == "" || to == "" {
						return usageError("--rename-column %q: expected OLD=NEW", r)
					}
					m[from] = to
				}
				body["rename"] = m
			}
			if len(body) == 0 {
				return usageError("nothing to change — give --description, --add-column, --update-column, --remove-column or --rename-column")
			}
			if err := a.requireConsent(); err != nil {
				return err
			}
			c, _, err := a.client()
			if err != nil {
				return err
			}
			what := "Change table " + args[0]
			if len(remove) > 0 {
				what += fmt.Sprintf(", removing column(s) %s and their values from every row", strings.Join(remove, ", "))
			}
			if err := a.confirm(what); err != nil {
				return err
			}
			resp, err := c.Do(ctxOf(cmd), http.MethodPatch, api.Path("tables", args[0]), nil, body)
			if err != nil {
				return err
			}
			return a.reportTable(resp, "Updated table", args[0])
		},
	}
	f := cmd.Flags()
	f.StringVar(&description, "description", "", "New description")
	f.StringArrayVar(&add, "add-column", nil, "Add a column, NAME:TYPE[:matchable][:required] (repeatable)")
	f.StringArrayVar(&update, "update-column", nil, "Change a column's type or flags, NAME:TYPE[:matchable][:required] (repeatable)")
	f.StringArrayVar(&remove, "remove-column", nil, "Remove a column and its values (repeatable)")
	f.StringArrayVar(&rename, "rename-column", nil, "Rename a column, OLD=NEW (repeatable)")
	return cmd
}

func (a *app) tablesDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <table>",
		Short: "Delete a table and every row in it",
		Args:  exactArgs(1, "a table name"),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.requireConsent(); err != nil {
				return err
			}
			c, _, err := a.client()
			if err != nil {
				return err
			}
			if err := a.confirm("Delete table " + args[0] + " and every row in it (a rule that reads it will match nothing)"); err != nil {
				return err
			}
			resp, err := c.Do(ctxOf(cmd), http.MethodDelete, api.Path("tables", args[0]), nil, nil)
			if err != nil {
				return err
			}
			if a.jsonOut {
				return a.printRaw(orEmptyObject(resp.Body))
			}
			a.printf("%s %s.\n", a.out.Good("Deleted table"), a.out.ID(args[0]))
			return nil
		},
	}
}

// --- rows ---------------------------------------------------------------------

func (a *app) tableRowsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rows",
		Short: "List, search, add, change and delete a table's rows",
	}
	cmd.AddCommand(
		a.rowsListCmd(),
		a.rowsGetCmd(),
		a.rowsSearchCmd(),
		a.rowsAddCmd(),
		a.rowsSetCmd(),
		a.rowsUpdateCmd(),
		a.rowsDeleteCmd(),
	)
	return cmd
}

func (a *app) rowsListCmd() *cobra.Command {
	var limit int
	cmd := &cobra.Command{
		Use:   "list <table>",
		Short: "List a table's rows",
		Args:  exactArgs(1, "a table name"),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, _, err := a.client()
			if err != nil {
				return err
			}
			rows, err := listAllRows(ctxOf(cmd), c, args[0], limit)
			if err != nil {
				return err
			}
			return a.printRows(rows, "")
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 0, "Stop after this many rows (default: all)")
	return cmd
}

func (a *app) rowsGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <table> <row-id>",
		Short: "Show one row",
		Args:  exactArgs(2, "a table name and a row id"),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, _, err := a.client()
			if err != nil {
				return err
			}
			if a.jsonOut {
				return a.rawGet(cmd, c, api.Path("tables", args[0], "rows", args[1]), nil)
			}
			var row tableRow
			if err := c.JSON(ctxOf(cmd), http.MethodGet, api.Path("tables", args[0], "rows", args[1]), nil, nil, &row); err != nil {
				return err
			}
			return a.printRows([]tableRow{row}, "")
		},
	}
}

func (a *app) rowsSearchCmd() *cobra.Command {
	var matches []string
	var contains string
	var limit int
	cmd := &cobra.Command{
		Use:   "search <table> (--match COLUMN=VALUE ... | --contains TEXT)",
		Short: "Find rows: which a value would match, or which contain some text",
		Long: "Two searches:\n\n" +
			"  --match COLUMN=VALUE   the rows a rule would match for that value — a CIDR row matches an IP inside it,\n" +
			"                         a suffix row a domain ending in it. Matchable columns only; repeat to AND columns.\n" +
			"                         Expired rows never match, as in a rule.\n" +
			"  --contains TEXT        rows whose id, any value or note contains TEXT (case-insensitive), expired included.\n\n" +
			"  clerk-protect tables rows search blocked_networks --match network=203.0.113.7",
		Args: exactArgs(1, "a table name"),
		RunE: func(cmd *cobra.Command, args []string) error {
			if (len(matches) == 0) == (contains == "") {
				return usageError("give --match COLUMN=VALUE or --contains TEXT (one of the two)")
			}
			c, _, err := a.client()
			if err != nil {
				return err
			}
			ctx := ctxOf(cmd)
			if contains != "" {
				rows, err := listAllRows(ctx, c, args[0], 0)
				if err != nil {
					return err
				}
				var hit []tableRow
				for _, r := range rows {
					if rowContains(r, contains) {
						hit = append(hit, r)
						if limit > 0 && len(hit) >= limit {
							break
						}
					}
				}
				return a.printRows(hit, fmt.Sprintf("%d of %d rows contain %q", len(hit), len(rows), contains))
			}
			inputs := map[string]string{}
			for _, m := range matches {
				col, val, ok := strings.Cut(m, "=")
				if !ok || col == "" {
					return usageError("--match %q: expected COLUMN=VALUE", m)
				}
				inputs[col] = val
			}
			body := map[string]any{"inputs": inputs}
			if limit > 0 {
				body["limit"] = limit
			}
			var out struct {
				Rows         []tableRow `json:"rows"`
				TotalMatches int        `json:"total_matches"`
			}
			if a.jsonOut {
				resp, err := c.Do(ctx, http.MethodPost, api.Path("tables", args[0], "query"), nil, body)
				if err != nil {
					return err
				}
				return a.printRaw(resp.Body)
			}
			if err := c.JSON(ctx, http.MethodPost, api.Path("tables", args[0], "query"), nil, body, &out); err != nil {
				return err
			}
			return a.printRows(out.Rows, fmt.Sprintf("%d live row(s) match", out.TotalMatches))
		},
	}
	f := cmd.Flags()
	f.StringArrayVar(&matches, "match", nil, "COLUMN=VALUE: rows a rule would match for this value (repeatable, ANDed)")
	f.StringVar(&contains, "contains", "", "Rows whose id, values or note contain this text")
	f.IntVar(&limit, "limit", 0, "Stop after this many matches")
	return cmd
}

// rowFlags are the flags that describe a row's contents, shared by add, set
// and update.
type rowFlags struct {
	values    []string
	matchers  []string
	fromFile  string
	expires   string
	note      string
	reference string

	// What --from-json carried besides fields, applied under the flags.
	fileID, fileExpires, fileNote, fileReference *string
}

func (rf *rowFlags) register(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringArrayVar(&rf.values, "value", nil, "COLUMN=VALUE: a literal value (repeatable; repeat a column for several)")
	f.StringArrayVar(&rf.matchers, "matcher", nil,
		"COLUMN=KIND:VALUE: a matcher on a matchable column, KIND one of "+strings.Join(entryKinds[1:], ", ")+" (repeatable)")
	f.StringVar(&rf.fromFile, "from-json", "",
		"Read the row from a JSON file ('-' for stdin): a row as `rows get --json` prints it, or just its fields map. Flags win over the file")
	f.StringVar(&rf.expires, "expires", "", "When the row stops matching (RFC 3339)")
	f.StringVar(&rf.note, "note", "", "A note on the row")
	f.StringVar(&rf.reference, "reference", "", "A link explaining the row")
}

func (rf *rowFlags) empty() bool {
	return len(rf.values) == 0 && len(rf.matchers) == 0 && rf.fromFile == ""
}

// fields builds the per-column entries the flags describe.
func (rf *rowFlags) fields(stdin io.Reader) (map[string][]tableEntry, error) {
	fields := map[string][]tableEntry{}
	if rf.fromFile != "" {
		var raw []byte
		var err error
		if rf.fromFile == "-" {
			raw, err = io.ReadAll(stdin)
		} else {
			raw, err = os.ReadFile(rf.fromFile)
		}
		if err != nil {
			return nil, fmt.Errorf("--from-json: %w", err)
		}
		var top map[string]json.RawMessage
		if err := json.Unmarshal(raw, &top); err != nil {
			return nil, usageError("--from-json: not a JSON object: %v", err)
		}
		// A whole row has "fields" holding an OBJECT (column -> entries). A bare
		// fields map may have a column that is itself named "fields", whose
		// value is a LIST of entries — so the shape decides, not the key.
		if f, isRow := top["fields"]; isRow && strings.HasPrefix(strings.TrimSpace(string(f)), "{") {
			// A whole row. Every key it carries is used or refused — never
			// silently dropped, which would turn an expiring row permanent.
			for k, v := range top {
				var str string
				switch k {
				case "fields":
					if err := json.Unmarshal(v, &fields); err != nil {
						return nil, usageError("--from-json: fields: %v", err)
					}
				case "id", "expires_at", "note", "reference":
					if err := json.Unmarshal(v, &str); err != nil {
						return nil, usageError("--from-json: %s must be a string", k)
					}
					val := str
					switch k {
					case "id":
						rf.fileID = &val
					case "expires_at":
						rf.fileExpires = &val
					case "note":
						rf.fileNote = &val
					case "reference":
						rf.fileReference = &val
					}
				case "added_by", "added_at", "source", "first_observed":
					// Recorded by the server, not written by a person: a save
					// keeps the stored values (see provenanceKeys).
				default:
					return nil, usageError("--from-json: unknown row key %q", k)
				}
			}
		} else if f, ok := top["fields"]; ok && strings.TrimSpace(string(f)) == "null" {
			return nil, usageError("--from-json: fields is null — give an object of COLUMN: [entries]")
		} else if err := json.Unmarshal(raw, &fields); err != nil {
			return nil, usageError("--from-json: expected a row {\"fields\": {COLUMN: [{\"value\": …}]}, …} or the fields map: %v", err)
		}
		if fields == nil {
			fields = map[string][]tableEntry{}
		}
	}
	for _, v := range rf.values {
		col, val, ok := strings.Cut(v, "=")
		if !ok || col == "" {
			return nil, usageError("--value %q: expected COLUMN=VALUE", v)
		}
		fields[col] = append(fields[col], tableEntry{Value: val})
	}
	for _, m := range rf.matchers {
		col, rest, ok := strings.Cut(m, "=")
		kind, val, ok2 := strings.Cut(rest, ":")
		kind = strings.ToUpper(kind)
		if !ok || !ok2 || col == "" || !contains(entryKinds, kind) {
			return nil, usageError("--matcher %q: expected COLUMN=KIND:VALUE, KIND one of %s", m, strings.Join(entryKinds, ", "))
		}
		fields[col] = append(fields[col], tableEntry{Kind: kind, Value: val})
	}
	return fields, nil
}

// apply sets the row's expiry, note and reference from --from-json, then from
// the flags, which win.
func (rf *rowFlags) apply(row *tableRow, cmd *cobra.Command) {
	for _, m := range []struct {
		flag string
		file *string
		val  string
		dst  *string
	}{
		{"expires", rf.fileExpires, rf.expires, &row.ExpiresAt},
		{"note", rf.fileNote, rf.note, &row.Note},
		{"reference", rf.fileReference, rf.reference, &row.Reference},
	} {
		if m.file != nil {
			*m.dst = *m.file
		}
		if cmd.Flags().Changed(m.flag) {
			*m.dst = m.val
		}
	}
}

// rowIDPattern is what the server accepts as a row id.
var rowIDPattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_\-]*$`)

// newRowID is an id for a row added without one: the server requires an id
// and assigns none.
func newRowID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "row-" + hex.EncodeToString(b), nil
}

func (a *app) rowsAddCmd() *cobra.Command {
	var rf rowFlags
	var id string
	cmd := &cobra.Command{
		Use:   "add <table>",
		Short: "Add a row",
		Long: "Add a row. Give each column's values with --value COLUMN=VALUE (a literal) or --matcher " +
			"COLUMN=KIND:VALUE (a CIDR, prefix, wildcard… on a matchable column), or the whole row with --from-json.\n\n" +
			"  clerk-protect tables rows add blocked_networks --matcher network=cidr:203.0.113.0/24 --value reason='abuse'",
		Args: exactArgs(1, "a table name"),
		RunE: func(cmd *cobra.Command, args []string) error {
			if rf.empty() {
				return usageError("give the row's values with --value, --matcher or --from-json")
			}
			fields, err := rf.fields(a.stdin)
			if err != nil {
				return err
			}
			if id == "" && rf.fileID != nil {
				id = *rf.fileID
			}
			if id == "" {
				if id, err = newRowID(); err != nil {
					return err
				}
			} else if !rowIDPattern.MatchString(id) {
				return usageError("--id %q: a row id starts with a letter and holds only letters, digits, _ and -", id)
			}
			row := tableRow{ID: id, Fields: fields}
			rf.apply(&row, cmd)
			if err := a.requireConsent(); err != nil {
				return err
			}
			c, _, err := a.client()
			if err != nil {
				return err
			}
			// A row write is a replacement by id, so adding under an id that is
			// taken would silently overwrite that row. Refuse, as the console does.
			existing, err := getRowRaw(ctxOf(cmd), c, args[0], id)
			if err != nil {
				return err
			}
			if existing != nil {
				return usageError("table %s already has a row %s — `rows update` or `rows set` changes it", args[0], id)
			}
			if err := a.confirm("Add a row to table " + args[0]); err != nil {
				return err
			}
			resp, err := c.Do(ctxOf(cmd), http.MethodPost, api.Path("tables", args[0], "rows"), nil, row)
			if err != nil {
				return err
			}
			return a.reportRow(resp, "Added row", args[0])
		},
	}
	rf.register(cmd)
	cmd.Flags().StringVar(&id, "id", "", "The row's id (default: a generated one)")
	return cmd
}

func (a *app) rowsSetCmd() *cobra.Command {
	var rf rowFlags
	cmd := &cobra.Command{
		Use:   "set <table> <row-id>",
		Short: "Replace a row with exactly the values given",
		Long: "Replace a row with exactly the values given — columns not given are emptied, as are the expiry, " +
			"note and reference unless given. To change some columns and keep the rest, use `rows update`.",
		Args: exactArgs(2, "a table name and a row id"),
		RunE: func(cmd *cobra.Command, args []string) error {
			if rf.empty() {
				return usageError("give the row's values with --value, --matcher or --from-json")
			}
			fields, err := rf.fields(a.stdin)
			if err != nil {
				return err
			}
			c, _, err := a.client()
			if err != nil {
				return err
			}
			stored, err := getRowRaw(ctxOf(cmd), c, args[0], args[1])
			if err != nil {
				return err
			}
			if stored == nil {
				return fmt.Errorf("table %s has no row %s — `rows add --id %s` creates it", args[0], args[1], args[1])
			}
			// Replace what the person owns — the values, expiry, note and
			// reference — and carry back what the server recorded about the row
			// (who added it, when, from where), which a save would otherwise erase.
			out := map[string]json.RawMessage{}
			for _, k := range provenanceKeys {
				if v, ok := stored[k]; ok {
					out[k] = v
				}
			}
			row := tableRow{ID: args[1], Fields: fields}
			rf.apply(&row, cmd)
			if err := mergeRow(out, row); err != nil {
				return err
			}
			return a.putRowRaw(cmd, args[0], args[1], out, "Replace row "+args[1]+" in table "+args[0], "Replaced row")
		},
	}
	rf.register(cmd)
	return cmd
}

func (a *app) rowsUpdateCmd() *cobra.Command {
	var rf rowFlags
	var clear []string
	cmd := &cobra.Command{
		Use:   "update <table> <row-id>",
		Short: "Change some of a row's columns, keeping the rest",
		Long: "Change some of a row's columns and keep the others. Each column named by --value, --matcher or " +
			"--from-json is replaced with what is given; --clear empties a column. The expiry, note and reference " +
			"change only when given.",
		Args: exactArgs(2, "a table name and a row id"),
		RunE: func(cmd *cobra.Command, args []string) error {
			if rf.empty() && len(clear) == 0 && !cmd.Flags().Changed("expires") &&
				!cmd.Flags().Changed("note") && !cmd.Flags().Changed("reference") {
				return usageError("nothing to change — give --value, --matcher, --from-json, --clear, --expires, --note or --reference")
			}
			changes, err := rf.fields(a.stdin)
			if err != nil {
				return err
			}
			c, _, err := a.client()
			if err != nil {
				return err
			}
			// Read as raw JSON and written back as a whole: the server's row write
			// is a replacement, so every field this command does not name —
			// including ones this CLI does not know — is kept only because it was
			// read first and sent back untouched.
			stored, err := getRowRaw(ctxOf(cmd), c, args[0], args[1])
			if err != nil {
				return err
			}
			if stored == nil {
				return fmt.Errorf("table %s has no row %s", args[0], args[1])
			}
			var current tableRow
			if raw, ok := stored["fields"]; ok {
				_ = json.Unmarshal(raw, &current.Fields)
			}
			if current.Fields == nil {
				current.Fields = map[string][]tableEntry{}
			}
			for col, entries := range changes {
				current.Fields[col] = entries
			}
			for _, col := range clear {
				delete(current.Fields, col)
			}
			current.ExpiresAt, current.Note, current.Reference = rawString(stored, "expires_at"), rawString(stored, "note"), rawString(stored, "reference")
			rf.apply(&current, cmd)
			if err := mergeRow(stored, current); err != nil {
				return err
			}
			return a.putRowRaw(cmd, args[0], args[1], stored, "Update row "+args[1]+" in table "+args[0], "Updated row")
		},
	}
	rf.register(cmd)
	cmd.Flags().StringArrayVar(&clear, "clear", nil, "Empty a column (repeatable)")
	return cmd
}

// provenanceKeys are what the server records about a row rather than what a
// person writes into it. A replacement must send them back or lose them.
var provenanceKeys = []string{"added_by", "added_at", "source", "first_observed"}

// getRowRaw reads one row as raw JSON fields, or nil when there is no such row.
func getRowRaw(ctx context.Context, c *api.Client, table, id string) (map[string]json.RawMessage, error) {
	resp, err := c.Do(ctx, http.MethodGet, api.Path("tables", table, "rows", id), nil, nil)
	if err != nil {
		var he *httperr.Error
		if errors.As(err, &he) && he.Status == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		return nil, fmt.Errorf("reading row %s: %w", id, err)
	}
	return out, nil
}

// mergeRow writes row's person-owned fields — id, values, expiry, note and
// reference — into out, dropping an optional one that is empty.
func mergeRow(out map[string]json.RawMessage, row tableRow) error {
	set := func(k string, v any) error {
		raw, err := json.Marshal(v)
		if err != nil {
			return err
		}
		out[k] = raw
		return nil
	}
	if err := set("id", row.ID); err != nil {
		return err
	}
	if err := set("fields", row.Fields); err != nil {
		return err
	}
	for k, v := range map[string]string{"expires_at": row.ExpiresAt, "note": row.Note, "reference": row.Reference} {
		if v == "" {
			delete(out, k)
			continue
		}
		if err := set(k, v); err != nil {
			return err
		}
	}
	return nil
}

func rawString(m map[string]json.RawMessage, k string) string {
	var s string
	if raw, ok := m[k]; ok {
		_ = json.Unmarshal(raw, &s)
	}
	return s
}

func (a *app) putRowRaw(cmd *cobra.Command, table, id string, row map[string]json.RawMessage, question, verb string) error {
	if err := a.requireConsent(); err != nil {
		return err
	}
	c, _, err := a.client()
	if err != nil {
		return err
	}
	if err := a.confirm(question); err != nil {
		return err
	}
	resp, err := c.Do(ctxOf(cmd), http.MethodPut, api.Path("tables", table, "rows", id), nil, row)
	if err != nil {
		return err
	}
	return a.reportRow(resp, verb, table)
}

func (a *app) rowsDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <table> <row-id>",
		Short: "Delete a row",
		Args:  exactArgs(2, "a table name and a row id"),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.requireConsent(); err != nil {
				return err
			}
			c, _, err := a.client()
			if err != nil {
				return err
			}
			if err := a.confirm("Delete row " + args[1] + " from table " + args[0]); err != nil {
				return err
			}
			resp, err := c.Do(ctxOf(cmd), http.MethodDelete, api.Path("tables", args[0], "rows", args[1]), nil, nil)
			if err != nil {
				return err
			}
			if a.jsonOut {
				return a.printRaw(orEmptyObject(resp.Body))
			}
			a.printf("%s %s from %s.\n", a.out.Good("Deleted row"), a.out.ID(args[1]), a.out.ID(args[0]))
			return nil
		},
	}
}

// --- helpers --------------------------------------------------------------------

// listAllRows follows next_page_token until the table is read or limit rows
// are in hand (0: all).
func listAllRows(ctx context.Context, c *api.Client, table string, limit int) ([]tableRow, error) {
	var all []tableRow
	after := ""
	for {
		q := url.Values{"limit": {"500"}}
		if after != "" {
			q.Set("after", after)
		}
		var page struct {
			Rows          []tableRow `json:"rows"`
			NextPageToken string     `json:"next_page_token"`
		}
		if err := c.JSON(ctx, http.MethodGet, api.Path("tables", table, "rows"), q, nil, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Rows...)
		if limit > 0 && len(all) >= limit {
			return all[:limit], nil
		}
		if page.NextPageToken == "" || len(page.Rows) == 0 {
			return all, nil
		}
		after = page.NextPageToken
	}
}

func (a *app) rawGet(cmd *cobra.Command, c *api.Client, path string, q url.Values) error {
	resp, err := c.Do(ctxOf(cmd), http.MethodGet, path, q, nil)
	if err != nil {
		return err
	}
	return a.printRaw(resp.Body)
}

// printRows prints rows as a table: id, then one column per table column, each
// cell its entries (a matcher shown as kind:value), then expiry. summary, when
// set, is printed on stderr after the table. With --json the rows are printed
// as a JSON list.
func (a *app) printRows(rows []tableRow, summary string) error {
	if a.jsonOut {
		return a.printJSON(map[string]any{"rows": rows})
	}
	if len(rows) == 0 {
		a.printf("No rows.\n")
		if summary != "" {
			a.notef("%s\n", a.errp.Muted(summary))
		}
		return nil
	}
	cols := map[string]bool{}
	for _, r := range rows {
		for col := range r.Fields {
			cols[col] = true
		}
	}
	names := make([]string, 0, len(cols))
	for col := range cols {
		names = append(names, col)
	}
	sort.Strings(names)
	header := append([]string{"ID"}, upper(names)...)
	header = append(header, "EXPIRES")
	tw := a.table()
	tw.Header(header...)
	tw.Style(0, a.out.ID)
	for _, r := range rows {
		cells := []any{r.ID}
		for _, col := range names {
			cells = append(cells, formatEntries(r.Fields[col]))
		}
		cells = append(cells, orDash(r.ExpiresAt))
		tw.Row(cells...)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if summary != "" {
		a.notef("%s\n", a.errp.Muted(summary))
	}
	return nil
}

func (a *app) reportTable(resp *api.Response, verb, name string) error {
	if a.jsonOut {
		return a.printRaw(orEmptyObject(resp.Body))
	}
	a.printf("%s %s.\n", a.out.Good(verb), a.out.ID(name))
	return nil
}

func (a *app) reportRow(resp *api.Response, verb, table string) error {
	if a.jsonOut {
		return a.printRaw(orEmptyObject(resp.Body))
	}
	var row tableRow
	_ = json.Unmarshal(resp.Body, &row)
	a.printf("%s %s in %s.\n", a.out.Good(verb), a.out.ID(orDash(row.ID)), a.out.ID(table))
	return nil
}

// parseColumn reads NAME:TYPE[:matchable][:required].
func parseColumn(spec string) (tableColumn, error) {
	parts := strings.Split(spec, ":")
	if len(parts) < 2 || parts[0] == "" {
		return tableColumn{}, usageError("--column %q: expected NAME:TYPE[:matchable][:required]", spec)
	}
	col := tableColumn{Name: parts[0], Type: strings.ToUpper(parts[1])}
	if !contains(columnTypes, col.Type) {
		return tableColumn{}, usageError("--column %q: type must be one of %s", spec, strings.Join(columnTypes, ", "))
	}
	for _, flag := range parts[2:] {
		switch strings.ToLower(flag) {
		case "matchable":
			col.Matchable = true
		case "required":
			col.Required = true
		default:
			return tableColumn{}, usageError("--column %q: %q is not matchable or required", spec, flag)
		}
	}
	return col, nil
}

func columnSummary(cols []tableColumn) string {
	parts := make([]string, 0, len(cols))
	for _, c := range cols {
		s := c.Name + ":" + strings.ToLower(c.Type)
		if c.Matchable {
			s += "*"
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ", ")
}

func formatEntries(entries []tableEntry) string {
	parts := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.Kind == "" || strings.EqualFold(e.Kind, "LITERAL") {
			parts = append(parts, e.Value)
		} else {
			parts = append(parts, strings.ToLower(e.Kind)+":"+e.Value)
		}
	}
	return strings.Join(parts, ", ")
}

func rowContains(r tableRow, text string) bool {
	needle := strings.ToLower(text)
	if strings.Contains(strings.ToLower(r.ID), needle) || strings.Contains(strings.ToLower(r.Note), needle) {
		return true
	}
	for _, entries := range r.Fields {
		for _, e := range entries {
			if strings.Contains(strings.ToLower(e.Value), needle) {
				return true
			}
		}
	}
	return false
}

func orEmptyObject(b []byte) []byte {
	if len(strings.TrimSpace(string(b))) == 0 {
		return []byte("{}")
	}
	return b
}

func upper(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = strings.ToUpper(s)
	}
	return out
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
