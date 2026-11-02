package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/spf13/cobra"

	"github.com/clerk/protect-cli/internal/api"
)

// Each request stays inside the API's page bound. The CLI combines pages only
// after every request succeeds, so an interrupted search prints no partial JSON.
const (
	insightsPageSize = 500
	maxSearchBytes   = 64 << 20
)

func (a *app) insightsSearchCmd() *cobra.Command {
	var q insightsQuery
	cmd := &cobra.Command{
		Use:   "search",
		Short: "List matching rows, newest first, following pages up to --limit",
		Long: `Return up to --limit rows as one JSON response, following the server's cursor
in pages of at most 500. The default is 100 rows. The response's window holds
the absolute from/to that was searched, and next_cursor continues after the
last row printed: pass both back with the same filters. When rows remain, the
continuation flags are also printed to stderr.

Buffered server responses must total less than 64 MiB. For larger exports, use
smaller limits and continue with --cursor. No result is printed if a page fails.`,
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			body, err := q.body(cmd, a.now(), a.readJSONFile)
			if err != nil {
				return err
			}
			if cmd.Flags().Changed("limit") {
				body["limit"], _ = cmd.Flags().GetInt("limit")
			}
			limit := 100
			if raw, ok := body["limit"]; ok {
				b, err := json.Marshal(raw)
				if raw == nil || err != nil || json.Unmarshal(b, &limit) != nil || limit <= 0 {
					return usageError("limit must be a positive whole number")
				}
			}
			if cmd.Flags().Changed("cursor") {
				body["cursor"], _ = cmd.Flags().GetString("cursor")
			}
			if exprs, _ := cmd.Flags().GetStringArray("computed"); len(exprs) > 0 {
				body["computed"] = exprs
			}
			c, _, err := a.client()
			if err != nil {
				return err
			}
			return a.searchInsights(cmd, c, body, limit)
		},
	}
	q.register(cmd)
	q.registerFlowID(cmd)
	cmd.Flags().Int("limit", 100, "Maximum total rows to return, following pages as needed")
	cmd.Flags().String("cursor", "", "Continue from a previous next_cursor; pass the --from/--to from its window and the same filters")
	cmd.Flags().StringArray("computed", nil, "Also answer this expression for every decision (repeatable)")
	return cmd
}

func (a *app) searchInsights(cmd *cobra.Command, c *api.Client, body map[string]any, limit int) error {
	rowKey := "decisions"
	switch body["unit"] {
	case "flows":
		rowKey = "flows"
	}
	var result map[string]json.RawMessage
	var rows []json.RawMessage
	seen := map[string]bool{}
	if cursor, _ := body["cursor"].(string); cursor != "" {
		seen[cursor] = true
	}
	totalBytes := 0
	for len(rows) < limit {
		pageSize := min(insightsPageSize, limit-len(rows))
		body["limit"] = pageSize
		resp, err := c.Do(ctxOf(cmd), http.MethodPost, api.Path("insights", "decisions", "search"), nil, body)
		if err != nil {
			return fmt.Errorf("search incomplete; no result printed: %w", err)
		}
		totalBytes += len(resp.Body)
		if totalBytes >= maxSearchBytes {
			return errors.New("search reached 64 MiB; use a smaller --limit and continue with --cursor; no result printed")
		}
		var page map[string]json.RawMessage
		if err := json.Unmarshal(resp.Body, &page); err != nil {
			return fmt.Errorf("unreadable search response: %w", err)
		}
		var batch []json.RawMessage
		if raw, ok := page[rowKey]; !ok || json.Unmarshal(raw, &batch) != nil {
			return fmt.Errorf("the server did not return %s", rowKey)
		}
		if len(batch) > pageSize {
			return errors.New("the server returned more rows than requested; no result printed")
		}
		var cursor string
		if raw, ok := page["next_cursor"]; ok {
			if err := json.Unmarshal(raw, &cursor); err != nil {
				return fmt.Errorf("unreadable search cursor: %w", err)
			}
		}
		if result == nil {
			result = page
			rows = batch
		} else if !sameSearchMetadata(result, page, rowKey) {
			return errors.New("search columns or metadata changed between pages; no result printed")
		} else {
			rows = append(rows, batch...)
		}
		cursorJSON := page["next_cursor"]
		if len(cursorJSON) > 0 {
			result["next_cursor"] = cursorJSON
		} else {
			delete(result, "next_cursor")
		}
		if cursor != "" {
			if len(batch) == 0 || seen[cursor] {
				return errors.New("search cursor did not advance; no result printed")
			}
			seen[cursor] = true
		}
		if cursor == "" {
			break
		}
		body["cursor"] = cursor
	}
	var err error
	result[rowKey], err = json.Marshal(rows)
	if err != nil {
		return err
	}
	// The cursor marks a row, not a window. A --since window is relative to
	// when it ran, so echo the absolute one that was sent; a continuation run
	// later with the same --since would start later and silently skip rows.
	result["window"], err = json.Marshal(map[string]any{"from": body["from"], "to": body["to"]})
	if err != nil {
		return err
	}
	out, err := json.Marshal(result)
	if err != nil {
		return err
	}
	if err := a.printRaw(out); err != nil {
		return err
	}
	var next string
	_ = json.Unmarshal(result["next_cursor"], &next)
	from, _ := body["from"].(string)
	to, _ := body["to"].(string)
	if next != "" && from != "" && to != "" {
		a.notef("More rows remain. Continue with the same filters and: --from %s --to %s --cursor %s\n", from, to, shellQuote(next))
	}
	return nil
}

// shellQuote makes a cursor safe to paste into a shell; decision cursors
// contain '|'.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func sameSearchMetadata(a, b map[string]json.RawMessage, rowKey string) bool {
	for key, value := range a {
		if key != rowKey && key != "next_cursor" && !bytes.Equal(value, b[key]) {
			return false
		}
	}
	for key := range b {
		if key != rowKey && key != "next_cursor" {
			if _, ok := a[key]; !ok {
				return false
			}
		}
	}
	return true
}
