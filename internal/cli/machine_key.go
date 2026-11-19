package cli

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/spf13/cobra"

	"github.com/clerk/protect-cli/internal/api"
	"github.com/clerk/protect-cli/internal/dpop"
	"github.com/clerk/protect-cli/internal/machinekey"
	"github.com/clerk/protect-cli/internal/version"
)

const machineKeyHelp = `Machine keys let servers, CI jobs and other automation use clerk-protect
without a person signing in every eight hours.

  1. Create a key pair:
       clerk-protect machine-key create --out ./ci-key.pem        (extractable file)
       clerk-protect machine-key create --non-extractable --name ci  (stays on this computer)
  2. Register it, signed in as yourself:
       clerk-protect login
       clerk-protect machine-key register --key ./ci-key.pem --name "CI deploys"
  3. An administrator of the instance approves it once, in Protect Labs under
     Command-line access, choosing what it may do and for how long (up to a year).
  4. Put an extractable key in your secret storage, and give each server its source:
       CLERK_PROTECT_MACHINE_KEY=<source> clerk-protect rules list

Sources:
  file:/path/to/key.pem             a file (a bare path works too)
  env:VAR                           an environment variable holding the PEM
  exec:/path/to/command args        a command that prints the PEM (no shell)
  keystore:NAME                     a non-extractable key made on this computer
  kms-aws:KEY                       an AWS KMS key (id, ARN or alias/NAME; ECC_NIST_P256)
  kms-gcp:projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/V
                                    a Google Cloud KMS key version (EC_SIGN_P256_SHA256)
  aws-ssm:/param/name               AWS Systems Manager Parameter Store (runs the aws CLI)
  gcp-secret:projects/P/secrets/S   Google Cloud Secret Manager (runs gcloud)
  vault:path#field                  HashiCorp Vault KV (runs vault)
  op://vault/item/field             1Password (runs op)

The store's own CLI must be installed and signed in with the server's identity.
A KMS key never leaves the KMS: create it there, register it with --key kms-aws:…
or kms-gcp:…, and grant the server's identity permission to sign with it.

Each run makes a fresh in-memory session key, and the machine key signs once to
mint a five-minute token bound to it; every request after is signed by the
session key. Nothing is saved to disk.
Revoking the key in Protect Labs stops every copy of it within five minutes.`

func (a *app) machineKeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "machine-key",
		Short: "Create, register and list keys that let servers act for this instance",
		Long:  machineKeyHelp,
	}
	cmd.AddCommand(a.machineKeyCreateCmd(), a.machineKeyRegisterCmd(), a.machineKeyListCmd(), a.machineKeyTestCmd())
	return cmd
}

func (a *app) machineKeyCreateCmd() *cobra.Command {
	var out, name string
	var nonExtractable bool
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a machine key pair: an extractable file, or a key that cannot leave this computer",
		Long: "Creates a P-256 key pair for a server to authenticate with.\n\n" +
			"--out PATH writes an EXTRACTABLE private key to PATH (mode 0600). Copy it into your secret storage; " +
			"anyone who can read it can act as the key once it is approved.\n\n" +
			"--non-extractable --name NAME creates the key inside this computer's hardware key store " +
			"(the Secure Enclave on a Mac, the TPM or Windows key storage on Windows). It works only on this " +
			"computer, as keystore:NAME. Linux has no supported store; use --out there.",
		Args: noArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			var key *machinekey.Key
			var source string
			var err error
			switch {
			case nonExtractable && out != "":
				return usageError("use either --out or --non-extractable, not both")
			case nonExtractable:
				if name == "" {
					return usageError("--non-extractable needs --name")
				}
				if key, err = machinekey.GenerateStored(name); err != nil {
					return err
				}
				source = "keystore:" + name
			case out != "":
				if name != "" {
					return usageError("--name is for --non-extractable keys; a file is named by its path")
				}
				if key, err = machinekey.Generate(out); err != nil {
					return err
				}
				source = "file:" + out
			default:
				return usageError("say where the key goes: --out PATH (an extractable file) or --non-extractable --name NAME")
			}
			if a.jsonOut {
				return a.printJSON(map[string]any{
					"source": source, "key_thumbprint": key.Thumbprint, "fingerprint": dpop.Fingerprint(key.Thumbprint),
					"extractable": key.Extractable, "backend": key.Backend,
				})
			}
			a.printf("%s %s\n", a.out.Good("Created a machine key:"), source)
			a.printf("Key:         %s\n", a.out.Emphasis(groupedThumbprint(key.Thumbprint)))
			if key.Extractable {
				a.notef("%s the file is the credential once approved. Store it in your secret storage and delete local copies you do not need.\n",
					a.errp.Warn("Keep it secret:"))
			}
			a.notef("Next: clerk-protect machine-key register --key %s --name <label>\n", source)
			return nil
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "Write an extractable private key to this file")
	cmd.Flags().BoolVar(&nonExtractable, "non-extractable", false, "Create the key in this computer's hardware key store instead")
	cmd.Flags().StringVar(&name, "name", "", "Name of a --non-extractable key (used as keystore:NAME)")
	return cmd
}

func (a *app) machineKeyRegisterCmd() *cobra.Command {
	var source, name string
	var scopes []string
	cmd := &cobra.Command{
		Use:   "register",
		Short: "Ask for a machine key to be approved for this instance",
		Long: "Registers a machine key's public half with the instance you are signed in to, proving you hold its " +
			"private half. An administrator of the instance then approves it in Protect Labs, choosing what it may " +
			"do and for how long. Until then it can do nothing.\n\n" +
			"--scope narrows what you ask for (repeatable); by default you ask for everything you yourself may do " +
			"that a machine key may hold.",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if name == "" {
				return usageError("--name is required: it is what the administrator sees when approving")
			}
			if source == "" {
				return usageError("--key is required: the machine key's source (see `clerk-protect machine-key --help`)")
			}
			if a.machineKeySpec() != "" {
				return usageError("register signs in as you, not as a machine key; unset %s and drop --machine-key", machinekey.EnvMachineKey)
			}
			ctx := ctxOf(cmd)
			key, err := machinekey.Resolve(ctx, source)
			if err != nil {
				return err
			}
			client, creds, err := a.personClient()
			if err != nil {
				return err
			}
			if key.Thumbprint == creds.KeyThumbprint {
				return errors.New("that is this computer's sign-in key; create a separate key for the machine")
			}
			path := api.Path("cli", "machine-keys")
			proofs, err := dpop.NewBuilder(key.Signer)
			if err != nil {
				return err
			}
			proof, err := proofs.Proof(http.MethodPost, client.Base+path, "")
			if err != nil {
				return err
			}
			body := map[string]any{
				"name": name, "key_backend": key.Backend,
				"client_name": "clerk-protect", "client_version": version.Version,
			}
			if len(scopes) > 0 {
				body["requested_scopes"] = scopes
			}
			resp, err := client.DoWith(ctx, http.MethodPost, path, nil, body, map[string]string{"Machine-Key-Proof": proof})
			if err != nil {
				return err
			}
			if a.jsonOut {
				return a.printRaw(resp.Body)
			}
			var out struct {
				MachineKey  machineKeyRow `json:"machine_key"`
				ApprovalURL string        `json:"approval_url"`
			}
			if err := json.Unmarshal(resp.Body, &out); err != nil {
				return errors.New("the server returned an unreadable response")
			}
			a.printf("%s %s (%s)\n", a.out.Good("Registered:"), out.MachineKey.KeyID, out.MachineKey.Name)
			a.printf("Key:         %s\n", a.out.Emphasis(groupedThumbprint(out.MachineKey.KeyThumbprint)))
			a.printf("Asked for:   %s\n", strings.Join(out.MachineKey.RequestedScopes, ", "))
			a.notef("The administrator sees this whole key value when approving; read it to them to confirm.\n")
			a.notef("It does nothing until an administrator of %s approves it in Protect Labs: %s\n",
				creds.InstanceID, out.ApprovalURL)
			return nil
		},
	}
	cmd.Flags().StringVar(&source, "key", "", "The machine key's source: a file, env:, exec:, keystore:, kms-aws:, kms-gcp:, aws-ssm:, gcp-secret:, vault: or op://")
	cmd.Flags().StringVar(&name, "name", "", "A label for the administrator who approves it (up to 64 characters)")
	cmd.Flags().StringSliceVar(&scopes, "scope", nil, "A scope to ask for (repeatable); default: every scope you hold that a machine key may")
	return cmd
}

// groupedThumbprint is a key's whole RFC 7638 thumbprint in groups of four —
// the value the approval screen shows. The short fingerprint is 48 bits, too
// few to tell a ground-out lookalike from the real key at approval.
func groupedThumbprint(t string) string {
	var b strings.Builder
	for i := 0; i < len(t); i += 4 {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(t[i:min(i+4, len(t))])
	}
	return b.String()
}

// machineKeyRow is one machine key as the server lists it.
type machineKeyRow struct {
	KeyID           string   `json:"key_id"`
	Name            string   `json:"name"`
	State           string   `json:"state"`
	KeyThumbprint   string   `json:"key_thumbprint"`
	KeyBackend      string   `json:"key_backend"`
	RequestedScopes []string `json:"requested_scopes"`
	Scopes          []string `json:"scopes"`
	RequestedBy     string   `json:"requested_by"`
	RequestedEmail  string   `json:"requested_email"`
	ApprovedEmail   string   `json:"approved_email"`
	ApprovedBy      string   `json:"approved_by"`
	ExpiresAt       string   `json:"expires_at"`
	LastUsedAt      string   `json:"last_used_at"`
}

func (a *app) machineKeyListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the instance's machine keys: pending, approved, and recently revoked",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, _, err := a.client()
			if err != nil {
				return err
			}
			path := api.Path("cli", "machine-keys")
			if a.jsonOut {
				var raw json.RawMessage
				if err := client.JSON(ctxOf(cmd), http.MethodGet, path, nil, nil, &raw); err != nil {
					return err
				}
				return a.printRaw(raw)
			}
			var list struct {
				Enabled bool            `json:"enabled"`
				Keys    []machineKeyRow `json:"machine_keys"`
			}
			if err := client.JSON(ctxOf(cmd), http.MethodGet, path, nil, nil, &list); err != nil {
				return err
			}
			if !list.Enabled {
				return errors.New("machine keys are not enabled in this environment")
			}
			if len(list.Keys) == 0 {
				a.printf("This instance has no machine keys.\n")
				return nil
			}
			tw := a.table()
			tw.Header("ID", "NAME", "STATE", "FINGERPRINT", "ENDS", "LAST USED", "SCOPES")
			tw.Style(3, a.out.Emphasis)
			for _, k := range list.Keys {
				ends, scopes := "", k.RequestedScopes
				if k.State == "approved" {
					ends, scopes = until(a.now(), k.ExpiresAt), k.Scopes
				}
				tw.Row(k.KeyID, k.Name, k.State, dpop.Fingerprint(k.KeyThumbprint), orDash(ends), orDash(k.LastUsedAt),
					strings.Join(scopes, ","))
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			a.notef("%s\n", a.errp.Muted("Approve, deny or revoke keys in Protect Labs under Command-line access."))
			return nil
		},
	}
}

func (a *app) machineKeyTestCmd() *cobra.Command {
	var source string
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Mint a token with a machine key and show what it may do",
		Long: "Checks a machine key end to end: reads it from its source, asks for a token, and prints the " +
			"instance, scopes and approval end the server answered with. Uses --key, else --machine-key, else " +
			machinekey.EnvMachineKey + ".",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if source != "" {
				a.machineKey = source
			}
			if a.machineKeySpec() == "" {
				return usageError("no machine key: pass --key, --machine-key or set %s", machinekey.EnvMachineKey)
			}
			client, creds, err := a.client()
			if err != nil {
				return err
			}
			var me map[string]any
			if err := client.JSON(ctxOf(cmd), http.MethodGet, api.Path("me"), nil, nil, &me); err != nil {
				return err
			}
			if a.jsonOut {
				return a.printJSON(map[string]any{
					"key_id": creds.Subject, "instance_id": creds.InstanceID, "scopes": creds.Scopes,
					"token_expires_at": creds.ExpiresAt, "approval_expires_at": creds.AuthorizationExpiresAt,
					"fingerprint": dpop.Fingerprint(creds.KeyThumbprint), "server": me,
				})
			}
			tw := a.kvTable()
			row := func(k, v string) { _, _ = tw.Write([]byte(k + "\t" + v + "\n")) }
			row("Machine key", creds.Subject+" (fingerprint "+dpop.Fingerprint(creds.KeyThumbprint)+")")
			row("Instance", creds.InstanceID)
			row("Permissions", strings.Join(creds.Scopes, ", "))
			row("Approval ends", creds.AuthorizationExpiresAt.UTC().Format("2006-01-02 15:04 MST"))
			row("API", client.Base)
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&source, "key", "", "The machine key's source (default: --machine-key or "+machinekey.EnvMachineKey+")")
	return cmd
}
