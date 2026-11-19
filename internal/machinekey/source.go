package machinekey

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// A SOURCE names where a machine key's private half comes from at run time.
//
//	file:/etc/clerk-protect/key.pem    a file (a bare path works too)
//	env:CLERK_PROTECT_MACHINE_KEY_PEM  an environment variable holding the PEM
//	exec:/usr/local/bin/fetch-key ci   a command whose standard output is the PEM
//	keystore:ci-runner                 a non-extractable key on this computer
//	kms-aws:alias/clerk-protect        a key held in AWS KMS (kms.go)
//	kms-gcp:projects/…/cryptoKeyVersions/1  a key held in Google Cloud KMS
//
// and, as shorthands for exec with each store's own command-line tool — which
// therefore has to be installed and signed in, with whatever identity the
// server already has (an instance role, a workload identity, a service account
// token):
//
//	aws-ssm:/prod/clerk-protect/key           aws ssm get-parameter --with-decryption
//	gcp-secret:projects/P/secrets/S[/versions/V]  gcloud secrets versions access
//	vault:secret/data/clerk-protect#key       vault kv get -field=key
//	op://Infra/clerk-protect/private-key      op read
//
// WHY COMMANDS AND NOT SDKs. This program links a short, reviewed list of
// modules, and each cloud's SDK would add hundreds. More to the point, every one
// of these stores already delivers secrets to processes as a file, an
// environment variable or its own CLI's output, with the store's own access
// control and audit — so reading from those three is reading from all of them.
//
// Nothing here is a shell: exec splits on spaces and runs the program directly,
// so a source cannot smuggle in a pipeline. A source that needs quoting belongs
// in a small script that exec names.

// SourceKind is what a source spec resolved to, for display.
type SourceKind string

const (
	SourceFile     SourceKind = "file"
	SourceEnv      SourceKind = "env"
	SourceExec     SourceKind = "exec"
	SourceKeystore SourceKind = "keystore"
	SourceAWSKMS   SourceKind = "kms-aws"
	SourceGCPKMS   SourceKind = "kms-gcp"
)

// execTimeout bounds a source command: a secret-store CLI waiting on an
// interactive sign-in would otherwise hang a server's job forever.
const execTimeout = 30 * time.Second

// maxSecret bounds what a source may produce. A P-256 PEM is a few hundred
// bytes; anything near this is the wrong secret.
const maxSecret = 64 << 10

var (
	gcpSecretRe = regexp.MustCompile(`^projects/([A-Za-z0-9-]{1,64})/secrets/([A-Za-z0-9_-]{1,255})(?:/versions/([A-Za-z0-9_-]{1,64}))?$`)
	envNameRe   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// runner runs a command and returns its standard output. A variable so tests
// can see the argv a shorthand expands to without the vendor tool installed.
var runner = func(ctx context.Context, argv []string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // G204: the operator's own configured source
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &stdout, n: maxSecret}
	cmd.Stderr = &limitedWriter{w: &stderr, n: 4 << 10}
	cmd.Stdin = nil
	// CommandContext kills only the direct child at the deadline. A child that
	// started its own process holding stdout open would keep Run waiting for the
	// pipe to close, past the limit; WaitDelay bounds that wait.
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("%s did not finish within %s", argv[0], execTimeout)
		}
		if msg != "" {
			return nil, fmt.Errorf("%s failed: %v: %s", argv[0], err, firstLine(msg))
		}
		return nil, fmt.Errorf("%s failed: %w", argv[0], err)
	}
	return stdout.Bytes(), nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if len(p) > l.n {
		return 0, errors.New("the key source produced too much output")
	}
	l.n -= len(p)
	return l.w.Write(p)
}

// Expand turns a source spec into what to read: a kind, and the path, variable
// name, argv or key name. Exported for `machine-key status`, which shows what a
// source would run without running it.
func Expand(spec string) (SourceKind, []string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", nil, errors.New("no machine key source given")
	}
	if strings.HasPrefix(spec, "-") {
		return "", nil, fmt.Errorf("a key source must not start with '-' (got %q)", spec)
	}
	noDash := func(what, v string) error {
		if v == "" || strings.HasPrefix(v, "-") {
			return fmt.Errorf("%s must not be empty or start with '-'", what)
		}
		return nil
	}
	switch {
	case strings.HasPrefix(spec, "file:"):
		p := strings.TrimPrefix(strings.TrimPrefix(spec, "file:"), "//")
		if err := noDash("a file path", p); err != nil {
			return "", nil, err
		}
		return SourceFile, []string{p}, nil
	case strings.HasPrefix(spec, "env:"):
		name := strings.TrimPrefix(spec, "env:")
		if !envNameRe.MatchString(name) {
			return "", nil, fmt.Errorf("%q is not an environment variable name", name)
		}
		return SourceEnv, []string{name}, nil
	case strings.HasPrefix(spec, "exec:"):
		argv := strings.Fields(strings.TrimPrefix(spec, "exec:"))
		if len(argv) == 0 {
			return "", nil, errors.New("exec: names no command")
		}
		if err := noDash("an exec command", argv[0]); err != nil {
			return "", nil, err
		}
		return SourceExec, argv, nil
	case strings.HasPrefix(spec, "keystore:"):
		name := strings.TrimPrefix(spec, "keystore:")
		if !ValidName(name) {
			return "", nil, fmt.Errorf("%q is not a key name", name)
		}
		return SourceKeystore, []string{name}, nil
	case strings.HasPrefix(spec, "kms-aws:"):
		id := strings.TrimPrefix(spec, "kms-aws:")
		if !awsKeyRe.MatchString(id) {
			return "", nil, fmt.Errorf("%q is not an AWS KMS key id, key ARN or alias", id)
		}
		return SourceAWSKMS, []string{id}, nil
	case strings.HasPrefix(spec, "kms-gcp:"):
		name := strings.TrimPrefix(spec, "kms-gcp:")
		if !gcpKeyRe.MatchString(name) {
			return "", nil, errors.New("kms-gcp: wants projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/V")
		}
		return SourceGCPKMS, []string{name}, nil
	case strings.HasPrefix(spec, "aws-ssm:"):
		name := strings.TrimPrefix(spec, "aws-ssm:")
		if err := noDash("an SSM parameter name", name); err != nil {
			return "", nil, err
		}
		return SourceExec, []string{"aws", "ssm", "get-parameter", "--name", name, "--with-decryption",
			"--query", "Parameter.Value", "--output", "text"}, nil
	case strings.HasPrefix(spec, "gcp-secret:"):
		m := gcpSecretRe.FindStringSubmatch(strings.TrimPrefix(spec, "gcp-secret:"))
		if m == nil {
			return "", nil, errors.New("gcp-secret: wants projects/<project>/secrets/<secret>[/versions/<version>]")
		}
		version := m[3]
		if version == "" {
			version = "latest"
		}
		return SourceExec, []string{"gcloud", "secrets", "versions", "access", version, "--secret", m[2], "--project", m[1]}, nil
	case strings.HasPrefix(spec, "vault:"):
		path, field, ok := strings.Cut(strings.TrimPrefix(spec, "vault:"), "#")
		if !ok || field == "" {
			return "", nil, errors.New("vault: wants <path>#<field>")
		}
		if err := noDash("a vault path", path); err != nil {
			return "", nil, err
		}
		if strings.ContainsAny(field, " =") {
			return "", nil, fmt.Errorf("%q is not a vault field name", field)
		}
		return SourceExec, []string{"vault", "kv", "get", "-field=" + field, path}, nil
	case strings.HasPrefix(spec, "op://"):
		return SourceExec, []string{"op", "read", "--no-newline", spec}, nil
	case strings.Contains(spec, "://"), strings.HasPrefix(spec, "http:"), strings.HasPrefix(spec, "https:"):
		return "", nil, fmt.Errorf("%q is not a key source this program knows; use file:, env:, exec:, keystore:, kms-aws:, kms-gcp:, aws-ssm:, gcp-secret:, vault: or op://", spec)
	default:
		if i := strings.IndexByte(spec, ':'); i > 1 && !strings.ContainsAny(spec[:i], `/\.`) {
			// "foo:bar" with no path separator before the colon is a scheme this
			// program does not know, not a file name.
			return "", nil, fmt.Errorf("%q is not a key source this program knows; use file:, env:, exec:, keystore:, kms-aws:, kms-gcp:, aws-ssm:, gcp-secret:, vault: or op://", spec)
		}
		return SourceFile, []string{spec}, nil
	}
}

// Resolve loads the machine key a source names.
func Resolve(ctx context.Context, spec string) (*Key, error) {
	kind, args, err := Expand(spec)
	if err != nil {
		return nil, err
	}
	var data []byte
	var warning string
	switch kind {
	case SourceKeystore:
		return openStored(args[0])
	case SourceAWSKMS:
		return openAWSKMS(ctx, args[0])
	case SourceGCPKMS:
		return openGCPKMS(ctx, args[0])
	case SourceFile:
		info, err := os.Stat(args[0])
		if err != nil {
			return nil, fmt.Errorf("read the machine key: %w", err)
		}
		// Warned, not refused: a Kubernetes secret volume mounts files 0644 by
		// default, inside a container nothing else shares, and refusing would
		// break the commonest way a server is handed this key. Where other
		// accounts really can read it, they can act as it — that is worth
		// saying on every run.
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			warning = fmt.Sprintf("%s is readable by other accounts on this system (mode %04o); anyone who can read it can act as this key", args[0], info.Mode().Perm())
		}
		if info.Size() > maxSecret {
			return nil, fmt.Errorf("%s is too large to be a machine key", args[0])
		}
		if data, err = os.ReadFile(args[0]); err != nil {
			return nil, fmt.Errorf("read the machine key: %w", err)
		}
	case SourceEnv:
		v, ok := os.LookupEnv(args[0])
		if !ok {
			return nil, fmt.Errorf("%s is not set", args[0])
		}
		data = []byte(v)
	case SourceExec:
		if data, err = runner(ctx, args); err != nil {
			return nil, fmt.Errorf("fetch the machine key: %w", err)
		}
	}
	k, err := Parse(data)
	if err != nil {
		return nil, err
	}
	k.Warning = warning
	return k, nil
}
