package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/clerk/protect-cli/internal/fsutil"
)

// Credentials is one instance's sign-in, as stored.
//
// The access token is useless without this machine's device key: every request
// must carry a proof signed by the key the token is bound to. It is still
// written 0600 and never printed, because "useless without the key" is a
// property of the server, and a file mode is a property of this machine.
type Credentials struct {
	APIBase     string   `json:"api_base"`
	InstanceID  string   `json:"instance_id"`
	Subject     string   `json:"subject"`
	Email       string   `json:"email,omitempty"`
	Scopes      []string `json:"scopes"`
	GrantID     string   `json:"grant_id"`
	AccessToken string   `json:"access_token"`
	// IssuedAt is when this machine received the token, by its own clock. With
	// ExpiresAt it gives the token's lifetime, which decides when it is renewed.
	// Zero in a credential stored before it was recorded.
	IssuedAt               time.Time `json:"issued_at,omitzero"`
	ExpiresAt              time.Time `json:"expires_at"`
	AuthorizationExpiresAt time.Time `json:"authorization_expires_at"`
	// KeyThumbprint is the device key the token was bound to at sign-in. A
	// token bound to a key this machine no longer holds fails every request, so
	// a mismatch is detected here and reported as "sign in again" rather than as
	// a server refusal nobody can interpret.
	KeyThumbprint string `json:"key_thumbprint"`
}

// ErrNotLoggedIn means no stored credential matches.
var ErrNotLoggedIn = LoginRequired("not signed in")

// instanceRe is the shape of an instance id. Checked before an id becomes a
// file name, because it arrives from the server and from --instance, and
// "../.." is neither.
//
// Underscores included: the server issues tokens for ids that carry them, and a
// narrower shape here would let a sign-in complete and then refuse to store it.
// An underscore is as safe in a file name as a letter.
var instanceRe = regexp.MustCompile(`^ins_[A-Za-z0-9_]{1,64}$`)

// ValidInstanceID reports whether s is shaped like an instance id.
func ValidInstanceID(s string) bool { return instanceRe.MatchString(s) }

// Store keeps credentials under <config dir>/credentials/<api host>/, one file
// per instance, with a `current` pointer per API host.
//
// PER HOST, so a credential for one deployment is never presented to another:
// the token would be refused anyway, but "you are signed in" would be a lie.
type Store struct {
	Dir string
}

func hostKey(base string) (string, error) {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid API base %q", base)
	}
	key := strings.ToLower(strings.ReplaceAll(u.Host, ":", "_"))
	for _, r := range key {
		allowed := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_'
		if !allowed {
			return "", fmt.Errorf("API host %q cannot be used as a directory name", u.Host)
		}
	}
	return key, nil
}

func (s Store) root(base string) (string, error) {
	key, err := hostKey(base)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.Dir, "credentials", key), nil
}

// Save writes a credential. It does not change the current instance: a
// renewal saves too, and a renewal for --instance must not quietly become the
// default that the next unflagged change lands on. SetCurrent does that, and
// only `login` calls it.
func (s Store) Save(c *Credentials) error {
	if !ValidInstanceID(c.InstanceID) {
		return fmt.Errorf("refusing to store a credential for instance %q", c.InstanceID)
	}
	root, err := s.root(c.APIBase)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(filepath.Join(root, c.InstanceID+".json"), data, 0o600)
}

// SetCurrent makes an instance the one commands act on when --instance is not
// given, for one API host.
func (s Store) SetCurrent(base, instance string) error {
	if !ValidInstanceID(instance) {
		return fmt.Errorf("%q is not an instance id", instance)
	}
	root, err := s.root(base)
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(filepath.Join(root, "current"), []byte(instance+"\n"), 0o600)
}

// Current names the current instance for an API host, or "".
func (s Store) Current(base string) (string, error) {
	root, err := s.root(base)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(filepath.Join(root, "current"))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(data))
	if !ValidInstanceID(id) {
		return "", nil
	}
	return id, nil
}

// Load reads a credential. An empty instance means the current one.
func (s Store) Load(base, instance string) (*Credentials, error) {
	if instance == "" {
		cur, err := s.Current(base)
		if err != nil {
			return nil, err
		}
		if cur == "" {
			return nil, ErrNotLoggedIn
		}
		instance = cur
	}
	if !ValidInstanceID(instance) {
		return nil, fmt.Errorf("%q is not an instance id (they look like ins_…)", instance)
	}
	root, err := s.root(base)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(root, instance+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, LoginRequired("not signed in to " + instance)
	}
	if err != nil {
		return nil, err
	}
	var c Credentials
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("the stored credential for %s is unreadable: %w", instance, err)
	}
	if c.InstanceID != instance || c.APIBase != base {
		return nil, LoginRequired("the stored credential for " + instance + " does not match its file")
	}
	return &c, nil
}

// List returns every credential stored for an API host, by instance id.
func (s Store) List(base string) ([]*Credentials, error) {
	root, err := s.root(base)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []*Credentials
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !ValidInstanceID(id) {
			continue
		}
		if c, err := s.Load(base, id); err == nil {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].InstanceID < out[j].InstanceID })
	return out, nil
}

// Remove deletes one instance's credential (the current one when instance is
// empty) and clears the current pointer if it named that instance.
func (s Store) Remove(base, instance string) (string, error) {
	cur, err := s.Current(base)
	if err != nil {
		return "", err
	}
	if instance == "" {
		instance = cur
	}
	if instance == "" {
		return "", ErrNotLoggedIn
	}
	if !ValidInstanceID(instance) {
		return "", fmt.Errorf("%q is not an instance id", instance)
	}
	root, err := s.root(base)
	if err != nil {
		return "", err
	}
	if err := os.Remove(filepath.Join(root, instance+".json")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if cur == instance {
		if err := os.Remove(filepath.Join(root, "current")); err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
	}
	return instance, nil
}

// RemoveAll deletes every stored credential for every API host.
func (s Store) RemoveAll() error {
	return os.RemoveAll(filepath.Join(s.Dir, "credentials"))
}
