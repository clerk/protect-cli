// Package profile keeps named choices of the instance, and the API origin,
// commands act on — so a person or a script working with one instance does not
// repeat --instance on every command.
//
// A profile is a DEFAULT, never a credential: it names an instance, and a
// command still needs a sign-in for that instance.
//
// EVERY PROBLEM IS AN ERROR. A profile that silently stopped applying — a file
// that failed to parse, a selected name that no longer exists — would not make
// a command fail. The command would fall back to the instance signed in to last,
// and an unflagged `rules delete --yes` would land on a different instance than
// the one the profile named.
package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/clerk/protect-cli/internal/auth"
	"github.com/clerk/protect-cli/internal/config"
	"github.com/clerk/protect-cli/internal/fsutil"
)

// EnvProfile selects a profile by name. The --profile flag wins over it.
const EnvProfile = "CLERK_PROTECT_PROFILE"

// Where a selected profile came from, as Selected reports it.
const (
	SourceFlag    = "--profile"
	SourceEnv     = EnvProfile
	SourceDefault = "default profile"
)

const fileName = "profiles.json"

// Profile is one named choice. Either field may be empty; not both.
type Profile struct {
	InstanceID string `json:"instance_id,omitempty"`
	APIURL     string `json:"api_url,omitempty"`
}

// Set is the profiles file: every profile, and which one is the default.
type Set struct {
	Default  string             `json:"default,omitempty"`
	Profiles map[string]Profile `json:"profiles"`
}

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// ValidName reports whether s can name a profile.
func ValidName(s string) bool { return nameRe.MatchString(s) }

// Path is the profiles file in a configuration directory.
func Path(dir string) string { return filepath.Join(dir, fileName) }

// Load reads the profiles in dir. No file means no profiles; a file that cannot
// be read, parsed or validated is an error that names it.
func Load(dir string) (*Set, error) {
	path := Path(dir)
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Set{Profiles: map[string]Profile{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var s Set
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("the profiles file %s is unreadable: %w", path, err)
	}
	if s.Profiles == nil {
		s.Profiles = map[string]Profile{}
	}
	if err := s.validate(); err != nil {
		return nil, fmt.Errorf("the profiles file %s: %w", path, err)
	}
	return &s, nil
}

// Save validates the set and writes it atomically, readable only by this user.
func (s *Set) Save(dir string) error {
	if err := s.validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(Path(dir), append(data, '\n'), 0o600)
}

func (s *Set) validate() error {
	for _, name := range s.Names() {
		if err := Check(name, s.Profiles[name]); err != nil {
			return err
		}
	}
	if s.Default != "" {
		if _, ok := s.Profiles[s.Default]; !ok {
			return fmt.Errorf("the default profile %q does not exist", s.Default)
		}
	}
	return nil
}

// Names lists the profiles in order.
func (s *Set) Names() []string {
	names := make([]string, 0, len(s.Profiles))
	for name := range s.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Check validates one profile.
func Check(name string, p Profile) error {
	if !ValidName(name) {
		return fmt.Errorf("%q cannot name a profile: use letters, digits, '.', '_' and '-', starting with a letter or digit", name)
	}
	if p.InstanceID == "" && p.APIURL == "" {
		return fmt.Errorf("profile %q names neither an instance nor an API URL", name)
	}
	if p.InstanceID != "" && !auth.ValidInstanceID(p.InstanceID) {
		return fmt.Errorf("profile %q: %q is not an instance id (they look like ins_…)", name, p.InstanceID)
	}
	if p.APIURL != "" {
		if _, err := config.ParseAPIBase(p.APIURL); err != nil {
			return fmt.Errorf("profile %q: %w", name, err)
		}
	}
	return nil
}

// Selected names the profile a command uses, and where that choice came from:
// the flag, then the environment, then the default. No name means no profile.
//
// A name that was asked for and does not exist is an error, whichever of the
// three asked: falling back to no profile is exactly the silent failure this
// package exists to refuse.
func (s *Set) Selected(flag string) (name, source string, err error) {
	switch {
	case strings.TrimSpace(flag) != "":
		name, source = strings.TrimSpace(flag), SourceFlag
	case strings.TrimSpace(os.Getenv(EnvProfile)) != "":
		name, source = strings.TrimSpace(os.Getenv(EnvProfile)), SourceEnv
	case s.Default != "":
		name, source = s.Default, SourceDefault
	default:
		return "", "", nil
	}
	if _, ok := s.Profiles[name]; !ok {
		return "", "", fmt.Errorf("there is no profile named %q (from %s); `clerk-protect profile list` shows the profiles on this computer", name, source)
	}
	return name, source, nil
}
