package profile

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestLoad_noFileIsNoProfiles(t *testing.T) {
	s, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Profiles) != 0 || s.Default != "" {
		t.Fatalf("got %+v, want no profiles", s)
	}
}

func TestSave_roundTripsAndIsPrivate(t *testing.T) {
	dir := t.TempDir()
	want := &Set{Default: "prod", Profiles: map[string]Profile{
		"prod":    {InstanceID: "ins_2abc"},
		"staging": {InstanceID: "ins_test_1", APIURL: "http://127.0.0.1:4000"},
	}}
	if err := want.Save(dir); err != nil {
		t.Fatal(err)
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Default != "prod" || got.Profiles["prod"] != want.Profiles["prod"] || got.Profiles["staging"] != want.Profiles["staging"] {
		t.Fatalf("round trip: got %+v, want %+v", got, want)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(Path(dir))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("profiles file mode %v, want 0600", info.Mode().Perm())
		}
	}
}

// A file that cannot be trusted is an error naming the file, never "no
// profiles": the second would send commands to the last instance signed in to.
func TestLoad_refusesAFileItCannotTrust(t *testing.T) {
	for name, content := range map[string]string{
		"not JSON":             `{"profiles":`,
		"a name with a slash":  `{"profiles":{"a/b":{"instance_id":"ins_2abc"}}}`,
		"not an instance id":   `{"profiles":{"prod":{"instance_id":"../ins_2abc"}}}`,
		"an empty profile":     `{"profiles":{"prod":{}}}`,
		"a missing default":    `{"default":"gone","profiles":{"prod":{"instance_id":"ins_2abc"}}}`,
		"a cleartext API URL":  `{"profiles":{"prod":{"api_url":"http://example.test"}}}`,
		"an API URL with path": `{"profiles":{"prod":{"api_url":"https://example.test/labs"}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(Path(dir), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(dir)
			if err == nil || !strings.Contains(err.Error(), Path(dir)) {
				t.Fatalf("Load = %v, want an error naming %s", err, Path(dir))
			}
		})
	}
}

func TestSave_refusesAnInvalidSet(t *testing.T) {
	for name, s := range map[string]*Set{
		"a bad name":        {Profiles: map[string]Profile{"-x": {InstanceID: "ins_2abc"}}},
		"a missing default": {Default: "prod", Profiles: map[string]Profile{}},
		"an empty profile":  {Profiles: map[string]Profile{"prod": {}}},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := s.Save(dir); err == nil {
				t.Fatal("Save accepted an invalid set")
			}
			if _, err := os.Stat(Path(dir)); !os.IsNotExist(err) {
				t.Fatalf("an invalid set was written: %v", err)
			}
		})
	}
}

func TestSelected_flagThenEnvironmentThenDefault(t *testing.T) {
	s := &Set{Default: "c", Profiles: map[string]Profile{
		"a": {InstanceID: "ins_a1"}, "b": {InstanceID: "ins_b1"}, "c": {InstanceID: "ins_c1"},
	}}
	for _, tc := range []struct {
		flag, env, want, source string
	}{
		{want: "c", source: SourceDefault},
		{env: "b", want: "b", source: SourceEnv},
		{flag: "a", env: "b", want: "a", source: SourceFlag},
	} {
		t.Setenv(EnvProfile, tc.env)
		name, source, err := s.Selected(tc.flag)
		if err != nil || name != tc.want || source != tc.source {
			t.Errorf("flag %q env %q: got %q from %q (%v), want %q from %q", tc.flag, tc.env, name, source, err, tc.want, tc.source)
		}
	}

	t.Setenv(EnvProfile, "")
	if name, _, err := (&Set{Profiles: map[string]Profile{}}).Selected(""); err != nil || name != "" {
		t.Fatalf("no profiles and none asked for: got %q, %v", name, err)
	}
}

// Asking for a profile that does not exist is an error from every source, not
// a quiet fall back to no profile.
func TestSelected_aMissingNameIsAnError(t *testing.T) {
	s := &Set{Profiles: map[string]Profile{"prod": {InstanceID: "ins_2abc"}}}
	t.Setenv(EnvProfile, "")
	if _, _, err := s.Selected("nope"); err == nil {
		t.Fatal("a missing --profile was accepted")
	}
	t.Setenv(EnvProfile, "nope")
	if _, _, err := s.Selected(""); err == nil {
		t.Fatal("a missing " + EnvProfile + " was accepted")
	}
}
