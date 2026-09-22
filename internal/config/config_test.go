package config

import (
	"path/filepath"
	"testing"
)

func TestDir_honoursItsOwnVariableOnly(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(EnvConfigDir, dir)
	// The variable another Clerk tool reads must not move this one.
	t.Setenv("CLERK_CONFIG_DIR", filepath.Join(dir, "somewhere-else"))
	got, err := Dir()
	if err != nil {
		t.Fatal(err)
	}
	if got != dir {
		t.Fatalf("Dir() = %q, want %q", got, dir)
	}
}

func TestAPIBase(t *testing.T) {
	t.Setenv(EnvAPIURL, "")
	cases := []struct {
		flag, env, profile, want, source string
		wantErr                          bool
	}{
		{want: DefaultAPIBase, source: SourceDefault},
		{flag: "https://example.test/", want: "https://example.test", source: SourceFlag},
		{env: "https://env.example.test", want: "https://env.example.test", source: SourceEnv},
		{flag: "https://flag.example.test", env: "https://env.example.test", want: "https://flag.example.test", source: SourceFlag},
		{profile: "https://profile.example.test", want: "https://profile.example.test", source: SourceProfile},
		// The environment beats a profile, and the flag beats both.
		{env: "https://env.example.test", profile: "https://profile.example.test", want: "https://env.example.test", source: SourceEnv},
		{flag: "https://flag.example.test", env: "https://env.example.test", profile: "https://profile.example.test", want: "https://flag.example.test", source: SourceFlag},
		{flag: "http://127.0.0.1:8080", want: "http://127.0.0.1:8080", source: SourceFlag},
		{flag: "http://localhost:5173", want: "http://localhost:5173", source: SourceFlag},
		{flag: "http://example.test", wantErr: true},
		{flag: "https://example.test/labs", wantErr: true},
		{flag: "https://user:pw@example.test", wantErr: true},
		{flag: "https://example.test?x=1", wantErr: true},
		{flag: "ftp://example.test", wantErr: true},
		{flag: "example.test", wantErr: true},
		{profile: "http://example.test", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.flag+"|"+tc.env+"|"+tc.profile, func(t *testing.T) {
			t.Setenv(EnvAPIURL, tc.env)
			got, source, err := APIBase(tc.flag, tc.profile)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("APIBase(%q, %q) = %q, want an error", tc.flag, tc.profile, got)
				}
				return
			}
			if err != nil || got != tc.want || source != tc.source {
				t.Fatalf("APIBase(%q, %q) = %q from %q, %v; want %q from %q", tc.flag, tc.profile, got, source, err, tc.want, tc.source)
			}
		})
	}
}

func TestParseAPIBase_refusesAnEmptyOrigin(t *testing.T) {
	if _, err := ParseAPIBase("  "); err == nil {
		t.Fatal("an empty API URL was accepted")
	}
}
