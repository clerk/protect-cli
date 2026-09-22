package auth

import (
	"strings"
	"testing"
)

// Instance ids can carry underscores, so a sign-in for one must store, become
// current and load like any other,
// while anything that could leave the credentials directory is still refused.
func TestStore_instanceIDsWithUnderscores(t *testing.T) {
	st := Store{Dir: t.TempDir()}
	const base = "https://dashboard.example.test"
	c := &Credentials{APIBase: base, InstanceID: "ins_example_2", Subject: "user_1", AccessToken: "tok"}
	if err := st.Save(c); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := st.SetCurrent(base, "ins_example_2"); err != nil {
		t.Fatalf("SetCurrent: %v", err)
	}
	got, err := st.Load(base, "")
	if err != nil || got.InstanceID != "ins_example_2" {
		t.Fatalf("Load: %+v, %v", got, err)
	}
	for _, bad := range []string{"ins_", "ins_../x", "ins_a/b", "ins_a.b", "../ins_a", "ins_" + strings.Repeat("a", 65)} {
		if ValidInstanceID(bad) {
			t.Errorf("ValidInstanceID(%q) = true", bad)
		}
	}
}
