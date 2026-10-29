package host

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSaveStateIsPrivateAndAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	// An existing state file with wider permissions (an older build, cp, umask).
	if err := os.WriteFile(path, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	nodes := []Node{{Name: "a", Key: "k1"}, {Name: "b", Key: "k2"}}
	if err := SaveState(nodes, path); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Fatalf("state file mode %o, want 600", perm)
		}
	}
	got, err := LoadState(path)
	if err != nil || len(got) != 2 || got[1].Key != "k2" {
		t.Fatalf("LoadState = %+v, %v", got, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
}

func TestSaveStateRelativePath(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := SaveState([]Node{{Name: "a"}}, "state.json"); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState("state.json"); err != nil {
		t.Fatal(err)
	}
}
