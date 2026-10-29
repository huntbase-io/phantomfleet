package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestResolveSecret(t *testing.T) {
	dir := t.TempDir()
	file := writeFile(t, dir, "secret", "  from-file\n")
	empty := writeFile(t, dir, "empty", "\n")
	cases := []struct {
		flag, file, env, want string
		wantErr               bool
	}{
		{flag: "from-flag", env: "from-env", want: "from-flag"},
		{file: file, env: "from-env", want: "from-file"},
		{env: "from-env\n", want: "from-env"},
		{flag: "x", file: file, wantErr: true},
		{file: filepath.Join(dir, "missing"), wantErr: true},
		{file: empty, wantErr: true},
		{wantErr: true},
	}
	for i, c := range cases {
		got, err := resolveSecret(c.flag, c.file, c.env)
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("case %d: got %q, %v", i, got, err)
		}
	}
}
