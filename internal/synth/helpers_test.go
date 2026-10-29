package synth

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

// writeFile is a copy of the cli test helper of the same name.
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

// loaderInputs are the loader flags (--extra-schema, --catalog, --seeds-dir)
// a test passes to LoadData.
type loaderInputs struct {
	ExtraSchemas []string
	Catalogs     []string
	SeedsDirs    []string
}

// loadData runs LoadData on in, as the cli does.
func loadData(in loaderInputs, w io.Writer) error {
	return LoadData(in.ExtraSchemas, in.Catalogs, in.SeedsDirs, w)
}
