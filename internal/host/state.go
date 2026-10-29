package host

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// LoadState loads nodes from a JSON file
func LoadState(filename string) ([]Node, error) {
	// #nosec G304 -- developer-supplied --nodes-file style path for a local
	// load-testing tool; runs with the developer's own privileges.
	data, err := os.ReadFile(filepath.Clean(filename))
	if err != nil {
		return nil, err
	}

	var nodes []Node
	if err := json.Unmarshal(data, &nodes); err != nil {
		return nil, err
	}

	return nodes, nil
}

// SaveState saves nodes to a JSON file. The file holds every node key, so it
// is always left with mode 0600 (an existing file with wider permissions is
// replaced, not rewritten in place). The write is atomic: the JSON goes to a
// temporary file in the same directory, is synced, then renamed over the old
// file, so a crash mid-write never leaves a truncated state.
func SaveState(nodes []Node, filename string) (err error) {
	data, err := json.MarshalIndent(nodes, "", "  ")
	if err != nil {
		return err
	}
	dir, base := filepath.Split(filepath.Clean(filename))
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if err = tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filename)
}
