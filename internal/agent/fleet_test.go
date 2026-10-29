package agent

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/huntbase-io/phantomfleet/internal/host"
	"github.com/huntbase-io/phantomfleet/internal/synth"
)

func testRand() *rand.Rand {
	return rand.New(rand.NewSource(1)) // #nosec G404 -- test fixture
}

func TestBuildNodesRefusesCorruptState(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state.json")
	// A state truncated by a crash mid-write.
	if err := os.WriteFile(state, []byte(`[{"name":"a","key":"k`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, cfg := range []Config{
		{Nodes: 5, StateFile: state},
		{Nodes: 5, StateFile: state, NodesFile: writeNodesFile(t, dir, 1)},
	} {
		if _, err := buildNodes(cfg, testRand()); err == nil || !strings.Contains(err.Error(), "cannot be loaded") {
			t.Errorf("nodes file %q: corrupt state accepted: %v", cfg.NodesFile, err)
		}
	}
	// The corrupt file is left for the user to inspect.
	if b, _ := os.ReadFile(state); !strings.Contains(string(b), `"k`) {
		t.Fatal("the corrupt state file was overwritten")
	}

	// A missing state file still starts a new fleet.
	nodes, err := buildNodes(Config{Nodes: 3, StateFile: filepath.Join(dir, "absent.json")}, testRand())
	if err != nil || len(nodes) != 3 {
		t.Fatalf("missing state: %d nodes, %v", len(nodes), err)
	}
}

func TestBuildNodesEnforcesLargeFleetOnFinalCount(t *testing.T) {
	dir := t.TempDir()

	// A state file with more than LargeFleet nodes, run with the default --nodes.
	state := filepath.Join(dir, "state.json")
	if err := host.SaveState(host.RandomNodes(LargeFleet+1, testRand(), nil, synth.ProfileOS), state); err != nil {
		t.Fatal(err)
	}
	// A nodes file pinning more than LargeFleet hosts.
	nodesFile := writeNodesFile(t, dir, LargeFleet+1)

	for name, cfg := range map[string]Config{
		"state":      {Nodes: 5, StateFile: state},
		"nodes file": {Nodes: 5, NodesFile: nodesFile},
	} {
		if _, err := buildNodes(cfg, testRand()); err == nil || !strings.Contains(err.Error(), "--allow-large-fleet") {
			t.Errorf("%s: large fleet accepted without the flag: %v", name, err)
		}
		cfg.AllowLargeFleet = true
		nodes, err := buildNodes(cfg, testRand())
		if err != nil || len(nodes) != LargeFleet+1 {
			t.Errorf("%s with the flag: %d nodes, %v", name, len(nodes), err)
		}
	}
}

// writeNodesFile writes a nodes file pinning n Linux hosts.
func writeNodesFile(t *testing.T, dir string, n int) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("nodes:\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "  - hostname: host-%d\n    platform: linux\n", i)
	}
	p := filepath.Join(dir, fmt.Sprintf("nodes-%d.yaml", n))
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
