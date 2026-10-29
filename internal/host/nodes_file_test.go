package host

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testNodesFile = `
namespace: 1b4e28ba-2fa1-11d2-883f-0016d3cca427
nodes:
  - hostname: finance-ws-12.corp.example.com
    platform: windows
    ip: 10.14.40.112
    uuid_seed: examplecorp/finance-ws-12
    osquery_version: 5.12.1
    os:
      name: Microsoft Windows 11 Enterprise
      version: 10.0.22631
      major: "10"
      minor: "0"
      build: "22631"
      platform: windows
      platform_like: windows
    hardware:
      vendor: Dell Inc.
      model: Latitude 7440
      serial: EXC7440A12
      cpu_brand: 13th Gen Intel(R) Core(TM) i7-1365U
      cpu_cores: 12
      physical_memory: 17179869184
  - hostname: web-prod-01.corp.example.com
    platform: ubuntu
    ip: 10.14.22.31
    uuid: 0f4c3d2e-1b0a-4f9e-8d7c-6b5a49382716
`

func parseTestNodes(t *testing.T) []Node {
	t.Helper()
	nodes, err := ParseNodesFile([]byte(testNodesFile))
	if err != nil {
		t.Fatalf("ParseNodesFile: %v", err)
	}
	return nodes
}

func TestParseNodesFilePinsIdentity(t *testing.T) {
	nodes := parseTestNodes(t)
	if len(nodes) != 2 {
		t.Fatalf("got %d nodes, want 2", len(nodes))
	}
	ws := nodes[0]
	if ws.Name != "finance-ws-12.corp.example.com" || ws.IP != "10.14.40.112" || ws.Target != "windows" {
		t.Fatalf("identity not pinned: %+v", ws)
	}
	if !ws.Pinned || ws.Version != "5.12.1" || ws.OS == nil || ws.Hardware == nil {
		t.Fatalf("pinned fields missing: %+v", ws)
	}
	if ws.Identifier != strings.ToUpper(ws.Identifier) {
		t.Fatalf("identifier should be upper-case like osquery's: %s", ws.Identifier)
	}
	// Explicit uuid wins over derivation; default osquery version applies.
	if nodes[1].Identifier != "0F4C3D2E-1B0A-4F9E-8D7C-6B5A49382716" || nodes[1].Version != "5.24.0" {
		t.Fatalf("explicit uuid / default version not honored: %+v", nodes[1])
	}
}

func TestUUIDSeedIsStableAndNamespaced(t *testing.T) {
	a := parseTestNodes(t)
	b := parseTestNodes(t)
	if a[0].Identifier != b[0].Identifier {
		t.Fatalf("uuid_seed derivation is not stable: %s vs %s", a[0].Identifier, b[0].Identifier)
	}
	other, err := ParseNodesFile([]byte(strings.Replace(testNodesFile, "1b4e28ba-2fa1-11d2-883f-0016d3cca427", "6ba7b810-9dad-11d1-80b4-00c04fd430c8", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if other[0].Identifier == a[0].Identifier {
		t.Fatal("a different namespace must derive a different identifier")
	}
}

func TestParseNodesFileRejectsBadEntries(t *testing.T) {
	cases := map[string]string{
		"missing hostname": "nodes:\n  - platform: windows\n",
		"missing platform": "nodes:\n  - hostname: a\n",
		"bad uuid":         "nodes:\n  - hostname: a\n    platform: ubuntu\n    uuid: nope\n",
		"duplicate":        "nodes:\n  - hostname: a\n    platform: ubuntu\n    uuid_seed: x\n  - hostname: b\n    platform: ubuntu\n    uuid_seed: x\n",
		"bad namespace":    "namespace: nope\nnodes: []\n",
	}
	for name, doc := range cases {
		if _, err := ParseNodesFile([]byte(doc)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestLoadNodesFileFromDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nodes.yaml")
	if err := os.WriteFile(path, []byte(testNodesFile), 0o600); err != nil {
		t.Fatal(err)
	}
	nodes, err := LoadNodesFile(path)
	if err != nil || len(nodes) != 2 {
		t.Fatalf("LoadNodesFile: %v (%d nodes)", err, len(nodes))
	}
	if _, err := LoadNodesFile(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("a missing nodes file must be an error")
	}
}

func TestMergePinnedNodesKeepsKeysAndTrimsRandomNodes(t *testing.T) {
	pinned := parseTestNodes(t)
	state := []Node{
		{Name: "old-name", Identifier: strings.ToLower(pinned[0].Identifier), Key: "key-ws", Pinned: true},
		{Name: "Ubuntu18-Dev", Identifier: "R1", Key: "key-r1"},
		{Name: "Windows-PC", Identifier: "R2", Key: "key-r2"},
	}

	merged := MergePinned(pinned, state, 2)
	if len(merged) != 2 {
		t.Fatalf("total 2 must keep only the pinned nodes, got %d", len(merged))
	}
	if merged[0].Key != "key-ws" || merged[0].Name != "finance-ws-12.corp.example.com" {
		t.Fatalf("pinned node must keep its state key and take the file's fields: %+v", merged[0])
	}
	if merged[1].Key != "" {
		t.Fatalf("a pinned node without state must enroll fresh: %+v", merged[1])
	}

	merged = MergePinned(pinned, state, 3)
	if len(merged) != 3 || merged[2].Identifier != "R1" || merged[2].Key != "key-r1" {
		t.Fatalf("room left by total must be filled with state's random nodes: %+v", merged)
	}
}
