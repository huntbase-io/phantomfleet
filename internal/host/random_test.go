package host

import (
	"math/rand"
	"net"
	"testing"
)

// stubOS stands in for the seed-profile OS lookup, which lives in synth.
func stubOS(target string) *NodeOS { return &NodeOS{Name: target, Platform: target} }

func TestRandomNodesAreUniqueAndPrivate(t *testing.T) {
	_, private, _ := net.ParseCIDR("10.0.0.0/8")
	r := rand.New(rand.NewSource(42))
	nodes := RandomNodes(5000, r, nil, stubOS)
	more := RandomNodes(500, r, nodes, stubOS)
	names := map[string]bool{}
	ips := map[string]bool{}
	for _, n := range append(nodes, more...) {
		if names[n.Name] {
			t.Fatalf("duplicate hostname %s", n.Name)
		}
		if ips[n.IP] {
			t.Fatalf("duplicate IP %s", n.IP)
		}
		names[n.Name], ips[n.IP] = true, true
		ip := net.ParseIP(n.IP)
		if ip == nil || !private.Contains(ip) {
			t.Fatalf("%s has IP %s outside 10.0.0.0/8", n.Name, n.IP)
		}
		if n.OS == nil {
			t.Fatalf("%s has no OS", n.Name)
		}
	}
	// The same identifier always gets the same name.
	if a, b := generateHostname("id-1", map[string]bool{}), generateHostname("id-1", map[string]bool{}); a != b {
		t.Fatalf("hostname not deterministic: %s vs %s", a, b)
	}
}
