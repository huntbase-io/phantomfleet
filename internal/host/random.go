package host

import (
	"fmt"
	"hash/fnv"
	"math/rand"

	"github.com/google/uuid"
)

var (
	// randomTargets are the osquery platforms random nodes are drawn from,
	// weighted by repetition. Each maps to a seed profile, and a random node
	// reports that profile's os_version row (see synth.ProfileOS), so what it says
	// at enrollment is what it answers later.
	randomTargets = []string{"ubuntu", "ubuntu", "windows", "windows", "darwin"}

	// osqueryVersions are recent osquery releases reported by random nodes.
	osqueryVersions = []string{"5.20.0", "5.21.0", "5.22.1", "5.23.1", "5.24.0"}

	// Word pools for random hostnames (adjective-noun-NN): 48 x 48 x 100
	// combinations, so collisions are rare and resolved by the suffix.
	hostAdjectives = []string{
		"amber", "azure", "bold", "brave", "brisk", "calm", "clever", "cobalt",
		"coral", "crimson", "eager", "fancy", "gentle", "golden", "grand", "happy",
		"hidden", "humble", "icy", "jolly", "keen", "lively", "lucky", "mellow",
		"misty", "noble", "olive", "polar", "proud", "quick", "quiet", "rapid",
		"rustic", "scarlet", "silent", "silver", "smooth", "solar", "steady", "stormy",
		"sunny", "swift", "tidy", "urban", "vivid", "wild", "witty", "zesty",
	}
	hostNouns = []string{
		"badger", "beacon", "bison", "canyon", "cedar", "comet", "condor", "coyote",
		"delta", "dune", "eagle", "falcon", "fjord", "forest", "fox", "glacier",
		"harbor", "hawk", "heron", "island", "jaguar", "lagoon", "lynx", "maple",
		"meadow", "mesa", "otter", "owl", "panda", "pine", "prairie", "quartz",
		"raven", "reef", "ridge", "river", "robin", "sparrow", "summit", "tiger",
		"tundra", "valley", "walrus", "willow", "wolf", "yak", "zebra", "orchid",
	}
)

// generateRandomIP returns a private (RFC 1918, 10.0.0.0/8) address not in
// taken. Random nodes never claim routable public addresses.
func generateRandomIP(r *rand.Rand, taken map[string]bool) string {
	for {
		ip := fmt.Sprintf("10.%d.%d.%d", r.Intn(256), r.Intn(256), 1+r.Intn(254))
		if !taken[ip] {
			taken[ip] = true
			return ip
		}
	}
}

// generateHostname returns a hostname of the form adjective-noun-NN derived
// from the node's identifier, so a node keeps its name, and not in taken: on
// a clash the numeric suffix moves on.
func generateHostname(identifier string, taken map[string]bool) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(identifier))
	sum := h.Sum64()
	adj := hostAdjectives[sum%uint64(len(hostAdjectives))]
	sum /= uint64(len(hostAdjectives))
	noun := hostNouns[sum%uint64(len(hostNouns))]
	sum /= uint64(len(hostNouns))
	for i := uint64(0); ; i++ {
		var name string
		if i < 100 {
			name = fmt.Sprintf("%s-%s-%02d", adj, noun, (sum+i)%100)
		} else {
			name = fmt.Sprintf("%s-%s-%d", adj, noun, i)
		}
		if !taken[name] {
			taken[name] = true
			return name
		}
	}
}

// generateRandomNode generates a random node whose name and IP are not in
// the taken sets. osFor gives the OS it reports for its target.
func generateRandomNode(r *rand.Rand, names, ips map[string]bool, osFor func(target string) *NodeOS) Node {
	target := randomTargets[r.Intn(len(randomTargets))]
	id := uuid.Must(uuid.NewRandomFromReader(r)).String()
	return Node{
		Target:     target,
		IP:         generateRandomIP(r, ips),
		Name:       generateHostname(id, names),
		Version:    osqueryVersions[r.Intn(len(osqueryVersions))],
		Identifier: id,
		OS:         osFor(target),
	}
}

// RandomNodes generates n random nodes whose hostnames and IPs are unique
// among themselves and among existing. osFor gives the OS a node of a target
// reports; it must not consume randomness from r.
func RandomNodes(n int, r *rand.Rand, existing []Node, osFor func(target string) *NodeOS) []Node {
	names := make(map[string]bool, len(existing)+n)
	ips := make(map[string]bool, len(existing)+n)
	for _, e := range existing {
		names[e.Name] = true
		ips[e.IP] = true
	}
	nodes := make([]Node, n)
	for i := 0; i < n; i++ {
		nodes[i] = generateRandomNode(r, names, ips, osFor)
	}
	return nodes
}
