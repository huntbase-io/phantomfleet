package host

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

// defaultNodesNamespace derives node identifiers from uuid_seed when a nodes file
// sets no namespace of its own. Never change it: identifiers (and so the node
// UUIDs that TLS servers and downstream inventory tools key on) are derived from it.
var defaultNodesNamespace = uuid.MustParse("8d1f2c3b-4a5e-5f60-9b7a-0c1d2e3f4a5b")

// NodeOS pins what a node reports in os_version (and at enrollment).
type NodeOS struct {
	Name         string `yaml:"name" json:"name"`
	Version      string `yaml:"version" json:"version"`
	Major        string `yaml:"major" json:"major"`
	Minor        string `yaml:"minor" json:"minor"`
	Patch        string `yaml:"patch" json:"patch"`
	Build        string `yaml:"build" json:"build,omitempty"`
	Codename     string `yaml:"codename" json:"codename,omitempty"`
	Platform     string `yaml:"platform" json:"platform"`
	PlatformLike string `yaml:"platform_like" json:"platform_like,omitempty"`
	Arch         string `yaml:"arch" json:"arch,omitempty"`
}

// NodeHardware pins what a node reports in system_info (and at enrollment).
type NodeHardware struct {
	Vendor         string `yaml:"vendor" json:"vendor,omitempty"`
	Model          string `yaml:"model" json:"model,omitempty"`
	Version        string `yaml:"version" json:"version,omitempty"`
	Serial         string `yaml:"serial" json:"serial,omitempty"`
	CPUBrand       string `yaml:"cpu_brand" json:"cpu_brand,omitempty"`
	CPUCores       int    `yaml:"cpu_cores" json:"cpu_cores,omitempty"`
	PhysicalMemory int64  `yaml:"physical_memory" json:"physical_memory,omitempty"`
}

// NodeSpec is one entry of a --nodes-file: a node whose identity is pinned
// instead of randomly generated.
type NodeSpec struct {
	Hostname       string `yaml:"hostname"`
	Platform       string `yaml:"platform"`
	IP             string `yaml:"ip"`
	UUID           string `yaml:"uuid"`
	UUIDSeed       string `yaml:"uuid_seed"`
	OsqueryVersion string `yaml:"osquery_version"`
	// The host's main interactive user (or service account), reported by
	// {{username}} and by user-like columns nothing else fills.
	PrimaryUser string        `yaml:"primary_user"`
	OS          *NodeOS       `yaml:"os"`
	Hardware    *NodeHardware `yaml:"hardware"`
}

// NodesFile is the --nodes-file document.
type NodesFile struct {
	// Namespace (a UUID) for deriving identifiers from uuid_seed. Optional.
	Namespace string     `yaml:"namespace"`
	Nodes     []NodeSpec `yaml:"nodes"`
}

// LoadNodesFile reads a --nodes-file and returns its nodes, identities pinned.
func LoadNodesFile(path string) ([]Node, error) {
	// #nosec G304 -- developer-supplied --nodes-file path for a local
	// load-testing tool; runs with the developer's own privileges.
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	return ParseNodesFile(raw)
}

// ParseNodesFile parses a nodes-file document. Every node needs a hostname and a
// platform; its identifier is `uuid`, else uuid5(namespace, uuid_seed), else
// uuid5(namespace, hostname) — stable across restarts either way.
func ParseNodesFile(raw []byte) ([]Node, error) {
	var doc NodesFile
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse nodes file: %w", err)
	}
	namespace := defaultNodesNamespace
	if strings.TrimSpace(doc.Namespace) != "" {
		ns, err := uuid.Parse(strings.TrimSpace(doc.Namespace))
		if err != nil {
			return nil, fmt.Errorf("nodes file namespace: %w", err)
		}
		namespace = ns
	}
	nodes := make([]Node, 0, len(doc.Nodes))
	seen := map[string]string{}
	for i, spec := range doc.Nodes {
		node, err := spec.toNode(namespace)
		if err != nil {
			return nil, fmt.Errorf("nodes file entry %d: %w", i+1, err)
		}
		if prev, dup := seen[node.Identifier]; dup {
			return nil, fmt.Errorf("nodes file entry %d (%s): identifier %s already used by %s", i+1, node.Name, node.Identifier, prev)
		}
		seen[node.Identifier] = node.Name
		nodes = append(nodes, node)
	}
	return nodes, nil
}

func (s NodeSpec) toNode(namespace uuid.UUID) (Node, error) {
	hostname := strings.TrimSpace(s.Hostname)
	if hostname == "" {
		return Node{}, fmt.Errorf("hostname is required")
	}
	platform := strings.ToLower(strings.TrimSpace(s.Platform))
	if platform == "" {
		return Node{}, fmt.Errorf("%s: platform is required", hostname)
	}
	identifier := strings.TrimSpace(s.UUID)
	if identifier != "" {
		parsed, err := uuid.Parse(identifier)
		if err != nil {
			return Node{}, fmt.Errorf("%s: uuid: %w", hostname, err)
		}
		identifier = parsed.String()
	} else {
		seed := strings.TrimSpace(s.UUIDSeed)
		if seed == "" {
			seed = hostname
		}
		identifier = uuid.NewSHA1(namespace, []byte(seed)).String()
	}
	version := strings.TrimSpace(s.OsqueryVersion)
	if version == "" {
		version = "5.24.0"
	}
	return Node{
		Target:      platform,
		IP:          strings.TrimSpace(s.IP),
		Name:        hostname,
		Version:     version,
		Identifier:  strings.ToUpper(identifier),
		Pinned:      true,
		PrimaryUser: strings.TrimSpace(s.PrimaryUser),
		OS:          s.OS,
		Hardware:    s.Hardware,
	}, nil
}

// MergePinned builds the node list for a run with a nodes file.
//
// Pinned nodes come first, in file order; each keeps the enrollment key it had in
// the resumed state (matched by identifier), so a restart does not re-enroll it,
// while its descriptive fields are refreshed from the file. Unpinned (random)
// nodes from the state follow, but only as many as `total` leaves room for.
func MergePinned(pinned, state []Node, total int) []Node {
	keys := make(map[string]string, len(state))
	for _, n := range state {
		if n.Key != "" {
			keys[strings.ToUpper(n.Identifier)] = n.Key
		}
	}
	out := make([]Node, 0, len(pinned))
	for _, n := range pinned {
		n.Key = keys[strings.ToUpper(n.Identifier)]
		out = append(out, n)
	}
	for _, n := range state {
		if len(out) >= total {
			break
		}
		if n.Pinned {
			continue
		}
		out = append(out, n)
	}
	return out
}
