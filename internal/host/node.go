// Package host is the simulated host model: the Node every other package
// passes around, --nodes-file parsing, random node generation and the state
// file.
package host

// Node represents a simulated osquery host
type Node struct {
	Target     string `json:"target"`
	IP         string `json:"ip"`
	Name       string `json:"name"`
	Version    string `json:"version"`
	Identifier string `json:"identifier"`
	Key        string `json:"key"`
	// Set for nodes pinned by --nodes-file (identity survives restarts).
	Pinned      bool          `json:"pinned,omitempty"`
	PrimaryUser string        `json:"primary_user,omitempty"`
	OS          *NodeOS       `json:"os,omitempty"`
	Hardware    *NodeHardware `json:"hardware,omitempty"`
}
