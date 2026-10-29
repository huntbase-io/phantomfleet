package agent

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/huntbase-io/phantomfleet/internal/host"
)

func TestOsqueryCommandPassesQueryOnStdin(t *testing.T) {
	for _, query := range []string{
		"--flagfile=/etc/passwd",
		"--extension /tmp/evil.ext; SELECT 1",
		"SELECT * FROM users",
	} {
		cmd := osqueryCommand(context.Background(), query)
		if len(cmd.Args) != 2 || cmd.Args[1] != "--json" {
			t.Fatalf("%q: args = %q, want [osqueryi --json]", query, cmd.Args)
		}
		for _, a := range cmd.Args {
			if strings.Contains(a, strings.TrimSpace(strings.TrimSuffix(query, ";"))) {
				t.Fatalf("%q: query leaked into argv %q", query, cmd.Args)
			}
		}
		if cmd.Stdin == nil {
			t.Fatalf("%q: query not passed on stdin", query)
		}
		in, err := io.ReadAll(cmd.Stdin)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.TrimSpace(string(in)); !strings.HasPrefix(got, strings.TrimSpace(query)) || !strings.HasSuffix(got, ";") {
			t.Fatalf("%q: stdin = %q", query, got)
		}
	}
}

func TestRedactedNodesMasksKeys(t *testing.T) {
	nodes := []host.Node{{Name: "a", Key: "secret-key"}, {Name: "b"}}
	out := redactedNodes(nodes)
	if out[0].Key != "****" || out[1].Key != "" || nodes[0].Key != "secret-key" {
		t.Fatalf("redactedNodes: %+v (original %+v)", out, nodes)
	}
}
