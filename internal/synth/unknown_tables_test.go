package synth

import (
	"testing"

	"github.com/huntbase-io/phantomfleet/internal/host"
)

// randomNodes are one random (unpinned) node per platform profile.
func randomNodes() []host.Node {
	var out []host.Node
	for _, target := range []string{"ubuntu", "windows", "darwin"} {
		n := host.Node{Name: "steady-owl-01", Target: target, Identifier: "id-" + target}
		n.OS = ProfileOS(target)
		out = append(out, n)
	}
	return out
}

func wantNoSuchTable(t *testing.T, n host.Node, q, table string) {
	t.Helper()
	res := Answer(n, q)
	if res.Status != 1 || res.Message != "no such table: "+table || len(res.Rows) != 0 {
		t.Errorf("%s: %q = status %d, message %q, %d rows; want no such table: %s", n.Target, q, res.Status, res.Message, len(res.Rows), table)
	}
}

func TestRandomNodesFailStatementsOnUnknownTables(t *testing.T) {
	isolateLoaders(t)
	for _, n := range randomNodes() {
		for _, c := range []struct{ q, table string }{
			{"SELECT * FROM example_unknown_events WHERE seq = 9", "example_unknown_events"},
			{"SELECT * FROM opera_extensions", "opera_extensions"},
			{"SELECT * FROM example_ext_events", "example_ext_events"},
			{"SELECT name, path FROM example_ext_events LIMIT 3", "example_ext_events"},
			{"SELECT count(*) FROM example_ext_events", "example_ext_events"},
			{"SELECT p.name FROM processes p JOIN example_ext_events e ON e.pid = p.pid", "example_ext_events"},
			{"SELECT name, (SELECT count(*) FROM example_ext_events) AS n FROM processes", "example_ext_events"},
			{"WITH x AS (SELECT * FROM example_ext_events) SELECT * FROM x", "example_ext_events"},
		} {
			wantNoSuchTable(t, n, c.q, c.table)
		}
		// Table-valued functions and statements without a table still run.
		if res := Answer(n, "SELECT value FROM json_each('[1,2,3]')"); res.Status != 0 || len(res.Rows) != 3 {
			t.Errorf("%s: json_each = %+v", n.Target, res)
		}
		if res := Answer(n, "SELECT 1 AS one"); res.Status != 0 || len(res.Rows) != 1 || res.Rows[0]["one"] != "1" {
			t.Errorf("%s: SELECT 1 = %+v", n.Target, res)
		}
	}
}

func TestRandomNodesFailStatementsOnOtherPlatformsTables(t *testing.T) {
	for _, n := range randomNodes() {
		if n.Target == "ubuntu" {
			continue
		}
		for _, q := range []string{
			"SELECT name, version FROM rpm_packages",
			"SELECT name, version || '-' || release AS version FROM rpm_packages",
			"SELECT name FROM rpm_packages WHERE name = 'openssl'",
			"WITH r AS (SELECT name, version FROM rpm_packages) SELECT name FROM r",
			"SELECT count(*) AS n FROM rpm_packages",
		} {
			wantNoSuchTable(t, n, q, "rpm_packages")
		}
	}
	// The table exists on Linux.
	n := randomNodes()[0]
	if res := Answer(n, "SELECT name, version FROM rpm_packages LIMIT 1"); res.Status != 0 {
		t.Errorf("ubuntu rpm_packages = %+v", res)
	}
}

func TestUnknownTableDiscoveryQueriesFail(t *testing.T) {
	isolateLoaders(t)
	for _, n := range randomNodes() {
		// A discovery query that reads the table itself fails, so the
		// query it gates is skipped; the registry form returns no rows.
		if res := Answer(n, "SELECT 1 FROM opera_extensions LIMIT 1"); res.Status != 1 {
			t.Errorf("%s: discovery on an unknown table = %+v", n.Target, res)
		}
		if res := Answer(n, discoveryFor("opera_extensions")); res.Status != 0 || len(res.Rows) != 0 {
			t.Errorf("%s: registry discovery = %+v", n.Target, res)
		}
	}
}

func TestPinnedAndRandomNodesAgreeOnUnknownTables(t *testing.T) {
	isolateLoaders(t)
	pinned := host.Node{Name: "srv", Target: "ubuntu", Identifier: "p-1", Pinned: true}
	random := host.Node{Name: "brisk-otter-01", Target: "ubuntu", Identifier: "r-1"}
	q := "SELECT * FROM example_unknown_events WHERE seq = 9"
	p, r := Answer(pinned, q), Answer(random, q)
	if p.Status != 1 || r.Status != 1 || p.Message != r.Message {
		t.Fatalf("pinned %+v, random %+v", p, r)
	}
}
