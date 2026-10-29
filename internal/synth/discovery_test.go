package synth

import (
	"encoding/json"
	"math/rand"
	"testing"

	"github.com/huntbase-io/phantomfleet/internal/host"
)

// discoveryFor is the discovery query shape Fleet sends for a table.
func discoveryFor(table string) string {
	return "SELECT 1 FROM osquery_registry WHERE active = true AND registry = 'table' AND name = '" + table + "'"
}

func TestRegistryListsOnlyTheNodesTables(t *testing.T) {
	linux := host.Node{Name: "brisk-otter-01", Target: "ubuntu", Identifier: "l-1"}
	win := host.Node{Name: "calm-heron-02", Target: "windows", Identifier: "w-1"}
	cases := []struct {
		node  host.Node
		table string
		want  bool
	}{
		{linux, "processes", true},
		{linux, "deb_packages", true},
		{linux, "services", false},
		{linux, "battery", false}, // darwin and windows only
		{linux, "kubernetes_info", false},
		{win, "services", true},
		{win, "battery", true},
		{win, "deb_packages", false},
	}
	for _, c := range cases {
		rows, err := sqliteEvalRows(c.node, discoveryFor(c.table))
		if err != nil {
			t.Fatalf("%s/%s: %v", c.node.Target, c.table, err)
		}
		if got := len(rows) > 0; got != c.want {
			t.Errorf("%s has %s = %v, want %v", c.node.Target, c.table, got, c.want)
		}
	}
	// The negated form Fleet uses for fallbacks.
	rows, err := sqliteEvalRows(linux, "SELECT 1 WHERE NOT EXISTS ("+discoveryFor("kubernetes_info")+")")
	if err != nil || len(rows) != 1 {
		t.Fatalf("NOT EXISTS = %v, %v", rows, err)
	}
}

func TestRandomNodeOSMatchesItsAnswers(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	for _, n := range host.RandomNodes(30, r, nil, ProfileOS) {
		enrolled := EnrollRequest(n, "s").HostDetails
		rows := schemaFakeRows(n, "SELECT name, version, platform FROM os_version")
		if len(rows) != 1 {
			t.Fatalf("%s: os_version rows = %v", n.Name, rows)
		}
		if rows[0]["name"] != enrolled.OSVersion.Name || rows[0]["version"] != enrolled.OSVersion.Version || rows[0]["platform"] != enrolled.OSVersion.Platform {
			t.Errorf("%s enrolled as %s %s (%s) but answers %v", n.Name, enrolled.OSVersion.Name, enrolled.OSVersion.Version, enrolled.OSVersion.Platform, rows[0])
		}
		sys := schemaFakeRows(n, "SELECT cpu_brand, physical_memory FROM system_info")
		if len(sys) != 1 || sys[0]["cpu_brand"] != enrolled.SystemInfo.CPUBrand || sys[0]["physical_memory"] != enrolled.SystemInfo.PhysicalMemory {
			t.Errorf("%s enrolled with %s/%s but answers %v", n.Name, enrolled.SystemInfo.CPUBrand, enrolled.SystemInfo.PhysicalMemory, sys)
		}
	}
}

func TestComputedSelectsAreExact(t *testing.T) {
	cases := []struct {
		target, query string
	}{
		{"ubuntu", "SELECT (blocks_available * 100 / blocks) AS pct, round((blocks_available * blocks_size * 10e-10), 2) AS gigs FROM mounts WHERE path = '/' LIMIT 1"},
		{"darwin", "SELECT (blocks_available * 100 / blocks) AS pct, round((blocks_available * blocks_size * 10e-10), 2) AS gigs FROM mounts WHERE path = '/' LIMIT 1"},
		{"windows", "SELECT ROUND((sum(free_space) * 100 * 10e-10) / (sum(size) * 10e-10)) AS pct, ROUND(sum(free_space) * 10e-10) AS gigs FROM logical_drives WHERE file_system = 'NTFS' LIMIT 1"},
	}
	for _, c := range cases {
		n := host.Node{Name: "steady-owl-01", Target: c.target, Identifier: "id-" + c.target}
		n.OS = ProfileOS(n.Target)
		res := Answer(n, c.query)
		if res.Status != 0 || len(res.Rows) != 1 {
			t.Fatalf("%s: %+v", c.target, res)
		}
		var pct, gigs float64
		if err := json.Unmarshal([]byte(res.Rows[0]["pct"].(string)), &pct); err != nil || pct <= 0 || pct > 100 {
			t.Errorf("%s: pct = %v", c.target, res.Rows[0]["pct"])
		}
		if err := json.Unmarshal([]byte(res.Rows[0]["gigs"].(string)), &gigs); err != nil || gigs <= 0 || gigs > 10000 {
			t.Errorf("%s: gigs = %v", c.target, res.Rows[0]["gigs"])
		}
	}
	if computedSelect("SELECT count(*) AS n FROM processes") || computedSelect("SELECT * FROM processes") || computedSelect("SELECT pid, (SELECT hostname FROM system_info) AS h FROM processes") {
		t.Error("plain listings and counts must keep the pattern answerer")
	}
}

func TestFleetWindowsVersionQuery(t *testing.T) {
	n := host.Node{Name: "keen-reef-01", Target: "windows", Identifier: "w-9"}
	n.OS = ProfileOS(n.Target)
	q := `WITH display_version_table AS (
			SELECT data as display_version FROM registry
			WHERE path = 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\DisplayVersion'
		), ubr_table AS (
			SELECT data AS ubr FROM registry
			WHERE path ='HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\UBR'
		)
		SELECT os.name, COALESCE(d.display_version, '') AS display_version,
			COALESCE(CONCAT((SELECT version FROM os_version), '.', u.ubr), k.version) AS version
		FROM os_version os, kernel_info k LEFT JOIN display_version_table d LEFT JOIN ubr_table u`
	res := Answer(n, q)
	if res.Status != 0 || len(res.Rows) != 1 {
		t.Fatalf("%+v", res)
	}
	if res.Rows[0]["version"] != "10.0.26100.6899" || res.Rows[0]["display_version"] != "24H2" {
		t.Fatalf("row = %v", res.Rows[0])
	}
	// Hidden columns can be named, as on osquery.
	res = Answer(n, "WITH u AS (SELECT uid, username, type FROM users WHERE type <> 'special') SELECT count(*) AS n FROM u")
	if res.Status != 0 {
		t.Fatalf("hidden column: %+v", res)
	}
}
