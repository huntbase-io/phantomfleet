package synth

import (
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/huntbase-io/phantomfleet/internal/host"
)

// testNodesFile and parseTestNodes are copies of the host package test
// helpers of the same name.
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

func parseTestNodes(t *testing.T) []host.Node {
	t.Helper()
	nodes, err := host.ParseNodesFile([]byte(testNodesFile))
	if err != nil {
		t.Fatalf("ParseNodesFile: %v", err)
	}
	return nodes
}

func TestEnrollRequestUsesPinnedOSAndHardware(t *testing.T) {
	ws := parseTestNodes(t)[0]
	req := EnrollRequest(ws, "secret")
	if req.HostIdentifier != ws.Identifier || req.PlatformType != "2" {
		t.Fatalf("unexpected enroll identity: %+v", req)
	}
	os := req.HostDetails.OSVersion
	if os.Name != "Microsoft Windows 11 Enterprise" || os.Version != "10.0.22631" || os.Build != "22631" {
		t.Fatalf("pinned OS not reported: %+v", os)
	}
	si := req.HostDetails.SystemInfo
	if si.Hostname != ws.Name || si.ComputerName != "finance-ws-12" || si.HardwareModel != "Latitude 7440" || si.CPULogicalCores != "12" {
		t.Fatalf("pinned hardware not reported: %+v", si)
	}

	random := host.Node{Target: "ubuntu18", Name: "Ubuntu18-Dev", Identifier: "X"}
	if got := EnrollRequest(random, "s").HostDetails.OSVersion; got.Name != "Ubuntu" {
		t.Fatalf("random nodes keep the platform default OS, got %+v", got)
	}
}

func TestIdentityTablesAnswerFromThePinnedNode(t *testing.T) {
	ws := parseTestNodes(t)[0]

	rows := schemaFakeRows(ws, "SELECT name, version FROM os_version")
	if len(rows) != 1 || rows[0]["name"] != "Microsoft Windows 11 Enterprise" || rows[0]["version"] != "10.0.22631" {
		t.Fatalf("os_version must answer the pinned OS: %+v", rows)
	}
	rows = schemaFakeRows(ws, "SELECT hostname, hardware_model, hardware_serial FROM system_info")
	if len(rows) != 1 || rows[0]["hostname"] != ws.Name || rows[0]["hardware_serial"] != "EXC7440A12" {
		t.Fatalf("system_info must answer the pinned host: %+v", rows)
	}
	rows = schemaFakeRows(ws, "SELECT address FROM interface_addresses WHERE address = '10.14.40.112'")
	if len(rows) == 0 {
		t.Fatalf("interface_addresses must carry the pinned IP: %+v", rows)
	}
}

func TestHostRestrictedSeedRows(t *testing.T) {
	saved := seedProfiles["windows"]["drivers"]
	t.Cleanup(func() { seedProfiles["windows"]["drivers"] = saved })
	seedProfiles["windows"]["drivers"] = append([]map[string]string{
		{"_hosts": "finance-ws-12", "service": "RTCore64", "image": `C:\Users\a.harper\AppData\Local\Temp\rtc.sys`},
		{"_hosts": "other-host|another.corp.example.com", "service": "Elsewhere"},
	}, saved...)

	ws := parseTestNodes(t)[0]
	rows := schemaFakeRows(ws, "SELECT service, image FROM drivers WHERE service = 'RTCore64'")
	if len(rows) != 1 || rows[0]["image"] != `C:\Users\a.harper\AppData\Local\Temp\rtc.sys` {
		t.Fatalf("the host-restricted row must reach its host: %+v", rows)
	}
	for _, row := range schemaFakeRows(ws, "SELECT * FROM drivers") {
		if row["service"] == "Elsewhere" {
			t.Fatal("a row restricted to other hosts leaked")
		}
		if _, ok := row[hostsColumn]; ok {
			t.Fatal("the _hosts column must be stripped")
		}
	}

	other := host.Node{Target: "windows", Name: "sales-ws-21.corp.example.com", Identifier: "OTHER"}
	if rows := schemaFakeRows(other, "SELECT service FROM drivers WHERE service = 'RTCore64'"); len(rows) != 0 {
		t.Fatalf("another host must not report the restricted row: %+v", rows)
	}
	another := host.Node{Target: "windows", Name: "another.corp.example.com", Identifier: "ANOTHER"}
	if rows := schemaFakeRows(another, "SELECT service FROM drivers WHERE service = 'Elsewhere'"); len(rows) != 1 {
		t.Fatalf("a full hostname in _hosts must match: %+v", rows)
	}
}

func TestAgoToken(t *testing.T) {
	node := host.Node{Name: "h", Identifier: "X"}
	got, err := strconv.ParseInt(resolveValue("{{ago:26h5m}}", node, stableFaker(node, "t", "t")), 10, 64)
	if err != nil {
		t.Fatalf("ago must render a unix time: %v", err)
	}
	want := time.Now().Add(-(26*time.Hour + 5*time.Minute)).Unix()
	if got < want-5 || got > want+5 {
		t.Fatalf("ago: got %d, want ~%d", got, want)
	}
	if v := resolveValue("{{ago:soon}}", node, stableFaker(node, "t", "t")); v != "{{ago:soon}}" {
		t.Fatalf("an unparseable duration is left as-is, got %q", v)
	}
	if rowHasGenerator(map[string]string{"time": "{{ago:1h}}"}) {
		t.Fatal("ago is a fixed point in the story, not a padding generator")
	}
}

// TestExampleCorpFleet loads the shipped Example Corp nodes file and seeds and
// checks the story rows land on the right hosts. Runs last and restores the
// global seed profiles it layers over.
func TestExampleCorpFleet(t *testing.T) {
	dir := filepath.Join("..", "..", "examples", "examplecorp")
	nodes, err := host.LoadNodesFile(filepath.Join(dir, "nodes.yaml"))
	if err != nil {
		t.Fatalf("nodes.yaml: %v", err)
	}
	if len(nodes) != 15 {
		t.Fatalf("Example Corp has 15 hosts, got %d", len(nodes))
	}

	saved := map[string]seedProfile{}
	for name, prof := range seedProfiles {
		cp := seedProfile{}
		for table, rows := range prof {
			cp[table] = append([]map[string]string(nil), rows...)
		}
		saved[name] = cp
	}
	savedCounts := map[string][2]int{}
	for k, v := range rowCounts {
		savedCounts[k] = v
	}
	t.Cleanup(func() {
		seedProfiles = saved
		rowCounts = savedCounts
	})
	if n, err := LoadSeedDir(filepath.Join(dir, "seeds")); err != nil || n != 4 {
		t.Fatalf("seeds: %d files, %v", n, err)
	}

	byShort := map[string]host.Node{}
	for _, n := range nodes {
		byShort[shortHostname(n.Name)] = n
	}
	ws := byShort["finance-ws-12"]
	rows := schemaFakeRows(ws, "SELECT d.service, h.sha256 FROM drivers d JOIN hash h ON d.image = h.path WHERE d.service = 'RTCore64'")
	if len(rows) != 1 || rows[0]["sha256"] != "01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd" {
		t.Fatalf("RTCore64 driver + hash on finance-ws-12: %+v", rows)
	}
	rows = schemaFakeRows(ws, "SELECT name, status FROM services WHERE status = 'STOPPED' AND name IN ('WinDefend','Sense','WdNisSvc')")
	if len(rows) != 3 {
		t.Fatalf("stopped Defender services on finance-ws-12: %+v", rows)
	}
	// _key: the host's stopped WinDefend replaces the profile's running one.
	rows = schemaFakeRows(ws, "SELECT status FROM services WHERE name = 'WinDefend'")
	if len(rows) != 1 || rows[0]["status"] != "STOPPED" {
		t.Fatalf("WinDefend on finance-ws-12 must be the stopped one only: %+v", rows)
	}
	if rows := schemaFakeRows(byShort["finance-ws-13"], "SELECT service FROM drivers WHERE service = 'RTCore64'"); len(rows) != 0 {
		t.Fatalf("the driver must stay on finance-ws-12: %+v", rows)
	}
	rows = schemaFakeRows(byShort["web-prod-01"], "SELECT name, version FROM deb_packages WHERE name = 'liblog4j2-java'")
	if len(rows) != 1 || rows[0]["version"] != "2.14.1-1" {
		t.Fatalf("log4j on web-prod-01: %+v", rows)
	}
	rows = schemaFakeRows(byShort["fw-edge-01"], "SELECT name, version FROM os_version")
	if len(rows) != 1 || rows[0]["name"] != "PAN-OS" || rows[0]["version"] != "11.1.0" {
		t.Fatalf("PAN-OS on fw-edge-01: %+v", rows)
	}
	rows = schemaFakeRows(byShort["eng-ws-07"], "SELECT bundle_short_version FROM apps WHERE bundle_identifier = 'com.google.Chrome'")
	if len(rows) != 1 || rows[0]["bundle_short_version"] != "116.0.5845.96" {
		t.Fatalf("vulnerable Chrome on eng-ws-07: %+v", rows)
	}
}
