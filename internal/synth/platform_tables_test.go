package synth

import (
	"testing"

	"github.com/huntbase-io/phantomfleet/internal/host"
)

func TestForeignPlatformTablesAreEmpty(t *testing.T) {
	win := host.Node{Name: "WIN-1", Target: "windows", Identifier: "w-1"}
	linux := host.Node{Name: "Ubuntu18-Dev", Target: "ubuntu18", Identifier: "l-1"}
	if rows := schemaFakeRows(win, "SELECT name FROM deb_packages"); len(rows) != 0 {
		t.Errorf("Windows answered deb_packages: %v", rows[0])
	}
	if rows := schemaFakeRows(linux, "SELECT name FROM services"); len(rows) != 0 {
		t.Errorf("Linux answered services: %v", rows[0])
	}
	if rows := schemaFakeRows(linux, "SELECT name FROM processes"); len(rows) == 0 {
		t.Error("Linux lost its processes")
	}
	// A random node fails the statement, as osquery does.
	if res := Answer(win, "SELECT name FROM deb_packages"); res.Status != 1 || res.Message != "no such table: deb_packages" {
		t.Errorf("Windows deb_packages = %+v", res)
	}
}

func TestApplianceHostsHaveNoDistroPackages(t *testing.T) {
	fleet := loadExampleCorp(t)
	for _, host := range []string{"fw-edge-01", "vpn-gw-01"} {
		node, ok := fleet[host]
		if !ok {
			t.Fatalf("no %s in the Example Corp fleet", host)
		}
		for _, q := range []string{
			"SELECT name, version FROM deb_packages",
			"SELECT name, version FROM rpm_packages",
			"SELECT * FROM apt_sources",
		} {
			if rows := schemaFakeRows(node, q); len(rows) != 0 {
				t.Errorf("%s: %q answered %d distro package rows: %+v", host, q, len(rows), rows[0])
			}
		}
	}
	if rows := schemaFakeRows(fleet["web-prod-01"], "SELECT name FROM deb_packages"); len(rows) == 0 {
		t.Fatal("web-prod-01 lost its deb_packages")
	}
}
