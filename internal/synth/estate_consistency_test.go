package synth

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/huntbase-io/phantomfleet/internal/host"
)

// inventorySyncQueries are the kind of run-on-connect / scheduled inventory
// "sync" queries a typical endpoint-management product issues. Their results
// usually become inventory records, so on the Example Corp sample fleet they
// must name only estate hosts, users and plausible identifiers, consistently
// across tables — never generated filler words.
var inventorySyncQueries = map[string]string{
	"interfaces":   "SELECT * FROM interface_addresses;",
	"usb":          "SELECT * FROM usb_devices;",
	"last":         "SELECT * FROM last;",
	"hardware":     "SELECT hostname, hardware_vendor, hardware_model, hardware_version, hardware_serial FROM system_info;",
	"logged_in":    "SELECT user, (SELECT hostname FROM system_info) AS hostname, (SELECT version FROM os_version) AS os_version, (SELECT version FROM platform_info) AS version FROM logged_in_users;",
	"local_admins": `SELECT username, groupname, type, u.UID, g.GID, Description, comment FROM users u JOIN user_groups ug ON ug.UID = u.UID JOIN groups g ON g.GID = ug.GID WHERE g.GROUPNAME = "Administrators" AND u.type = "local";`,
	"patches":      "SELECT csname, hotfix_id, description FROM patches;",
	"chrome":       "SELECT name, identifier, version, default_locale AS locale FROM chrome_extensions;",
}

func loadExampleCorp(t *testing.T) map[string]host.Node {
	t.Helper()
	dir := filepath.Join("..", "..", "examples", "examplecorp")
	nodes, err := host.LoadNodesFile(filepath.Join(dir, "nodes.yaml"))
	if err != nil {
		t.Fatalf("nodes.yaml: %v", err)
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
	if _, err := LoadSeedDir(filepath.Join(dir, "seeds")); err != nil {
		t.Fatal(err)
	}
	byShort := map[string]host.Node{}
	for _, n := range nodes {
		byShort[shortHostname(n.Name)] = n
	}
	return byShort
}

var (
	reKB         = regexp.MustCompile(`^KB\d{7}$`)
	reExtID      = regexp.MustCompile(`^[a-p]{32}$`)
	estateUsers  = map[string]bool{"a.harper": true, "s.novak": true, "j.chen": true, "p.ivanova": true, "m.delgado": true, "r.okonkwo": true, "svc_backup": true, "svc_deploy": true, "admin": true, "reboot": true}
	estateSubnet = "10.14."
)

func TestExampleCorpInventoryQueriesStayInTheEstate(t *testing.T) {
	hosts := loadExampleCorp(t)
	if len(hosts) != 15 {
		t.Fatalf("want 15 hosts, got %d", len(hosts))
	}
	for short, node := range hosts {
		win := profileForPlatform(node.Target) == "windows"
		for name, q := range inventorySyncQueries {
			rows := schemaFakeRows(node, q)
			for _, row := range rows {
				get := func(k string) string { v, _ := row[k].(string); return v }
				switch name {
				case "interfaces":
					addr := get("address")
					if addr != "127.0.0.1" && addr != node.IP {
						t.Errorf("%s interfaces: address %q", short, addr)
					}
				case "hardware":
					if get("hostname") != node.Name || get("hardware_serial") != node.Hardware.Serial || get("hardware_model") != node.Hardware.Model {
						t.Errorf("%s hardware: %+v", short, row)
					}
				case "logged_in", "last":
					user := get("user")
					if name == "last" {
						user = get("username")
					}
					if !estateUsers[user] {
						t.Errorf("%s %s: user %q is not an estate user", short, name, user)
					}
					if name == "logged_in" && (get("hostname") != node.Name || get("os_version") != node.OS.Version || get("version") == "") {
						t.Errorf("%s logged_in: %+v", short, row)
					}
					if host := get("host"); host != "" && !strings.HasPrefix(host, estateSubnet) {
						t.Errorf("%s %s: host %q", short, name, host)
					}
				case "local_admins":
					if get("username") != "Administrator" || get("groupname") != "Administrators" {
						t.Errorf("%s local_admins: %+v", short, row)
					}
				case "patches":
					if !win || !reKB.MatchString(get("hotfix_id")) || get("csname") != strings.ToUpper(short) {
						t.Errorf("%s patches: %+v", short, row)
					}
				case "chrome":
					if !reExtID.MatchString(get("identifier")) || get("locale") != "en" {
						t.Errorf("%s chrome: %+v", short, row)
					}
				}
			}
			if win && (name == "patches" || name == "local_admins") && len(rows) == 0 {
				t.Errorf("%s: %s returned nothing", short, name)
			}
			if !win && name == "patches" && len(rows) != 0 {
				t.Errorf("%s: a non-Windows host reported patches", short)
			}
			if name == "hardware" && len(rows) != 1 {
				t.Errorf("%s: hardware returned %d rows", short, len(rows))
			}
		}
	}
}

func TestPinnedIdentityColumnsNeverGetWords(t *testing.T) {
	node := parseTestNodes(t)[0] // finance-ws-12, primary user unset
	for _, q := range []string{
		"SELECT csname, computer_name, hostname, device_name, uuid, hardware_serial, username FROM some_unseeded_table",
		"SELECT * FROM appcompat_shims",
	} {
		for _, row := range schemaFakeRows(node, q) {
			for col, want := range map[string]string{
				"csname":          "finance-ws-12",
				"computer_name":   "finance-ws-12",
				"hostname":        node.Name,
				"device_name":     "finance-ws-12",
				"uuid":            node.Identifier,
				"hardware_serial": "EXC7440A12",
				"username":        "Administrator",
			} {
				if v, ok := row[col]; ok && v != want {
					t.Errorf("%s: %s = %v, want %s", q, col, v, want)
				}
			}
		}
	}
}

func TestScalarSubqueriesAreAnswered(t *testing.T) {
	node := parseTestNodes(t)[0]
	q, subs := extractSubqueries("SELECT user, (SELECT hostname FROM system_info) AS h FROM logged_in_users WHERE x IN (select 1)")
	if len(subs) != 2 || strings.Contains(strings.ToLower(q), "select hostname") {
		t.Fatalf("extractSubqueries: %q %v", q, subs)
	}
	rows := schemaFakeRows(node, "SELECT (SELECT hostname FROM system_info) AS h FROM os_version")
	if len(rows) != 1 || rows[0]["h"] != node.Name {
		t.Fatalf("scalar subquery: %+v", rows)
	}
}

func TestEqualityJoinsForPinnedHosts(t *testing.T) {
	terms := parseJoins("SELECT * FROM users u JOIN user_groups ug ON ug.UID = u.UID LEFT JOIN groups AS g ON g.GID = ug.GID WHERE 1")
	if len(terms) != 3 || terms[1].alias != "ug" || terms[2].alias != "g" || !terms[2].left || terms[1].left {
		t.Fatalf("parseJoins: %+v", terms)
	}
	if len(terms[1].on) != 1 || terms[1].on[0] != [2]string{"ug.UID", "u.UID"} {
		t.Fatalf("ON parse: %+v", terms[1].on)
	}
}
