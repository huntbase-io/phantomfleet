package synth

import (
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/huntbase-io/phantomfleet/internal/host"
	"gopkg.in/yaml.v3"
)

// --- --seeds-dir layers ------------------------------------------------------

func TestSeedsDirsLayerInOrder(t *testing.T) {
	isolateLoaders(t)
	dir := t.TempDir()
	// Layer 1 replaces the built-in services with its own baseline.
	writeFile(t, dir, "base/windows.yaml", `_replace: [services]
services:
  - {name: BaseSvc, status: RUNNING}
  - {name: SharedSvc, status: RUNNING}
`)
	writeFile(t, dir, "base/rowcounts.yaml", "services: [2, 2]\n")
	// Layer 2 appends to it and overrides one host's copy of a row.
	writeFile(t, dir, "estate/windows.yaml", `services:
  - {_hosts: ws-01, _key: name, name: SharedSvc, status: STOPPED}
  - {name: EstateSvc, status: RUNNING}
`)
	writeFile(t, dir, "estate/rowcounts.yaml", "services: [3, 3]\n")
	cfg := loaderInputs{SeedsDirs: []string{filepath.Join(dir, "base"), filepath.Join(dir, "estate")}}
	if err := loadData(cfg, io.Discard); err != nil {
		t.Fatal(err)
	}
	ws := host.Node{Name: "ws-01.lab.example.com", Target: "windows", Pinned: true, Identifier: "ws-01"}
	rows := schemaFakeRows(ws, "SELECT name, status FROM services")
	got := map[string]string{}
	for _, r := range rows {
		got[r["name"].(string)] = r["status"].(string)
	}
	want := map[string]string{"BaseSvc": "RUNNING", "SharedSvc": "STOPPED", "EstateSvc": "RUNNING"}
	if len(got) != len(want) {
		t.Fatalf("services = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("services = %v, want %v", got, want)
		}
	}

	// A _replace in a later layer drops the rows of every earlier one.
	isolateLoaders(t)
	writeFile(t, dir, "estate2/windows.yaml", "_replace: [services]\nservices:\n  - {name: OnlySvc, status: RUNNING}\n")
	cfg.SeedsDirs = []string{filepath.Join(dir, "base"), filepath.Join(dir, "estate2")}
	if err := loadData(cfg, io.Discard); err != nil {
		t.Fatal(err)
	}
	rows = schemaFakeRows(ws, "SELECT name FROM services")
	if len(rows) != 1 || rows[0]["name"] != "OnlySvc" {
		t.Fatalf("services after a later _replace = %v", rows)
	}
}

func TestLaterLayerViewReplacesEarlierView(t *testing.T) {
	isolateLoaders(t)
	dir := t.TempDir()
	cfg := loaderInputs{
		ExtraSchemas: []string{writeFile(t, dir, "ext.json", `{"example_ext_v": [{"name": "v", "type": "text"}]}`)},
		SeedsDirs: []string{
			filepath.Dir(writeFile(t, dir, "one/linux.yaml", "_views:\n  example_ext_v: SELECT 'one' AS v\n")),
			filepath.Dir(writeFile(t, dir, "two/all.yaml", "_views:\n  example_ext_v: SELECT 'two' AS v\n")),
		},
	}
	if err := loadData(cfg, io.Discard); err != nil {
		t.Fatal(err)
	}
	rows, err := sqliteEvalRows(host.Node{Name: "srv", Target: "linux", Pinned: true}, "SELECT v FROM example_ext_v")
	if err != nil || len(rows) != 1 || rows[0]["v"] != "two" {
		t.Fatalf("rows = %v, %v", rows, err)
	}
}

// --- views over their own seed rows -------------------------------------------

func TestViewReadsItsOwnSeedRows(t *testing.T) {
	isolateLoaders(t)
	dir := t.TempDir()
	cfg := loaderInputs{
		ExtraSchemas: []string{writeFile(t, dir, "ext.json", `{"example_ext_log": [
			{"name": "ts", "type": "bigint"}, {"name": "day", "type": "text"},
			{"name": "who", "type": "text"}, {"name": "who_name", "type": "text"}]}`)},
		SeedsDirs: []string{filepath.Dir(writeFile(t, dir, "seeds/all.yaml", `example_ext_log:
  - {_hosts: srv, ts: "1700000000", who: "1000"}
  - {_hosts: srv, ts: "1700090000", day: "1999-12-31", who: "0", who_name: root}
_views:
  example_ext_log: |
    SELECT ts, COALESCE(day, strftime('%Y-%m-%d', ts, 'unixepoch')) AS day,
           who, COALESCE(NULLIF(who_name, ''), who) AS who_name
    FROM example_ext_log
`))},
	}
	if err := loadData(cfg, io.Discard); err != nil {
		t.Fatal(err)
	}
	srv := host.Node{Name: "srv.lab.example.com", Target: "linux", Pinned: true}
	rows, err := sqliteEvalRows(srv, "SELECT day, who_name FROM example_ext_log ORDER BY ts")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0]["day"] != "2023-11-14" || rows[0]["who_name"] != "1000" ||
		rows[1]["day"] != "1999-12-31" || rows[1]["who_name"] != "root" {
		t.Fatalf("rows = %v", rows)
	}
	// Another view reads the post-processed rows.
	other := host.Node{Name: "other", Target: "linux", Pinned: true}
	if rows, err := sqliteEvalRows(other, "SELECT * FROM example_ext_log"); err != nil || len(rows) != 0 {
		t.Fatalf("host without seed rows: %v, %v", rows, err)
	}
}

// --- unknown tables on pinned hosts ------------------------------------------

func TestPinnedHostsFailStatementsOnUnknownTables(t *testing.T) {
	isolateLoaders(t)
	pinned := host.Node{Name: "srv", Target: "linux", Pinned: true}
	q := "SELECT name FROM not_an_osquery_table WHERE name = 'x'"
	if !wantsSQLiteEval(pinned, q) {
		t.Fatal("a pinned host must run a statement on an unknown table in SQLite")
	}
	if _, err := sqliteEvalRows(pinned, q); err == nil || !strings.Contains(err.Error(), "no such table: not_an_osquery_table") {
		t.Fatalf("err = %v", err)
	}
	// Table-valued functions are SQLite's own and still work.
	rows, err := sqliteEvalRows(pinned, `SELECT value FROM json_each('[1,2]')`)
	if err != nil || len(rows) != 2 {
		t.Fatalf("json_each = %v, %v", rows, err)
	}
	// Core tables keep the pattern answerer; random nodes keep answering.
	if wantsSQLiteEval(pinned, "SELECT name FROM processes") {
		t.Fatal("a core table must keep the pattern answerer")
	}
	if wantsSQLiteEval(host.Node{Name: "r", Target: "linux"}, q) {
		t.Fatal("random nodes must keep the pattern answerer")
	}
}

func TestSeededTablesAreNotUnknown(t *testing.T) {
	isolateLoaders(t)
	dir := t.TempDir()
	writeFile(t, dir, "linux.yaml", "custom_inventory:\n  - {item: widget}\n")
	if _, err := LoadSeedDir(dir); err != nil {
		t.Fatal(err)
	}
	if wantsSQLiteEval(host.Node{Name: "srv", Target: "linux", Pinned: true}, "SELECT item FROM custom_inventory") {
		t.Fatal("a seeded table is known on its platform")
	}
}

// --- joins with an empty table -------------------------------------------------

func TestZipJoinWithAnEmptyTableHasNoRows(t *testing.T) {
	isolateLoaders(t)
	dir := t.TempDir()
	writeFile(t, dir, "windows.yaml", "_replace: [chrome_extensions]\nchrome_extensions: []\n")
	if _, err := LoadSeedDir(dir); err != nil {
		t.Fatal(err)
	}
	// A pinned host's chrome_extensions is empty, as declared.
	ws := host.Node{Name: "ws", Target: "windows", Pinned: true, Identifier: "ws"}
	rows := schemaFakeRows(ws, "SELECT u.username, c.name FROM users u, chrome_extensions c")
	if len(rows) != 0 {
		t.Fatalf("join with an empty table answered %d rows", len(rows))
	}
}

// --- built-in seeds ------------------------------------------------------------

func TestBuiltInSeedsNameOnlyCoreTables(t *testing.T) {
	entries, err := seedFiles.ReadDir("seeds")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		raw, err := seedFiles.ReadFile("seeds/" + e.Name())
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]interface{}
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		for table := range doc {
			if _, ok := osquerySchema[strings.ToLower(table)]; !ok {
				t.Errorf("seeds/%s: %s is not an osquery table", e.Name(), table)
			}
		}
	}
	var counts map[string]interface{}
	if err := yaml.Unmarshal(rowCountsYAML, &counts); err != nil {
		t.Fatal(err)
	}
	for table := range counts {
		if _, ok := osquerySchema[table]; !ok && table != "default" {
			t.Errorf("rowcounts.yaml: %s is not an osquery table", table)
		}
	}
}
