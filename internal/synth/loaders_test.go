package synth

import (
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/huntbase-io/phantomfleet/internal/host"
)

// isolateLoaders snapshots every global the loaders write (schema, extension
// tables, catalogs, seed profiles, views and row counts) and restores it when
// the test ends.
func isolateLoaders(t *testing.T) {
	t.Helper()
	savedSchema := make(map[string][]schemaColumn, len(osquerySchema))
	for k, v := range osquerySchema {
		savedSchema[k] = v
	}
	savedExt := map[string]bool{}
	for k, v := range extensionTables {
		savedExt[k] = v
	}
	savedCatalogs := map[string][]map[string]string{}
	for k, v := range catalogs {
		savedCatalogs[k] = v
	}
	savedProfiles := map[string]seedProfile{}
	for name, prof := range seedProfiles {
		cp := seedProfile{}
		for table, rows := range prof {
			cp[table] = append([]map[string]string(nil), rows...)
		}
		savedProfiles[name] = cp
	}
	savedViews := map[string]map[string]string{}
	for p, vs := range seedViews {
		cp := map[string]string{}
		for k, v := range vs {
			cp[k] = v
		}
		savedViews[p] = cp
	}
	savedCounts := map[string][2]int{}
	for k, v := range rowCounts {
		savedCounts[k] = v
	}
	t.Cleanup(func() {
		osquerySchema = savedSchema
		extensionTables = savedExt
		catalogs = savedCatalogs
		seedProfiles = savedProfiles
		seedViews = savedViews
		rowCounts = savedCounts
	})
}

// loadExtensionExample loads examples/extension-tables the way main does and
// returns its pinned hosts by short name.
func loadExtensionExample(t *testing.T) map[string]host.Node {
	t.Helper()
	isolateLoaders(t)
	dir := filepath.Join("..", "..", "examples", "extension-tables")
	cfg := loaderInputs{
		ExtraSchemas: []string{filepath.Join(dir, "schema.json")},
		Catalogs:     []string{filepath.Join(dir, "catalog.yaml")},
		SeedsDirs:    []string{filepath.Join(dir, "seeds")},
	}
	var out strings.Builder
	if err := loadData(cfg, &out); err != nil {
		t.Fatalf("loadData: %v", err)
	}
	nodes, err := host.LoadNodesFile(filepath.Join(dir, "nodes.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	byShort := map[string]host.Node{}
	for _, n := range nodes {
		byShort[shortHostname(n.Name)] = n
	}
	return byShort
}

// --- --extra-schema ---------------------------------------------------------

func TestExtraSchemaMergesNewTables(t *testing.T) {
	isolateLoaders(t)
	p := writeFile(t, t.TempDir(), "ext.json", `{"example_ext_downloads": [{"name": "ts", "type": "bigint"}, {"name": "Kind", "type": "TEXT"}]}`)
	n, err := LoadExtraSchema(p)
	if err != nil || n != 1 {
		t.Fatalf("LoadExtraSchema = %d, %v", n, err)
	}
	if !isExtensionTable("example_ext_downloads") {
		t.Fatal("example_ext_downloads is not registered as an extension table")
	}
	cols := osquerySchema["example_ext_downloads"]
	if len(cols) != 2 || cols[1].Name != "kind" || cols[1].Type != "text" {
		t.Fatalf("columns not normalized: %+v", cols)
	}
	// Loading the same file again is not a clash.
	if _, err := LoadExtraSchema(p); err != nil {
		t.Fatalf("identical reload: %v", err)
	}
}

func TestExtraSchemaClashWithEmbeddedTable(t *testing.T) {
	isolateLoaders(t)
	dir := t.TempDir()
	p := writeFile(t, dir, "clash.json", `{"processes": [{"name": "pid", "type": "bigint"}]}`)
	_, err := LoadExtraSchema(p)
	if err == nil || !strings.Contains(err.Error(), "embedded osquery schema") {
		t.Fatalf("want a clash with the embedded schema, got %v", err)
	}

	// An identical copy of an embedded table is accepted and stays a core table.
	same, _ := json.Marshal(map[string][]schemaColumn{"uptime": osquerySchema["uptime"]})
	if _, err := LoadExtraSchema(writeFile(t, dir, "same.json", string(same))); err != nil {
		t.Fatalf("identical embedded table: %v", err)
	}
	if isExtensionTable("uptime") {
		t.Fatal("an identical embedded table must not become an extension table")
	}
}

func TestExtraSchemaClashBetweenFiles(t *testing.T) {
	isolateLoaders(t)
	dir := t.TempDir()
	a := writeFile(t, dir, "a.json", `{"example_ext_downloads": [{"name": "ts", "type": "bigint"}]}`)
	b := writeFile(t, dir, "b.json", `{"example_ext_downloads": [{"name": "ts", "type": "text"}], "example_ext_other": [{"name": "x", "type": "text"}]}`)
	if _, err := LoadExtraSchema(a); err != nil {
		t.Fatal(err)
	}
	_, err := LoadExtraSchema(b)
	if err == nil || !strings.Contains(err.Error(), "earlier --extra-schema") {
		t.Fatalf("want a clash between files, got %v", err)
	}
	if isExtensionTable("example_ext_other") {
		t.Fatal("a file with a clash must not be merged partly")
	}
}

func TestExtraSchemaRejectsBadInput(t *testing.T) {
	for name, doc := range map[string]string{
		"not json":       `{"t": `,
		"bad type":       `{"example_ext_t": [{"name": "a", "type": "varchar"}]}`,
		"no columns":     `{"example_ext_t": []}`,
		"bad table name": `{"example-ext": [{"name": "a", "type": "text"}]}`,
		"bad column":     `{"example_ext_t": [{"name": "a b", "type": "text"}]}`,
		"dup column":     `{"example_ext_t": [{"name": "a", "type": "text"}, {"name": "A", "type": "text"}]}`,
	} {
		if _, err := parseExtraSchema([]byte(doc)); err == nil {
			t.Errorf("%s: accepted %s", name, doc)
		}
	}
}

func TestExtensionTableWithNoSeedRowsIsEmpty(t *testing.T) {
	hosts := loadExtensionExample(t)
	srv := hosts["srv-01"] // linux: no example_ext_* rows at all
	q := "SELECT * FROM example_ext_downloads"
	if !wantsSQLiteEval(srv, q) {
		t.Fatal("a pinned host must answer extension tables through SQLite")
	}
	rows, err := sqliteEvalRows(srv, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("pinned host with no seed rows answered %d rows: %v", len(rows), rows[0])
	}
	// Counting an empty store is 0, not a random number.
	rows, err = sqliteEvalRows(srv, "SELECT count(*) AS n FROM example_ext_folders")
	if err != nil || len(rows) != 1 || rows[0]["n"] != "0" {
		t.Fatalf("count on empty store = %v, %v", rows, err)
	}
	// The pattern answerer never invents rows for an extension table either.
	if rows := schemaFakeRows(srv, q); len(rows) != 0 {
		t.Fatalf("pattern answerer generated %d rows", len(rows))
	}
}

func TestRandomNodesAnswerExtensionTablesWithNoRows(t *testing.T) {
	loadExtensionExample(t)
	random := host.Node{Name: "brisk-otter-01", Target: "windows", Identifier: "r-1", IP: "192.0.2.99"}
	if wantsSQLiteEval(random, "SELECT * FROM example_ext_downloads") {
		t.Fatal("random nodes must not use the SQLite engine")
	}
	for _, q := range []string{
		"SELECT * FROM example_ext_downloads",
		"SELECT user, ts FROM example_ext_downloads WHERE verdict = 'allowed'",
		"SELECT count(*) FROM example_ext_folders",
		"SELECT u.username, d.file FROM users u JOIN example_ext_downloads d ON u.username = d.user",
	} {
		if rows := schemaFakeRows(random, q); len(rows) != 0 {
			t.Errorf("%q answered %d rows on a random node", q, len(rows))
		}
	}
}

func TestExtensionTableAnswersFromSeedRows(t *testing.T) {
	hosts := loadExtensionExample(t)
	ws := hosts["ws-01"]
	rows, err := sqliteEvalRows(ws, "SELECT verdict, count(*) AS n FROM example_ext_downloads GROUP BY verdict ORDER BY verdict")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range rows {
		got[r["verdict"].(string)] = r["n"].(string)
	}
	if got["allowed"] != "4" || got["blocked"] != "1" {
		t.Fatalf("download counts = %v", got)
	}
	// A join between an extension table and its sibling evaluates for real.
	rows, err = sqliteEvalRows(ws, "SELECT f.name FROM example_ext_downloads d JOIN example_ext_folders f ON f.folder_id = d.folder_id WHERE d.verdict = 'blocked'")
	if err != nil || len(rows) != 1 || rows[0]["name"] != "Downloads" {
		t.Fatalf("join = %v, %v", rows, err)
	}
}

// --- _views: constraint-driven extension tables ------------------------------

func TestViewSummaryUsesConstraints(t *testing.T) {
	hosts := loadExtensionExample(t)
	ws := hosts["ws-01"]
	rows, err := sqliteEvalRows(ws, "SELECT source_host, downloads, total_bytes, verdicts FROM example_ext_download_summary WHERE user = 'j.doe'")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range rows {
		got[r["source_host"].(string)] = r["downloads"].(string) + "/" + r["total_bytes"].(string)
	}
	if len(got) != 2 || got["downloads.example.com"] != "2/21000000" || got["docs.example.org"] != "2/370000" {
		t.Fatalf("j.doe summary = %v", got)
	}

	// A second input narrows further: the constraints reach the view.
	rows, err = sqliteEvalRows(ws, "SELECT sum(downloads) AS n FROM example_ext_download_summary WHERE min_bytes = 1000000")
	if err != nil || len(rows) != 1 || rows[0]["n"] != "3" {
		t.Fatalf("min_bytes = 1000000: %v, %v (want 3 downloads)", rows, err)
	}

	// Unconstrained, the view's own defaults apply (every user, every size).
	rows, err = sqliteEvalRows(ws, "SELECT sum(downloads) AS n, count(*) AS groups FROM example_ext_download_summary")
	if err != nil || len(rows) != 1 || rows[0]["n"] != "5" || rows[0]["groups"] != "3" {
		t.Fatalf("default summary = %v, %v", rows, err)
	}

	// JSON functions work inside views.
	rows, err = sqliteEvalRows(ws, "SELECT verdicts FROM example_ext_download_summary WHERE user = 'svc-backup'")
	if err != nil || len(rows) != 1 {
		t.Fatalf("svc-backup summary = %v, %v", rows, err)
	}
	var verdicts []string
	if err := json.Unmarshal([]byte(rows[0]["verdicts"].(string)), &verdicts); err != nil || len(verdicts) != 1 || verdicts[0] != "blocked" {
		t.Errorf("svc-backup verdicts = %v (%v)", rows[0]["verdicts"], err)
	}

	// Another host has no stored rows, so its summary is empty too.
	rows, err = sqliteEvalRows(hosts["srv-01"], "SELECT * FROM example_ext_download_summary")
	if err != nil || len(rows) != 0 {
		t.Fatalf("srv-01 summary = %v, %v", rows, err)
	}
}

func TestViewFolderSizesWalksDown(t *testing.T) {
	hosts := loadExtensionExample(t)
	ws := hosts["ws-01"]
	rows, err := sqliteEvalRows(ws, "SELECT folder_id, level, total_bytes, subfolders FROM example_ext_folder_sizes WHERE folder = 'f-1' AND max_depth = 1")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	byID := map[string]map[string]interface{}{}
	for _, r := range rows {
		got = append(got, r["folder_id"].(string)+"@"+r["level"].(string))
		byID[r["folder_id"].(string)] = r
	}
	want := "f-1@0 f-2@1 f-3@1"
	if strings.Join(got, " ") != want {
		t.Fatalf("folders = %s, want %s", strings.Join(got, " "), want)
	}
	if byID["f-1"]["total_bytes"] != "36000" || byID["f-1"]["subfolders"] != "2" {
		t.Errorf("f-1 = %v", byID["f-1"])
	}
	if byID["f-2"]["total_bytes"] != "15000" {
		t.Errorf("f-2 total_bytes = %v", byID["f-2"]["total_bytes"])
	}

	// Default max_depth (2) stops above f-5.
	rows, err = sqliteEvalRows(ws, "SELECT folder_id FROM example_ext_folder_sizes WHERE folder = 'f-1'")
	if err != nil || len(rows) != 4 {
		t.Fatalf("default depth = %v, %v", rows, err)
	}
	// No folder, no rows.
	rows, err = sqliteEvalRows(ws, "SELECT * FROM example_ext_folder_sizes")
	if err != nil || len(rows) != 0 {
		t.Fatalf("unconstrained folder sizes = %v, %v", rows, err)
	}
}

func TestViewsAreValidatedAtLoad(t *testing.T) {
	isolateLoaders(t)
	dir := t.TempDir()
	if _, err := LoadExtraSchema(writeFile(t, dir, "ext.json", `{"example_ext_t": [{"name": "a", "type": "text"}]}`)); err != nil {
		t.Fatal(err)
	}
	for name, doc := range map[string]string{
		"core table":     "_views:\n  processes: SELECT 1 AS pid\n",
		"not a select":   "_views:\n  example_ext_t: DELETE FROM x\n",
		"two statements": "_views:\n  example_ext_t: SELECT 1 AS a; SELECT 2 AS a\n",
		"not a string":   "_views:\n  example_ext_t: [1, 2]\n",
		"not a mapping":  "_views: [example_ext_t]\n",
	} {
		seeds := filepath.Join(dir, strings.ReplaceAll(name, " ", "_"))
		writeFile(t, seeds, "all.yaml", doc)
		if _, err := LoadSeedDir(seeds); err == nil {
			t.Errorf("%s: view accepted", name)
		}
	}
}

func TestViewCycleIsAnError(t *testing.T) {
	isolateLoaders(t)
	dir := t.TempDir()
	if _, err := LoadExtraSchema(writeFile(t, dir, "ext.json", `{"example_ext_a": [{"name": "x", "type": "text"}], "example_ext_b": [{"name": "x", "type": "text"}]}`)); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "seeds/all.yaml", "_views:\n  example_ext_a: SELECT x FROM example_ext_b\n  example_ext_b: SELECT x FROM example_ext_a\n")
	if _, err := LoadSeedDir(filepath.Join(dir, "seeds")); err != nil {
		t.Fatal(err)
	}
	node := host.Node{Name: "ws-01.lab.example.com", Target: "linux", Pinned: true}
	if _, err := sqliteEvalRows(node, "SELECT * FROM example_ext_a"); err == nil || !strings.Contains(err.Error(), "refers to itself") {
		t.Fatalf("want a cycle error, got %v", err)
	}
}

func TestConstraintValue(t *testing.T) {
	q := `SELECT * FROM t h WHERE h."from" = 100 AND "to" = -5 AND folder = 'it''s' AND ratio = 0.5`
	for col, want := range map[string]interface{}{"from": int64(100), "to": int64(-5), "folder": "it's", "ratio": 0.5} {
		got, ok := constraintValue(q, col)
		if !ok || got != want {
			t.Errorf("%s = %v (%v), want %v", col, got, ok, want)
		}
	}
	if _, ok := constraintValue(q, "missing"); ok {
		t.Error("an unconstrained column must bind NULL")
	}
	if _, ok := constraintValue("SELECT * FROM t WHERE level > 2", "level"); ok {
		t.Error("only equality constraints are inputs")
	}
}

// --- --catalog --------------------------------------------------------------

func TestCatalogRowsStayCoherentAndUnique(t *testing.T) {
	hosts := loadExtensionExample(t)
	srv := hosts["srv-01"]
	want := map[string]string{}
	for _, e := range catalogs["example_linux_services"] {
		want[e["name"]] = e["path"]
	}
	seen := map[string]int{}
	for _, r := range schemaFakeRows(srv, "SELECT name, path FROM processes") {
		name, path := r["name"].(string), r["path"].(string)
		if p, ok := want[name]; ok && p == path {
			seen[name]++
		}
	}
	if len(seen) == 0 {
		t.Fatal("no catalog-backed process rows")
	}
	for name, n := range seen {
		if n > 1 {
			t.Errorf("catalog entry %s used %d times", name, n)
		}
	}
	// Anchor rows of the built-in seeds keep their values: a catalog entry
	// with an anchor's name is skipped, never substituted.
	for _, r := range schemaFakeRows(srv, "SELECT name, path FROM processes WHERE name = 'systemd'") {
		if r["path"] != "/usr/lib/systemd/systemd" {
			t.Errorf("anchor systemd row changed: %v", r)
		}
	}
}

func TestCatalogPickerExhaustsAndSkipsAnchors(t *testing.T) {
	isolateLoaders(t)
	catalogs = map[string][]map[string]string{
		"example_cat": {{"name": "a", "v": "1"}, {"name": "b", "v": "2"}, {"name": "c", "v": "3"}},
	}
	f := stableFaker(host.Node{Name: "n"}, "test", "picker")
	picker := newRowPicker(f, map[string]bool{"b": true})
	tmpl := map[string]string{"name": "{{row:example_cat.name}}", "value": "v={{row:example_cat.V}}"}
	var names []string
	for {
		row, ok := expandRowTokens(tmpl, f, picker)
		if !ok {
			break
		}
		if row["value"] != "v="+map[string]string{"a": "1", "c": "3"}[row["name"]] {
			t.Fatalf("fields from different entries: %v", row)
		}
		names = append(names, row["name"])
	}
	if len(names) != 2 || strings.Contains(strings.Join(names, ","), "b") {
		t.Fatalf("picked %v, want a and c once each", names)
	}
	if _, ok := expandRowTokens(map[string]string{"x": "{{row:nope.name}}"}, f, nil); ok {
		t.Fatal("an unknown catalog must not expand")
	}
	if row := resolveRow(map[string]string{"x": "[{{row:nope.name}}]"}, host.Node{}, f); row["x"] != "[]" {
		t.Fatalf("resolveRow with an unknown catalog = %q", row["x"])
	}
}

func TestCatalogClashAndValidation(t *testing.T) {
	isolateLoaders(t)
	dir := t.TempDir()
	a := writeFile(t, dir, "a.yaml", "example_cat:\n  - {name: a, path: /a}\n")
	same := writeFile(t, dir, "same.yaml", "example_cat:\n  - {name: a, path: /a}\n")
	diff := writeFile(t, dir, "diff.yaml", "example_cat:\n  - {name: a, path: /b}\n")
	if n, err := LoadCatalog(a); err != nil || n != 1 {
		t.Fatalf("LoadCatalog = %d, %v", n, err)
	}
	if _, err := LoadCatalog(same); err != nil {
		t.Fatalf("identical catalog: %v", err)
	}
	if _, err := LoadCatalog(diff); err == nil || !strings.Contains(err.Error(), "clashes") {
		t.Fatalf("want a clash, got %v", err)
	}
	for name, doc := range map[string]string{
		"not yaml list": "example_cat: {name: a}\n",
		"empty":         "example_cat: []\n",
		"bad name":      "example-cat:\n  - {name: a}\n",
		"empty entry":   "example_cat:\n  - {}\n",
	} {
		if _, err := parseCatalog([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// --- SQLite engine ------------------------------------------------------------

func TestReferencedTablesSkipsCTEs(t *testing.T) {
	q := "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM r WHERE n < 3), x AS (SELECT 1 FROM os_version) " +
		"SELECT * FROM system_info s JOIN x ON 1 WHERE (SELECT COUNT(*) FROM users WHERE username = 'from processes') > 0"
	got := strings.Join(referencedTables(q), ",")
	if got != "os_version,system_info,users" {
		t.Fatalf("referencedTables = %s", got)
	}
}

func TestPlainQueriesKeepThePatternAnswerer(t *testing.T) {
	if wantsSQLiteEval(host.Node{Pinned: true}, "SELECT * FROM processes") {
		t.Fatal("a plain SELECT must not switch engines")
	}
	if wantsSQLiteEval(host.Node{}, "WITH x AS (SELECT 1) SELECT * FROM x") {
		t.Fatal("random (unpinned) nodes keep the pattern answerer")
	}
}

func TestPinnedHostsRunCTEsForReal(t *testing.T) {
	fleet := loadExampleCorp(t)
	ws := fleet["finance-ws-12"]
	q := `WITH s AS (SELECT name, status FROM services)
	      SELECT COUNT(*) AS total,
	             SUM(CASE WHEN status = 'STOPPED' THEN 1 ELSE 0 END) AS stopped,
	             (SELECT hostname FROM system_info) AS host
	      FROM s, os_version`
	if !wantsSQLiteEval(ws, q) {
		t.Fatal("a WITH statement on a pinned host uses SQLite")
	}
	rows, err := sqliteEvalRows(ws, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0]["host"] != ws.Name || rows[0]["total"] == "0" {
		t.Fatalf("rows = %v", rows)
	}
	stopped, _ := strconv.Atoi(rows[0]["stopped"].(string))
	if stopped == 0 {
		t.Fatalf("finance-ws-12 has stopped services in its seeds: %v", rows)
	}
	// A table another platform owns is empty (osquery's --enable_foreign).
	rows, err = sqliteEvalRows(ws, "WITH a AS (SELECT name FROM deb_packages) SELECT COUNT(*) AS n FROM a")
	if err != nil || rows[0]["n"] != "0" {
		t.Fatalf("deb_packages on Windows = %v, %v", rows, err)
	}
}

func TestSQLiteRefusesNonReadStatements(t *testing.T) {
	ws := host.Node{Name: "ws", Target: "windows", Pinned: true}
	for _, q := range []string{
		"WITH x AS (SELECT 1) SELECT * FROM x; ATTACH DATABASE '/tmp/pf.db' AS evil",
		"ATTACH DATABASE '/tmp/pf.db' AS evil",
		"PRAGMA table_info(processes)",
	} {
		if _, err := sqliteEvalRows(ws, q); err == nil {
			t.Errorf("accepted %q", q)
		}
	}
	// A semicolon inside a string literal is fine.
	rows, err := sqliteEvalRows(ws, "WITH x AS (SELECT 'a;b' AS v) SELECT v FROM x;")
	if err != nil || len(rows) != 1 || rows[0]["v"] != "a;b" {
		t.Fatalf("literal semicolon: %v, %v", rows, err)
	}
	// An unknown table is an osquery-style error.
	if _, err := sqliteEvalRows(ws, "WITH x AS (SELECT 1) SELECT * FROM no_such_table_here"); err == nil {
		t.Fatal("an unknown table must be reported")
	}
}

func TestSQLiteStatementsAreBounded(t *testing.T) {
	ws := host.Node{Name: "ws", Target: "windows", Pinned: true}
	q := "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM r) SELECT n FROM r"
	rows, err := sqliteEvalRows(ws, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != maxPopulation {
		t.Fatalf("unbounded statement returned %d rows, want the %d cap", len(rows), maxPopulation)
	}
}

func TestInvalidSeedYAMLIsAnError(t *testing.T) {
	isolateLoaders(t)
	for name, content := range map[string]string{
		"linux.yaml":     "processes:\n  - {name: sshd\n",
		"all.yaml":       "- just\n- a list\n",
		"rowcounts.yaml": "processes: [1, 2\n",
	} {
		dir := t.TempDir()
		writeFile(t, dir, "darwin.yaml", "example_marker_table:\n  - {item: should-not-load}\n")
		writeFile(t, dir, name, content)
		n, err := LoadSeedDir(dir)
		if err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: n = %d, err = %v; want an error naming the file", name, n, err)
		}
		if tableDeclared("darwin", "example_marker_table") {
			t.Errorf("%s: a valid file in the same directory was applied", name)
		}
	}
}

func TestShippedSeedDirectoriesLoad(t *testing.T) {
	for _, dir := range []string{"examples/examplecorp/seeds", "examples/extension-tables/seeds", "deploy/seeds"} {
		t.Run(dir, func(t *testing.T) {
			isolateLoaders(t)
			if dir == "examples/extension-tables/seeds" {
				if _, err := LoadExtraSchema(filepath.Join("..", "..", "examples", "extension-tables", "schema.json")); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := LoadSeedDir(filepath.Join("..", "..", dir)); err != nil {
				t.Fatal(err)
			}
		})
	}
}
