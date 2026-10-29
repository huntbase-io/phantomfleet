package synth

import (
	"context"
	"database/sql"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/huntbase-io/phantomfleet/internal/host"
)

// Regression tests for the SQLite statement guard. Statements come from the
// server, so none of these may run more than one statement, attach a file,
// write a file or load code. See SECURITY.md for which layer stops what.

// guardNodes are a random node (which runs EXISTS / osquery_registry /
// pragma_* probes in SQLite with default flags) and a pinned one.
func guardNodes() []host.Node {
	// #nosec G404 -- test fixture
	random := host.RandomNodes(1, rand.New(rand.NewSource(1)), nil, ProfileOS)[0]
	return []host.Node{random, {Name: "ws", Target: "windows", Pinned: true}}
}

// makeVictimDB creates a SQLite file holding a secret, as a browser history or
// app database on the user's disk would.
func makeVictimDB(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE s(secret TEXT); INSERT INTO s VALUES('hunter2')`); err != nil {
		t.Fatal(err)
	}
}

// identQuotes hide "--", "/*" or ";" from a tokenizer that only knows
// string literals: each quote style SQLite accepts for identifiers.
var identQuotes = []struct{ name, open, close string }{
	{"double", `"`, `"`},
	{"bracket", `[`, `]`},
	{"backtick", "`", "`"},
}

func TestSQLiteGuardRefusesAttachThroughQuotedIdentifiers(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.db")
	makeVictimDB(t, victim)
	before, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}

	for _, quote := range identQuotes {
		for _, hide := range []string{"--", "/*", ";", "x;y"} {
			ident := quote.open + hide + quote.close
			target := filepath.Join(dir, "planted-"+quote.name+".sh")
			probes := map[string]string{
				"write": `SELECT 1 FROM osquery_registry WHERE name = ` + ident + `; ATTACH '` + target + `' AS e; ` +
					`CREATE TABLE e.t(x); INSERT INTO e.t VALUES(char(10)||'touch /tmp/pwned'||char(10))`,
				"read":  `SELECT name FROM osquery_registry WHERE name = ` + ident + `; ATTACH '` + victim + `' AS v; SELECT secret FROM v.s`,
				"alias": `SELECT EXISTS(SELECT 1) AS ` + ident + `; ATTACH DATABASE '` + target + `' AS x; CREATE TABLE x.t(a)`,
			}
			for kind, q := range probes {
				for _, n := range guardNodes() {
					rows, err := sqliteEvalRows(n, q)
					if err == nil {
						t.Errorf("%s %s %q on %s: accepted (rows %v)", quote.name, kind, hide, n.Name, rows)
					}
					res := Answer(n, q)
					if res.Status != 1 {
						t.Errorf("%s %s %q on %s: Answer status %d, want 1", quote.name, kind, hide, n.Name, res.Status)
					}
					for _, r := range append(rows, res.Rows...) {
						for _, v := range r {
							if strings.Contains(v.(string), "hunter2") {
								t.Fatalf("%s %s %q: read the victim database: %v", quote.name, kind, hide, r)
							}
						}
					}
					if _, err := os.Stat(target); err == nil {
						t.Fatalf("%s %s %q: created %s", quote.name, kind, hide, target)
					}
				}
			}
		}
	}
	after, err := os.ReadFile(victim)
	if err != nil || string(after) != string(before) {
		t.Fatal("the victim database was modified")
	}
	assertOnlyFiles(t, dir, "victim.db")
}

func TestSQLiteGuardRefusesStackedAndFileStatements(t *testing.T) {
	dir := t.TempDir()
	p := func(name string) string { return filepath.Join(dir, name) }
	for _, q := range []string{
		`SELECT EXISTS(SELECT 1); VACUUM INTO '` + p("d.db") + `'`,
		`SELECT EXISTS(SELECT 1) AS "--"; VACUUM INTO '` + p("v.db") + `'`,
		`SELECT EXISTS(SELECT 1) AS "/*"; VACUUM INTO '` + p("w.db") + `'; --*/`,
		`SELECT EXISTS(SELECT 1) AS [--]; VACUUM INTO '` + p("b.db") + `'`,
		`VACUUM INTO '` + p("plain.db") + `'`,
		`ATTACH DATABASE '` + p("c.db") + `' AS x`,
		`SELECT 1 WHERE EXISTS(SELECT 1); SELECT 2`,
		`SELECT 1 WHERE EXISTS(SELECT 1); PRAGMA writable_schema = ON`,
		`SELECT 1 WHERE EXISTS(SELECT 1); /* c */ CREATE TABLE t(x)`,
		`PRAGMA query_only = OFF`,
		"SELECT 1 WHERE EXISTS(SELECT 1)\x00; ATTACH '" + p("nul.db") + "' AS x",
		`SELECT load_extension('/nonexistent.so') WHERE EXISTS(SELECT 1)`,
		`SELECT load_extension('` + p("x.so") + `') FROM osquery_registry`,
		`SELECT writefile('` + p("wf") + `', 'x') WHERE EXISTS(SELECT 1)`,
		`SELECT readfile('/etc/passwd') WHERE EXISTS(SELECT 1)`,
		`SELECT edit('x', 'vi') WHERE EXISTS(SELECT 1)`,
		`SELECT fts3_tokenizer('simple') WHERE EXISTS(SELECT 1)`,
		`SELECT hex(randomblob(400000000)) AS z WHERE EXISTS(SELECT 1)`,
		`SELECT length(zeroblob(900000000)) AS z WHERE EXISTS(SELECT 1)`,
	} {
		for _, n := range guardNodes() {
			if rows, err := sqliteEvalRows(n, q); err == nil {
				t.Errorf("%s accepted %q (rows %v)", n.Name, q, rows)
			}
		}
	}
	assertOnlyFiles(t, dir)
}

func TestSQLiteGuardKeepsValidStatements(t *testing.T) {
	ws := host.Node{Name: "ws", Target: "windows", Pinned: true}
	for q, want := range map[string]string{
		`SELECT 'a;b' AS v WHERE EXISTS(SELECT 1);`:                                   "a;b",
		`SELECT 1 AS "x;--/*" WHERE EXISTS(SELECT 1);; -- c`:                          "",
		"SELECT `--` FROM (SELECT 'v' AS `--`) WHERE EXISTS(SELECT 1) /* trailing */": "v",
		`SELECT [;] FROM (SELECT 'w' AS [;]) WHERE EXISTS(SELECT 1)`:                  "w",
	} {
		rows, err := sqliteEvalRows(ws, q)
		if err != nil || len(rows) != 1 {
			t.Errorf("%q: %v, %v", q, rows, err)
			continue
		}
		if want != "" {
			for _, v := range rows[0] {
				if v != want {
					t.Errorf("%q: got %v, want %s", q, rows[0], want)
				}
			}
		}
	}
}

// Each layer on its own, so a later change to one is caught even while the
// others still stop the probes.

func TestStripSQLLiteralsQuoteStyles(t *testing.T) {
	for in, want := range map[string]string{
		`SELECT "--"; X`:          `SELECT "  "; X`,
		`SELECT [/*]; X`:          `SELECT [  ]; X`,
		"SELECT `a;b`; X":         "SELECT `a b`; X",
		`SELECT "a""--"; X`:       `SELECT "a    "; X`,
		`SELECT "processes" FROM`: `SELECT "processes" FROM`,
		`SELECT '--;' -- c`:       `SELECT '   '     `,
		`SELECT /* ; */ 1`:        `SELECT         1`,
		"SELECT [a]]; X":          "SELECT [a]]; X",
	} {
		if got := stripSQLLiterals(in); got != want {
			t.Errorf("stripSQLLiterals(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCheckReadStatementUsesSQLiteTokenizer(t *testing.T) {
	// SQLite's tokenizer (sqlite3_complete) ends the first statement at the
	// semicolon after the quoted identifier; the rest is refused.
	for _, quote := range identQuotes {
		q := `SELECT 1 AS ` + quote.open + `--` + quote.close + `; ATTACH 'x' AS y`
		if end, err := firstStatementEnd(q); err != nil || end != strings.Index(q, "; ATTACH") {
			t.Errorf("%s: firstStatementEnd = %d, %v", quote.name, end, err)
		}
		if _, err := checkReadStatement(q); err == nil {
			t.Errorf("%s: accepted %q", quote.name, q)
		}
	}
	got, err := checkReadStatement("  SELECT ';' AS [x;y] ; ;\n-- done\n")
	if err != nil || got != "SELECT ';' AS [x;y]" {
		t.Fatalf("checkReadStatement = %q, %v", got, err)
	}
	if _, err := checkReadStatement(strings.Repeat(" ", maxStatementLength) + "SELECT 1"); err == nil {
		t.Fatal("an over-long statement was accepted")
	}
}

func TestSQLiteConnectionIsHardened(t *testing.T) {
	ctx := context.Background()
	db, conn, err := openSQLite(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	defer conn.Close()
	dir := t.TempDir()

	// Limits alone stop ATTACH and VACUUM INTO, even outside the guard.
	for _, q := range []string{
		`ATTACH DATABASE '` + filepath.Join(dir, "a.db") + `' AS x`,
		`ATTACH DATABASE 'file:` + filepath.Join(dir, "u.db") + `?mode=rwc' AS x`,
		`VACUUM INTO '` + filepath.Join(dir, "v.db") + `'`,
	} {
		if _, err := conn.ExecContext(ctx, q); err == nil {
			t.Errorf("hardened connection ran %q", q)
		}
	}
	assertOnlyFiles(t, dir)

	for _, q := range []string{
		`SELECT hex(randomblob(400000000))`,
		`SELECT load_extension('` + filepath.Join(dir, "x.so") + `')`,
		`SELECT 1` + strings.Repeat(" UNION ALL SELECT 1", 200),
	} {
		rows, err := conn.QueryContext(ctx, q)
		if err == nil {
			for rows.Next() {
			}
			err = rows.Err()
			_ = rows.Close()
		}
		if err == nil {
			t.Errorf("hardened connection ran %q", q[:min(len(q), 60)])
		}
	}

	// While the server's statement runs, the connection is query_only.
	l := &sqliteLoader{ctx: ctx, db: conn}
	if err := l.setQueryOnly(true); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, `CREATE TABLE t(x)`); err == nil {
		t.Error("query_only connection created a table")
	}
}

// assertOnlyFiles fails if dir holds anything but the named files.
func assertOnlyFiles(t *testing.T, dir string, allowed ...string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	for _, e := range entries {
		if !ok[e.Name()] {
			t.Errorf("unexpected file %s", e.Name())
		}
	}
}
