package synth

import (
	"context"
	"strings"
	"testing"

	"github.com/huntbase-io/phantomfleet/internal/host"
)

// evalScalar runs SELECT <expr> in the evaluator and returns the value as
// osquery would report it, or the error message.
func evalScalar(t *testing.T, expr string) (string, string) {
	t.Helper()
	n := host.Node{Name: "srv", Target: "ubuntu", Identifier: "f-1"}
	res := Answer(n, "SELECT "+expr+" AS v")
	if res.Status != 0 {
		return "", res.Message
	}
	if len(res.Rows) != 1 {
		t.Fatalf("%s: rows = %v", expr, res.Rows)
	}
	return res.Rows[0]["v"].(string), ""
}

func TestOSQuerySQLFunctions(t *testing.T) {
	cases := []struct{ expr, want, err string }{
		// split: any of the token characters, empty pieces dropped, trimmed.
		{"split('192.168.0.1', '.', 1)", "168", ""},
		{"split('192.168.0.1', '.0', 0)", "192", ""},
		{"split('a, b,,c', ',', 2)", "c", ""},
		{"split('3006.9+ds-1', '.', 0)", "3006", ""},
		{"split('a.b', '.', 5)", "", ""},
		{"split('a.b', '.', -1)", "", ""},
		{"split(NULL, '.', 0)", "", ""},
		{"split('a.b', '', 0)", "", "Invalid input to split function"},
		// regex_split: the token is a regular expression.
		{`regex_split('192.168.0.1', '\.', 3)`, "1", ""},
		{`regex_split('192.168.0.1', '\.0', 0)`, "192.168", ""},
		{`regex_split('a..b', '\.', 1)`, "", ""},
		{`regex_split('a.b.', '\.', 2)`, "", ""},
		{"regex_split('a', '(', 0)", "", "Invalid regex"},
		// regex_match: a group of the first match.
		{"regex_match('osquery 5.24.0', '([0-9]+)\\.([0-9]+)', 2)", "24", ""},
		{"regex_match('osquery 5.24.0', '[0-9]+', 0)", "5", ""},
		{"regex_match('abc', 'x', 0)", "", ""},
		{"regex_match('abc', 'a(x)?', 1)", "", ""},
		{"regex_match('abc', '" + strings.Repeat("a", 300) + "', 0)", "", "Invalid regex: too big, max size is 256 bytes"},
		// concat and concat_ws skip NULLs; concat_ws keeps the separator
		// after an argument followed by a NULL one, as osquery does.
		{"concat('a', NULL, 'b', 1)", "ab1", ""},
		{"concat_ws('-', 'a', NULL, 'b')", "a-b", ""},
		{"concat_ws('-', 'a', 'b', NULL)", "a-b-", ""},
		{"concat_ws('.', 5, 24, 0)", "5.24.0", ""},
		// Base64.
		{"to_base64('osquery')", "b3NxdWVyeQ==", ""},
		{"from_base64('b3NxdWVyeQ==')", "osquery", ""},
		{"from_base64('b3NxdWVyeQ')", "osquery", ""},
		{"from_base64('!!')", "", ""},
		{"conditional_to_base64('plain text')", "plain text", ""},
		{"conditional_to_base64(char(1, 2))", "AQI=", ""},
		// inet_aton.
		{"inet_aton('10.14.22.31')", "168695327", ""},
		{"inet_aton('::1')", "", ""},
		{"inet_aton('10.1')", "", ""},
		// Maths: log is the natural logarithm, as in osquery.
		{"round(log(100), 4)", "4.6052", ""},
		{"log10(1000)", "3", ""},
		{"sqrt(16)", "4", ""},
		{"power(2, 10)", "1024", ""},
		{"ceil(1.2)", "2", ""},
		{"floor(-1.2)", "-2", ""},
		{"round(cot(1), 4)", "0.6421", ""},
		{"round(degrees(pi()), 4)", "180", ""},
		{"log(0)", "", "Numerical result out of range"},
		{"log(-1)", "", "Numerical argument out of domain"},
	}
	for _, c := range cases {
		got, msg := evalScalar(t, c.expr)
		if got != c.want || msg != c.err {
			t.Errorf("%s = %q (error %q), want %q (error %q)", c.expr, got, msg, c.want, c.err)
		}
	}
}

func TestOSQueryFunctionsBoundTheirOutput(t *testing.T) {
	_, msg := evalScalar(t, "length(concat(zeroblob(3000000), zeroblob(3000000)))")
	if msg == "" {
		t.Fatal("concat built a value over the length limit")
	}
	_, msg = evalScalar(t, "length(to_base64(zeroblob(4000000)))")
	if msg == "" {
		t.Fatal("to_base64 built a value over the length limit")
	}
}

func TestSplitInVersionQueries(t *testing.T) {
	isolateLoaders(t)
	dir := t.TempDir()
	writeFile(t, dir, "linux.yaml", `_replace: [deb_packages]
deb_packages:
  - {name: salt-master, version: "3006.9+ds-1", source: salt, arch: all}
`)
	if _, err := LoadSeedDir(dir); err != nil {
		t.Fatal(err)
	}
	random := host.Node{Name: "brisk-otter-01", Target: "ubuntu", Identifier: "r-1"}
	random.OS = ProfileOS(random.Target)
	pinned := host.Node{Name: "srv", Target: "ubuntu", Identifier: "p-1", Pinned: true}
	for _, q := range []string{
		"SELECT CAST(split(version, '.', 0) AS INTEGER) AS major FROM deb_packages WHERE name = 'salt-master'",
		"WITH v AS (SELECT CAST(split(version, '.', 0) AS INTEGER) AS major FROM deb_packages WHERE name = 'salt-master') SELECT major FROM v WHERE major >= 3000",
	} {
		for _, n := range []host.Node{random, pinned} {
			res := Answer(n, q)
			if res.Status != 0 || len(res.Rows) != 1 || res.Rows[0]["major"] != "3006" {
				t.Errorf("pinned=%v %q = %+v", n.Pinned, q, res)
			}
		}
	}
}

func TestOSQueryFunctionsKeepTheConnectionHardened(t *testing.T) {
	// Registering functions must not loosen the guard: still one statement,
	// no ATTACH, read-only.
	db, conn, err := openSQLite(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), "ATTACH DATABASE ':memory:' AS x"); err == nil {
		t.Fatal("ATTACH allowed")
	}
	ws := host.Node{Name: "ws", Target: "windows", Pinned: true}
	if _, err := sqliteEvalRows(ws, "SELECT split('a.b', '.', 0); SELECT 1"); err == nil {
		t.Fatal("stacked statement accepted")
	}
}
