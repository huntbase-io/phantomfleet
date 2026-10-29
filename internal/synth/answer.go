// Package synth answers osquery distributed queries with synthetic rows: the
// embedded osquery schema, the seed profiles and loaders (--seeds-dir,
// --extra-schema, --catalog), the pattern answerer, the SQLite evaluator
// and each node's identity (what it reports at enrollment matches what it
// answers later).
package synth

import (
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/huntbase-io/phantomfleet/internal/host"
)

// Result is one distributed query's synthetic answer as osquery reports it:
// the rows, the status (0 ok, 1 failed) and the error message.
type Result struct {
	Rows    []map[string]interface{}
	Status  int
	Message string
}

// Answer answers a distributed query for n with synthetic rows, the same
// way for a discovery query as for the query it guards. Rows is never nil.
func Answer(n host.Node, queryStr string) Result {
	res := Result{}
	if !n.Pinned {
		// A random node has exactly the tables osquery has on its platform,
		// plus the --extra-schema tables: naming any other table fails the
		// statement, as on osquery. (A pinned host gets the same answer from
		// SQLite, where such a table does not exist.)
		if t, ok := missingTable(n, queryStr); ok {
			res.Rows, res.Status, res.Message = []map[string]interface{}{}, 1, "no such table: "+t
			if explainEnabled {
				fmt.Printf("[explain] %s no such table %s :: %s\n", n.Name, t, queryStr)
			}
			return res
		}
	}
	if wantsSQLiteEval(n, queryStr) || needsSQLEval(queryStr) || wantsComputedEval(n, queryStr) || readsNoTable(queryStr) {
		// A pinned host's statement that needs real SQL semantics (CTE,
		// CASE, aggregate subqueries) or reads an extension table, or any
		// node's EXISTS / osquery_registry probe, values computed over
		// curated tables or a statement that reads no table at all: run it
		// on the host's curated tables.
		rows, err := sqliteEvalRows(n, queryStr)
		if err != nil {
			// What osquery does with a statement it cannot run: no rows,
			// non-zero status and the SQLite error as the message.
			rows, res.Status, res.Message = []map[string]interface{}{}, 1, sqliteMessage(err)
		}
		res.Rows = rows
		if explainEnabled {
			fmt.Printf("[explain] %s [sqlite] rows=%d err=%q :: %s\n", n.Name, len(rows), res.Message, queryStr)
		}
	} else {
		// Return synthetic, schema-aware rows.
		rows, err := answerSafely(n, queryStr)
		if err != nil {
			rows, res.Status, res.Message = []map[string]interface{}{}, 1, err.Error()
		}
		res.Rows = rows
	}
	if res.Rows == nil {
		res.Rows = []map[string]interface{}{}
	}
	return res
}

// SetExplain turns on --explain logging of how each query is answered.
func SetExplain(on bool) {
	explainEnabled = on
}

// answerSafely runs the pattern answerer, turning a panic on an unexpected
// query shape into a failed query (status 1) instead of stopping every
// simulated node in the process.
func answerSafely(n host.Node, query string) (rows []map[string]interface{}, err error) {
	defer func() {
		if r := recover(); r != nil {
			rows, err = nil, fmt.Errorf("phantomfleet could not answer the query: %v", r)
		}
	}()
	return schemaFakeRows(n, query), nil
}

// LoadData loads extension tables (--extra-schema), catalogs (--catalog) and
// extra seeds (--seeds-dir), in that order (seed views refer to extension
// tables), reporting each load on w. Any loader error is fatal.
func LoadData(extraSchemas, catalogs, seedsDirs []string, w io.Writer) error {
	for _, path := range extraSchemas {
		n, err := LoadExtraSchema(path)
		if err != nil {
			return fmt.Errorf("--extra-schema %s: %w", path, err)
		}
		fmt.Fprintf(w, "Loaded %d extension table(s) from %s\n", n, path)
	}
	for _, path := range catalogs {
		n, err := LoadCatalog(path)
		if err != nil {
			return fmt.Errorf("--catalog %s: %w", path, err)
		}
		fmt.Fprintf(w, "Loaded %d catalog(s) from %s\n", n, path)
	}
	// Layer user-supplied seed data over the built-in fake data, one
	// directory after another: a later layer appends to (or, with _replace,
	// replaces) what the earlier ones built.
	for _, dir := range seedsDirs {
		n, err := LoadSeedDir(dir)
		if err != nil {
			return fmt.Errorf("--seeds-dir %s: %w", dir, err)
		}
		if n > 0 {
			fmt.Fprintf(w, "Loaded %d extra seed file(s) from %s\n", n, dir)
		}
	}
	return nil
}

// missingTable returns the first table q names that n does not have: one in
// neither the embedded schema, the --extra-schema tables nor n's platform
// seeds, or one that belongs to another platform (osquery fails a query on
// such a table with "no such table"). Table-valued functions such as
// json_each are not tables.
func missingTable(n host.Node, q string) (string, bool) {
	funcs := tableFunctions(q)
	platform := profileForPlatform(n.Target)
	for _, t := range statementTables(q) {
		if funcs[t] || isExtensionTable(t) {
			continue
		}
		if _, ok := osquerySchema[t]; !ok && !tableDeclared(platform, t) {
			return t, true
		}
		if foreignTable(n, t) {
			return t, true
		}
	}
	return "", false
}

// reTableFunc spots table-valued function calls in a FROM or JOIN clause.
var reTableFunc = regexp.MustCompile("(?is)\\b(?:from|join)\\s+[\"`]?([a-z_][a-z0-9_]*)[\"`]?\\s*\\(")

// statementTables lists every table q reads: those after FROM or JOIN
// anywhere in the statement and those in comma lists of the first FROM
// clause, without CTE names.
func statementTables(q string) []string {
	bare := stripSQLLiterals(q)
	tables := referencedTables(q)
	seen := make(map[string]bool, len(tables))
	for _, t := range tables {
		seen[t] = true
	}
	ctes := map[string]bool{}
	for _, m := range reCTEName.FindAllStringSubmatch(bare, -1) {
		ctes[strings.ToLower(m[1])] = true
	}
	for _, t := range extractTables(bare) {
		if !seen[t] && !ctes[t] && !sqliteReserved[t] {
			seen[t] = true
			tables = append(tables, t)
		}
	}
	return tables
}

// readsNoTable reports whether q reads no stored table: it has no FROM
// clause (SELECT 1, SELECT sqrt(16)) or reads only table-valued functions
// (json_each). SQLite computes such a statement exactly.
func readsNoTable(q string) bool {
	funcs := tableFunctions(q)
	for _, t := range statementTables(q) {
		if !funcs[t] {
			return false
		}
	}
	return true
}

// tableFunctions lists the table-valued functions q calls in a FROM or JOIN
// clause.
func tableFunctions(q string) map[string]bool {
	funcs := map[string]bool{}
	for _, m := range reTableFunc.FindAllStringSubmatch(stripSQLLiterals(q), -1) {
		funcs[strings.ToLower(m[1])] = true
	}
	return funcs
}

// sqliteMessage is a SQLite error as osquery reports it: SQLite's own
// message, without the Go driver's "SQL logic error: " prefix and
// " (1)" result code suffix.
func sqliteMessage(err error) string {
	msg := err.Error()
	if m := reDriverError.FindStringSubmatch(msg); m != nil {
		return m[1]
	}
	return msg
}

var reDriverError = regexp.MustCompile(`(?s)^[A-Za-z ]+error(?: \([0-9]+\))?: (.*?)(?: \([0-9]+\))?$`)
