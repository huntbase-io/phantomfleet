package synth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/huntbase-io/phantomfleet/internal/host"
	"modernc.org/libc"
	"modernc.org/sqlite" // pure Go, keeps CGO_ENABLED=0 builds working
	sqlite3 "modernc.org/sqlite/lib"
)

// SQLite evaluation for pinned (--nodes-file) hosts.
//
// The pattern-based answerer approximates joins and aggregates, which is fine
// for listings but not for statements whose result depends on real SQL
// semantics: a CTE, CASE, COALESCE, GROUP BY or aggregate scalar subqueries.
// For a pinned host such a statement runs for real: every table it names is
// loaded into an in-memory SQLite database from the host's curated data, and
// the statement executes as osquery would run it.
//
// A pinned host uses this engine for:
//
//   - any statement that starts with WITH,
//   - any statement that reads an extension table (--extra-schema), and
//   - any statement that names a table the host doesn't have (no schema, no
//     seeds), which then fails with "no such table", as on osquery.
//
// Everything else keeps the pattern answerer.
//
// Tables follow osquery's --enable_foreign semantics: a table the host's
// platform profile does not declare, and that has no identity or host-scoped
// seed rows, exists with its schema columns but holds no rows. So a
// Windows-only table is empty on a Mac instead of padded with random values.
//
// Extension tables hold the host's seed rows (shared and _hosts rows,
// resolved once, never padded). An extension table can instead be a view: a
// SELECT defined in the seeds under _views and evaluated per statement, with
// the statement's `column = literal` constraints bound as :column parameters.
// That is how tables whose rows depend on their inputs (a summary filtered by
// a threshold, the folders under a given folder) are answered without code. See
// docs/extensions.md.

const (
	// sqliteTimeout bounds one statement (query text comes from the server).
	sqliteTimeout = 5 * time.Second
	// maxViewDepth bounds views built on other views.
	maxViewDepth = 8
)

var (
	reWithPrefix   = regexp.MustCompile(`(?is)^\s*with\b`)
	reSelectOrWith = regexp.MustCompile(`(?is)^\s*(?:with|select)\b`)
	reTableRef     = regexp.MustCompile("(?is)\\b(?:from|join)\\s+[\"`]?([a-z_][a-z0-9_]*)")
	reCTEName      = regexp.MustCompile(`(?is)(?:\bwith(?:\s+recursive)?|,)\s*([a-z_][a-z0-9_]*)\s*(?:\([^()]*\))?\s*as\s*(?:not\s+)?(?:materialized\s+)?\(`)
	reParam        = regexp.MustCompile(`[:@$]([A-Za-z_][A-Za-z0-9_]*)`)
	reNoSuchTable  = regexp.MustCompile(`no such table: (?:main\.)?([A-Za-z_][A-Za-z0-9_]*)`)
	sqliteReserved = map[string]bool{"select": true}
)

// wantsSQLiteEval reports whether a pinned node should answer q with real SQL.
func wantsSQLiteEval(node host.Node, q string) bool {
	return node.Pinned && (reWithPrefix.MatchString(q) || readsExtensionTable(q) || readsUnknownTable(node, q))
}

// reNeedsSQL spots statements the pattern answerer cannot model on any node:
// EXISTS subqueries, table-valued pragma functions and reads of the plugin
// registry. Servers send exactly these as discovery queries ("does this host
// have table X?"), so they run in SQLite, for random nodes too, where the
// answer comes from the host's own osquery_registry rows.
var reNeedsSQL = regexp.MustCompile(`(?i)\bexists\s*\(|\bpragma_[a-z_]+\s*\(|\bosquery_registry\b`)

// needsSQLEval reports whether q must run in SQLite whatever the node.
func needsSQLEval(q string) bool {
	return reNeedsSQL.MatchString(stripSQLLiterals(q))
}

var (
	reSelectList = regexp.MustCompile(`(?is)^\s*select\s+(.*?)\bfrom\b`)
	reFuncCall   = regexp.MustCompile(`(?i)\b([a-z_][a-z0-9_]*)\s*\(`)
	reArithmetic = regexp.MustCompile(`[\w)]\s*(?:[-+*/%]|\|\|)\s*[\w(]`)
)

// computedSelect reports whether q's SELECT list computes values (arithmetic,
// or a function other than count, including inside scalar subqueries) that
// the pattern answerer would fill with random numbers, e.g. a free-space
// percentage from mounts.
func computedSelect(q string) bool {
	m := reSelectList.FindStringSubmatch(stripSQLLiterals(q))
	if m == nil {
		return false
	}
	list := m[1]
	for _, f := range reFuncCall.FindAllStringSubmatch(list, -1) {
		if !strings.EqualFold(f[1], "count") {
			return true
		}
	}
	return reArithmetic.MatchString(list)
}

// curatedFor reports whether SQLite can answer q for node from the node's
// own data: every table q reads is known (in the schema or the platform's
// seeds, not an extension table) and at least one has curated data (identity
// rows, seed rows or a seed declaration). Known tables without curated data
// are empty there, as a foreign table is.
func curatedFor(node host.Node, q string) bool {
	tables := referencedTables(q)
	profile := profileForPlatform(node.Target)
	curated := false
	for _, t := range tables {
		if isExtensionTable(t) {
			return false
		}
		if len(osquerySchema[t]) == 0 && !tableDeclared(profile, t) {
			return false
		}
		if len(identityRows(node, t)) > 0 || tableDeclared(profile, t) {
			curated = true
			continue
		}
		if hostRows, _ := seedRowsSplit(node, t); len(hostRows) > 0 {
			curated = true
		}
	}
	return curated
}

// wantsComputedEval reports whether q is a WITH statement or computes values,
// over tables the node has curated data for: SQLite then evaluates it exactly
// over the same population the pattern answerer would list.
func wantsComputedEval(node host.Node, q string) bool {
	return (reWithPrefix.MatchString(q) || computedSelect(q)) && curatedFor(node, q)
}

// readsUnknownTable reports whether q names a table the host does not have:
// one in neither the schema (embedded or --extra-schema) nor the seeds of the
// host's platform. osquery fails such a statement ("no such table"), and so
// does a pinned host, by running it in SQLite, where the table is missing
// too. (Table-valued functions such as json_each run there for real.)
func readsUnknownTable(node host.Node, q string) bool {
	platform := profileForPlatform(node.Target)
	for _, t := range referencedTables(q) {
		if _, ok := osquerySchema[t]; ok {
			continue
		}
		if !tableDeclared(platform, t) {
			return true
		}
	}
	return false
}

// referencedTables lists the tables q reads, CTE names excluded.
func referencedTables(q string) []string {
	q = stripSQLLiterals(q)
	ctes := map[string]bool{}
	for _, m := range reCTEName.FindAllStringSubmatch(q, -1) {
		ctes[strings.ToLower(m[1])] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, m := range reTableRef.FindAllStringSubmatch(q, -1) {
		t := strings.ToLower(m[1])
		if ctes[t] || seen[t] || sqliteReserved[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
		if len(out) == maxQueryTables*4 {
			break
		}
	}
	return out
}

// stripSQLLiterals blanks string literals and comments (keeping length), so
// regular expressions over the statement only see SQL. It follows SQLite's
// tokenizer: '...' strings and "...", `...` and [...] identifiers (doubled
// quotes escape a quote; [...] has no escape), -- comments to the end of the
// line and /* ... */ comments. Inside a quoted identifier, characters other
// than letters, digits and underscores are blanked too (the quotes and the
// name itself stay, so `FROM "processes"` is still seen as a table read), so
// a "--", "/*" or ";" in an identifier can never hide or start anything.
func stripSQLLiterals(q string) string {
	b := []byte(q)
	// blankQuoted blanks from i (just past the opening quote) to the closing
	// quote; keepIdent keeps identifier characters. It returns the index of
	// the closing quote (or len(b)).
	blankQuoted := func(i int, closer byte, doubled, keepIdent bool) int {
		for ; i < len(b); i++ {
			if b[i] == closer {
				if doubled && i+1 < len(b) && b[i+1] == closer {
					b[i], b[i+1] = ' ', ' '
					i++
					continue
				}
				return i
			}
			if !keepIdent || !isIdentByte(b[i]) {
				b[i] = ' '
			}
		}
		return i
	}
	for i := 0; i < len(b); i++ {
		switch {
		case b[i] == '\'':
			i = blankQuoted(i+1, '\'', true, false)
		case b[i] == '"':
			i = blankQuoted(i+1, '"', true, true)
		case b[i] == '`':
			i = blankQuoted(i+1, '`', true, true)
		case b[i] == '[':
			i = blankQuoted(i+1, ']', false, true)
		case b[i] == '-' && i+1 < len(b) && b[i+1] == '-':
			for ; i < len(b) && b[i] != '\n'; i++ {
				b[i] = ' '
			}
		case b[i] == '/' && i+1 < len(b) && b[i+1] == '*':
			for ; i < len(b); i++ {
				if b[i] == '*' && i+1 < len(b) && b[i+1] == '/' {
					b[i], b[i+1] = ' ', ' '
					i++
					break
				}
				b[i] = ' '
			}
		}
	}
	return string(b)
}

func isIdentByte(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// maxStatementLength bounds a statement's text (SQLITE_LIMIT_SQL_LENGTH on
// the connection, and checked before tokenizing).
const maxStatementLength = 256 << 10

// firstStatementEnd returns the index of the semicolon that ends q's first
// statement, as SQLite's own tokenizer (sqlite3_complete) sees it, or -1
// when q has no terminating semicolon (it is then at most one statement).
func firstStatementEnd(q string) (int, error) {
	if !strings.Contains(q, ";") {
		return -1, nil
	}
	tls := libc.NewTLS()
	defer tls.Close()
	for i := 0; i < len(q); i++ {
		if q[i] != ';' {
			continue
		}
		p, err := libc.CString(q[:i+1])
		if err != nil {
			return 0, err
		}
		complete := sqlite3.Xsqlite3_complete(tls, p) != 0
		libc.Xfree(tls, p)
		if complete {
			return i, nil
		}
	}
	return -1, nil
}

// checkReadStatement accepts a single SELECT or WITH statement and returns
// it without its terminating semicolon. The engine runs server-supplied text,
// so anything else (ATTACH, PRAGMA, VACUUM, a second statement) is refused
// before it reaches SQLite.
//
// Where the first statement ends is decided by SQLite's tokenizer, and only
// that statement is ever handed to the engine, so text after it cannot run
// even if it were misjudged here. Our own tokenizer (stripSQLLiterals) must
// then also find no semicolon in it: both have to agree it is one statement.
func checkReadStatement(q string) (string, error) {
	if len(q) > maxStatementLength {
		return "", fmt.Errorf("statement is longer than %d bytes", maxStatementLength)
	}
	if strings.IndexByte(q, 0) >= 0 {
		return "", errors.New("statement contains a NUL byte")
	}
	q = strings.TrimSpace(q)
	end, err := firstStatementEnd(q)
	if err != nil {
		return "", err
	}
	if end >= 0 {
		if !onlyTrivia(q[end+1:]) {
			return "", errors.New("only one statement is supported")
		}
		q = strings.TrimSpace(q[:end])
	}
	bare := stripSQLLiterals(q)
	if strings.Contains(bare, ";") {
		return "", errors.New("only one statement is supported")
	}
	if !reSelectOrWith.MatchString(bare) {
		return "", errors.New("only SELECT and WITH statements are supported")
	}
	return q, nil
}

// onlyTrivia reports whether s holds nothing but whitespace, comments and
// semicolons.
func onlyTrivia(s string) bool {
	return strings.Trim(stripSQLLiterals(s), " \t\r\n\f\v;") == ""
}

// curatedRows is a pinned host's data for table, or nil when the host has
// nothing curated for it (the table is then empty, as a foreign table is).
func curatedRows(node host.Node, table string) ([]map[string]string, []string) {
	identity := identityRows(node, table)
	hostRows, _ := seedRowsSplit(node, table)
	declared := tableDeclared(profileForPlatform(node.Target), table)
	if len(identity) == 0 && len(hostRows) == 0 && !declared {
		return nil, nil
	}
	rows, cols, ok := buildPopulation(node, table)
	if !ok {
		return nil, nil
	}
	return rows, cols
}

// extensionRows is a pinned host's seed rows for an extension table: its
// _hosts rows then the shared ones, each resolved once and never padded.
func extensionRows(node host.Node, table string) []map[string]string {
	hostRows, shared := seedRowsSplit(node, table)
	raw := append(append([]map[string]string(nil), hostRows...), shared...)
	if len(raw) == 0 {
		return nil
	}
	f := stableFaker(node, "ext", table)
	out := make([]map[string]string, 0, len(raw))
	for _, r := range raw {
		out = append(out, resolveRow(r, node, f))
	}
	return out
}

func sqliteType(osqueryType string) string {
	switch strings.ToUpper(osqueryType) {
	case "INTEGER", "BIGINT", "UNSIGNED_BIGINT":
		return "INTEGER"
	case "DOUBLE":
		return "REAL"
	default:
		return "TEXT"
	}
}

func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

// maxLoadRetries bounds how many tables are loaded on demand for one statement.
const maxLoadRetries = 16

// retryMissingTables runs fn, loading a table SQLite reports missing (one the
// regular expressions did not spot, such as a comma join) and trying again.
func (l *sqliteLoader) retryMissingTables(depth int, fn func() error) error {
	for i := 0; ; i++ {
		err := fn()
		if err == nil || i == maxLoadRetries {
			return err
		}
		m := reNoSuchTable.FindStringSubmatch(err.Error())
		if m == nil {
			return err
		}
		table := strings.ToLower(m[1])
		if l.loaded[table] {
			return err
		}
		if lerr := l.loadWritable(table, depth); lerr != nil {
			return lerr
		}
	}
}

// loadWritable loads table with query_only switched off for the load, then
// restores it.
func (l *sqliteLoader) loadWritable(table string, depth int) error {
	was := l.queryOnly
	if err := l.setQueryOnly(false); err != nil {
		return err
	}
	if err := l.ensure(table, depth); err != nil {
		return err
	}
	return l.setQueryOnly(was)
}

// setQueryOnly switches PRAGMA query_only, which makes the connection refuse
// every write while the server's statement runs.
func (l *sqliteLoader) setQueryOnly(on bool) error {
	if l.queryOnly == on {
		return nil
	}
	v := "OFF"
	if on {
		v = "ON"
	}
	if _, err := l.db.ExecContext(l.ctx, "PRAGMA query_only = "+v); err != nil {
		return err
	}
	l.queryOnly = on
	return nil
}

// sqliteDSN is a private in-memory database in defensive mode (no
// writable_schema, no writes to sqlite_dbpage or shadow tables). It never
// names a file, so nothing on disk is opened.
const sqliteDSN = ":memory:?_defensive=1"

// sqliteLimits are applied to every connection before any statement runs.
// The statement text comes from the server, so these bound what it can do
// even if it got past checkReadStatement.
var sqliteLimits = []struct {
	name   string
	id, to int
}{
	// No ATTACH (and so no VACUUM INTO, which attaches its target): the
	// statement can only see the in-memory main database.
	{"attached", sqlite3.SQLITE_LIMIT_ATTACHED, 0},
	// Largest string, blob or row: stops hex(randomblob(1e9)) and friends.
	{"length", sqlite3.SQLITE_LIMIT_LENGTH, 4 << 20},
	{"sql_length", sqlite3.SQLITE_LIMIT_SQL_LENGTH, maxStatementLength},
	{"compound_select", sqlite3.SQLITE_LIMIT_COMPOUND_SELECT, 128},
	{"expr_depth", sqlite3.SQLITE_LIMIT_EXPR_DEPTH, 500},
}

// openSQLite opens a hardened in-memory database for one statement and
// returns its only connection, with osquery's extra SQL functions
// (sqlite_funcs.go). Extension loading is never enabled by the
// driver (load_extension fails with "not authorized"), the database is in
// memory, and the connection's limits forbid ATTACH. Close both when done.
func openSQLite(ctx context.Context) (*sql.DB, *sql.Conn, error) {
	if err := registerOSQueryFunctions(ctx); err != nil {
		return nil, nil, err
	}
	db, err := sql.Open("sqlite", sqliteDSN)
	if err != nil {
		return nil, nil, err
	}
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(ctx)
	if err != nil {
		_ = db.Close()
		return nil, nil, err
	}
	fail := func(err error) (*sql.DB, *sql.Conn, error) {
		_ = conn.Close()
		_ = db.Close()
		return nil, nil, err
	}
	for _, lim := range sqliteLimits {
		if _, err := sqlite.Limit(conn, lim.id, lim.to); err != nil {
			return fail(fmt.Errorf("sqlite limit %s: %w", lim.name, err))
		}
	}
	// Functions in the schema (views, triggers) may not have side effects.
	if _, err := conn.ExecContext(ctx, "PRAGMA trusted_schema = OFF"); err != nil {
		return fail(err)
	}
	return db, conn, nil
}

// sqliteLoader fills one in-memory database for one statement on one host.
type sqliteLoader struct {
	ctx       context.Context
	db        *sql.Conn
	queryOnly bool // PRAGMA query_only is on (while the statement runs)
	node      host.Node
	q         string // the statement being answered (constraints come from it)
	loaded    map[string]bool
	active    map[string]bool // views being built (cycle guard)
}

// ensure creates table (and, for a view, everything it reads) once.
func (l *sqliteLoader) ensure(table string, depth int) error {
	if l.loaded[table] || !reIdent.MatchString(table) {
		return nil
	}
	if sqlText, ok := seedView(l.node, table); ok {
		if l.active[table] {
			return fmt.Errorf("view %s refers to itself", table)
		}
		if depth >= maxViewDepth {
			return fmt.Errorf("view %s: views nested deeper than %d", table, maxViewDepth)
		}
		l.active[table] = true
		defer delete(l.active, table)
		for _, src := range referencedTables(sqlText) {
			if src == table {
				// Inside its own view, a table's name reads its seed rows,
				// so a view can post-process them (derive a column, fill a
				// default). The view's result then replaces them.
				if err := l.loadStored(table); err != nil {
					return err
				}
				continue
			}
			if err := l.ensure(src, depth+1); err != nil {
				return err
			}
		}
		if err := l.retryMissingTables(depth+1, func() error { return l.materializeView(table, sqlText) }); err != nil {
			return fmt.Errorf("view %s: %w", table, err)
		}
		l.loaded[table] = true
		return nil
	}
	return l.loadStored(table)
}

// loadStored creates table from the host's rows: an extension table's seed
// rows, or a core table's curated data.
func (l *sqliteLoader) loadStored(table string) error {
	var rows []map[string]string
	var cols []string
	if isExtensionTable(table) {
		rows = extensionRows(l.node, table)
		for _, r := range rows {
			for c := range r {
				cols = append(cols, c)
			}
		}
	} else {
		rows, cols = curatedRows(l.node, table)
	}
	typeOf := map[string]string{}
	var colOrder []string
	for _, c := range osquerySchema[table] {
		typeOf[c.Name] = c.Type
		colOrder = append(colOrder, c.Name)
	}
	hidden := map[string]bool{}
	for _, c := range hiddenColumns[table] {
		if _, ok := typeOf[c.Name]; !ok {
			typeOf[c.Name] = c.Type
			colOrder = append(colOrder, c.Name)
			hidden[c.Name] = true
		}
	}
	var extra []string
	for _, c := range cols {
		if _, ok := typeOf[c]; !ok && reIdent.MatchString(c) {
			typeOf[c] = "text"
			extra = append(extra, c)
		}
	}
	sort.Strings(extra)
	colOrder = append(colOrder, extra...)
	l.loaded[table] = true
	if len(colOrder) == 0 {
		return nil // unknown table: let SQLite report "no such table", as osquery does
	}
	defs := make([]string, 0, len(colOrder))
	for _, c := range colOrder {
		defs = append(defs, quoteIdent(c)+" "+sqliteType(typeOf[c]))
	}
	if _, err := l.db.ExecContext(l.ctx, fmt.Sprintf(`CREATE TABLE %s (%s)`, quoteIdent(table), strings.Join(defs, ", "))); err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil
	}
	quoted := make([]string, len(colOrder))
	for i, c := range colOrder {
		quoted[i] = quoteIdent(c)
	}
	ph := strings.TrimSuffix(strings.Repeat("?, ", len(colOrder)), ", ")
	// #nosec G201 -- identifiers are quoted with quoteIdent; values are bound.
	ins := fmt.Sprintf(`INSERT INTO %s (%s) VALUES (%s)`, quoteIdent(table), strings.Join(quoted, ", "), ph)
	for _, r := range rows {
		args := make([]interface{}, len(colOrder))
		for i, c := range colOrder {
			v, ok := r[c]
			if !ok && hidden[c] && sqliteType(typeOf[c]) == "TEXT" {
				args[i] = "" // osquery reports an unset hidden column as empty text
				continue
			}
			if !ok || (v == "" && sqliteType(typeOf[c]) != "TEXT") {
				args[i] = nil
			} else {
				args[i] = v
			}
		}
		if _, err := l.db.ExecContext(l.ctx, ins, args...); err != nil {
			return err
		}
	}
	return nil
}

// materializeView runs a view's SELECT with the statement's constraints bound
// and stores the result as table, typed by the table's schema columns.
func (l *sqliteLoader) materializeView(table, sqlText string) error {
	var args []interface{}
	seen := map[string]bool{}
	for _, m := range reParam.FindAllStringSubmatch(stripSQLLiterals(sqlText), -1) {
		name := m[1]
		if seen[name] {
			continue
		}
		seen[name] = true
		var v interface{}
		if c, ok := constraintValue(l.q, name); ok {
			v = c
		}
		args = append(args, sql.Named(name, v))
	}
	res, err := l.db.QueryContext(l.ctx, sqlText, args...)
	if err != nil {
		return err
	}
	defer res.Close()
	names, err := res.Columns()
	if err != nil {
		return err
	}
	typeOf := map[string]string{}
	var colOrder []string
	for _, c := range osquerySchema[table] {
		typeOf[c.Name] = c.Type
		colOrder = append(colOrder, c.Name)
	}
	for _, n := range names {
		if _, ok := typeOf[n]; !ok {
			typeOf[n] = "text"
			colOrder = append(colOrder, n)
		}
	}
	var data [][]interface{}
	for res.Next() {
		vals := make([]interface{}, len(names))
		ptrs := make([]interface{}, len(names))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := res.Scan(ptrs...); err != nil {
			return err
		}
		data = append(data, vals)
		if len(data) >= maxPopulation {
			break
		}
	}
	if err := res.Err(); err != nil {
		return err
	}
	if err := res.Close(); err != nil {
		return err
	}

	defs := make([]string, 0, len(colOrder))
	for _, c := range colOrder {
		defs = append(defs, quoteIdent(c)+" "+sqliteType(typeOf[c]))
	}
	// A view that reads its own table replaces the seed rows it was given.
	if _, err := l.db.ExecContext(l.ctx, `DROP TABLE IF EXISTS `+quoteIdent(table)); err != nil {
		return err
	}
	if _, err := l.db.ExecContext(l.ctx, fmt.Sprintf(`CREATE TABLE %s (%s)`, quoteIdent(table), strings.Join(defs, ", "))); err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = quoteIdent(n)
	}
	ph := strings.TrimSuffix(strings.Repeat("?, ", len(names)), ", ")
	// #nosec G201 -- identifiers are quoted with quoteIdent; values are bound.
	ins := fmt.Sprintf(`INSERT INTO %s (%s) VALUES (%s)`, quoteIdent(table), strings.Join(quoted, ", "), ph)
	for _, vals := range data {
		if _, err := l.db.ExecContext(l.ctx, ins, vals...); err != nil {
			return err
		}
	}
	return nil
}

// constraintValue finds the first `column = literal` comparison on column in
// q (bare, quoted or alias-qualified column; integer, real or quoted string
// literal). That is how a statement passes inputs to a view, as osquery
// passes them to a table's hidden input columns.
func constraintValue(q, column string) (interface{}, bool) {
	c := regexp.QuoteMeta(column)
	re := regexp.MustCompile(`(?is)(?:"` + c + `"|` + "`" + c + "`" + `|\b` + c + `\b)\s*==?\s*(-?\d+(?:\.\d+)?|'((?:[^']|'')*)')`)
	m := re.FindStringSubmatch(q)
	if m == nil {
		return nil, false
	}
	lit := m[1]
	if strings.HasPrefix(lit, "'") {
		return strings.ReplaceAll(m[2], "''", "'"), true
	}
	if n, err := strconv.ParseInt(lit, 10, 64); err == nil {
		return n, true
	}
	if f, err := strconv.ParseFloat(lit, 64); err == nil {
		return f, true
	}
	return nil, false
}

// sqliteEvalRows runs q against the host's curated tables. An error is what
// osquery would report for the statement: the caller answers with no rows,
// status 1 and the message.
func sqliteEvalRows(node host.Node, q string) ([]map[string]interface{}, error) {
	stmt, err := checkReadStatement(q)
	if err != nil {
		return nil, err
	}
	stmt = normalizeRegistryPaths(stmt)
	ctx, cancel := context.WithTimeout(context.Background(), sqliteTimeout)
	defer cancel()

	db, conn, err := openSQLite(ctx)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	defer conn.Close()

	l := &sqliteLoader{ctx: ctx, db: conn, node: node, q: stmt, loaded: map[string]bool{}, active: map[string]bool{}}
	for _, table := range referencedTables(stmt) {
		if err := l.ensure(table, 0); err != nil {
			return nil, err
		}
	}

	// The server's statement runs read-only: any write it could make
	// (CREATE, INSERT, ...) fails.
	if err := l.setQueryOnly(true); err != nil {
		return nil, err
	}
	var res *sql.Rows
	err = l.retryMissingTables(0, func() error {
		var qerr error
		res, qerr = conn.QueryContext(ctx, stmt) // closed below
		return qerr
	})
	if err != nil {
		return nil, err
	}
	defer res.Close()
	names, err := res.Columns()
	if err != nil {
		return nil, err
	}
	var out []map[string]interface{}
	for res.Next() {
		vals := make([]interface{}, len(names))
		ptrs := make([]interface{}, len(names))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := res.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := make(map[string]interface{}, len(names))
		for i, n := range names {
			// osquery reports every value as a string, NULL as "".
			switch v := vals[i].(type) {
			case nil:
				row[n] = ""
			case []byte:
				row[n] = string(v)
			default:
				row[n] = fmt.Sprint(v)
			}
		}
		out = append(out, row)
		if len(out) >= maxPopulation {
			break
		}
	}
	return out, res.Err()
}

var reBackslashRun = regexp.MustCompile(`\\{2,}`)

// normalizeRegistryPaths collapses runs of backslashes in a statement that
// reads the Windows registry table. osquery's registry table treats
// HKEY_LOCAL_MACHINE\\SOFTWARE and HKEY_LOCAL_MACHINE\SOFTWARE as the same
// key path, and servers send both spellings (Fleet sends the doubled one).
func normalizeRegistryPaths(q string) string {
	for _, t := range referencedTables(q) {
		if t == "registry" {
			return reBackslashRun.ReplaceAllString(q, `\`)
		}
	}
	return q
}
