package synth

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"regexp"
	"strings"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/huntbase-io/phantomfleet/internal/host"
)

// osquerySchemaJSON is a slimmed osquery schema (table -> [{name,type}]) generated
// from the official osquery schema JSON. Refresh by re-running the slimming step in
// the README and rebuilding. Pinned to the osquery version noted there.
//
//go:embed osquery_schema.json
var osquerySchemaJSON []byte

type schemaColumn struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Hidden bool   `json:"hidden,omitempty"`
}

// osquerySchema maps table name -> ordered columns that SELECT * returns.
var osquerySchema map[string][]schemaColumn

// hiddenColumns maps table name -> its hidden columns: osquery leaves them
// out of SELECT * but a statement can name them (users.type, for one). They
// exist, empty, when a statement runs in SQLite.
var hiddenColumns = map[string][]schemaColumn{}

func init() {
	var all map[string][]schemaColumn
	if err := json.Unmarshal(osquerySchemaJSON, &all); err != nil {
		// A broken embed shouldn't crash the simulator; schemaFakeRows falls back.
		osquerySchema = map[string][]schemaColumn{}
		return
	}
	osquerySchema = make(map[string][]schemaColumn, len(all))
	for t, cols := range all {
		visible := make([]schemaColumn, 0, len(cols))
		for _, c := range cols {
			if c.Hidden {
				hiddenColumns[t] = append(hiddenColumns[t], c)
				continue
			}
			visible = append(visible, c)
		}
		osquerySchema[t] = visible
	}
}

var (
	reFrom         = regexp.MustCompile(`(?is)\bfrom\s+[` + "`" + `"']?([a-zA-Z0-9_]+)`)
	reLimit        = regexp.MustCompile(`(?is)\blimit\s+(\d+)`)
	reSelectAll    = regexp.MustCompile(`(?is)^\s*select\s+(?:distinct\s+)?\*`)
	reAgg          = regexp.MustCompile(`(?i)^(count|sum|avg|min|max|total|group_concat)\s*\(`)
	reSelectPrefix = regexp.MustCompile(`(?is)^\s*select\s+(distinct\s+)?`)
	reAsSplit      = regexp.MustCompile(`(?is)\s+as\s+`)
	reFromClause   = regexp.MustCompile(`(?is)\bfrom\b(.*?)(?:\bwhere\b|\bgroup\s+by\b|\border\s+by\b|\bhaving\b|\blimit\b|;|$)`)
	reJoinSplit    = regexp.MustCompile(`(?is)\b(?:inner|left|right|outer|cross|full)?\s*join\b|,`)
	reLeadIdent    = regexp.MustCompile(`(?is)^[` + "`" + `"']?([a-zA-Z_][a-zA-Z0-9_]*)`)
	maxPopulation  = 5000
	// maxQueryTables bounds how many FROM/JOIN tables one query may pull in. The
	// query text comes from the server, so this keeps a hostile query from making
	// the simulator build a population for every one of thousands of tables.
	maxQueryTables = 8
)

// explainEnabled, when true (via --explain), logs how each query was decomposed.
var explainEnabled bool

// selCol is one entry in a SELECT list.
type selCol struct {
	label   string // output column name returned to the server
	base    string // underlying column the value is drawn from
	aggFunc string // "" for plain columns; otherwise count/sum/avg/min/max/...
}

// schemaFakeRows produces semi-realistic rows for an arbitrary osquery SQL query.
// Each node has a deterministic per-table "population" (curated seed rows from the
// platform profile, padded with schema-generated rows up to a realistic count). The
// query then views that population: WHERE filters it, count(*) counts it, LIMIT caps
// it. Joins/GROUP BY/non-count aggregates are approximated, not truly evaluated.
// Output values are strings to match osquery's JSON result wire format.
func schemaFakeRows(node host.Node, query string) []map[string]interface{} {
	q := strings.TrimSpace(strings.TrimRight(strings.TrimSpace(query), ";"))
	// Scalar subqueries ("(SELECT hostname FROM system_info) AS hostname") are
	// answered on their own and stand in the outer query as a placeholder column.
	q, subqueries := extractSubqueries(q)

	tables := extractTables(q)
	for _, t := range tables {
		// Extension tables (--extra-schema) never get schema-generated rows. A
		// pinned host answers them through the SQLite evaluator from its seed
		// rows; anything that reaches this answerer (a random node) has an
		// empty store.
		if isExtensionTable(t) {
			if explainEnabled {
				fmt.Printf("[explain] %s extension table %s: no rows\n", node.Name, t)
			}
			return []map[string]interface{}{}
		}
		// osquery fails a query that names another platform's table: no rows,
		// rather than schema-generated values for a table the host can't have.
		if foreignTable(node, t) {
			if explainEnabled {
				fmt.Printf("[explain] %s/%s foreign table %s: no rows\n", node.Name, profileForPlatform(node.Target), t)
			}
			return []map[string]interface{}{}
		}
	}
	selectAll := reSelectAll.MatchString(q)
	sels := parseSelect(q, selectAll)
	if !selectAll && len(sels) == 0 {
		selectAll = true
	}

	var pop []map[string]string
	var cols []string
	var ok bool
	if node.Pinned {
		pop, cols, ok = buildJoinedPopulation(node, q, tables)
	} else {
		pop, cols, ok = buildPopulationMulti(node, tables)
	}
	if len(subqueries) > 0 {
		values := make(map[string]string, len(subqueries))
		for placeholder, inner := range subqueries {
			values[placeholder] = firstValue(schemaFakeRows(node, inner))
		}
		for _, row := range pop {
			for k, v := range values {
				row[k] = v
			}
		}
	}
	if !ok {
		// No table this node has (Answer fails such a statement with "no
		// such table" before it gets here): no rows, never invented ones.
		if explainEnabled {
			explainLog(node, q, tables, 0, 0)
		}
		return []map[string]interface{}{}
	}

	filtered := applyWhere(pop, q)
	if explainEnabled {
		explainLog(node, q, tables, len(pop), len(filtered))
	}

	// Aggregate query (count is exact over the filtered population; others approximated).
	if hasAggregate(sels) {
		f := stableFaker(node, "agg", q)
		row := make(map[string]interface{}, len(sels))
		for _, s := range sels {
			switch s.aggFunc {
			case "count":
				row[s.label] = itoa(len(filtered))
			case "":
				if len(filtered) > 0 {
					row[s.label] = filtered[0][s.base]
				} else {
					row[s.label] = ""
				}
			default:
				row[s.label] = itoa(f.Number(0, 1000))
			}
		}
		return []map[string]interface{}{row}
	}

	// LIMIT.
	limit := len(filtered)
	if m := reLimit.FindStringSubmatch(q); m != nil {
		if n := atoiSafe(m[1]); n >= 0 && n < limit {
			limit = n
		}
	}
	filtered = filtered[:limit]

	// Project.
	out := make([]map[string]interface{}, 0, len(filtered))
	for _, r := range filtered {
		row := map[string]interface{}{}
		if selectAll {
			if len(cols) > 0 {
				for _, c := range cols {
					row[c] = r[c]
				}
			} else {
				for k, v := range r {
					row[k] = v
				}
			}
		} else {
			for _, s := range sels {
				row[s.label] = r[s.base] // missing column -> "" via zero value lookup
			}
		}
		out = append(out, row)
	}
	return out
}

// parseSelect extracts the SELECT-list columns (empty when selectAll).
func parseSelect(q string, selectAll bool) []selCol {
	if selectAll {
		return nil
	}
	selectClause := q
	if li := reFrom.FindStringIndex(q); li != nil {
		selectClause = q[:li[0]]
	}
	selectClause = reSelectPrefix.ReplaceAllString(selectClause, "")

	var sels []selCol
	for _, raw := range splitTopLevel(selectClause) {
		expr := strings.TrimSpace(raw)
		if expr == "" {
			continue
		}
		expr, base := expr, expr
		explicitAlias := false
		label := expr
		if parts := reAsSplit.Split(expr, 2); len(parts) == 2 {
			base = strings.TrimSpace(parts[0])
			label = strings.Trim(strings.TrimSpace(parts[1]), "`\"'")
			explicitAlias = true
		}
		aggFunc := ""
		if am := reAgg.FindStringSubmatch(base); am != nil {
			aggFunc = strings.ToLower(am[1])
		}
		bare := base
		if i := strings.LastIndex(bare, "("); i >= 0 {
			bare = bare[i+1:]
		}
		bare = strings.TrimRight(bare, ") ")
		if dot := strings.LastIndex(bare, "."); dot >= 0 {
			bare = bare[dot+1:]
		}
		bare = strings.ToLower(strings.Trim(strings.TrimSpace(bare), "`\"'"))
		// Without an explicit alias, osquery labels a plain column with its bare name
		// ("p.name" -> "name"); functions/expressions keep their text ("count(*)").
		if !explicitAlias && aggFunc == "" && !strings.Contains(base, "(") {
			label = bare
		}
		sels = append(sels, selCol{label: label, base: bare, aggFunc: aggFunc})
	}
	return sels
}

func hasAggregate(sels []selCol) bool {
	for _, s := range sels {
		if s.aggFunc != "" {
			return true
		}
	}
	return false
}

// buildPopulation returns a node's deterministic row population for a table plus the
// column universe (for SELECT *). ok is false for tables with no schema and no seed.
//
// Fixed seed rows become one-off anchors (e.g. pid 1 = systemd). Seed rows that carry
// generator patterns ({{int:..}}, {{choice:..}}, …) are repeatable templates: padding
// clones them, regenerating the patterns each time, so the population looks varied but
// realistic. Tables with no patterned templates are padded with schema-typed values.
func buildPopulation(node host.Node, table string) ([]map[string]string, []string, bool) {
	schemaCols := osquerySchema[table]
	// A pinned node's identity rows lead, then its host-restricted seed rows, then
	// the platform's shared ones.
	identity := identityRows(node, table)
	hostRows, sharedRows := seedRowsSplit(node, table)
	rawSeeds := append(append(identity, hostRows...), sharedRows...)
	hasSeed := len(rawSeeds) > 0
	// A pinned (curated) host answers a table its platform profile declares from
	// the seeds alone: no schema-generated rows, so no invented values.
	curated := node.Pinned && tableDeclared(profileForPlatform(node.Target), table)
	if len(schemaCols) == 0 && !hasSeed && !curated {
		return nil, nil, false
	}

	colNames, typeOf := columnUniverse(schemaCols, rawSeeds)

	f := stableFaker(node, "pop", table)
	target := rowCountFor(f, table)
	if target > maxPopulation {
		target = maxPopulation
	}
	// Rows written for this very host are always reported.
	if pinnedRows := len(identity) + len(hostRows); target < pinnedRows {
		target = pinnedRows
	}

	// Patterned seed rows are reusable templates for padding.
	var templates []map[string]string
	for _, r := range rawSeeds {
		if rowHasGenerator(r) {
			templates = append(templates, r)
		}
	}

	// Catalog-backed templates ({{row:...}}) hand out each catalog entry once
	// and never one an anchor row already names.
	anchorNames := map[string]bool{}
	for _, r := range rawSeeds {
		if !rowHasGenerator(r) && r["name"] != "" {
			anchorNames[strings.ToLower(resolveIdentity(r["name"], node))] = true
		}
	}
	picker := newRowPicker(f, anchorNames)

	pop := make([]map[string]string, 0, target)
	// Curated anchors first (each emitted once), filled out to the full column set.
	for _, raw := range rawSeeds {
		if len(pop) >= target {
			break
		}
		row, ok := resolveRowPicked(raw, node, f, picker)
		if !ok {
			continue
		}
		pop = append(pop, fillRow(row, table, colNames, typeOf, node, f))
	}
	if curated && len(templates) == 0 {
		return pop, colNames, true
	}
	// Pad up to the target: clone patterned templates if any, else schema-generate.
	// A template whose catalog runs out is retired; a table padded only from
	// catalogs stops at the catalog size rather than repeating entries.
	for len(pop) < target {
		var row map[string]string
		if len(templates) > 0 {
			i := f.Number(0, len(templates)-1)
			resolved, ok := resolveRowPicked(templates[i], node, f, picker)
			if !ok {
				templates = append(templates[:i:i], templates[i+1:]...)
				if len(templates) == 0 {
					break
				}
				continue
			}
			row = fillRow(resolved, table, colNames, typeOf, node, f)
		} else {
			row = make(map[string]string, len(colNames))
			for _, cn := range colNames {
				row[cn] = fakeValue(f, table, cn, typeOf[cn], node)
			}
		}
		pop = append(pop, row)
	}
	return pop, colNames, true
}

// columnUniverse merges schema columns with any extra columns present only in seeds.
func columnUniverse(schemaCols []schemaColumn, rawSeeds []map[string]string) ([]string, map[string]string) {
	var colNames []string
	typeOf := map[string]string{}
	seen := map[string]bool{}
	for _, c := range schemaCols {
		colNames = append(colNames, c.Name)
		typeOf[c.Name] = c.Type
		seen[c.Name] = true
	}
	// Seed-only columns follow in sorted order (fillRow draws their values
	// from a seeded faker in this order).
	for _, r := range rawSeeds {
		for _, k := range sortedKeys(r) {
			if !seen[k] {
				seen[k] = true
				colNames = append(colNames, k)
				typeOf[k] = "text"
			}
		}
	}
	return colNames, typeOf
}

// fillRow ensures a resolved row has every column; missing ones get fake values.
// On a pinned host a curated row is taken as complete: a column it leaves out is
// the host's own identity value when it is one, else empty — never invented.
func fillRow(row map[string]string, table string, colNames []string, typeOf map[string]string, node host.Node, f *gofakeit.Faker) map[string]string {
	for _, cn := range colNames {
		if _, ok := row[cn]; ok {
			continue
		}
		if node.Pinned {
			v, _ := identityValue(node, table, cn)
			row[cn] = v
			continue
		}
		row[cn] = fakeValue(f, table, cn, typeOf[cn], node)
	}
	return row
}

// extractTables returns every table referenced in the FROM/JOIN clause (handles
// "FROM a JOIN b ON …" and "FROM a, b"). The first entry is the driver table.
func extractTables(q string) []string {
	m := reFromClause.FindStringSubmatch(q)
	if m == nil {
		return nil
	}
	var tables []string
	seen := map[string]bool{}
	for _, part := range reJoinSplit.Split(m[1], -1) {
		im := reLeadIdent.FindStringSubmatch(strings.TrimSpace(part))
		if im == nil {
			continue
		}
		t := strings.ToLower(im[1])
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		tables = append(tables, t)
		if len(tables) == maxQueryTables {
			break
		}
	}
	return tables
}

// buildPopulationMulti breaks a (possibly joined) query into its tables, builds each
// table's population, and zip-merges them into combined rows so columns from every
// joined table are populated. This approximates a join — it does not evaluate ON
// predicates — which is enough for visibility-style listings.
func buildPopulationMulti(node host.Node, tables []string) ([]map[string]string, []string, bool) {
	if len(tables) == 0 {
		return nil, nil, false
	}
	if len(tables) == 1 {
		return buildPopulation(node, tables[0])
	}
	type tablePop struct {
		rows []map[string]string
	}
	var pops []tablePop
	var colUnion []string
	seen := map[string]bool{}
	for _, t := range tables {
		rows, cols, ok := buildPopulation(node, t)
		if !ok {
			continue
		}
		pops = append(pops, tablePop{rows})
		for _, cn := range cols {
			if !seen[cn] {
				seen[cn] = true
				colUnion = append(colUnion, cn)
			}
		}
	}
	if len(pops) == 0 {
		return nil, nil, false
	}
	for _, p := range pops {
		if len(p.rows) == 0 {
			// A join with an empty table has no rows (and nothing to zip).
			return []map[string]string{}, colUnion, true
		}
	}
	driver := pops[0]
	merged := make([]map[string]string, 0, len(driver.rows))
	for i := range driver.rows {
		row := map[string]string{}
		for _, p := range pops {
			src := p.rows[i%len(p.rows)]
			for k, v := range src {
				row[k] = v // later tables win on column-name collision
			}
		}
		merged = append(merged, row)
	}
	return merged, colUnion, true
}

// stableFaker returns a faker seeded deterministically from a node, a namespace, and a key.
func stableFaker(node host.Node, ns, key string) *gofakeit.Faker {
	h := fnv.New64a()
	_, _ = h.Write([]byte(node.Identifier + "|" + ns + "|" + strings.ToLower(key)))
	return gofakeit.New(h.Sum64())
}

// explainLog prints how a query was broken down: the tables it touched, whether each
// was seeded for this node's platform, the population size and the post-WHERE count.
func explainLog(node host.Node, q string, tables []string, popN, filteredN int) {
	platform := profileForPlatform(node.Target)
	parts := make([]string, 0, len(tables))
	for _, t := range tables {
		src := "schema/random"
		if _, ok := seedRowsRaw(platform, t); ok {
			src = "seeded"
		} else if _, ok := osquerySchema[t]; !ok {
			src = "unknown"
		}
		parts = append(parts, fmt.Sprintf("%s(%s)", t, src))
	}
	join := ""
	if len(tables) > 1 {
		join = " [join]"
	}
	oneLine := strings.Join(strings.Fields(q), " ")
	if len(oneLine) > 120 {
		oneLine = oneLine[:120] + "…"
	}
	fmt.Printf("[explain] %s/%s%s tables=%s population=%d afterWHERE=%d :: %s\n",
		node.Name, platform, join, strings.Join(parts, ","), popN, filteredN, oneLine)
}

// fakeValue generates a plausible string value for a column, preferring name-based
// heuristics and falling back to the osquery column type.
func fakeValue(f *gofakeit.Faker, table, name, colType string, node host.Node) string {
	n := strings.ToLower(name)
	if v, ok := identityValue(node, table, n); ok {
		return v
	}

	contains := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(n, s) {
				return true
			}
		}
		return false
	}

	switch {
	case n == "uid" || n == "gid" || n == "euid" || n == "egid" || contains("_uid", "_gid"):
		return itoa(f.Number(0, 2000))
	case n == "pid" || n == "ppid" || contains("pid"):
		return itoa(f.Number(1, 65535))
	case contains("port"):
		return itoa(f.Number(1, 65535))
	case contains("mac_address") || n == "mac" || n == "interface_mac":
		return f.MacAddress()
	case contains("address", "ipv4", "destination", "gateway", "netmask") && !contains("mac"):
		return f.IPv4Address()
	case n == "interface" || contains("interface"):
		return []string{"eth0", "en0", "wlan0", "lo", "ens33"}[f.Number(0, 4)]
	case contains("cmdline", "command"):
		return pickString(f, platformPaths(node))
	case contains("path", "directory", "cwd", "source", "destination_path") || n == "root":
		return pickString(f, platformPaths(node))
	case contains("hostname") || n == "host":
		return node.Name
	case contains("username") || n == "user" || n == "owner":
		return f.Username()
	case contains("uuid", "guid"):
		return f.UUID()
	case contains("version"):
		return f.AppVersion()
	case strings.HasSuffix(n, "sha256") || n == "sha256":
		return hexN(f, 64)
	case strings.HasSuffix(n, "sha1") || n == "sha1":
		return hexN(f, 40)
	case strings.HasSuffix(n, "md5") || n == "md5":
		return hexN(f, 32)
	case contains("hash"):
		return hexN(f, 64)
	case contains("time", "epoch", "atime", "mtime", "ctime", "btime", "_at", "seconds"):
		return itoa(f.Number(1600000000, 1750000000))
	case contains("size", "bytes", "memory", "disk", "space"):
		return itoa(f.Number(0, 1<<30))
	case n == "name" || contains("_name"):
		return f.AppName()
	case contains("description", "comment", "summary", "message"):
		return pickString(f, neutralDescriptions)
	case contains("enabled", "disabled", "active", "hidden", "visible") || strings.HasPrefix(n, "is_"):
		return itoa(f.Number(0, 1))
	}

	// Fall back to the osquery column type.
	switch colType {
	case "integer":
		return itoa(f.Number(0, 1000))
	case "bigint", "unsigned_bigint":
		return itoa(f.Number(0, 1<<31))
	case "double":
		return fmt.Sprintf("%.2f", f.Float64Range(0, 1000))
	default: // text or unknown
		return f.Word()
	}
}

// --- small helpers ---

func itoa(i int) string { return fmt.Sprintf("%d", i) }

func atoiSafe(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return n
		}
		n = n*10 + int(r-'0')
	}
	return n
}

func hexN(f *gofakeit.Faker, n int) string {
	const hexChars = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = hexChars[f.Number(0, 15)]
	}
	return string(b)
}

// splitTopLevel splits a comma-separated list, ignoring commas inside parentheses.
func splitTopLevel(s string) []string {
	var out []string
	depth := 0
	start := 0
	for i, r := range s {
		switch r {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, s[start:])
	return out
}
