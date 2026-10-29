package synth

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/huntbase-io/phantomfleet/internal/host"
	"gopkg.in/yaml.v3"
)

// seedFiles holds per-platform seed data so queries against common tables return
// realistic, internally-consistent rows (and WHERE/aggregates actually work).
// One file per platform profile; the file name (sans .yaml) is the profile key.
//
//go:embed seeds/*.yaml
var seedFiles embed.FS

// rowCountsYAML maps a table to the [min,max] number of rows a node reports for it.
//
//go:embed rowcounts.yaml
var rowCountsYAML []byte

// rowCounts: table -> [min,max]. "default" applies to tables not listed.
var rowCounts = map[string][2]int{}

func init() {
	mergeRowCounts(rowCountsYAML)
}

// mergeRowCounts parses a rowcounts YAML (table -> [min,max]) over the current map.
func mergeRowCounts(raw []byte) {
	parsed, err := parseRowCounts(raw)
	if err != nil {
		return
	}
	applyRowCounts(parsed)
}

// parseRowCounts parses a rowcounts YAML file: table -> [min, max].
func parseRowCounts(raw []byte) (map[string][]int, error) {
	var parsed map[string][]int
	if err := yaml.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("not a valid rowcounts file (table: [min, max]): %w", err)
	}
	return parsed, nil
}

// applyRowCounts merges parsed counts over the current map; an entry that
// isn't a valid [min, max] pair is ignored.
func applyRowCounts(parsed map[string][]int) {
	for table, mm := range parsed {
		if len(mm) == 2 && mm[0] >= 0 && mm[1] >= mm[0] {
			rowCounts[strings.ToLower(table)] = [2]int{mm[0], mm[1]}
		}
	}
}

// rowCountFor returns how many rows a node should report for a table, drawn from
// the configured [min,max] using the supplied faker (deterministic per seed).
func rowCountFor(f *gofakeit.Faker, table string) int {
	mm, ok := rowCounts[strings.ToLower(table)]
	if !ok {
		if mm, ok = rowCounts["default"]; !ok {
			mm = [2]int{1, 8}
		}
	}
	if mm[1] <= mm[0] {
		return mm[0]
	}
	return f.Number(mm[0], mm[1])
}

// seedProfile: table name -> rows (each row is column -> string value).
type seedProfile map[string][]map[string]string

// seedProfiles: platform profile -> seedProfile.
var seedProfiles = map[string]seedProfile{}

func init() {
	entries, err := seedFiles.ReadDir("seeds")
	if err != nil {
		return
	}
	parsedByName := map[string]seedProfile{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		raw, err := seedFiles.ReadFile("seeds/" + e.Name())
		if err != nil {
			continue
		}
		parsedByName[strings.TrimSuffix(e.Name(), ".yaml")] = parseSeedBytes(raw)
	}

	// "all.yaml" is a shared base merged into every platform profile; a platform
	// file that defines the same table replaces the base table for that platform.
	base := parsedByName["all"]
	for name, prof := range parsedByName {
		if name == "all" {
			continue
		}
		merged := seedProfile{}
		for t, rows := range base {
			merged[t] = rows
		}
		for t, rows := range prof {
			merged[t] = rows
		}
		seedProfiles[name] = merged
	}
}

// replaceKey is a reserved top-level key of an external seed file: the tables it
// lists replace the built-in rows (for that platform, or every platform from
// all.yaml) instead of being appended to them.
const replaceKey = "_replace"

// viewsKey is a reserved top-level key of an external seed file: a mapping of
// extension table name to the SQL SELECT that computes its rows per statement
// (see sqlite_eval.go and docs/extensions.md).
const viewsKey = "_views"

// seedViews: platform profile -> table -> view SQL.
var seedViews = map[string]map[string]string{}

// seedView returns the view defined for table on the node's platform profile.
func seedView(node host.Node, table string) (string, bool) {
	v, ok := seedViews[profileForPlatform(node.Target)][strings.ToLower(table)]
	return v, ok
}

// seedDoc is one parsed seed file.
type seedDoc struct {
	prof    seedProfile
	replace []string
	views   map[string]string
}

// parseSeedBytes parses a seed YAML (table -> rows) and stringifies every value so
// unquoted numbers/bools work. A table given as an empty list is kept, with no
// rows: it declares the table exists on the platform but has nothing to report.
func parseSeedBytes(raw []byte) seedProfile {
	doc, _ := parseSeedDoc(raw)
	return doc.prof
}

// parseSeedDoc parses a seed file: its tables, _replace list and _views. A
// file that is not YAML yields an empty document; a malformed _views entry is
// an error.
func parseSeedDoc(raw []byte) (seedDoc, error) {
	doc := seedDoc{prof: seedProfile{}}
	var parsed map[string]interface{}
	if err := yaml.Unmarshal(raw, &parsed); err != nil {
		return doc, fmt.Errorf("not a valid seed file (a YAML mapping of table names to rows): %w", err)
	}
	prof := doc.prof
	var replace []string
	for table, value := range parsed {
		lt := strings.ToLower(table)
		list, ok := value.([]interface{})
		if lt == replaceKey {
			for _, t := range list {
				replace = append(replace, strings.ToLower(fmt.Sprint(t)))
			}
			continue
		}
		if lt == viewsKey {
			views, err := parseViews(value)
			if err != nil {
				return doc, err
			}
			doc.views = views
			continue
		}
		if !ok && value != nil {
			continue // not a table
		}
		prof[lt] = []map[string]string{}
		for _, item := range list {
			row, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			sr := make(map[string]string, len(row))
			for k, v := range row {
				sr[strings.ToLower(k)] = fmt.Sprint(v)
			}
			prof[lt] = append(prof[lt], sr)
		}
	}
	doc.replace = replace
	return doc, nil
}

// parseViews validates a _views mapping: each key names an extension table and
// each value is a single SELECT (or WITH ... SELECT) statement.
func parseViews(value interface{}) (map[string]string, error) {
	m, ok := value.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%s must map table names to SQL", viewsKey)
	}
	views := make(map[string]string, len(m))
	for name, v := range m {
		table := strings.ToLower(strings.TrimSpace(name))
		text, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("%s.%s: the view must be a SQL string", viewsKey, name)
		}
		if !isExtensionTable(table) {
			return nil, fmt.Errorf("%s.%s: views are only allowed for extension tables loaded with --extra-schema", viewsKey, table)
		}
		stmt, err := checkReadStatement(text)
		if err != nil {
			return nil, fmt.Errorf("%s.%s: %w", viewsKey, table, err)
		}
		views[table] = stmt
	}
	return views, nil
}

// addViews records views for a platform profile (a later definition of the
// same table replaces an earlier one).
func addViews(platform string, views map[string]string) {
	if len(views) == 0 {
		return
	}
	if seedViews[platform] == nil {
		seedViews[platform] = map[string]string{}
	}
	for t, v := range views {
		seedViews[platform][t] = v
	}
}

// LoadSeedDir layers on-disk YAML over the embedded defaults so users can add fake
// data without rebuilding. It is additive: external rows are appended to the matching
// table (built-in anchors/templates remain). Recognized files in dir:
//
//	all.yaml         rows added to every platform profile
//	linux.yaml       rows added to the linux profile (likewise darwin.yaml, windows.yaml)
//	rowcounts.yaml   [min,max] row counts, overriding the built-in counts per table
//
//	_views           (key inside any seed file) views computing extension tables
//
// Returns the number of seed files applied. A missing directory is not an error.
// A file that can't be read or isn't valid YAML of the right shape, or a
// malformed _views entry, is an error, and then nothing is applied.
func LoadSeedDir(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	applied := 0
	var rowCountFiles []map[string][]int
	var external []struct {
		name string
		doc  seedDoc
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		// #nosec G304 -- dir is the developer-supplied seed directory and
		// e.Name() is a plain entry name from os.ReadDir (no separators).
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return 0, err
		}
		name := strings.TrimSuffix(e.Name(), ".yaml")
		if name == "rowcounts" {
			counts, err := parseRowCounts(raw)
			if err != nil {
				return 0, fmt.Errorf("%s: %w", e.Name(), err)
			}
			rowCountFiles = append(rowCountFiles, counts)
			applied++
			continue
		}
		doc, err := parseSeedDoc(raw)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", e.Name(), err)
		}
		external = append(external, struct {
			name string
			doc  seedDoc
		}{name, doc})
		applied++
	}
	// Nothing is applied until every file has parsed.
	for _, counts := range rowCountFiles {
		applyRowCounts(counts)
	}
	// Apply "all" to every platform first, then platform-specific files.
	for _, ext := range external {
		if ext.name != "all" {
			continue
		}
		for p := range seedProfiles {
			dropTables(seedProfiles[p], ext.doc.replace)
			appendTables(seedProfiles[p], ext.doc.prof)
			addViews(p, ext.doc.views)
		}
	}
	for _, ext := range external {
		if ext.name == "all" {
			continue
		}
		if _, ok := seedProfiles[ext.name]; !ok {
			seedProfiles[ext.name] = seedProfile{}
		}
		dropTables(seedProfiles[ext.name], ext.doc.replace)
		appendTables(seedProfiles[ext.name], ext.doc.prof)
		addViews(ext.name, ext.doc.views)
	}
	return applied, nil
}

// appendTables appends src's rows onto dst (additive merge). A table src declares
// (even with no rows) is declared in dst.
func appendTables(dst, src seedProfile) {
	for t, rows := range src {
		if dst[t] == nil {
			dst[t] = []map[string]string{}
		}
		dst[t] = append(dst[t], rows...)
	}
}

// dropTables forgets the built-in rows of the listed tables (_replace).
func dropTables(prof seedProfile, tables []string) {
	for _, t := range tables {
		delete(prof, t)
	}
}

// tableDeclared reports whether a platform profile defines a table at all (rows
// for any host, or an explicit empty list).
func tableDeclared(platform, table string) bool {
	prof, ok := seedProfiles[platform]
	if !ok {
		return false
	}
	_, ok = prof[strings.ToLower(table)]
	return ok
}

// profileForPlatform maps a node's osquery platform (node.Target) to a seed profile.
func profileForPlatform(platform string) string {
	p := strings.ToLower(platform)
	switch {
	case strings.HasPrefix(p, "darwin") || strings.Contains(p, "macos") || p == "mac":
		return "darwin"
	case strings.HasPrefix(p, "windows") || p == "win":
		return "windows"
	default:
		// ubuntu*/centos*/debian*/rhel*/freebsd*/linux -> linux
		return "linux"
	}
}

// nodeUsername derives a stable, plausible username for a node.
func nodeUsername(node host.Node) string {
	if node.PrimaryUser != "" {
		return node.PrimaryUser
	}
	if node.Pinned {
		return defaultOSUser(node)
	}
	s := strings.ToLower(node.Name)
	s = regexp.MustCompile(`[^a-z0-9]`).ReplaceAllString(s, "")
	if s == "" {
		return "osquery"
	}
	if len(s) > 16 {
		s = s[:16]
	}
	return s
}

// seedRowsRaw returns the unresolved seed rows (still containing {{...}} tokens) for
// a table on a node's platform, or (nil, false) when the table isn't seeded.
func seedRowsRaw(platform, table string) ([]map[string]string, bool) {
	prof, ok := seedProfiles[platform]
	if !ok {
		return nil, false
	}
	rows, ok := prof[strings.ToLower(table)]
	if !ok || len(rows) == 0 {
		return nil, false
	}
	return rows, true
}

// Reserved seed columns, stripped before a row is used:
//
//   - hostsColumn: the row is reported only by the nodes it names
//     ("finance-ws-12" or "finance-ws-12|file-srv-01"; a short name matches the
//     FQDN too).
//   - keyColumn: on a host-restricted row, names a column (e.g.
//     bundle_identifier) whose value this row owns on its hosts — a shared row
//     with the same value is dropped there, so a host-specific Chrome 116 or a
//     stopped WinDefend replaces the profile's generic one instead of joining it.
const (
	hostsColumn = "_hosts"
	keyColumn   = "_key"
)

// rowMatchesNode reports whether a seed row applies to a node (true for rows
// without a _hosts restriction).
func rowMatchesNode(row map[string]string, node host.Node) bool {
	want, ok := row[hostsColumn]
	if !ok {
		return true
	}
	name := strings.ToLower(node.Name)
	short := strings.ToLower(shortHostname(node.Name))
	for _, h := range strings.FieldsFunc(want, func(r rune) bool { return r == '|' || r == ',' }) {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" && (h == name || h == short) {
			return true
		}
	}
	return false
}

// withoutReserved copies a row minus the reserved columns.
func withoutReserved(row map[string]string) map[string]string {
	clean := make(map[string]string, len(row))
	for k, v := range row {
		if k != hostsColumn && k != keyColumn {
			clean[k] = v
		}
	}
	return clean
}

// seedRowsSplit returns the node's seed rows for a table as (rows restricted to
// this host, rows every node of the platform shares minus any a host row
// replaces via keyColumn). Host rows go first so padding never crowds them out.
func seedRowsSplit(node host.Node, table string) ([]map[string]string, []map[string]string) {
	raw, ok := seedRowsRaw(profileForPlatform(node.Target), table)
	if !ok {
		return nil, nil
	}
	var pinned, shared []map[string]string
	replaced := map[string]map[string]bool{} // column -> lower-cased values
	for _, row := range raw {
		if _, restricted := row[hostsColumn]; !restricted {
			shared = append(shared, row)
			continue
		}
		if !rowMatchesNode(row, node) {
			continue
		}
		clean := withoutReserved(row)
		if col := strings.ToLower(strings.TrimSpace(row[keyColumn])); col != "" {
			if replaced[col] == nil {
				replaced[col] = map[string]bool{}
			}
			replaced[col][strings.ToLower(resolveIdentity(clean[col], node))] = true
		}
		pinned = append(pinned, clean)
	}
	var kept []map[string]string
	for _, row := range shared {
		drop := false
		for col, values := range replaced {
			if v, ok := row[col]; ok && values[strings.ToLower(resolveIdentity(v, node))] {
				drop = true
				break
			}
		}
		if !drop {
			kept = append(kept, withoutReserved(row))
		}
	}
	return pinned, kept
}

// --- seed value templating: fixed strings and/or {{token}} patterns ---

var (
	// any {{...}} token
	reToken = regexp.MustCompile(`\{\{([^{}]+)\}\}`)
	// generator tokens that vary per resolution (i.e. make a row a repeatable template);
	// node placeholders like {{hostname}} are NOT generators.
	reGenerator = regexp.MustCompile(`\{\{\s*(int|float|choice|ipv4|mac|uuid4|hex|word|words|semver|bool|unixtime|date|row)\b[^{}]*\}\}`)
)

// rowHasGenerator reports whether a row contains any generator token. Such rows are
// treated as repeatable templates (padding clones them, regenerating the patterns);
// rows with only fixed values / node placeholders are one-off anchors.
func rowHasGenerator(row map[string]string) bool {
	for _, v := range row {
		if reGenerator.MatchString(v) {
			return true
		}
	}
	return false
}

// resolveValue expands node placeholders and generator patterns in a seed value.
// Fixed text is returned unchanged, so literals and patterns can be freely mixed.
func resolveValue(s string, node host.Node, f *gofakeit.Faker) string {
	if !strings.Contains(s, "{{") {
		return s
	}
	return reToken.ReplaceAllStringFunc(s, func(tok string) string {
		inner := strings.TrimSpace(tok[2 : len(tok)-2])
		name, arg := inner, ""
		if i := strings.IndexByte(inner, ':'); i >= 0 {
			name, arg = strings.TrimSpace(inner[:i]), strings.TrimSpace(inner[i+1:])
		}
		switch strings.ToLower(name) {
		case "hostname":
			return node.Name
		case "shorthost":
			return shortHostname(node.Name)
		case "ip":
			return node.IP
		case "uuid":
			return node.Identifier
		case "version":
			return node.Version
		case "username":
			return nodeUsername(node)
		case "ago":
			// Unix time `arg` (a Go duration, e.g. 26h5m) before now: story events
			// that stay the same age relative to whenever they are queried.
			d, err := time.ParseDuration(arg)
			if err != nil {
				return tok
			}
			return strconv.FormatInt(seedNow().Add(-d).Unix(), 10)
		case "int":
			lo, hi := parseRange(arg, 0, 1000)
			return itoa(f.Number(lo, hi))
		case "float":
			lo, hi := parseRangeF(arg, 0, 1000)
			return fmt.Sprintf("%.2f", f.Float64Range(lo, hi))
		case "choice":
			opts := strings.Split(arg, "|")
			return strings.TrimSpace(opts[f.Number(0, len(opts)-1)])
		case "ipv4":
			return f.IPv4Address()
		case "mac":
			return f.MacAddress()
		case "uuid4":
			return f.UUID()
		case "hex":
			n := atoiSafe(arg)
			if n <= 0 {
				n = 16
			}
			return hexN(f, n)
		case "word":
			return f.Word()
		case "words":
			return f.Word() + " " + f.Word()
		case "semver":
			return f.AppVersion()
		case "bool":
			return itoa(f.Number(0, 1))
		case "unixtime":
			lo, hi := parseRange(arg, 1600000000, 1750000000)
			return itoa(f.Number(lo, hi))
		case "date":
			return fmt.Sprintf("%04d-%02d-%02d", f.Number(2019, 2024), f.Number(1, 12), f.Number(1, 28))
		default:
			return tok // unknown token left as-is
		}
	})
}

// resolveRow expands every value in a row. {{row:...}} tokens draw one random
// catalog entry for the whole row (see resolveRowPicked for de-duplication); a
// row that names an unknown catalog keeps the tokens' text empty.
func resolveRow(raw map[string]string, node host.Node, f *gofakeit.Faker) map[string]string {
	row, ok := resolveRowPicked(raw, node, f, nil)
	if !ok {
		stripped := make(map[string]string, len(raw))
		for k, v := range raw {
			stripped[k] = reRowToken.ReplaceAllString(v, "")
		}
		return resolveValues(stripped, node, f)
	}
	return row
}

// resolveRowPicked expands a row, drawing its {{row:...}} catalog entries from
// picker (each entry once per population). ok is false when a catalog the row
// needs is exhausted or unknown.
func resolveRowPicked(raw map[string]string, node host.Node, f *gofakeit.Faker, picker *rowPicker) (map[string]string, bool) {
	expanded, ok := expandRowTokens(raw, f, picker)
	if !ok {
		return nil, false
	}
	return resolveValues(expanded, node, f), true
}

// resolveValues expands node placeholders and generator patterns in every value.
// Columns are resolved in sorted order: every value draws from the one
// shared faker, so map order would move values between runs.
func resolveValues(raw map[string]string, node host.Node, f *gofakeit.Faker) map[string]string {
	out := make(map[string]string, len(raw))
	for _, k := range sortedKeys(raw) {
		out[k] = resolveValue(raw[k], node, f)
	}
	return out
}

// sortedKeys returns m's keys in order.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func parseRange(arg string, dlo, dhi int) (int, int) {
	if p := strings.SplitN(arg, "..", 2); len(p) == 2 {
		lo, hi := atoiSafe(strings.TrimSpace(p[0])), atoiSafe(strings.TrimSpace(p[1]))
		if hi >= lo {
			return lo, hi
		}
	}
	return dlo, dhi
}

func parseRangeF(arg string, dlo, dhi float64) (float64, float64) {
	if p := strings.SplitN(arg, "..", 2); len(p) == 2 {
		lo, e1 := strconv.ParseFloat(strings.TrimSpace(p[0]), 64)
		hi, e2 := strconv.ParseFloat(strings.TrimSpace(p[1]), 64)
		if e1 == nil && e2 == nil && hi >= lo {
			return lo, hi
		}
	}
	return dlo, dhi
}

// --- minimal WHERE evaluation over seeded rows ---

var (
	reWhereClause = regexp.MustCompile(`(?is)\bwhere\b(.*?)(?:\bgroup\s+by\b|\border\s+by\b|\bhaving\b|\blimit\b|;|$)`)
	reCond        = regexp.MustCompile(`(?is)^\s*([a-z0-9_."` + "`" + `]+)\s*(=|==|!=|<>|>=|<=|>|<|not\s+like|like)\s*(.+?)\s*$`)
	reInCond      = regexp.MustCompile(`(?is)^\s*([a-z0-9_."` + "`" + `]+)\s+(not\s+in|in)\s*\((.+)\)\s*$`)
)

// applyWhere filters rows by a (flat) WHERE clause. Supports AND/OR (no nested
// parentheses), =, !=, <>, <, >, <=, >=, LIKE, NOT LIKE, IN, NOT IN. Unknown or
// unparseable conditions are treated as "match" so we never drop everything by mistake.
func applyWhere(rows []map[string]string, query string) []map[string]string {
	m := reWhereClause.FindStringSubmatch(query)
	if m == nil || strings.TrimSpace(m[1]) == "" {
		return rows
	}
	clause := strings.TrimSpace(m[1])

	// OR groups (split on " or "), each an AND of conditions.
	orGroups := regexp.MustCompile(`(?i)\s+or\s+`).Split(clause, -1)
	out := make([]map[string]string, 0, len(rows))
	for _, row := range rows {
		matched := false
		for _, g := range orGroups {
			conds := regexp.MustCompile(`(?i)\s+and\s+`).Split(g, -1)
			all := true
			for _, c := range conds {
				if !evalCond(row, c) {
					all = false
					break
				}
			}
			if all {
				matched = true
				break
			}
		}
		if matched {
			out = append(out, row)
		}
	}
	return out
}

func evalCond(row map[string]string, cond string) bool {
	cond = strings.TrimSpace(cond)
	if cond == "" {
		return true
	}
	if m := reInCond.FindStringSubmatch(cond); m != nil {
		col := bareCol(m[1])
		neg := strings.Contains(strings.ToLower(m[2]), "not")
		val, ok := row[col]
		if !ok {
			return true // column not in seed row -> don't filter it out
		}
		in := false
		for _, item := range splitTopLevel(m[3]) {
			if strings.EqualFold(val, unquote(item)) {
				in = true
				break
			}
		}
		return in != neg
	}
	m := reCond.FindStringSubmatch(cond)
	if m == nil {
		return true // unparseable -> don't filter
	}
	col := bareCol(m[1])
	op := strings.ToLower(strings.Join(strings.Fields(m[2]), " "))
	want := unquote(strings.TrimSpace(m[3]))
	got, ok := row[col]
	if !ok {
		return true
	}

	switch op {
	case "=", "==":
		return strings.EqualFold(got, want)
	case "!=", "<>":
		return !strings.EqualFold(got, want)
	case "like", "not like":
		matched := likeMatch(got, want)
		if op == "not like" {
			return !matched
		}
		return matched
	case ">", "<", ">=", "<=":
		gf, gerr := strconv.ParseFloat(got, 64)
		wf, werr := strconv.ParseFloat(want, 64)
		if gerr == nil && werr == nil {
			switch op {
			case ">":
				return gf > wf
			case "<":
				return gf < wf
			case ">=":
				return gf >= wf
			case "<=":
				return gf <= wf
			}
		}
		// string comparison fallback
		switch op {
		case ">":
			return got > want
		case "<":
			return got < want
		case ">=":
			return got >= want
		case "<=":
			return got <= want
		}
	}
	return true
}

// likeMatch implements SQL LIKE (% and _) case-insensitively.
func likeMatch(s, pattern string) bool {
	var b strings.Builder
	b.WriteString("(?is)^")
	for _, r := range pattern {
		switch r {
		case '%':
			b.WriteString(".*")
		case '_':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return false
	}
	return re.MatchString(s)
}

func bareCol(s string) string {
	s = strings.Trim(strings.TrimSpace(s), "`\"'")
	if dot := strings.LastIndex(s, "."); dot >= 0 {
		s = s[dot+1:]
	}
	return strings.ToLower(strings.Trim(s, "`\"'"))
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// seedNow is the clock {{ago:..}} counts back from (tests fix it).
var seedNow = time.Now
