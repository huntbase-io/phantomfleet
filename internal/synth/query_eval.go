package synth

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/huntbase-io/phantomfleet/internal/host"
)

// Query evaluation used for pinned (--nodes-file) hosts, whose curated data is
// consistent enough for real joins: equality ON predicates are evaluated instead
// of zip-merging the joined tables' populations.

var (
	reSubqueryStart = regexp.MustCompile(`(?i)^\(\s*select\b`)
	reJoinSep       = regexp.MustCompile(`(?is)\b(left\s+(?:outer\s+)?join|(?:inner\s+|cross\s+)?join)\b|,`)
	reOnSplit       = regexp.MustCompile(`(?is)\bon\b`)
	reAndSplit      = regexp.MustCompile(`(?is)\s+and\s+`)
	reEquality      = regexp.MustCompile(`(?is)^\s*([a-z0-9_."` + "`" + `]+)\s*==?\s*([a-z0-9_."` + "`" + `]+)\s*$`)
	reAliasWords    = map[string]bool{"on": true, "where": true, "join": true, "left": true, "inner": true, "cross": true, "using": true}
)

// extractSubqueries replaces every parenthesised "(SELECT ...)" in q with a
// placeholder column name (__sq0__, __sq1__, …) and returns the rewritten query
// with the inner queries by placeholder.
func extractSubqueries(q string) (string, map[string]string) {
	var subs map[string]string
	var b strings.Builder
	for i := 0; i < len(q); {
		if q[i] == '(' && reSubqueryStart.MatchString(q[i:]) {
			depth, end := 0, -1
			for j := i; j < len(q) && end < 0; j++ {
				switch q[j] {
				case '(':
					depth++
				case ')':
					depth--
					if depth == 0 {
						end = j
					}
				}
			}
			if end > 0 {
				if subs == nil {
					subs = map[string]string{}
				}
				name := fmt.Sprintf("__sq%d__", len(subs))
				subs[name] = strings.TrimSpace(q[i+1 : end])
				b.WriteString(name)
				i = end + 1
				continue
			}
		}
		b.WriteByte(q[i])
		i++
	}
	return b.String(), subs
}

// firstValue is the first column of the first row (a scalar subquery's value).
func firstValue(rows []map[string]interface{}) string {
	if len(rows) == 0 {
		return ""
	}
	keys := make([]string, 0, len(rows[0]))
	for k := range rows[0] {
		keys = append(keys, k)
	}
	if len(keys) != 1 {
		return ""
	}
	if v, ok := rows[0][keys[0]].(string); ok {
		return v
	}
	return fmt.Sprint(rows[0][keys[0]])
}

type joinTerm struct {
	table string
	alias string
	left  bool
	on    [][2]string // equality pairs, as written (alias.col or col)
}

// parseJoins breaks the FROM clause into its tables, aliases, join kinds and
// equality ON predicates.
func parseJoins(q string) []joinTerm {
	m := reFromClause.FindStringSubmatch(q)
	if m == nil {
		return nil
	}
	clause := m[1]
	seps := reJoinSep.FindAllStringSubmatchIndex(clause, -1)
	var parts []string
	var lefts []bool
	start, left := 0, false
	for _, sep := range seps {
		parts = append(parts, clause[start:sep[0]])
		lefts = append(lefts, left)
		left = sep[2] >= 0 && strings.HasPrefix(strings.ToLower(clause[sep[2]:sep[3]]), "left")
		start = sep[1]
	}
	parts = append(parts, clause[start:])
	lefts = append(lefts, left)

	if len(parts) > maxQueryTables {
		parts, lefts = parts[:maxQueryTables], lefts[:maxQueryTables]
	}
	var terms []joinTerm
	for i, part := range parts {
		pieces := reOnSplit.Split(part, 2)
		head := strings.Fields(strings.TrimSpace(pieces[0]))
		if len(head) == 0 {
			continue
		}
		t := joinTerm{table: strings.ToLower(strings.Trim(head[0], "`\"'")), left: lefts[i]}
		t.alias = t.table
		rest := head[1:]
		if len(rest) > 0 && strings.EqualFold(rest[0], "as") {
			rest = rest[1:]
		}
		if len(rest) > 0 && !reAliasWords[strings.ToLower(rest[0])] {
			t.alias = strings.ToLower(strings.Trim(rest[0], "`\"'"))
		}
		if len(pieces) == 2 {
			for _, cond := range reAndSplit.Split(pieces[1], -1) {
				if em := reEquality.FindStringSubmatch(cond); em != nil {
					t.on = append(t.on, [2]string{em[1], em[2]})
				}
			}
		}
		terms = append(terms, t)
	}
	return terms
}

// refParts splits "alias.col" into ("alias", "col"); a bare column has no alias.
func refParts(ref string) (string, string) {
	ref = strings.ToLower(strings.Trim(strings.TrimSpace(ref), "`\"'"))
	if dot := strings.LastIndex(ref, "."); dot >= 0 {
		return strings.Trim(ref[:dot], "`\"'"), strings.Trim(ref[dot+1:], "`\"'")
	}
	return "", ref
}

// buildJoinedPopulation builds the population a pinned host answers a query
// from. Joined tables are combined on their equality ON predicates (inner or
// left join); a join without usable predicates falls back to the zip-merge.
// Every row carries bare column names (later tables win) plus alias.column.
func buildJoinedPopulation(node host.Node, q string, tables []string) ([]map[string]string, []string, bool) {
	terms := parseJoins(q)
	if len(terms) < 2 {
		return buildPopulationMulti(node, tables)
	}
	for _, t := range terms[1:] {
		if len(t.on) == 0 {
			return buildPopulationMulti(node, tables)
		}
	}

	var rows []map[string]string
	var colUnion []string
	seen := map[string]bool{}
	for i, t := range terms {
		pop, cols, ok := buildPopulation(node, t.table)
		if !ok {
			if i == 0 {
				return nil, nil, false
			}
			pop = nil
		}
		for _, cn := range cols {
			if !seen[cn] {
				seen[cn] = true
				colUnion = append(colUnion, cn)
			}
		}
		if i == 0 {
			for _, r := range pop {
				rows = append(rows, withAlias(nil, r, t.alias))
			}
			continue
		}
		// The join result is capped at maxPopulation as a whole, not per left row,
		// so chained joins can't multiply the population past the cap.
		var joined []map[string]string
	accLoop:
		for _, acc := range rows {
			matched := false
			for _, r := range pop {
				if !joinMatches(acc, r, t) {
					continue
				}
				if len(joined) >= maxPopulation {
					break accLoop
				}
				joined = append(joined, withAlias(acc, r, t.alias))
				matched = true
			}
			if !matched && t.left {
				if len(joined) >= maxPopulation {
					break
				}
				joined = append(joined, acc)
			}
		}
		rows = joined
	}
	return rows, colUnion, true
}

// withAlias copies acc and adds r's columns, bare and alias-qualified.
func withAlias(acc, r map[string]string, alias string) map[string]string {
	out := make(map[string]string, len(acc)+2*len(r))
	for k, v := range acc {
		out[k] = v
	}
	for k, v := range r {
		out[k] = v
		out[alias+"."+k] = v
	}
	return out
}

// joinMatches evaluates a term's equality predicates between the rows joined so
// far (acc) and a candidate row of the term's table (r).
func joinMatches(acc, r map[string]string, t joinTerm) bool {
	for _, pair := range t.on {
		la, lc := refParts(pair[0])
		ra, rc := refParts(pair[1])
		var newCol, oldRef string
		switch {
		case la == t.alias || la == t.table:
			newCol, oldRef = lc, pair[1]
		case ra == t.alias || ra == t.table:
			newCol, oldRef = rc, pair[0]
		default:
			newCol, oldRef = rc, pair[0]
		}
		oa, oc := refParts(oldRef)
		old, ok := acc[oa+"."+oc]
		if oa == "" || !ok {
			old = acc[oc]
		}
		if !strings.EqualFold(old, r[newCol]) {
			return false
		}
	}
	return true
}
