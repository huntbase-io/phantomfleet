package synth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Extension tables (--extra-schema).
//
// osquery extensions add tables that the core schema does not know about. An
// extra schema file declares them in exactly the shape of the embedded
// osquery_schema.json:
//
//	{"example_ext_downloads": [{"name": "ts", "type": "bigint"}, {"name": "user", "type": "text"}]}
//
// Loaded tables are merged into the schema at start-up. They behave like an
// agent whose extension has recorded nothing until seed data says otherwise:
//
//   - A pinned host answers an extension table from its seed rows only (shared
//     and _hosts rows, never padded), through the SQLite evaluator, so the
//     statement runs with real SQL semantics. No seed rows means no rows.
//   - A random node answers every extension table with no rows.
//   - Schema-generated (random) values are never used for an extension table.
//
// A table whose rows depend on the query's constraints can be defined as a
// view in the seeds (_views); see sqlite_eval.go and docs/extensions.md.

// extensionTables is the set of tables loaded with --extra-schema that are not
// in the embedded schema.
var extensionTables = map[string]bool{}

var (
	reIdent = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)
	// schemaTypes are the column types the embedded schema uses.
	schemaTypes = map[string]bool{"text": true, "integer": true, "bigint": true, "unsigned_bigint": true, "double": true}
)

// isExtensionTable reports whether table was loaded with --extra-schema.
func isExtensionTable(table string) bool {
	return extensionTables[strings.ToLower(table)]
}

// readsExtensionTable reports whether a query names an extension table.
func readsExtensionTable(q string) bool {
	if len(extensionTables) == 0 {
		return false
	}
	for _, t := range referencedTables(q) {
		if extensionTables[t] {
			return true
		}
	}
	return false
}

// LoadExtraSchema reads one --extra-schema file and merges its tables into the
// schema. It returns the number of tables the file declares. A table that is
// already known (embedded, or from an earlier file) is accepted only when its
// definition is identical; any other clash is an error.
func LoadExtraSchema(path string) (int, error) {
	// #nosec G304 -- operator-supplied --extra-schema path for a local testing tool.
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return 0, err
	}
	tables, err := parseExtraSchema(raw)
	if err != nil {
		return 0, err
	}
	return len(tables), mergeExtraSchema(tables)
}

// parseExtraSchema decodes and validates an extra schema document.
func parseExtraSchema(raw []byte) (map[string][]schemaColumn, error) {
	var parsed map[string][]schemaColumn
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("not a schema file (want {\"table\": [{\"name\": ..., \"type\": ...}]}): %w", err)
	}
	out := make(map[string][]schemaColumn, len(parsed))
	for name, cols := range parsed {
		table := strings.ToLower(strings.TrimSpace(name))
		if !reIdent.MatchString(table) {
			return nil, fmt.Errorf("table %q: name must match [a-z_][a-z0-9_]*", name)
		}
		if _, dup := out[table]; dup {
			return nil, fmt.Errorf("table %q is declared twice", table)
		}
		if len(cols) == 0 {
			return nil, fmt.Errorf("table %q has no columns", table)
		}
		seen := map[string]bool{}
		norm := make([]schemaColumn, 0, len(cols))
		for _, c := range cols {
			col := strings.ToLower(strings.TrimSpace(c.Name))
			typ := strings.ToLower(strings.TrimSpace(c.Type))
			if !reIdent.MatchString(col) {
				return nil, fmt.Errorf("table %q: column name %q must match [a-z_][a-z0-9_]*", table, c.Name)
			}
			if seen[col] {
				return nil, fmt.Errorf("table %q: column %q is declared twice", table, col)
			}
			if !schemaTypes[typ] {
				return nil, fmt.Errorf("table %q: column %q has type %q; want one of text, integer, bigint, unsigned_bigint, double", table, col, c.Type)
			}
			seen[col] = true
			norm = append(norm, schemaColumn{Name: col, Type: typ})
		}
		out[table] = norm
	}
	return out, nil
}

// mergeExtraSchema adds tables to the schema. Nothing is merged when any table
// clashes with a different existing definition.
func mergeExtraSchema(tables map[string][]schemaColumn) error {
	names := make([]string, 0, len(tables))
	for t := range tables {
		names = append(names, t)
	}
	sort.Strings(names)
	for _, t := range names {
		existing, ok := osquerySchema[t]
		if ok && !sameColumns(existing, tables[t]) {
			origin := "the embedded osquery schema"
			if extensionTables[t] {
				origin = "an earlier --extra-schema file"
			}
			return fmt.Errorf("table %q clashes with a different definition in %s", t, origin)
		}
	}
	for _, t := range names {
		if _, ok := osquerySchema[t]; ok {
			continue // identical: nothing to do, and an embedded table stays a core table
		}
		osquerySchema[t] = tables[t]
		extensionTables[t] = true
	}
	return nil
}

// sameColumns reports whether two column lists are identical (names, types and
// order; types compared case-insensitively).
func sameColumns(a, b []schemaColumn) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !strings.EqualFold(a[i].Name, b[i].Name) || !strings.EqualFold(a[i].Type, b[i].Type) {
			return false
		}
	}
	return true
}
