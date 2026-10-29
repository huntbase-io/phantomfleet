package synth

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/brianvoe/gofakeit/v7"
	"gopkg.in/yaml.v3"
)

// Row catalogs (--catalog).
//
// A catalog is a named list of coherent records that seed templates draw from
// with {{row:<catalog>.<field>}}, so a padded table lists real-looking entries
// (a service whose name, image path and DLL belong together) instead of
// independent random words. A catalog file is YAML mapping catalog name to a
// list of entries, each a mapping of field to value:
//
//	example_services:
//	  - {name: nginx, path: /usr/sbin/nginx, user: www-data}
//	  - {name: cron, path: /usr/sbin/cron, user: root}
//
// Every {{row:...}} token of one seed row resolves from the same entry. A
// padded population draws each entry at most once and skips entries whose
// name an anchor row of the table already uses, so a table padded only from
// catalogs stops at the catalog's size. No catalog is built in.

// catalogs: catalog name -> entries (field -> value).
var catalogs = map[string][]map[string]string{}

// reRowToken matches {{row:<catalog>.<field>}}.
var reRowToken = regexp.MustCompile(`\{\{\s*row:\s*([A-Za-z0-9_]+)\.([A-Za-z0-9_]+)\s*\}\}`)

var reCatalogName = regexp.MustCompile(`^[a-z0-9_]+$`)

// LoadCatalog reads one --catalog file and merges its catalogs. It returns the
// number of catalogs the file defines. A catalog name defined by an earlier
// file is accepted only when the entries are identical.
func LoadCatalog(path string) (int, error) {
	// #nosec G304 -- operator-supplied --catalog path for a local testing tool.
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return 0, err
	}
	parsed, err := parseCatalog(raw)
	if err != nil {
		return 0, err
	}
	return len(parsed), mergeCatalogs(parsed)
}

// parseCatalog decodes and validates a catalog document.
func parseCatalog(raw []byte) (map[string][]map[string]string, error) {
	var doc map[string][]map[string]interface{}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("not a catalog file (want catalog: [{field: value}, ...]): %w", err)
	}
	out := make(map[string][]map[string]string, len(doc))
	for name, entries := range doc {
		cat := strings.ToLower(strings.TrimSpace(name))
		if !reCatalogName.MatchString(cat) {
			return nil, fmt.Errorf("catalog %q: name must match [a-z0-9_]+", name)
		}
		if _, dup := out[cat]; dup {
			return nil, fmt.Errorf("catalog %q is defined twice", cat)
		}
		if len(entries) == 0 {
			return nil, fmt.Errorf("catalog %q has no entries", cat)
		}
		rows := make([]map[string]string, 0, len(entries))
		for i, e := range entries {
			if len(e) == 0 {
				return nil, fmt.Errorf("catalog %q: entry %d is empty", cat, i)
			}
			row := make(map[string]string, len(e))
			for k, v := range e {
				if v == nil {
					v = ""
				}
				row[strings.ToLower(k)] = fmt.Sprint(v)
			}
			rows = append(rows, row)
		}
		out[cat] = rows
	}
	return out, nil
}

// mergeCatalogs adds parsed catalogs. Nothing is merged when any catalog
// clashes with a different existing one.
func mergeCatalogs(parsed map[string][]map[string]string) error {
	names := make([]string, 0, len(parsed))
	for n := range parsed {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if existing, ok := catalogs[n]; ok && !reflect.DeepEqual(existing, parsed[n]) {
			return fmt.Errorf("catalog %q clashes with a different definition in an earlier --catalog file", n)
		}
	}
	for _, n := range names {
		catalogs[n] = parsed[n]
	}
	return nil
}

// rowCatalogs lists the catalogs a raw seed row draws from, sorted.
func rowCatalogs(raw map[string]string) []string {
	seen := map[string]bool{}
	for _, v := range raw {
		for _, m := range reRowToken.FindAllStringSubmatch(v, -1) {
			seen[strings.ToLower(m[1])] = true
		}
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// rowPicker hands out catalog entries for one table population: each entry at
// most once, in a deterministic per-population order, skipping entries whose
// name is already taken by an anchor row.
type rowPicker struct {
	f       *gofakeit.Faker
	exclude map[string]bool // lower-cased anchor names
	order   map[string][]int
	next    map[string]int
}

func newRowPicker(f *gofakeit.Faker, anchorNames map[string]bool) *rowPicker {
	return &rowPicker{f: f, exclude: anchorNames, order: map[string][]int{}, next: map[string]int{}}
}

// pick returns the next unused entry of catalog, or false when it is exhausted
// (or unknown).
func (p *rowPicker) pick(catalog string) (map[string]string, bool) {
	entries := catalogs[catalog]
	if len(entries) == 0 {
		return nil, false
	}
	order, ok := p.order[catalog]
	if !ok {
		order = make([]int, 0, len(entries))
		for i, e := range entries {
			if !p.exclude[strings.ToLower(e["name"])] {
				order = append(order, i)
			}
		}
		p.f.ShuffleAnySlice(order)
		p.order[catalog] = order
	}
	i := p.next[catalog]
	if i >= len(order) {
		return nil, false
	}
	p.next[catalog] = i + 1
	return entries[order[i]], true
}

// expandRowTokens replaces every {{row:...}} token in raw with the picked
// entries' fields. ok is false when a catalog the row needs is exhausted or
// unknown. A nil picker draws a single entry at random (no de-duplication).
func expandRowTokens(raw map[string]string, f *gofakeit.Faker, picker *rowPicker) (map[string]string, bool) {
	cats := rowCatalogs(raw)
	if len(cats) == 0 {
		return raw, true
	}
	chosen := make(map[string]map[string]string, len(cats))
	for _, c := range cats {
		if picker != nil {
			entry, ok := picker.pick(c)
			if !ok {
				return nil, false
			}
			chosen[c] = entry
			continue
		}
		entries := catalogs[c]
		if len(entries) == 0 {
			return nil, false
		}
		chosen[c] = entries[f.Number(0, len(entries)-1)]
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		out[k] = reRowToken.ReplaceAllStringFunc(v, func(tok string) string {
			m := reRowToken.FindStringSubmatch(tok)
			return chosen[strings.ToLower(m[1])][strings.ToLower(m[2])]
		})
	}
	return out, true
}
