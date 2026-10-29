package synth

import (
	"fmt"
	"strings"
	"testing"
)

// Query text comes from the server, so a hostile query must not be able to make
// the simulator build an unbounded population.
func TestHostileQueriesAreBounded(t *testing.T) {
	var many []string
	for i := 0; i < 50; i++ {
		many = append(many, fmt.Sprintf("t%d", i))
	}
	q := "SELECT * FROM " + strings.Join(many, ", ")
	if got := len(extractTables(q)); got > maxQueryTables {
		t.Fatalf("extractTables kept %d tables, cap is %d", got, maxQueryTables)
	}
	if got := len(parseJoins(q)); got > maxQueryTables {
		t.Fatalf("parseJoins kept %d terms, cap is %d", got, maxQueryTables)
	}

	// An ON predicate over a column neither side has always matches, so this is
	// a 6-way cross product (8^6 = 262144 rows on this host) without the cap.
	node := loadExampleCorp(t)["dc-01"]
	cross := "SELECT * FROM processes a"
	for _, alias := range []string{"b", "c", "d", "e", "f"} {
		cross += fmt.Sprintf(" JOIN processes %s ON %s.nope = a.nope", alias, alias)
	}
	rows, _, ok := buildJoinedPopulation(node, cross, extractTables(cross))
	if !ok {
		t.Fatal("cross join produced no population")
	}
	if len(rows) > maxPopulation {
		t.Fatalf("joined population %d exceeds cap %d", len(rows), maxPopulation)
	}
}
