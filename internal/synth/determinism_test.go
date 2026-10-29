package synth

import (
	"encoding/json"
	"sort"
	"testing"
	"time"
)

// TestSameSeedSameAnswers loads the Example Corp fleet twice from a fresh
// state in one process and requires byte-identical answers: values are
// drawn from seeded fakers, so nothing may depend on Go's map order.
func TestSameSeedSameAnswers(t *testing.T) {
	fixed := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	seedNow = func() time.Time { return fixed }
	t.Cleanup(func() { seedNow = time.Now })

	queries := []string{
		"SELECT * FROM processes",
		"SELECT * FROM deb_packages",
		"SELECT * FROM services",
		"SELECT * FROM scheduled_tasks",
		"SELECT * FROM apps",
		"SELECT name, version FROM deb_packages WHERE name LIKE 'lib%'",
		"SELECT p.name, p.cmdline, u.username FROM processes p JOIN users u ON p.uid = u.uid",
	}
	run := func() []byte {
		var out []byte
		t.Run("load", func(t *testing.T) {
			hosts := loadExampleCorp(t)
			names := make([]string, 0, len(hosts))
			for n := range hosts {
				names = append(names, n)
			}
			sort.Strings(names)
			answers := map[string]map[string]Result{}
			for _, name := range names {
				answers[name] = map[string]Result{}
				for _, q := range queries {
					answers[name][q] = Answer(hosts[name], q)
				}
			}
			b, err := json.Marshal(answers)
			if err != nil {
				t.Fatal(err)
			}
			out = b
		})
		return out
	}
	first, second := run(), run()
	if len(first) == 0 || string(first) != string(second) {
		t.Fatalf("answers differ between two loads of the same seeds (%d and %d bytes)", len(first), len(second))
	}
}
