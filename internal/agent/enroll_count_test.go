package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/huntbase-io/phantomfleet/internal/host"
	"github.com/huntbase-io/phantomfleet/internal/protocol"
	"github.com/huntbase-io/phantomfleet/internal/stats"
	"github.com/huntbase-io/phantomfleet/internal/synth"
)

func enrollFixture(t *testing.T, handler http.HandlerFunc) (*protocol.HTTPClient, []host.Node, []int, string) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	nodes := host.RandomNodes(5, testRand(), nil, synth.ProfileOS)
	toEnroll := []int{0, 1, 2, 3, 4}
	return protocol.NewHTTPClient(false, false), nodes, toEnroll, srv.URL + "/enroll"
}

func TestEnrollNodesCountsSuccesses(t *testing.T) {
	var calls int64
	client, nodes, toEnroll, url := enrollFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt64(&calls, 1)%2 == 0 {
			http.Error(w, "nope", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"node_key": "k"}`))
	})
	got := enrollNodes(context.Background(), client, nodes, toEnroll, 1, url, Config{OutputMode: stats.QuietMode})
	if got != 3 {
		t.Fatalf("enrolled = %d, want 3 of 5 (every second attempt fails)", got)
	}
}

func TestInterruptedEnrollmentCountsNoFailures(t *testing.T) {
	// Every attempt is throttled; Ctrl-C arrives while the nodes wait.
	client, nodes, toEnroll, url := enrollFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if got := enrollNodes(ctx, client, nodes, toEnroll, 5, url, Config{OutputMode: stats.QuietMode}); got != 0 {
		t.Fatalf("enrolled = %d after every attempt failed, want 0", got)
	}
	for _, n := range nodes {
		if n.Key != "" {
			t.Fatalf("%s has a key", n.Name)
		}
	}
}
