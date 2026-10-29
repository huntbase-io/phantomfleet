package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/huntbase-io/phantomfleet/internal/host"
	"github.com/huntbase-io/phantomfleet/internal/protocol"
	"github.com/huntbase-io/phantomfleet/internal/stats"
	"github.com/huntbase-io/phantomfleet/internal/synth"
)

// discoveryFor is a copy of the synth test helper of the same name.
func discoveryFor(table string) string {
	return "SELECT 1 FROM osquery_registry WHERE active = true AND registry = 'table' AND name = '" + table + "'"
}

func TestDiscoveryQueriesGateTheirQueries(t *testing.T) {
	var (
		mu     sync.Mutex
		writes []protocol.QueryWriteRequest
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var got protocol.QueryWriteRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
		}
		mu.Lock()
		writes = append(writes, got)
		mu.Unlock()
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	urls, err := protocol.BuildEndpoints(srv.URL, protocol.FlavorGeneric, "", protocol.EndpointPaths{})
	if err != nil {
		t.Fatal(err)
	}
	node := host.Node{Name: "brisk-otter-01", Target: "ubuntu", Identifier: "l-1", Key: "k", IP: "10.1.2.3"}
	node.OS = synth.ProfileOS(node.Target)
	var nodeMu sync.Mutex
	queries := map[string]interface{}{
		"plain":      "SELECT pid, name FROM processes LIMIT 2",
		"kubequery":  "SELECT * FROM kubernetes_info",
		"present":    "SELECT name FROM deb_packages LIMIT 1",
		"no_battery": "SELECT * FROM battery",
		"fallback":   "SELECT path FROM mounts WHERE path = '/'",
		"opera":      "SELECT * FROM opera_extensions",
	}
	discovery := map[string]interface{}{
		"kubequery":  discoveryFor("kubernetes_info"),
		"present":    discoveryFor("deb_packages"),
		"no_battery": discoveryFor("battery"),
		"fallback":   "SELECT 1 WHERE NOT EXISTS (" + discoveryFor("disk_space") + ");",
		// A probe of the table itself fails on a host without it.
		"opera": "SELECT 1 FROM opera_extensions LIMIT 1",
	}
	queryWrite(protocol.NewHTTPClient(false, false), &node, &nodeMu, node, queries, discovery, urls, Config{FakeResults: true, OutputMode: stats.QuietMode})

	if len(writes) != 1 {
		t.Fatalf("got %d distributed writes, want one for the whole read", len(writes))
	}
	got := writes[0]
	for _, name := range []string{"plain", "present", "fallback"} {
		if _, ok := got.Queries[name]; !ok {
			t.Errorf("%s was not answered", name)
		}
	}
	for _, name := range []string{"kubequery", "no_battery", "opera"} {
		if _, ok := got.Queries[name]; ok {
			t.Errorf("%s was answered although its discovery query returned no rows", name)
		}
		if _, ok := got.Statuses[name]; ok {
			t.Errorf("%s has a status although it was skipped", name)
		}
	}
	if rows, _ := got.Queries["fallback"].([]interface{}); len(rows) != 1 {
		t.Errorf("mounts '/' rows = %v, want exactly one", got.Queries["fallback"])
	}
}

func TestRequestsIdentifyThemselvesAndDoNotSpoofByDefault(t *testing.T) {
	var ua, realIP []string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		ua = append(ua, r.Header.Get("User-Agent"))
		realIP = append(realIP, r.Header.Get("X-Real-IP"))
		mu.Unlock()
		_, _ = w.Write([]byte(`{"node_key": "k"}`))
	}))
	defer srv.Close()
	client := protocol.NewHTTPClient(false, false)
	client.SetUserAgent(protocol.UserAgent("dev"))
	node := host.Node{Name: "n", Target: "ubuntu", Identifier: "i", IP: "10.9.9.9"}
	enrollNode(client, node, "s", srv.URL, Config{OutputMode: stats.QuietMode})
	enrollNode(client, node, "s", srv.URL, Config{OutputMode: stats.QuietMode, SpoofRealIP: true})
	if !strings.HasPrefix(ua[0], "phantomfleet/") {
		t.Errorf("User-Agent = %q", ua[0])
	}
	if realIP[0] != "" {
		t.Errorf("X-Real-IP sent without --spoof-real-ip: %q", realIP[0])
	}
	if realIP[1] != "10.9.9.9" {
		t.Errorf("X-Real-IP with --spoof-real-ip = %q", realIP[1])
	}
}

func TestEnrollmentWaitsOutRateLimits(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		if n <= 2 {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`{"node_key": "fresh"}`))
	}))
	defer srv.Close()
	warned := 0
	key := enrollWithBackoff(t.Context(), protocol.NewHTTPClient(false, false), host.Node{Name: "n", Target: "ubuntu", Identifier: "i"}, "s", srv.URL, Config{OutputMode: stats.QuietMode}, func(time.Duration) { warned++ })
	if key != "fresh" || calls != 3 || warned != 2 {
		t.Fatalf("key %q after %d calls (%d throttle callbacks)", key, calls, warned)
	}
}

func TestSQLiteErrorsArePostedLikeOsquery(t *testing.T) {
	var got protocol.QueryWriteRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
		}
		_, _ = w.Write([]byte(`{"node_invalid": false}`))
	}))
	defer srv.Close()
	urls, err := protocol.BuildEndpoints(srv.URL, protocol.FlavorGeneric, "", protocol.EndpointPaths{})
	if err != nil {
		t.Fatal(err)
	}
	node := host.Node{Name: "ws", Target: "windows", Pinned: true, Key: "k", IP: "192.0.2.1"}
	var mu sync.Mutex
	cfg := Config{FakeResults: true, OutputMode: stats.QuietMode}
	queryWrite(protocol.NewHTTPClient(false, false), &node, &mu, node, map[string]interface{}{"q1": "WITH x AS (SELECT 1) SELECT * FROM x JOIN no_such_table_here"}, nil, urls, cfg)
	if got.Statuses["q1"] != 1 || !strings.Contains(got.Messages["q1"], "no_such_table_here") {
		t.Fatalf("status %d message %q", got.Statuses["q1"], got.Messages["q1"])
	}
	if rows, ok := got.Queries["q1"].([]interface{}); !ok || len(rows) != 0 {
		t.Fatalf("rows = %#v, want an empty list", got.Queries["q1"])
	}
}

func TestStartExclusiveSkipsWhileInFlight(t *testing.T) {
	var running atomic.Bool
	release := make(chan struct{})
	finished := make(chan struct{})
	var calls atomic.Int32
	if !startExclusive(&running, func() {
		calls.Add(1)
		<-release
		close(finished)
	}) {
		t.Fatal("first write did not start")
	}
	for i := 0; i < 5; i++ {
		if startExclusive(&running, func() { calls.Add(1) }) {
			t.Fatal("a second write started while the first was in flight")
		}
	}
	close(release)
	<-finished
	deadline := time.Now().Add(5 * time.Second)
	for running.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	done := make(chan struct{})
	if !startExclusive(&running, func() { calls.Add(1); close(done) }) {
		t.Fatal("a write did not start after the previous one finished")
	}
	<-done
	if n := calls.Load(); n != 2 {
		t.Fatalf("%d writes ran, want 2", n)
	}
}
