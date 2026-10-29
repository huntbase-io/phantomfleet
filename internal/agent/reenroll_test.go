package agent

import (
	"context"
	"encoding/json"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/huntbase-io/phantomfleet/internal/host"
	"github.com/huntbase-io/phantomfleet/internal/protocol"
	"github.com/huntbase-io/phantomfleet/internal/stats"
	"github.com/huntbase-io/phantomfleet/internal/synth"
)

func TestNodeInvalid(t *testing.T) {
	cases := []struct {
		name string
		code int
		resp map[string]interface{}
		want bool
	}{
		{"osctrl 200 with node_invalid", 200, map[string]interface{}{"node_invalid": true}, true},
		{"fleet 401 with node_invalid", 401, map[string]interface{}{"node_invalid": true, "error": "invalid node key"}, true},
		{"bare 401", 401, nil, true},
		{"ok", 200, map[string]interface{}{"node_invalid": false}, false},
		{"server error", 500, nil, false},
	}
	for _, c := range cases {
		if got := nodeInvalid(c.code, c.resp); got != c.want {
			t.Errorf("%s: nodeInvalid = %v, want %v", c.name, got, c.want)
		}
	}
}

// fleetLike answers like Fleet: 401 + node_invalid for any key but the one it
// issued, and a fresh key on enroll. It counts enrollments.
type fleetLike struct {
	enrolls int64
	key     atomic.Value
}

func (f *fleetLike) handler() http.Handler {
	mux := http.NewServeMux()
	reply := func(w http.ResponseWriter, code int, v interface{}) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("/api/v1/osquery/enroll", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&f.enrolls, 1)
		f.key.Store("fresh-key")
		reply(w, 200, map[string]interface{}{"node_key": "fresh-key"})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if k, _ := f.key.Load().(string); k == "" || body["node_key"] != k {
			reply(w, 401, map[string]interface{}{"error": "invalid node key", "node_invalid": true})
			return
		}
		reply(w, 200, map[string]interface{}{"node_invalid": false, "queries": map[string]interface{}{}})
	})
	return mux
}

func TestStaleKeyReenrollsOnceAgainstFleet(t *testing.T) {
	t.Chdir(t.TempDir()) // the client appends non-200 responses to ./http_errors.log
	f := &fleetLike{}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	urls, err := protocol.BuildEndpoints(srv.URL, protocol.FlavorGeneric, "", protocol.EndpointPaths{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Secret: "s", OutputMode: stats.QuietMode, StatusInterval: 1, ResultInterval: 1, ConfigInterval: 1, QueryInterval: 1}
	node := host.RandomNodes(1, rand.New(rand.NewSource(1)), nil, synth.ProfileOS)[0]
	node.Key = "stale-key"
	var mu sync.Mutex

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := protocol.NewHTTPClient(false, false)
	// All four loops hit the stale key at roughly the same moment.
	for _, op := range []stats.OperationType{stats.StatusOp, stats.ResultOp, stats.ConfigOp, stats.QueryReadOp} {
		go pollLoop(ctx, client, &node, &mu, op, urls[protocol.EndpointConfig], 20*time.Millisecond,
			func(n host.Node) interface{} { return protocol.NewConfigRequest(n.Key) }, nil, urls, cfg.Secret, cfg)
	}

	deadline := time.Now().Add(3 * time.Second)
	for snapshot(&node, &mu).Key != "fresh-key" {
		if time.Now().After(deadline) {
			t.Fatal("node never re-enrolled after 401 node_invalid")
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond) // let the other loops see the new key
	cancel()
	if n := atomic.LoadInt64(&f.enrolls); n != 1 {
		t.Fatalf("enrolled %d times, want exactly 1", n)
	}
}

func TestSaveStateWritesCurrentKeys(t *testing.T) {
	nodes := host.RandomNodes(3, rand.New(rand.NewSource(1)), nil, synth.ProfileOS)
	for i := range nodes {
		nodes[i].Key = "k" + nodes[i].Identifier
	}
	locks := make([]sync.Mutex, len(nodes))
	file := filepath.Join(t.TempDir(), "state.json")
	saveState(nodes, locks, file)
	got, err := host.LoadState(file)
	if err != nil || len(got) != 3 || got[2].Key != nodes[2].Key {
		t.Fatalf("round trip: %v %+v", err, got)
	}
	saveState(nodes, locks, "") // blank disables state; must not panic or write
}
