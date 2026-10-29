// Package agent runs the simulated fleet: enrollment, the per-node request
// loops, distributed query answers and the state file.
package agent

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/huntbase-io/phantomfleet/internal/host"
	"github.com/huntbase-io/phantomfleet/internal/protocol"
	"github.com/huntbase-io/phantomfleet/internal/stats"
	"github.com/huntbase-io/phantomfleet/internal/synth"
)

// enrollNode enrolls a node and returns the node key
func enrollNode(client *protocol.HTTPClient, node host.Node, secret string, enrollURL string, config Config) string {
	key, _ := enrollOnce(client, node, secret, enrollURL, config)
	return key
}

// enrollOnce makes one enrollment request. It returns the new node key (or the
// node's old one on failure) and, when the server throttled the request (HTTP
// 429/503), how long to wait before trying again.
func enrollOnce(client *protocol.HTTPClient, node host.Node, secret string, enrollURL string, config Config) (string, time.Duration) {
	start := time.Now()
	headers := nodeHeaders(node, config)
	data := synth.EnrollRequest(node, secret)

	code, resp, wait, err := client.PostWithRetryAfter(enrollURL, data, headers)
	requestTime := time.Since(start)

	success := err == nil && code == 200
	stats.Log(stats.EnrollOp, node.Name, enrollURL, requestTime, success, config.OutputMode)

	if err != nil {
		if config.OutputMode == stats.VerboseMode {
			fmt.Printf("HTTP request failed: %v\n", err)
		}
		return node.Key, 0
	}

	if code != 200 {
		if config.OutputMode == stats.VerboseMode {
			fmt.Printf("HTTP %d with %s\n", code, enrollURL)
		}
		if protocol.Throttled(code) {
			if wait == 0 {
				wait = 5 * time.Second
			}
			return node.Key, wait
		}
		return node.Key, 0
	}

	if nodeKey, ok := resp["node_key"].(string); ok {
		return nodeKey, 0
	}

	return node.Key, 0
}

// enrollWithBackoff enrolls a node at startup, waiting out the server's rate
// limiting (HTTP 429/503 with Retry-After) as osquery does, until it gets an
// answer or ctx is canceled. throttledOnce is called the first time any
// node is throttled.
func enrollWithBackoff(ctx context.Context, client *protocol.HTTPClient, node host.Node, secret, enrollURL string, config Config, throttledOnce func(time.Duration)) string {
	for {
		key, wait := enrollOnce(client, node, secret, enrollURL, config)
		if wait == 0 {
			return key
		}
		throttledOnce(wait)
		select {
		case <-ctx.Done():
			return key
		case <-time.After(wait):
		}
	}
}

// nodeHeaders are the extra request headers for node. With --spoof-real-ip
// they carry the node's simulated IP in X-Real-IP, which servers that trust
// the header (directly or behind a proxy) record as the host's address. Off
// by default: a server should only record a fake source address when its
// operator asked for one.
func nodeHeaders(node host.Node, config Config) map[string]string {
	if !config.SpoofRealIP || node.IP == "" {
		return nil
	}
	return map[string]string{"X-Real-IP": node.IP}
}

// nodeInvalid reports whether the server rejected a node's key. osquery
// re-enrolls whenever a response carries node_invalid, whatever the HTTP status:
// osctrl answers 200 with node_invalid, Fleet answers 401 (with node_invalid in
// the body). A bare 401 is treated the same way.
func nodeInvalid(code int, resp map[string]interface{}) bool {
	if v, ok := resp["node_invalid"].(bool); ok && v {
		return true
	}
	return code == http.StatusUnauthorized
}

// snapshot copies node under its lock so a request is built from a consistent
// identity and key while another loop may be re-enrolling it.
func snapshot(node *host.Node, mu *sync.Mutex) host.Node {
	mu.Lock()
	defer mu.Unlock()
	return *node
}

// reenroll replaces node's key after the server rejected staleKey. All four
// request loops of a node can see the same rejection, so only the first one to
// get the lock enrolls; the others find the key already changed and skip.
func reenroll(client *protocol.HTTPClient, node *host.Node, mu *sync.Mutex, staleKey, secret, enrollURL string, config Config) {
	mu.Lock()
	defer mu.Unlock()
	if node.Key != staleKey {
		return
	}
	if config.OutputMode == stats.VerboseMode {
		fmt.Printf("Node key rejected for %s, re-enrolling\n", node.Name)
	}
	node.Key = enrollNode(client, *node, secret, enrollURL, config)
}

// pollLoop posts build(node) to url every interval until ctx is done. It records
// the operation, re-enrolls the node when the server rejects its key, and hands
// successful responses to onOK (which may be nil).
func pollLoop(ctx context.Context, client *protocol.HTTPClient, node *host.Node, mu *sync.Mutex, op stats.OperationType, url string, interval time.Duration,
	build func(host.Node) interface{}, onOK func(host.Node, map[string]interface{}), urls map[string]string, secret string, config Config) {
	// Start at a random point in the first interval, as a real fleet's hosts
	// do, rather than every node hitting the server on the same tick.
	// #nosec G404 -- scheduling jitter, not security-sensitive.
	select {
	case <-ctx.Done():
		return
	case <-time.After(time.Duration(rand.Int63n(int64(interval)))):
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n := snapshot(node, mu)
			start := time.Now()
			code, resp, err := client.Post(url, build(n), nodeHeaders(n, config))
			requestTime := time.Since(start)

			success := err == nil && code == http.StatusOK
			stats.Log(op, n.Name, url, requestTime, success, config.OutputMode)

			if err != nil {
				if config.OutputMode == stats.VerboseMode {
					fmt.Printf("HTTP request failed: %v\n", err)
				}
				continue
			}
			if nodeInvalid(code, resp) {
				reenroll(client, node, mu, n.Key, secret, urls[protocol.EndpointEnroll], config)
				continue
			}
			if code != http.StatusOK {
				if config.OutputMode == stats.VerboseMode {
					fmt.Printf("HTTP %d with %s\n", code, url)
				}
				continue
			}
			if onOK != nil {
				onOK(n, resp)
			}
		}
	}
}

// runNode starts the four request loops (status log, result log, config,
// distributed read) for one node.
func runNode(ctx context.Context, client *protocol.HTTPClient, node *host.Node, mu *sync.Mutex, urls map[string]string, config Config) {
	secs := func(n int) time.Duration { return time.Duration(n) * time.Second }
	secret := config.Secret
	var writing atomic.Bool // a distributed write is in flight for this node

	go pollLoop(ctx, client, node, mu, stats.StatusOp, urls[protocol.EndpointLog], secs(config.StatusInterval),
		func(n host.Node) interface{} { return protocol.NewStatusLog(n) }, nil, urls, secret, config)
	go pollLoop(ctx, client, node, mu, stats.ResultOp, urls[protocol.EndpointLog], secs(config.ResultInterval),
		func(n host.Node) interface{} { return protocol.NewResultLog(n) }, nil, urls, secret, config)
	go pollLoop(ctx, client, node, mu, stats.ConfigOp, urls[protocol.EndpointConfig], secs(config.ConfigInterval),
		func(n host.Node) interface{} { return protocol.NewConfigRequest(n.Key) }, nil, urls, secret, config)
	go pollLoop(ctx, client, node, mu, stats.QueryReadOp, urls[protocol.EndpointRead], secs(config.QueryInterval),
		func(n host.Node) interface{} { return protocol.NewQueryReadRequest(n.Key) },
		func(n host.Node, resp map[string]interface{}) {
			queries, _ := resp["queries"].(map[string]interface{})
			if len(queries) == 0 {
				return
			}
			discovery, _ := resp["discovery"].(map[string]interface{})
			started := startExclusive(&writing, func() {
				queryWrite(client, node, mu, n, queries, discovery, urls, config)
			})
			if !started && config.Explain {
				fmt.Printf("[explain] %s skipped a distributed read's queries: the previous write is still in flight\n", n.Name)
			}
		}, urls, secret, config)
}

// startExclusive runs fn in a new goroutine unless the previous one started
// through the same flag is still running, and reports whether it started fn.
// osquery reads, answers and writes serially: while a write is in flight the
// server still lists the same queries as pending, so answering them again
// would post duplicate results (and pile up goroutines against a slow
// server). The skipped queries are read again on the next tick.
func startExclusive(running *atomic.Bool, fn func()) bool {
	if !running.CompareAndSwap(false, true) {
		return false
	}
	go func() {
		defer running.Store(false)
		fn()
	}()
	return true
}

// queryResult is one distributed query's answer as osquery reports it.
type queryResult struct {
	rows    []map[string]interface{}
	status  int
	message string
}

// answerQuery answers one distributed query for node, the same way for a
// discovery query as for the query it guards. ok is false when the query
// cannot run at all (--fake-results=false and osqueryi failed).
func answerQuery(n host.Node, queryStr string, config Config) (queryResult, bool) {
	if config.FakeResults {
		// Skip osqueryi entirely and return synthetic, schema-aware rows.
		r := synth.Answer(n, queryStr)
		return queryResult{rows: r.Rows, status: r.Status, message: r.Message}, true
	}
	res := queryResult{}
	rows, err := executeOSQuery(queryStr)
	if err != nil {
		if config.OutputMode == stats.VerboseMode {
			fmt.Printf("Failed to execute osquery: %v\n", err)
		}
		return res, false
	}
	res.rows = rows
	if res.rows == nil {
		res.rows = []map[string]interface{}{}
	}
	return res, true
}

// discovered reports whether a query's discovery query (if any) lets it run.
// As in osquery, a query is skipped, and not reported at all, when its
// discovery query returns no rows or fails.
func discovered(n host.Node, name string, discovery map[string]interface{}, config Config) bool {
	raw, ok := discovery[name]
	if !ok {
		return true
	}
	q, ok := raw.(string)
	if !ok || strings.TrimSpace(q) == "" {
		return true
	}
	res, ok := answerQuery(n, q, config)
	return ok && res.status == 0 && len(res.rows) > 0
}

// queryWrite answers one distributed read's queries and reports them in a
// single distributed write, as osquery does. Queries whose discovery query
// returns nothing are left out.
func queryWrite(client *protocol.HTTPClient, node *host.Node, mu *sync.Mutex, n host.Node, queries, discovery map[string]interface{}, urls map[string]string, config Config) {
	writeURL := urls[protocol.EndpointWrite]
	start := time.Now()

	data := protocol.QueryWriteRequest{
		NodeKey:  n.Key,
		Queries:  make(map[string]interface{}, len(queries)),
		Statuses: make(map[string]int, len(queries)),
		Messages: make(map[string]string, len(queries)),
	}
	for queryName, query := range queries {
		queryStr, ok := query.(string)
		if !ok {
			if config.OutputMode == stats.VerboseMode {
				fmt.Printf("Invalid query format for %s\n", queryName)
			}
			continue
		}
		if !discovered(n, queryName, discovery, config) {
			if config.Explain {
				fmt.Printf("[explain] %s skipped %s: discovery returned no rows\n", n.Name, queryName)
			}
			continue
		}
		res, ok := answerQuery(n, queryStr, config)
		if !ok {
			continue
		}
		data.Queries[queryName] = res.rows
		data.Statuses[queryName] = res.status
		data.Messages[queryName] = res.message
	}
	if len(data.Queries) == 0 {
		return
	}

	code, resp, err := client.Post(writeURL, data, nodeHeaders(n, config))
	requestTime := time.Since(start)

	success := err == nil && code == 200
	stats.Log(stats.QueryWriteOp, n.Name, writeURL, requestTime, success, config.OutputMode)

	if err != nil {
		if config.OutputMode == stats.VerboseMode {
			fmt.Printf("HTTP request failed: %v\n", err)
		}
		return
	}

	if nodeInvalid(code, resp) {
		reenroll(client, node, mu, n.Key, config.Secret, urls[protocol.EndpointEnroll], config)
		return
	}
	if code != http.StatusOK {
		if config.OutputMode == stats.VerboseMode {
			fmt.Printf("HTTP %d with %s\n", code, writeURL)
		}
		return
	}

	if config.OutputMode == stats.VerboseMode && client.Debug() {
		fmt.Printf("%s\n", protocol.RedactedIndent(resp))
	}
}
