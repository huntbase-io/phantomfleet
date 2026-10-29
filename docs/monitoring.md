# Monitoring and output modes

phantomfleet records the latency and outcome of every request it makes and can
report them in five ways, selected with `--mode`. The statistics are the same
in every mode; only the presentation changes.

## What is measured

Six operation types are tracked:

| Operation | Request |
|---|---|
| Enroll | Enrollment, at startup and on re-enrollment |
| Status | Status log posts |
| Result | Result log posts |
| Config | Config requests |
| Query Read | Distributed query reads |
| Query Write | Distributed query writes |

For each operation phantomfleet keeps a count, success and failure counts,
min/avg/max latency over the whole run, and p95/p99 latency over the most
recent 1000 requests. A request counts as successful when it completes with
HTTP 200. Per-URL totals (count, success, failure) are tracked as well.

Query Write latency is measured from the moment the query is picked up, so it
includes the time spent generating the answer (or running `osqueryi`), not just
the HTTP round trip.

## Modes

### `summary` (default)

Every `--summary-interval` seconds (default 30) a table is printed:

```
================================================================================
PHANTOMFLEET - PERFORMANCE SUMMARY
Uptime: 2m30s
================================================================================
Enroll       | Count:     50 | Success: 100.0% | Min:   45ms | Avg:   78ms | Max:  156ms | P95:  134ms | P99:  145ms
Status       | Count:    150 | Success: 100.0% | Min:   12ms | Avg:   23ms | Max:   89ms | P95:   45ms | P99:   67ms
Result       | Count:    150 | Success: 100.0% | Min:   15ms | Avg:   28ms | Max:   95ms | P95:   52ms | P99:   78ms
Config       | Count:    200 | Success: 100.0% | Min:   18ms | Avg:   31ms | Max:  102ms | P95:   58ms | P99:   85ms
Query Read   | Count:    250 | Success: 100.0% | Min:   22ms | Avg:   35ms | Max:  125ms | P95:   67ms | P99:   98ms
Query Write  | Count:     50 | Success: 100.0% | Min:   45ms | Avg:   89ms | Max:  234ms | P95:  156ms | P99:  198ms
================================================================================
URL STATISTICS - ABSOLUTE NUMBERS
================================================================================
...
```

(Numbers are illustrative.) Operations that have not happened yet are omitted.

### `quiet`

Startup lines only, then nothing. Use it for long or very large runs where you
watch the server rather than the client.

### `verbose`

One line per request with latency, outcome, node and URL, plus the full request
and response bodies. `-v` / `--verbose` forces this mode regardless of
`--mode`. Use it with a handful of nodes and short intervals when debugging:

```bash
phantomfleet --url ... --secret-file ... --nodes 3 --mode verbose \
  --status 5 --result 5 --config 10 --query 5
```

`enroll_secret` and `node_key` values are masked in this output, but verbose
logs still contain hostnames, queries and results, so review them before
sharing.

### `dashboard`

Clears the screen and repaints the statistics every 2 seconds. Run it in an
interactive terminal.

### `json`

Every `--summary-interval` seconds a pretty-printed JSON document is written
to stdout:

```json
{
  "operations": {
    "config": { "avg_ms": 31, "count": 200, "fail_count": 0, "max_ms": 102, "min_ms": 18, "p95_ms": 58, "p99_ms": 85, "success_count": 200, "success_rate": 100 },
    "enroll": { "...": "..." },
    "query_read": { "...": "..." },
    "query_write": { "...": "..." },
    "result": { "...": "..." },
    "status": { "...": "..." }
  },
  "timestamp": 1760000000,
  "uptime_seconds": 150.5,
  "urls": {
    "https://fleet.example.com/api/v1/osquery/config": { "count": 200, "fail_count": 0, "success_count": 200, "success_rate": 100 }
  }
}
```

Operation keys are `enroll`, `status`, `result`, `config`, `query_read` and
`query_write`.

stdout also carries startup lines and any error messages as plain text, and
each document spans several lines. To feed the documents to `jq`, keep only
the JSON blocks first:

```bash
phantomfleet ... --mode json \
  | sed -n '/^{/,/^}/p' \
  | jq '.operations.query_write.p95_ms'
```

## Errors

Whatever the mode, a non-200 response is printed to stdout together with its
body and appended to `http_errors.log` in the working directory (created with
mode 0600; `enroll_secret` and `node_key` values are masked). In the container
image the working directory is `/data`.
Connection errors are only printed in `verbose` mode, but they are always
counted as failures.

## Running large fleets

- Use `quiet` or `summary` with a longer `--summary-interval`; `verbose`
  output at thousands of nodes costs more than the requests.
- Each node runs four long-lived goroutines, one per request loop, plus one
  for each distributed read that returns queries (at most one at a time per
  node: a read that arrives while the previous write is still in flight is
  skipped), so memory grows with node count. Large populations (`--fake-results` on tables
  with high row counts) are built per query, per node.
- Each request loop starts at a random point in its first interval, so the
  fleet's requests are spread out rather than sent on the same tick.
- All nodes share one HTTP client, which opens at most 1,024 connections to
  a server host; requests beyond that wait for a free connection. Run several
  processes for more concurrent connections.
- Raise `--enroll-concurrency` to speed up cold starts, keeping in mind that
  the server sees that many enrollments at once.
- Keep `--state` enabled so restarts reuse existing enrollments instead of
  creating new hosts.
- Lengthen the intervals to model realistic agents. osquery's own defaults
  poll far less often than a stress test does.
- Watch success rates and p99 latency on the server side as well: phantomfleet
  only sees the client's view.
