# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-29

First public release. phantomfleet was extracted
from the `fake_news` load-testing tool in [osctrl](https://github.com/jmpsec/osctrl).

### Upgrade notes

These change behaviour for anyone who ran a pre-release build:

- A state file that exists but cannot be parsed now stops the run with an
  error, also with `--nodes-file`. Earlier builds generated and enrolled a
  new fleet over it. Fix or delete the file to continue; a missing state
  file still starts a new fleet.
- A redirect to another scheme or host, and a response body over 16 MiB,
  are now request errors.
- A node no longer answers a distributed read while its previous
  distributed write is still in flight: the read is skipped and the queries
  are read again on the next tick.
- `--allow-large-fleet` is checked against the final fleet size (random,
  pinned and resumed nodes), so a large state file or nodes file needs it
  too.
- Random nodes fail a statement that names a table they don't have, or
  another platform's table, with status 1 and `no such table: <name>`,
  instead of answering with made-up rows or no rows.
- A `--seeds-dir` file that can't be read or isn't valid YAML of the right
  shape is now a start-up error naming the file. It used to be skipped and
  still counted as loaded.
- Pinned nodes report osquery 5.24.0 by default, not 5.12.1.

### Added

- Simulated osquery hosts that enroll with an enroll secret and run status
  log, result log, config and distributed query loops on configurable
  intervals, with bounded parallel enrollment (`--enroll-concurrency`).
  Each loop starts at a random point in its first interval, and all nodes
  share one HTTP client with at most 1,024 connections per server host.
- Server flavors: `--flavor osctrl` (default; environment-scoped URLs with
  `--env`) and `--flavor generic` (osquery's standard
  `/api/v1/osquery/...` paths, for Fleet and other servers), plus per-endpoint
  path overrides (`--enroll-path`, `--config-path`, `--log-path`,
  `--read-path`, `--write-path`).
- Synthetic answers to distributed queries (`--fake-results`, on by default)
  built from the embedded osquery 5.24.0 schema, including hidden columns,
  per-platform seed profiles and per-table row counts, with heuristic WHERE,
  `count(*)`, LIMIT, projection, scalar subquery and join handling.
- `--explain` to log how each synthetic query is decomposed.
- Seed directories (`--seeds-dir`, repeatable and layered in the order
  given) over the built-in data, with `_hosts`, `_key` and `_replace` for
  host-specific and replacement rows.
- Pinned node identities (`--nodes-file`) with deterministic UUIDv5
  identifiers, pinned OS and hardware, primary users, curated tables and
  evaluated equality joins.
- Generic loaders, so a fleet can be described without changing code:
  - `--extra-schema <file>` (repeatable) declares osquery extension tables
    in the shape of the embedded schema. A table that clashes with a
    different existing definition is an error.
  - `_views` in seed files: extension tables computed per statement by a SQL
    `SELECT`, with the statement's `column = literal` constraints bound as
    `:column` parameters. Inside a view, the view's own table name reads that
    table's seed rows.
  - `--catalog <file>` (repeatable) loads row catalogs for the
    `{{row:<catalog>.<field>}}` seed token: every `row:` token of a seed row
    reads the same record, and padding uses each record at most once.
- An in-memory SQLite evaluator (`modernc.org/sqlite`, pure Go). Pinned
  hosts run `WITH` statements, reads of extension tables and statements on
  unknown tables in it. Every node runs `EXISTS`, `pragma_*` and
  `osquery_registry` statements, statements that read no table, and CTEs or
  computed SELECT lists over seeded tables in it, so server probes and
  computed values are exact. Errors are reported the osquery way: no rows,
  status 1 and SQLite's message.
- osquery's extra SQL functions in the evaluator, with osquery's semantics:
  `split`, `regex_split`, `regex_match`, `concat`, `concat_ws`, `inet_aton`,
  `to_base64`, `from_base64`, `conditional_to_base64`, the natural-log
  `log(x)`, and osquery's maths functions where SQLite lacks them (`cot`).
- Fleet discovery support: distributed reads honour the `discovery` map (a
  query runs only when its discovery query returns rows, as on osquery), all
  answers of one read go in a single distributed write, and
  `osquery_registry` lists the tables each node has, using per-table
  platform data from the osquery schema.
- Seeds for the root filesystem (`mounts`), the Windows system drive
  (`logical_drives`), Windows version registry values and a Windows
  `programs` list.
- Node state persistence and resume (`--state`, default
  `phantomfleet_state.json`), including scaling up a resumed fleet.
- Output modes `quiet`, `summary`, `verbose`, `dashboard` and `json` with
  per-operation and per-URL latency statistics.
- The enroll secret from `--secret-file <file>` or `PHANTOMFLEET_SECRET`,
  so it stays out of argv. The Compose files pass `PHANTOMFLEET_SECRET`.
- `--spoof-real-ip` (default off) to send each node's IP in `X-Real-IP`.
- `--allow-large-fleet`, required above 1,000 nodes.
- Requests send
  `User-Agent: phantomfleet/<version> (+https://github.com/huntbase-io/phantomfleet)`.
- Enrollment waits out HTTP 429/503 (honouring `Retry-After`).
- Examples: the fictional 15-host Example Corp fleet in
  `examples/examplecorp/` and a neutral extension-tables example in
  `examples/extension-tables/`, with Compose files in `deploy/`.
- `--version`, release binaries and a container image at
  `ghcr.io/huntbase-io/phantomfleet`. Release archives and the image
  (`/licenses`) include LICENSE, NOTICE and the licence and notice files of
  every linked Go module (`THIRD_PARTY_LICENSES/`).
- Documentation in `docs/`, `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1),
  `CONTRIBUTING.md` and `SECURITY.md`.

### Changed

- Renamed from `fake_news` to `phantomfleet`; the default state file is
  `phantomfleet_state.json` instead of `state.json`.
- `--fake-results` is on by default; pass `--fake-results=false` to answer
  queries with a local `osqueryi`.
- Nodes re-enroll when a response carries `node_invalid: true` at any HTTP
  status, or on a bare HTTP 401, so they recover on Fleet as well as osctrl.
  Each node re-enrolls once, even when several of its loops see the
  rejection together.
- State is saved right after enrollment and on Ctrl-C/SIGTERM, not only every
  10 seconds.
- Random nodes have exactly the tables osquery has on their platform, plus
  the `--extra-schema` tables (which answer no rows) and seeded tables. A
  statement on any other table fails with `no such table: <name>`, as on
  osquery, so a discovery query that probes it fails and its query is
  skipped. Pinned hosts fail statements on unknown tables the same way and
  answer another platform's table with no rows (osquery's
  `--enable_foreign`).
- PAN-OS appliances (`panos`) answer no distro package tables unless rows
  are seeded for that host.
- Random nodes: hostnames are `adjective-noun-NN`, derived from the node's
  UUID and unique within a run; addresses are unique and private
  (`10.0.0.0/8`); platforms are Ubuntu, Windows and macOS, enrolling with the
  OS and hardware of their seed profile; osquery versions are 5.20 to 5.24.
  Pinned nodes default to osquery 5.24.0.
- Schema-generated path, command line and description values come from
  per-platform binaries and neutral text instead of dictionary words.
- Built-in seed OS versions are current (Ubuntu 24.04.3 LTS, Windows 11 Pro
  24H2, macOS 15.6.1), built-in hardware serials are obviously synthetic
  (`PF-<hex>`), and the built-in seeds no longer include tables that osquery
  doesn't have (`cve`, `open_files`, `listening_ports_open`).
- Loader errors stop phantomfleet at start-up with an error naming the file:
  a file that can't be read or parsed, a schema clash, or a malformed
  `_views` entry. A missing seed directory is still not an error.
- Non-positive intervals and negative `--nodes` are rejected at start-up.
- `go install …@version` builds report the module version instead of `dev`.
- Go sources live under `internal/` (`cli`, `agent`, `synth`, `protocol`,
  `host`, `stats`) behind a thin `main.go`; flags, output, the state file
  and the install path are unchanged.

### Fixed

- A join with a table that has no rows no longer panics with a division by
  zero, which stopped every simulated node in the process. A query the
  answerer cannot handle now fails that query (status 1) instead.
- With the same seed, generated values no longer move between runs: seed
  row columns are resolved, and seed-only columns added, in sorted order.
- `CAST(split(version, '.', 0) AS INTEGER)` and other queries using
  osquery's SQL functions no longer fail with `no such function`.
- Ctrl-C during enrollment reports how many nodes enrolled, not how many
  were attempted.

### Security

- The SQLite evaluator runs exactly one read-only statement: SQLite's own
  tokenizer finds where the first statement ends and anything after it is
  refused. The connection is in memory and in defensive mode, can't attach
  databases or load extensions, runs the statement with `query_only`, and
  caps value size, statement length, compound SELECTs and expression depth.
  Statements are stopped after 5 seconds and results capped at 5000 rows.
- The Go toolchain is pinned to a patched release, and CI runs govulncheck.
- Enroll secrets and node keys are masked in all printed and logged output,
  including error bodies that echo a request.
- Redirects to another scheme or host are refused, so a credential is never
  re-sent elsewhere; response bodies are capped at 16 MiB.
- The state file is written atomically with mode 0600, and a corrupt state
  file stops the run instead of being replaced.
- `--allow-large-fleet` is checked against the final fleet size.
- A node never has two distributed writes in flight: an overlapping read is
  skipped.
- A warning is printed at start-up when `--fake-results=false`, since the
  server can then run osquery SQL on the local machine.

[Unreleased]: https://github.com/huntbase-io/phantomfleet/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/huntbase-io/phantomfleet/releases/tag/v0.1.0
