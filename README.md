<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.svg">
    <img src="docs/assets/logo-light.svg" alt="Phantom Fleet logo" width="96" height="96">
  </picture>
</p>

<h1 align="center">phantomfleet</h1>

**A synthetic osquery fleet that enrolls into osquery TLS servers such as
osctrl and Fleet and answers distributed queries with plausible,
schema-shaped rows.**

phantomfleet simulates a fleet of osquery hosts from a single process. Each simulated host enrolls with an enroll secret, polls for config,
posts status and result logs, and picks up distributed (ad-hoc) queries over
the osquery TLS protocol, the way `osqueryd` does. No osquery binary is needed:
every query is answered with plausible rows built from
the osquery table schema, curated per-platform seed data and per-table row
counts.

Use it for:

- **Demos**: a populated console with named hosts, believable inventories and
  a story to dig into, without touching real endpoints.
- **Integration testing**: exercise enrollment, re-enrollment, config, logging
  and distributed query flows of an osquery TLS server or anything built on it.
- **Query and content development**: run the queries you are writing against a
  mixed Linux, macOS and Windows fleet and get rows back in the right shape.
- **Light load generation**: many goroutine-driven nodes per process (see [Scale](#scale)) with latency
  statistics per operation and per endpoint.

It works with [osctrl](https://github.com/jmpsec/osctrl) out of the box
(`--flavor osctrl`, the default) and has basic support for servers that use
osquery's standard TLS endpoint paths, such as [Fleet](https://fleetdm.com)
(`--flavor generic`); see [Tested with](#tested-with) for what was verified
and the known gaps.

phantomfleet is maintained by [Huntbase](https://github.com/huntbase-io). It
grew out of the `fake_news` load-testing tool in osctrl; see
[Credits](#credits).

## Responsible use

phantomfleet is for testing and demos. Point it only at osquery servers you
operate or have written permission to test, preferably non-production ones.

- Don't use it to impersonate real hosts. A nodes file can pin any hostname,
  UUID or serial; use invented ones.
- Every request carries
  `User-Agent: phantomfleet/<version> (+https://github.com/huntbase-io/phantomfleet)`,
  so server operators can recognise, filter or block simulated fleets.
- Simulated nodes don't claim source addresses unless you ask:
  `--spoof-real-ip` (off by default) sends each node's simulated private IP
  in `X-Real-IP`.
- A fleet of more than 1,000 nodes (random, pinned or resumed from the state
  file) needs `--allow-large-fleet`. This guards against typos; it is not a
  limit.

See [SECURITY.md](SECURITY.md) for the details.

## What makes it different

Most osquery load generators replay a fixed payload. phantomfleet is built to
be *queried*:

- **Any table, any query.** The embedded osquery 5.24.0 schema (292 tables) means a
  query against any core table returns rows with the right column names and
  value types, even for tables nobody wrote seed data for.
- **Curated where it matters.** Seed YAML per platform (`linux`, `darwin`,
  `windows`, plus a shared base) makes `os_version`, `processes`, `users`,
  packages, services, persistence and network tables look like the OS they
  claim to be.
- **Realistic volume.** `rowcounts.yaml` gives each table a `[min, max]` row
  count, so `processes` returns a few hundred rows and `os_version` returns one.
- **Queries are evaluated, approximately.** WHERE filters, `count(*)`, LIMIT,
  scalar subqueries and (for pinned hosts) equality joins operate on each
  host's data. `--explain` shows how each query was broken down.
- **Stable, consistent hosts.** A nodes file pins hostnames, platforms, IPs,
  OS and hardware, and derives deterministic UUIDs, so the server keeps the
  same hosts across restarts and identity columns agree across tables.
- **A ready-made sample estate.** [Example Corp](examples/examplecorp/) is a
  15-host fictional company with vulnerable software and an intrusion story
  baked into its seed data.

## Quick start

You need a reachable osquery TLS server and its enroll secret. To try it
without one, start a local server first: see [Try it locally](#try-it-locally).

### Install

```bash
# Go toolchain (Go 1.26+)
go install github.com/huntbase-io/phantomfleet@latest

# Container image
docker pull ghcr.io/huntbase-io/phantomfleet:latest

# From source
git clone https://github.com/huntbase-io/phantomfleet.git
cd phantomfleet
go build -o phantomfleet .
```

Prebuilt binaries are attached to each
[GitHub release](https://github.com/huntbase-io/phantomfleet/releases).

### osctrl

osctrl scopes its TLS endpoints by environment, so `--env` (the environment
UUID) is required. Endpoints resolve to
`<url>/<env>/{enroll,config,log,read,write}`; a `--url` that already ends in
`/<env>` is accepted as-is.

```bash
export PHANTOMFLEET_SECRET="$ENROLL_SECRET"   # or --secret-file <file>
phantomfleet \
  --url https://osctrl-tls.example.com \
  --env 00000000-0000-0000-0000-000000000000 \
  --nodes 50
```

### Fleet and other standard servers

`--flavor generic` uses osquery's default TLS endpoint paths and needs no
`--env`:

| Endpoint | Path |
|---|---|
| enroll | `/api/v1/osquery/enroll` |
| config | `/api/v1/osquery/config` |
| log | `/api/v1/osquery/log` |
| distributed read | `/api/v1/osquery/distributed/read` |
| distributed write | `/api/v1/osquery/distributed/write` |

```bash
phantomfleet \
  --flavor generic \
  --url https://fleet.example.com \
  --secret-file ./enroll_secret \
  --nodes 50
```

If your server uses different paths, override any of them with
`--enroll-path`, `--config-path`, `--log-path`, `--read-path` and
`--write-path`. Overrides are appended to `--url` and work with either flavor;
with `--flavor osctrl`, an override replaces the whole `/<env>/<endpoint>`
path.

phantomfleet prints the resolved endpoint URLs at startup. Check them first if
enrollment fails.

### Try it locally

**Fleet** (Docker, about two minutes):

```bash
docker network create pf-lab
docker run -d --name pf-mysql --network pf-lab -e MYSQL_ROOT_PASSWORD=toor \
  -e MYSQL_DATABASE=fleet -e MYSQL_USER=fleet -e MYSQL_PASSWORD=fleet mysql:8.0.36
docker run -d --name pf-redis --network pf-lab redis:7.4-alpine
cat > fleet.env <<'ENV'
FLEET_MYSQL_ADDRESS=pf-mysql:3306
FLEET_MYSQL_USERNAME=fleet
FLEET_MYSQL_PASSWORD=fleet
FLEET_REDIS_ADDRESS=pf-redis:6379
FLEET_SERVER_TLS=false
ENV
sleep 30   # let MySQL initialise
docker run --rm --network pf-lab --env-file fleet.env fleetdm/fleet:v4.93.2 fleet prepare db
docker run -d --name pf-fleet --network pf-lab -p 127.0.0.1:8080:8080 --env-file fleet.env \
  fleetdm/fleet:v4.93.2 fleet serve
```

Open <http://127.0.0.1:8080>, create the admin account, copy the enroll
secret from **Hosts > Add hosts** into `./enroll_secret`, then:

```bash
phantomfleet --flavor generic --url http://127.0.0.1:8080 --secret-file ./enroll_secret --nodes 20
```

**osctrl** (built from source, Postgres and Redis in Docker):

```bash
git clone --depth 1 --branch v0.6.2 https://github.com/jmpsec/osctrl.git && cd osctrl
go build -o osctrl-tls ./cmd/tls && go build -o osctrl-cli ./cmd/cli
docker run -d --name pf-pg -p 127.0.0.1:5432:5432 -e POSTGRES_USER=osctrl \
  -e POSTGRES_PASSWORD=osctrl -e POSTGRES_DB=osctrl postgres:13.5-alpine
docker run -d --name pf-oredis -p 127.0.0.1:6379:6379 redis:6.2.6-alpine3.15
export DB_USER=osctrl DB_PASS=osctrl SERVICE_AUTH=none
./osctrl-tls &
./osctrl-cli --db env add --name dev --hostname 127.0.0.1
docker exec pf-pg psql -U osctrl -At -c "select uuid, secret from tls_environments where name = 'dev'"
```

Put the secret in `./enroll_secret` and run:

```bash
phantomfleet --url http://127.0.0.1:9000 --env <uuid> --secret-file ./enroll_secret --nodes 20
```

osctrl v0.6.2 allows 20 enrollments per minute per source address by
default; phantomfleet waits out the HTTP 429s, so larger fleets enroll at
that pace. For a lab server, raise `rateLimits.enroll.burst` in the
osctrl-tls YAML configuration (`--config --config-file tls.yml`).

### Tested with

| Server | Version | Result (2026-10-28, 20 nodes, random Linux, macOS and Windows) |
|---|---|---|
| osctrl | v0.6.2 (osctrl-tls, Postgres 13.5) | All nodes enrolled; status, result, config and distributed read 100% HTTP 2xx; 4 of 4 distributed queries completed 20/20 with no errors. |
| Fleet | v4.93.2 (MySQL 8.0.36, Redis 7.4) | All nodes enrolled and online with stable hostname, OS, osquery version, hardware, disk space and software inventory; distributed reads and writes 100% HTTP 2xx; no ingestion errors or warnings in Fleet's log over 2 minutes. |

Random nodes report osquery 5.20 to 5.24, and pinned nodes 5.24.0 unless
their nodes file sets `osquery_version`; the embedded schema is osquery
5.24.0.

**Fleet support is basic.** Known gaps:

- No scheduled queries, so Fleet's query reports and any pack results stay
  empty, and status and result logs are fixed placeholder records.
- No file carving.
- Fleet's own extension tables (fleetd/orbit) and the macadmins tables (`mdm`,
  `munki_info` and others) are not present, so the matching Fleet host
  details are empty. Discovery queries report them as missing, as osquery
  would.
- Policy and label queries get synthetic answers, so results are plausible
  but arbitrary.
- Software inventory pads Linux packages with generated names.
- Only enrollment with the global enroll secret was tested; not team
  secrets, MDM or Fleet Desktop.

### Docker

The image is distroless, runs as an unprivileged user and uses `/data` as its
working directory, so the state file lands on a volume. It contains no
`osqueryi`, so leave `--fake-results` on (the default).

```bash
docker run --rm -it \
  -v phantomfleet-data:/data \
  -e PHANTOMFLEET_SECRET="$ENROLL_SECRET" \
  ghcr.io/huntbase-io/phantomfleet:latest \
  --flavor generic \
  --url https://fleet.example.com \
  --nodes 100
```

To read the secret from a file instead, mount it and pass `--secret-file`.
The image runs as UID 65532, so the file must be readable by that user:

```bash
sudo chown 65532 enroll_secret && sudo chmod 0400 enroll_secret
docker run --rm -it \
  -v phantomfleet-data:/data \
  -v "$PWD/enroll_secret:/run/secrets/enroll_secret:ro" \
  ghcr.io/huntbase-io/phantomfleet:latest \
  --flavor generic \
  --url https://fleet.example.com \
  --secret-file /run/secrets/enroll_secret \
  --nodes 100
```

To use your own nodes file or seeds, bind-mount them and pass the in-container
paths. Compose files for running a fleet (including Example Corp) are in
[`deploy/`](deploy/).

### Example Corp in one command

```bash
phantomfleet \
  --url https://osctrl-tls.example.com --env "$ENV_UUID" --secret-file ./enroll_secret \
  --nodes-file examples/examplecorp/nodes.yaml \
  --seeds-dir examples/examplecorp/seeds \
  --state examplecorp_state.json
```

Then query the fleet from your server, for example
`SELECT name, status FROM services WHERE name = 'WinDefend';` against the
Windows hosts. See [examples/examplecorp/README.md](examples/examplecorp/README.md).

## Command-line flags

Single-letter aliases follow the long form. Flags accept one or two leading
dashes (Go `flag` package).

### Connection

| Flag | Default | Description |
|---|---|---|
| `--url`, `-u` | `http://localhost:9000/` | Base URL of the osquery TLS server. Must be an absolute `http(s)` URL. |
| `--flavor` | `osctrl` | `osctrl` (environment-scoped URLs, needs `--env`) or `generic` (standard osquery TLS paths). |
| `--env` | | Environment UUID. Required with `--flavor osctrl`, ignored with `generic`. |
| `--secret-file` | | File holding the enroll secret (surrounding whitespace is trimmed). |
| `--secret`, `-s` | | Enroll secret on the command line. Other local users can read it from the process list, so prefer `--secret-file` or `$PHANTOMFLEET_SECRET`. |
| `--enroll-path` | | Override the enroll endpoint path. |
| `--config-path` | | Override the config endpoint path. |
| `--log-path` | | Override the log endpoint path. |
| `--read-path` | | Override the distributed read endpoint path. |
| `--write-path` | | Override the distributed write endpoint path. |
| `--insecure` | `false` | Skip TLS certificate verification (self-signed lab servers only). |

An enroll secret is required. phantomfleet takes it from `--secret`, then
`--secret-file`, then the `PHANTOMFLEET_SECRET` environment variable; giving
both flags is an error. The Compose files in [`deploy/`](deploy/) pass it as
`PHANTOMFLEET_SECRET`.

### Fleet

| Flag | Default | Description |
|---|---|---|
| `--nodes`, `-n` | `5` | Number of nodes to simulate. With `--nodes-file`, only nodes beyond the pinned ones are random. |
| `--nodes-file` | | YAML file pinning node identities. See [Pinned nodes](#pinned-nodes). |
| `--state` | `phantomfleet_state.json` | JSON file used to persist and resume node identities and enrollment keys. Empty disables persistence. |
| `--enroll-concurrency` | `50` | Nodes enrolled in parallel at startup. |
| `--allow-large-fleet` | `false` | Allow a fleet of more than 1,000 nodes (counting random, pinned and resumed nodes). |
| `--spoof-real-ip` | `false` | Send each node's simulated IP in an `X-Real-IP` header. Only for servers you operate. |

### Traffic intervals (seconds)

| Flag | Default | Description |
|---|---|---|
| `--status`, `-S` | `60` | Status log posts. |
| `--result`, `-R` | `60` | Result log posts. |
| `--config`, `-c` | `45` | Config requests. |
| `--query`, `-q` | `30` | Distributed query reads. |

### Query answers

| Flag | Default | Description |
|---|---|---|
| `--fake-results`, `-f` | `true` | Answer distributed queries with synthetic rows. With `--fake-results=false`, queries run on the local machine through `osqueryi` (see [Security notes](#security-notes)). |
| `--seeds-dir` | | Directory of extra seed YAML layered over the built-in data. Repeatable: directories are layered in the order given. |
| `--extra-schema` | | JSON file of extension tables, in the shape of the embedded `osquery_schema.json`. Repeatable. See [Extension tables and catalogs](#extension-tables-and-catalogs). |
| `--catalog` | | YAML file of row catalogs for `{{row:<catalog>.<field>}}` seed tokens. Repeatable. |
| `--explain` | `false` | Log how each synthetic query is decomposed. |

### Output

| Flag | Default | Description |
|---|---|---|
| `--mode` | `summary` | `quiet`, `summary`, `verbose`, `dashboard` or `json`. |
| `--summary-interval` | `30` | Seconds between `summary` and `json` reports. |
| `--verbose`, `-v` | `false` | Per-request output including request and response bodies; forces `verbose` mode. |
| `--version` | | Print the version and exit. |

## How it works

For every node, four goroutines run on the configured intervals:

| Loop | Request | Notes |
|---|---|---|
| status | `log`, `log_type: status` | A fixed status line. |
| result | `log`, `log_type: result` | A fixed `uptime` result row with host decorations. |
| config | `config` | The response is not applied; phantomfleet does not run scheduled queries. |
| query | distributed read | The returned queries are answered and posted in one distributed write, as osquery does. A query with a `discovery` query runs only if its discovery query returns rows. |

Requests carry
`User-Agent: phantomfleet/<version> (+https://github.com/huntbase-io/phantomfleet)`.
With `--spoof-real-ip`
they also carry the node's simulated IP in `X-Real-IP`. As with osquery, a response
carrying `"node_invalid": true` makes the node re-enroll, whatever the HTTP
status (osctrl answers 200, Fleet 401); a bare HTTP 401 is treated the same
way. A node re-enrolls once even when several of its request loops see the
rejection at the same time.

**Startup and state.** Nodes without a node key are enrolled at startup by a
bounded worker pool (`--enroll-concurrency`), with progress every 500 nodes.
Node identities and keys are written to the state file as soon as enrollment
completes, every 10 seconds after that, and on Ctrl-C or SIGTERM (so
`docker stop` keeps them too). They are resumed on the next run, so restarts
don't create new hosts on the server. If
the state holds fewer nodes than `--nodes`, the difference is generated and
enrolled; lowering `--nodes` keeps the extras (delete the state file to
shrink).

**Random nodes.** Without a nodes file, each node is Ubuntu, Windows or macOS
and reports the OS and hardware of that platform's seed profile (Ubuntu
24.04.3 LTS, Windows 11 Pro 24H2, macOS 15.6.1 by default) at enrollment and
in every answer. It gets a unique hostname such as `brisk-otter-07` (derived
from its UUID), a unique private address in `10.0.0.0/8`, an osquery version
from 5.20 to 5.24 and a random UUID. Their answers are still deterministic per node: the
same node gives the same answer to the same query, across restarts too, apart
from time-relative values.

## How synthetic results work

With `--fake-results`, a node never runs SQL. It builds a deterministic
**population** of rows for every table the query names, then **views** that
population through the query.

1. **Schema.** `osquery_schema.json` (embedded) lists every core osquery table
   with its columns and types. It decides which columns exist and supplies
   type-appropriate values for anything not seeded.
2. **Seeds.** The node's platform picks a seed profile: `darwin` for macOS,
   `windows` for Windows, `linux` for everything else (Ubuntu, CentOS, Debian,
   FreeBSD, and any other platform name). Seed rows come first in the
   population. Rows with only fixed values appear once (anchors such as
   pid 1 = `systemd`); rows containing generator tokens are templates that are
   cloned, with fresh values, to pad the table.
3. **Row counts.** `rowcounts.yaml` sets a `[min, max]` range per table
   (`default: [1, 8]` for the rest). Each node draws its own count, capped at
   5000. Padding clones seed templates if the table has any, otherwise it
   generates schema-typed values with name-based heuristics (pids, ports, IPs,
   MAC addresses, paths, hashes, timestamps, versions and so on).
4. **Consistency.** Identity-like columns never get random words on any node:
   `hostname`, `host`, `fqdn` carry the node's name; `computer_name`,
   `local_hostname`, `csname` and similar carry its short name; `uuid`,
   `host_uuid`, `hardware_uuid`, `host_identifier` carry its identifier. Pinned
   nodes go further: user-like columns report the host's `primary_user`, and
   hardware serials come from the nodes file.

Then the query is applied:

- **WHERE**: `=`, `==`, `!=`, `<>`, `<`, `>`, `<=`, `>=`, `LIKE`, `NOT LIKE`,
  `IN`, `NOT IN`, combined with `AND` and `OR`. Equality and `LIKE` are
  case-insensitive; ordering comparisons are numeric when both sides are
  numbers.
- **Aggregates**: `count(...)` returns the size of the filtered population.
  `sum`, `avg`, `min`, `max`, `total` and `group_concat` return a plausible
  number, not a computed one. Plain columns next to an aggregate take the
  first filtered row's value.
- **LIMIT n** caps the rows returned.
- **Projection**: `SELECT *` returns every schema and seed column. Explicit
  columns are labelled the way osquery labels them (`p.name` becomes `name`,
  `count(*)` stays `count(*)`, `AS` aliases are honoured).
- **Scalar subqueries** such as `(SELECT hostname FROM system_info) AS hostname`
  are answered separately and their first value is used.
- **Joins**: every table in `FROM`, `JOIN` and comma lists gets a population.
  For random nodes the populations are zip-merged row by row, so all joined
  columns are filled but `ON` is not evaluated. For pinned nodes, equality `ON`
  predicates in `INNER` and `LEFT` joins are evaluated against the curated
  data.
- **Unknown tables**: a statement that names a table the node doesn't have
  (in neither the embedded schema, the `--extra-schema` tables nor the
  platform's seeds, or a table of another platform, such as `services` on
  Linux) fails with status `1` and `no such table: <name>`, as on osquery.
  So does a discovery query that reads such a table, and the query it gates
  is skipped.

Every result is posted with status `0` (success), except statements on
tables the node doesn't have (above), statements that SQLite rejects (see
below) and queries the pattern answerer cannot handle, which get status `1`
and an error message.

### Real SQL for pinned hosts

A pinned host runs three kinds of statement for real, in an in-memory SQLite
database (pure Go, [`modernc.org/sqlite`](https://gitlab.com/cznic/sqlite)):
statements that start with `WITH`, statements that read an
[extension table](#extension-tables-and-catalogs), and statements that name a
table the host doesn't have (in neither the schema nor its platform's seeds),
which fail with `no such table: <name>` as they would on osquery. Every table the statement
names is loaded from the host's curated data, so CTEs, `CASE`, `COALESCE`,
`GROUP BY` and aggregate subqueries evaluate exactly. A table the host's
platform profile does not declare, with no identity or `_hosts` rows for it,
exists but is empty, which is osquery's `--enable_foreign` behaviour. A
statement SQLite cannot run is reported the osquery way: no rows, status `1`
and the error as the message. Only single `SELECT`/`WITH` statements are
accepted, each runs for at most 5 seconds, and results are capped at 5000
rows. Every other query keeps the pattern answerer above.

SQLite has osquery's extra SQL functions, with osquery's semantics:
`split`, `regex_split`, `regex_match`, `concat`, `concat_ws`, `inet_aton`,
`to_base64`, `from_base64`, `conditional_to_base64`, and the one-argument
`log` as the natural logarithm. The other osquery maths functions (`sqrt`,
`power`, `ceil`, `floor`, `cot`, ...) are SQLite's own, or osquery's where
SQLite lacks them. Regular expressions use Go's RE2 syntax, which has no
backreferences or lookaround, and patterns are limited to 256 bytes, as in
osquery.

### `--explain`

```
[explain] brisk-otter-07/linux [join] tables=processes(seeded),users(seeded) population=177 afterWHERE=177 :: SELECT p.name, u.username FROM processes p JOIN users u ON p.uid = u.uid
```

Each line shows the node, its seed profile, every table with its source
(`seeded`, `schema/random` or `unknown`), the population size and the row
count after WHERE.

See [docs/synthetic-results.md](docs/synthetic-results.md) for the details and
[Limitations](#limitations) for what is not supported.

## Seed data

Built-in seeds are embedded in the binary:

| File | Purpose |
|---|---|
| `internal/synth/osquery_schema.json` | Slimmed osquery schema (table to columns and types). |
| `internal/synth/rowcounts.yaml` | Per-table `[min, max]` row counts. |
| `internal/synth/seeds/all.yaml` | Cross-platform tables merged into every profile. |
| `internal/synth/seeds/linux.yaml`, `internal/synth/seeds/darwin.yaml`, `internal/synth/seeds/windows.yaml` | Platform profiles. A platform file that defines a table replaces that table from `all.yaml`. |

Seeded tables cover identity (`os_version`, `system_info`, `osquery_info`,
`kernel_info`, `uptime`), users and sessions (`users`, `logged_in_users`),
`processes` and `listening_ports`, inventory (`deb_packages`, `programs`,
`apps`, `homebrew_packages`, `chocolatey_packages`, `python_packages`,
`chrome_extensions`, `firefox_addons`, `browser_plugins`, `vscode_extensions`,
`usb_devices`), persistence (`crontab`, `authorized_keys`, `services`,
`scheduled_tasks`, `startup_items`, `launchd`, `autoexec`, `kernel_modules`,
`suid_bin`, `shell_history`), networking (`interface_addresses`) and Windows
`patches`. The built-in seeds and row counts name only core osquery tables;
data for extension tables goes in your own seeds (see
[Extension tables and catalogs](#extension-tables-and-catalogs)).

To add data without rebuilding, point `--seeds-dir` at a directory containing
any of `all.yaml`, `linux.yaml`, `darwin.yaml`, `windows.yaml` and
`rowcounts.yaml`. External rows are **appended** to the built-in tables; new
tables are created on demand. Repeat `--seeds-dir` to layer several
directories in order, for example a shared baseline under a per-fleet story:
`--seeds-dir baseline/ --seeds-dir fleet-a/`.

A seed file maps table names to lists of rows. Each value is a literal, a
`{{token}}`, or a mix of both:

```yaml
processes:
  - { pid: "1", name: systemd, path: /usr/lib/systemd/systemd, uid: "0" }   # anchor
  - pid: "{{int:300..65000}}"                                              # template
    name: "{{choice:nginx|redis-server|postgres|python3|node|java}}"
    path: "/usr/bin/{{word}}"
    uid: "{{int:0..1500}}"

services:
  # only reported by finance-ws-12; replaces the profile's WinDefend row there
  - { _hosts: finance-ws-12, _key: name, name: WinDefend, status: STOPPED }

_replace: [users]   # external files only: drop the built-in users rows first
patches: []         # declare a table with nothing to report
```

Tokens: `{{hostname}}`, `{{shorthost}}`, `{{ip}}`, `{{uuid}}`, `{{version}}`,
`{{username}}`, `{{ago:26h5m}}`, `{{int:MIN..MAX}}`, `{{float:MIN..MAX}}`,
`{{choice:a|b|c}}`, `{{ipv4}}`, `{{mac}}`, `{{uuid4}}`, `{{hex:N}}`, `{{word}}`,
`{{words}}`, `{{semver}}`, `{{bool}}`, `{{unixtime[:MIN..MAX]}}`, `{{date}}`.

The full format, including how `_hosts`, `_key` and `_replace` interact, is in
[docs/seeds.md](docs/seeds.md).

## Extension tables and catalogs

osquery extensions add tables the core schema doesn't have. Declare them with
`--extra-schema`, a JSON file in the same shape as the embedded schema:

```json
{"example_ext_downloads": [{"name": "ts", "type": "bigint"}, {"name": "user", "type": "text"}]}
```

Column types are `text`, `integer`, `bigint`, `unsigned_bigint` or `double`.
A table that already exists is an error unless the definition is identical.
Extension tables never get schema-generated values: a pinned host answers them
from its seed rows (through the SQLite engine), and a host with no seed rows,
like every random node, answers with no rows. Tables whose rows depend on the
query's inputs, such as a summary filtered by a threshold or the folders under a
given folder, are defined as SQL views in the seeds (`_views`), with the statement's
`column = value` constraints bound as `:column` parameters.

`--catalog` loads named lists of coherent records that seed templates draw
from with `{{row:<catalog>.<field>}}`, so padded rows look like real entries
rather than random words. No catalog is built in.

The full reference, with a runnable example in
[`examples/extension-tables/`](examples/extension-tables/), is
[docs/extensions.md](docs/extensions.md).

## Pinned nodes

By default every node is random. A nodes file (`--nodes-file`) pins them for a
stable, named fleet:

```yaml
namespace: 2b7c1e44-9d3a-5f1e-8c6b-4a0e9f3d7a11   # optional UUID for uuid_seed
nodes:
  - hostname: finance-ws-12.corp.example.com       # required
    platform: windows                              # required: seed profile + enrollment platform
    ip: 10.14.40.112
    uuid_seed: examplecorp/finance-ws-12           # or `uuid:` for an explicit identifier
    osquery_version: "5.24.0"                      # default 5.24.0
    primary_user: a.harper
    os: {name: Microsoft Windows 11 Enterprise, version: 10.0.22631, major: "10", minor: "0", patch: "0", build: "22631", platform: windows}
    hardware: {vendor: Dell Inc., model: Latitude 7440, serial: EXC7440A12, cpu_brand: "13th Gen Intel(R) Core(TM) i7-1365U", cpu_cores: 12, physical_memory: 17179869184}
```

- The host identifier is `uuid` if set, otherwise UUIDv5(`namespace`,
  `uuid_seed`), otherwise UUIDv5(`namespace`, `hostname`). It is the same on
  every run, so the server keeps the host. Duplicate identifiers are rejected.
- `os` and `hardware` are sent at enrollment and answer `os_version`,
  `system_info` and `osquery_info` for that host.
- A table the platform profile declares is answered from its seed rows only:
  padded by seed templates if it has any, never by schema-generated values,
  and columns a curated row omits are left empty. Answers stay consistent
  across tables, which is what makes real equality joins worthwhile.
- Pinned hosts keep their enrollment keys across restarts via `--state`.
- The fleet size is the larger of `--nodes` and the number of pinned
  nodes; any nodes beyond the pinned ones are random.

Full reference: [docs/nodes-file.md](docs/nodes-file.md).

## Output and monitoring

| Mode | Output |
|---|---|
| `quiet` | Startup lines only. |
| `summary` (default) | Every `--summary-interval` seconds: per-operation count, success rate, min/avg/max/p95/p99 latency, and per-URL totals. |
| `verbose` | One line per request, plus request and response bodies. |
| `dashboard` | Full-screen live view repainted every 2 seconds (needs a TTY). |
| `json` | The `summary` statistics as JSON every `--summary-interval` seconds. |

Any non-200 response is printed and appended to `http_errors.log` in the
working directory, in every mode. See [docs/monitoring.md](docs/monitoring.md)
for sample output and tips for large runs.

## Scale

Measured on 2026-10-29 with one phantomfleet process against a local osctrl
v0.6.2 (osctrl-tls, Postgres 13.5, Redis 6.2 in Docker) on an 8-core / 16-thread
Intel i7-10700K under WSL2. Default intervals (status and result 60 s, config
45 s, distributed read 30 s), random nodes, osctrl's enroll rate limit raised
for the run. CPU and memory are for the phantomfleet process over a 2-minute
steady-state window after a 1-minute warm-up.

| Nodes | Enrollment | Requests/s | Failed requests | CPU (cores, avg) | RSS avg / peak |
|---:|---:|---:|---:|---:|---:|
| 500 | 1 s | 44 | 0 of 6,499 | 0.03 | 47 / 50 MB |
| 2,000 | 3 s | 178 | 0 of 25,998 | 0.09 | 124 / 135 MB |
| 5,000 | 6 s | 444 | 0 of 64,908 | 0.23 | 278 / 305 MB |

These runs carried no distributed queries; answering queries costs more CPU
per query (Fleet's detail queries, for example). Each node starts each of
its request loops at a random point in the loop's first interval, so a fleet
spreads its requests out instead of polling on the same tick. All nodes
share one HTTP client, which opens at most 1,024 connections to a server
host; requests beyond that wait for a free connection. The server, not
phantomfleet, is usually the limit: run more than 1,000 nodes only against a
server you operate, with `--allow-large-fleet`.

## Limitations

- **It is synthetic.** Rows are plausible, not true. Don't treat phantomfleet
  output as evidence about real systems, and keep simulated hosts out of
  production tenants where they could be mistaken for real ones.
- **SQL support is heuristic, not a SQL engine,** except for the statements a
  pinned host runs in SQLite (see [Real SQL for pinned
  hosts](#real-sql-for-pinned-hosts)). Other queries are taken apart with
  regular expressions. Not supported: `GROUP BY` (aggregates always return a
  single row), `ORDER BY`, `DISTINCT`, `HAVING`, parenthesised WHERE groups,
  `NOT`, `BETWEEN`, `IS NULL`, `RIGHT`/`FULL` joins, `USING`, non-equality join
  predicates, and CTEs or functions in the SELECT list (`lower(name)`
  returns the unmodified `name` value) over tables without seed data.
  Statements that use `EXISTS`, `pragma_*` functions or `osquery_registry`,
  and CTEs or computed SELECT lists over seeded tables, run in SQLite on every
  node. WHERE conditions the parser cannot read,
  conditions on columns a row doesn't have, and `IN (SELECT ...)` subqueries
  do not filter anything.
- **Joins are only real for pinned nodes.** Random nodes zip-merge joined
  tables, so related columns don't correspond.
- **Queries are bounded.** Only the first 8 tables in a FROM/JOIN clause are
  used, and a query's population (including a join result) is capped at 5000
  rows. Query text comes from the server, so these limits keep a hostile or
  careless query from exhausting the simulator's memory.
- **Invalid SQL mostly succeeds.** The pattern answerer gives almost every
  query rows and status `0`. Only statements that run in SQLite (see above)
  report SQL errors, and statements on tables a node doesn't have report
  `no such table`.
- **No scheduled queries.** The config response is ignored, and status and
  result logs are fixed placeholder records, not results of your packs.
- **Time-relative values** (`{{ago:...}}`) move with the clock; everything else
  is deterministic per node.
- **With `--fake-results=false`**, every node runs the query on the local
  machine through `osqueryi`, so the whole fleet reports the same host's data.
- **Three seed profiles.** Anything that is not macOS or Windows answers as
  Linux.

## Security notes

See also [Responsible use](#responsible-use).

- With `--fake-results=false`, the server you connect to can run arbitrary
  osquery SQL on the machine running phantomfleet. Leave it on (the default)
  unless you intend that.
- `--insecure` disables certificate verification for every request, including
  enrollment, which carries the enroll secret.
- The state file holds every node's key; keep it private. It is written
  atomically with mode 0600, and a state file that can't be parsed stops the
  run instead of being replaced.
- `--secret` puts the enroll secret in the process list. Use `--secret-file`
  or `PHANTOMFLEET_SECRET` on shared machines.
- Some server-supplied statements run in an in-memory SQLite database that
  holds only synthetic data: on pinned hosts, `WITH` statements and reads of
  extension or unknown tables; on every node, random ones included,
  statements that use `EXISTS`, `pragma_*` functions or `osquery_registry`,
  statements that read no table, and computed SELECT lists over seeded
  tables. Only a single `SELECT` or
  `WITH` statement is accepted: SQLite's own tokenizer finds where the
  first statement ends, and anything after it is refused, never run. The
  connection can't attach databases (so no `ATTACH` or `VACUUM INTO`),
  can't load extensions, runs the statement read-only (`query_only`), and
  caps value size, statement length, compound SELECTs and expression depth.
  Statements over 5 seconds are stopped.
- Error bodies in output and `http_errors.log` have the enroll secret and
  every node key masked, whatever their format. Redirects to another host or
  scheme are refused, since they would re-send credentials, and responses
  over 16 MiB are rejected.

See [SECURITY.md](SECURITY.md) for details and how to report vulnerabilities.

## Development

```bash
go test ./...
go build -o phantomfleet .
```

See [CONTRIBUTING.md](CONTRIBUTING.md), including how to refresh the embedded
osquery schema for a new osquery release.

## Credits

phantomfleet is derived from [osctrl](https://github.com/jmpsec/osctrl) by
Javier Marcos de Prado. It started as osctrl's `fake_news` load-testing tool,
which simulated osquery nodes enrolling into osctrl-tls; the enrollment and
request loops, statistics and output modes come from that work. Huntbase
extended it with schema-driven synthetic results, seeds, SQL decomposition,
pinned identities, generic server support and the Example Corp estate, then
extracted it into this project. Thank you to Javier and the osctrl
contributors.

The embedded table schema (`internal/synth/osquery_schema.json`,
`internal/synth/osquery_platforms.json`) is adapted from the
[osquery table schema 5.24.0](https://github.com/osquery/osquery-site/tree/source/src/data/osquery_schema_versions)
by the osquery authors, published in
[osquery/osquery-site](https://github.com/osquery/osquery-site) under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). It has been
modified: only table names, platforms and column names, types and hidden
flags are kept. See [NOTICE](NOTICE).

## Licence

MIT. Copyright (c) 2026 Huntbase Ltd and Copyright (c) 2020 Javier
Marcos de Prado; see [LICENSE](LICENSE) and [NOTICE](NOTICE). Release
archives and the container image (`/licenses`) include the licences of
third-party Go modules in `THIRD_PARTY_LICENSES/`.

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
