# Contributing to phantomfleet

Thanks for your interest. Bug reports, seed data, query-evaluation
improvements and docs fixes are all welcome.

## Before you start

- For anything bigger than a small fix, open an issue first so we can agree on
  the approach.
- Security issues: do not open a public issue; see [SECURITY.md](SECURITY.md).
- This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).
- Never commit real host data, credentials, enroll secrets, internal hostnames
  or IPs. Seed data and examples must be fictional (use `example.com`,
  `*.test`, `10.0.0.0/8` and documentation IP ranges).

## Development setup

You need Go 1.26 or newer (see `go.mod`) and, for linting,
[golangci-lint](https://golangci-lint.run/welcome/install/).

```bash
git clone https://github.com/huntbase-io/phantomfleet.git
cd phantomfleet
make all          # gofmt -s check, go vet, tests, build
```

Or without make:

```bash
gofmt -s -l .             # must print nothing
go vet ./...
go test -race ./...
golangci-lint run
go build -o phantomfleet .
```

`make help` lists the other targets (`lint`, `fmt`, `docker`, `snapshot`, ...).

To try a change end to end you need an osquery TLS server. A local osctrl or
Fleet in Docker works well; run phantomfleet against it with a few nodes,
`--mode verbose`, short intervals and `--explain`.

## Pull requests

- Keep each PR focused, with tests for behaviour changes; extend the existing
  `*_test.go` files where they cover the area.
- Run `gofmt -s`, `go vet`, the tests and `golangci-lint` before pushing; CI runs
  the same checks.
- Update the README or `docs/` when you change flags, seed syntax or query
  behaviour, and add an entry under `Unreleased` in
  [CHANGELOG.md](CHANGELOG.md).
- If you change the Example Corp nodes or seeds, keep `nodes.yaml` and the seed
  files consistent; the estate consistency tests will tell you if they drift.

## Code layout

The `phantomfleet` command is a thin `main.go` at the repository root; the
code lives in packages under `internal/`:

| Package | Contents |
|---|---|
| `internal/cli` | Flags, usage, validation and the enroll secret; calls `agent.Run`. |
| `internal/agent` | The fleet runner: enrollment, per-node request loops, distributed query answers (synthetic or via `osqueryi`) and the state file. |
| `internal/synth` | Synthetic answers: the embedded osquery schema, built-in seeds and row counts, the `--seeds-dir`, `--extra-schema` and `--catalog` loaders, the pattern answerer and SQLite evaluator, and node identity. |
| `internal/protocol` | osquery TLS wire types, request builders, endpoint URLs per `--flavor` and the HTTP client. |
| `internal/host` | The `Node` model, `--nodes-file` parsing, random node generation and the state file format. |
| `internal/stats` | Latency statistics and the summary, dashboard and JSON reports. |

Imports only point down this table: `cli` uses `agent`, `synth`, `protocol`
and `stats`; `agent` uses `synth`, `protocol`, `host` and `stats`; `synth`
uses `protocol` and `host`; `protocol` uses `host`. `host` and `stats` import
no other phantomfleet package. Keep it that way, so there are no cycles.

## Seed data contributions

Seeds live in `internal/synth/seeds/` (built-in) and `examples/` (sample
fleets). See [docs/seeds.md](docs/seeds.md) for the format. Good seed
contributions are realistic for the platform, use templates for volume and
anchors for well-known rows, and keep row counts in
`internal/synth/rowcounts.yaml` sensible.

## Refreshing the osquery schema

`internal/synth/osquery_schema.json` (table name to columns, with their
types and hidden flags) and `internal/synth/osquery_platforms.json` (table
name to platforms) are slimmed copies of the osquery table schema, embedded
at build time. To update them for
a new osquery release, replace `<VERSION>` with the release (for example
`5.24.0`):

```bash
curl -fsSL "https://raw.githubusercontent.com/osquery/osquery-site/source/src/data/osquery_schema_versions/<VERSION>.json" \
  -o /tmp/osquery_schema_full.json
python3 - <<'PY'
import json
d = json.load(open('/tmp/osquery_schema_full.json'))
def col(c):
    e = {'name': c['name'], 'type': c['type']}
    if c.get('hidden'):
        e['hidden'] = True
    return e
json.dump({t['name']: [col(c) for c in t['columns']] for t in d},
          open('internal/synth/osquery_schema.json', 'w'), separators=(',', ':'), sort_keys=True)
json.dump({t['name']: sorted(t['platforms']) for t in d},
          open('internal/synth/osquery_platforms.json', 'w'), separators=(',', ':'), sort_keys=True)
PY
go test ./... && go build -o phantomfleet .
```

The schema is published under CC BY 4.0: update the version named in
[NOTICE](NOTICE) and mention the osquery version in your PR and in the
changelog.

## Licence

By contributing you agree that your contributions are licensed under the
project's [MIT License](LICENSE).
