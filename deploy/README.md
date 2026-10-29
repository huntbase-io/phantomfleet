# Running phantomfleet with Docker Compose

Two ready-made Compose stacks run phantomfleet against an osquery TLS server
such as osctrl or Fleet. Simulated
hosts enroll, then send status/result logs, poll for config and answer
distributed queries, so they show up in the server as live hosts.

| File | What it runs |
|---|---|
| `docker-compose.yml` | N randomly generated hosts (`PHANTOMFLEET_NODES`), plus any extra seed YAML you drop in `./seeds` |
| `docker-compose.examplecorp.yml` | The fixed 15-host Example Corp fleet from [`../examples/examplecorp`](../examples/examplecorp) (pinned identities + story seeds) |

Both read the same `.env` and use the published image
`ghcr.io/huntbase-io/phantomfleet` by default. The Example Corp stack always
runs the 15 pinned hosts with synthetic answers, so it ignores
`PHANTOMFLEET_NODES`, `PHANTOMFLEET_ENROLL_CONCURRENCY` (it uses the default,
50) and `PHANTOMFLEET_FAKE_RESULTS`.

## Quick start

```bash
cd deploy
cp .env.example .env          # set PHANTOMFLEET_URL, PHANTOMFLEET_ENV, PHANTOMFLEET_SECRET
docker compose up -d
docker compose logs -f        # enrollment + periodic summaries
docker compose down           # stop; host identities persist in the volume
```

Example Corp fleet:

```bash
docker compose -f docker-compose.examplecorp.yml up -d
docker compose -f docker-compose.examplecorp.yml logs -f
```

Retune without editing files:

```bash
PHANTOMFLEET_NODES=50 docker compose up -d
```

### Building the image locally

Both Compose files carry a `build:` section pointing at the repository root
`Dockerfile`, so you can run from a checkout without pulling:

```bash
docker compose up -d --build
# or build it yourself from the repo root:
make docker                    # tags phantomfleet:<version> and phantomfleet:dev
PHANTOMFLEET_IMAGE=phantomfleet:dev docker compose up -d
```

To pin a release, set `PHANTOMFLEET_IMAGE=ghcr.io/huntbase-io/phantomfleet:vX.Y.Z`.
Every push to `main` also publishes `ghcr.io/huntbase-io/phantomfleet:main` and an
immutable `:sha-<short>` tag, for running an unreleased build.

## Configuration

All settings come from `.env` (see `.env.example`):

| Variable | Default | Flag | Meaning |
|---|---|---|---|
| `PHANTOMFLEET_URL` | required | `--url` | Base URL of the osquery TLS server |
| `PHANTOMFLEET_ENV` | empty | `--env` | osctrl environment UUID (leave empty for generic servers) |
| `PHANTOMFLEET_SECRET` | required | (environment) | Enroll secret. Passed as an environment variable, which phantomfleet reads directly, so it never appears in the container's command line |
| `PHANTOMFLEET_FLAVOR` | `osctrl` | `--flavor` | `osctrl` or `generic` |
| `PHANTOMFLEET_IMAGE` | `ghcr.io/huntbase-io/phantomfleet:latest` | | Image to run |
| `PHANTOMFLEET_NODES` | 5 | `--nodes` | Number of simulated hosts |
| `PHANTOMFLEET_ENROLL_CONCURRENCY` | 50 | `--enroll-concurrency` | Hosts enrolled in parallel at startup |
| `PHANTOMFLEET_STATUS_INTERVAL` | 60 | `--status` | Seconds between status log posts |
| `PHANTOMFLEET_RESULT_INTERVAL` | 60 | `--result` | Seconds between result log posts |
| `PHANTOMFLEET_CONFIG_INTERVAL` | 45 | `--config` | Seconds between config requests |
| `PHANTOMFLEET_QUERY_INTERVAL` | 30 (15 for Example Corp) | `--query` | Seconds between distributed-query reads |
| `PHANTOMFLEET_INSECURE` | false | `--insecure` | Skip TLS verification (self-signed test servers only) |
| `PHANTOMFLEET_FAKE_RESULTS` | true | `--fake-results` | Answer queries with synthetic rows (no osqueryi) |
| `PHANTOMFLEET_EXPLAIN` | false | `--explain` | Log how each fake-result query is decomposed |
| `PHANTOMFLEET_MODE` | summary | `--mode` | `quiet` / `summary` / `verbose` / `dashboard` / `json` |
| `TZ` | UTC | | Container time zone |

Run `docker run --rm ghcr.io/huntbase-io/phantomfleet --help` for every flag.

### osctrl vs generic servers

With `PHANTOMFLEET_FLAVOR=osctrl`, requests go to the osctrl-tls
per-environment paths under the environment UUID (`/<env>/enroll`,
`/<env>/config`, `/<env>/log`, `/<env>/read`, `/<env>/write`).

With `PHANTOMFLEET_FLAVOR=generic` (for example Fleet), leave
`PHANTOMFLEET_ENV` empty. Fleet serves osquery's standard paths, so it needs
no path overrides.

For a server whose endpoint paths differ from the generic defaults, add the
path flags in a `docker-compose.override.yml` next to `docker-compose.yml`
(Compose merges it automatically). `command` is replaced, not merged, so the
override must repeat every flag of the base file, including `--seeds-dir`,
or those settings are lost. This override keeps everything
`docker-compose.yml` passes and adds the paths (the `/custom/...` paths are
placeholders for your server's):

```yaml
# docker-compose.override.yml: custom endpoint paths
services:
  phantomfleet:
    command:
      - --url=${PHANTOMFLEET_URL:?set PHANTOMFLEET_URL in .env}
      - --env=${PHANTOMFLEET_ENV:-}
      - --flavor=generic
      - --enroll-path=/custom/osquery/enroll
      - --config-path=/custom/osquery/config
      - --log-path=/custom/osquery/log
      - --read-path=/custom/osquery/distributed/read
      - --write-path=/custom/osquery/distributed/write
      - --nodes=${PHANTOMFLEET_NODES:-5}
      - --enroll-concurrency=${PHANTOMFLEET_ENROLL_CONCURRENCY:-50}
      - --status=${PHANTOMFLEET_STATUS_INTERVAL:-60}
      - --result=${PHANTOMFLEET_RESULT_INTERVAL:-60}
      - --config=${PHANTOMFLEET_CONFIG_INTERVAL:-45}
      - --query=${PHANTOMFLEET_QUERY_INTERVAL:-30}
      - --insecure=${PHANTOMFLEET_INSECURE:-false}
      - --fake-results=${PHANTOMFLEET_FAKE_RESULTS:-true}
      - --explain=${PHANTOMFLEET_EXPLAIN:-false}
      - --mode=${PHANTOMFLEET_MODE:-summary}
      - --state=/data/phantomfleet_state.json
      - --seeds-dir=/seeds
```

Check the resolved command with `docker compose config` before starting.

## State

Host identities (node keys, UUIDs, hostnames) are written to
`/data/phantomfleet_state.json` on a named volume, so restarts resume the same
simulated fleet instead of enrolling new hosts. To start over with a fresh
fleet, remove the volume:

```bash
docker compose down -v
```

## Adding your own fake data (no rebuild)

The built-in seed data is compiled into the binary. `docker-compose.yml` also
bind-mounts `./seeds` to `/seeds` and passes `--seeds-dir=/seeds`, so YAML you
drop there is layered on top at startup:

```bash
$EDITOR seeds/linux.yaml       # or all.yaml / windows.yaml / darwin.yaml / rowcounts.yaml
docker compose up -d --force-recreate
```

Merging is additive: your rows are appended to the built-in tables and new
tables are created. See [`seeds/README.md`](seeds/README.md) for file names,
`{{token}}` patterns and an example. The Example Corp variant mounts
`../examples/examplecorp/seeds` instead.

## Running without Compose

```bash
docker run -d --name phantomfleet \
  -v phantomfleet-state:/data \
  -e PHANTOMFLEET_SECRET=replace-with-enroll-secret \
  ghcr.io/huntbase-io/phantomfleet:latest \
  --url=https://osctrl.example.com/ \
  --env=00000000-0000-0000-0000-000000000000 \
  --nodes=10
```

The image is distroless, runs as UID 65532 and uses `/data` as its working
directory, so the default `--state` file lands on the volume.
