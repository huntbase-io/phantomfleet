# Seed data reference

Seed data is what makes synthetic answers look like a real operating system.
phantomfleet ships built-in seeds embedded in the binary and can layer extra
seed files from a directory at startup (`--seeds-dir`), without rebuilding.

## Built-in seeds

| File | Contents |
|---|---|
| `internal/synth/seeds/all.yaml` | Shared base merged into every platform profile: browser extensions, `python_packages`, `vscode_extensions`, `usb_devices`. |
| `internal/synth/seeds/linux.yaml` | Linux profile (Ubuntu-flavoured). Also used by every platform that is not macOS or Windows. |
| `internal/synth/seeds/darwin.yaml` | macOS profile. |
| `internal/synth/seeds/windows.yaml` | Windows profile. |
| `internal/synth/rowcounts.yaml` | `[min, max]` rows per table. |

For built-in seeds, a platform file that defines a table **replaces** the
`all.yaml` table of the same name for that platform.

Editing these files requires a rebuild (`go build`), since they are compiled
in with `go:embed`.

## External seeds (`--seeds-dir`)

`--seeds-dir` is repeatable. Each directory is a **layer**, applied in the
order given on top of the built-in seeds and the layers before it:

```bash
phantomfleet ... --seeds-dir baseline/seeds --seeds-dir fleet-a/seeds
```

A shared baseline (realistic padding templates, views) can then serve several
fleets, each adding its own hosts and story in a later layer.

Each directory may contain:

| File | Effect |
|---|---|
| `all.yaml` | Rows appended to every platform profile. |
| `linux.yaml`, `darwin.yaml`, `windows.yaml` | Rows appended to that profile. |
| `rowcounts.yaml` | Row counts that override the built-in ones per table. |

Rules:

- Only files ending in `.yaml` are read (not `.yml`); subdirectories are
  ignored.
- Merging is **additive**: external rows are appended after the built-in rows
  (and the rows of earlier layers) of the same table, and new tables are
  created. Use `_replace` to start a table from scratch.
- Within a layer, `all.yaml` is applied first, then the platform files.
  Layers apply one after another, so a later layer's `rowcounts.yaml` entries
  and `_views` replace an earlier layer's.
- Other file names create profiles that no node uses, because nodes only map
  to `linux`, `darwin` or `windows`.
- A missing directory is not an error. A file that can't be read, isn't
  valid YAML or isn't a mapping (of tables to rows, or for `rowcounts.yaml`
  of tables to `[min, max]`), and a malformed `_views` entry, stop
  phantomfleet at start-up with an error naming the file; nothing from that
  directory is applied. Use `--explain` to confirm that a table is `seeded`.

## File format

A seed file is a YAML mapping of table name to a list of rows. Each row maps
column name to value.

```yaml
listening_ports:
  - { pid: "712", port: "88", protocol: "6", family: "2", address: 0.0.0.0, path: C:\Windows\System32\lsass.exe }
  - port: "{{int:49152..65535}}"
    protocol: "6"
    address: 0.0.0.0
```

- Table and column names are case-insensitive (stored lower-case).
- Every value is converted to a string, so unquoted numbers and booleans work.
  Quote values that YAML would otherwise reinterpret.
- Columns that are not in the osquery schema are allowed; they are added to
  the table's column set as text.
- A table listed with an empty list (`patches: []`) or no value declares that
  the table exists on the platform but has no rows. On [pinned
  nodes](nodes-file.md) that makes the table answer with nothing; on random
  nodes it is padded from the schema as usual.
- Keys whose value is not a list are ignored, apart from the reserved
  `_replace` and `_views` keys.

## Values: literals and tokens

A value is a literal, one or more `{{token}}` patterns, or a mix
(`/home/{{username}}/.ssh/authorized_keys`). Unknown tokens are left as-is.

### Node tokens

Resolved per node. They do not make a row a template.

| Token | Value |
|---|---|
| `{{hostname}}` | Node hostname. |
| `{{shorthost}}` | First label of the hostname. |
| `{{ip}}` | Node IP. |
| `{{uuid}}` | Node identifier. |
| `{{version}}` | Node osquery version. |
| `{{username}}` | Pinned nodes: `primary_user`, else `Administrator` (Windows) or `root`. Random nodes: the hostname, lower-cased, alphanumerics only, at most 16 characters. |
| `{{ago:DURATION}}` | Unix time `DURATION` before the query, as a Go duration (`26h5m`, `90m`). Keeps story events the same age whenever they are queried. |

### Generator tokens

Each resolution produces a new value. A row containing any of these is a
**template** (see below).

| Token | Value |
|---|---|
| `{{int:MIN..MAX}}` | Integer in range (default 0..1000). |
| `{{float:MIN..MAX}}` | Float with two decimals (default 0..1000). |
| `{{choice:a\|b\|c}}` | One of the options. |
| `{{ipv4}}` | IPv4 address. |
| `{{mac}}` | MAC address. |
| `{{uuid4}}` | Random UUID. |
| `{{hex:N}}` | `N` hex characters (default 16). |
| `{{word}}`, `{{words}}` | One or two random words. |
| `{{semver}}` | Version string. |
| `{{bool}}` | `0` or `1`. |
| `{{unixtime}}`, `{{unixtime:MIN..MAX}}` | Unix time (default 1600000000..1750000000). |
| `{{date}}` | `YYYY-MM-DD` between 2019 and 2024. |
| `{{row:CATALOG.FIELD}}` | `FIELD` of one entry of a catalog loaded with `--catalog`. Every `row:` token of one row reads the same entry. See [catalogs](extensions.md#catalogs---catalog). |

Generated values are deterministic per node and table, so a node answers the
same way every time.

## Anchors and templates

- A row **without** generator tokens is an **anchor**: it appears once, in
  file order, e.g. pid 1 being `systemd`.
- A row **with** generator tokens is a **template**: after the anchors, the
  table is padded to its row count by cloning random templates with fresh
  values.
- A table with no templates is padded with values generated from the osquery
  schema (on random nodes; see [synthetic results](synthetic-results.md)).

Templates are how a seed file controls the bulk of a long table: a few
realistic patterns cloned dozens of times look far better than schema-random
values.

## Host-specific rows: `_hosts` and `_key`

Two reserved columns are removed from rows before they are used.

**`_hosts`** limits a row to the named nodes. Names are separated by `|` or
`,`, compared case-insensitively against the full hostname or its first label:

```yaml
deb_packages:
  - _hosts: web-prod-01|web-prod-02
    name: nginx
    version: 1.24.0-1~jammy
```

Rows for a host come before the shared rows and are always reported, even if
that exceeds the table's row count.

**`_key`** goes on a `_hosts` row and names a column. On the matching hosts,
shared rows (those without `_hosts`) with the same value in that column are
dropped, so the host row *replaces* the profile's row instead of duplicating
it:

```yaml
services:
  - _hosts: finance-ws-12
    _key: name
    name: WinDefend
    status: STOPPED
```

The comparison is case-insensitive and node tokens are resolved first.

## Replacing built-in tables: `_replace`

In an external file, a top-level `_replace` list drops the rows of those
tables, built-in and from earlier `--seeds-dir` layers, before the file's rows
are appended. In `all.yaml` it applies to
every platform; in a platform file, to that platform.

```yaml
_replace: [users, groups, logged_in_users]
users:
  - { uid: "0", username: root, directory: /root, shell: /bin/bash }
```

Combined with an explicit table declaration, this lets a sample fleet report
exactly the rows you wrote. [Example Corp](../examples/examplecorp/) uses it
for users, groups, interfaces and similar identity tables.

## Computed extension tables: `_views`

In an external file, a top-level `_views` mapping defines extension tables
(loaded with `--extra-schema`) whose rows are computed per statement by a SQL
`SELECT`, with the statement's constraints as parameters. In `all.yaml` a view
applies to every platform; in a platform file, to that platform, replacing an
`all.yaml` view of the same table in the same layer. A later layer's view
replaces an earlier layer's. See
[extensions.md](extensions.md#computed-tables-_views).

```yaml
_views:
  example_ext_download_summary: |
    WITH args AS (SELECT COALESCE(:min_bytes, 0) AS m)
    SELECT args.m AS min_bytes, user, COUNT(*) AS downloads
    FROM example_ext_downloads JOIN args WHERE bytes >= args.m GROUP BY user
```

## Row counts

`rowcounts.yaml` maps a table to `[min, max]`. Each node draws its count in
that range (deterministically), capped at 5000:

```yaml
default: [1, 8]      # tables not listed
os_version: [1, 1]
processes: [80, 240]
```

Entries with a negative minimum or `max < min` are ignored. A file in
`--seeds-dir` overrides individual entries and leaves the rest. Lower a count
to keep a table short; raise it for load testing.

Shared seed anchors beyond the count are dropped, so if every anchor must
appear, make sure the minimum is at least the number of anchors.

## Workflow tips

- Start from a query: run it with `--explain` and look at which tables are
  `schema/random`. Those are candidates for seeds.
- Put a few anchors that tell your story, then one or two templates for
  volume.
- Use `{{ago:..}}` for timestamps in a story so that "yesterday" stays
  yesterday.
- Use `_hosts` for anything that should only exist on one machine, and `_key`
  when it should replace something every host has.
