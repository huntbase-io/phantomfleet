# Extension tables and catalogs

osquery extensions add tables that the core schema doesn't have, and a
believable host needs realistic rows in the tables an analyst reads. Four
start-up inputs cover both, without changing phantomfleet's code:

| Input | Flag | Format |
|---|---|---|
| Extension table schemas | `--extra-schema <file>` (repeatable) | JSON, same shape as the embedded `osquery_schema.json` |
| Extension table rows | `--seeds-dir <dir>` (repeatable, layered in order) | Seed YAML, as for any other table ([seeds.md](seeds.md)) |
| Computed extension tables | `_views` in the seed files | SQL `SELECT` per table |
| Row catalogs | `--catalog <file>` (repeatable) | YAML: catalog name to a list of records |

A runnable example is in
[`examples/extension-tables/`](../examples/extension-tables/):

```bash
phantomfleet --flavor generic --url https://fleet.example.com --secret-file ./enroll_secret \
  --nodes-file examples/extension-tables/nodes.yaml --nodes 2 \
  --extra-schema examples/extension-tables/schema.json \
  --catalog examples/extension-tables/catalog.yaml \
  --seeds-dir examples/extension-tables/seeds
```

Load order is extra schemas, then catalogs, then seeds (views name extension
tables, so their schema must already be loaded). A file that can't be read or
parsed, a schema clash, or a malformed `_views` entry stops phantomfleet at
start-up with an error naming the file.

## Extension tables: `--extra-schema`

The file maps a table name to its ordered columns:

```json
{
  "example_ext_downloads": [
    {"name": "ts", "type": "bigint"},
    {"name": "user", "type": "text"},
    {"name": "bytes", "type": "bigint"}
  ]
}
```

- Table and column names match `[a-z_][a-z0-9_]*` (they are lower-cased
  first).
- `type` is one of `text`, `integer`, `bigint`, `unsigned_bigint`, `double`
  (case-insensitive).
- A table that already exists, in the embedded schema or an earlier
  `--extra-schema` file, is an error unless its definition is identical
  (same columns, order and types). An identical copy of an embedded table is
  accepted and stays an ordinary core table. A file with a clash merges
  nothing.

### How extension tables answer

Extension tables behave like an agent whose extension has recorded only what
the seeds say:

- **Pinned hosts** answer from the table's seed rows: the host's `_hosts`
  rows, then the shared rows, each resolved once (tokens such as
  `{{ago:2h}}` work). Seed row counts and padding don't apply, and no value is
  ever generated from the schema. Any statement that reads an extension table
  runs in the [SQLite engine](../README.md#real-sql-for-pinned-hosts), so
  joins, `GROUP BY` and aggregates are exact.
- **A pinned host with no seed rows** for the table answers with no rows
  (`count(*)` is `0`).
- **Random nodes** answer every query that names an extension table with no
  rows.

Seed rows for extension tables go in the usual seed files:

```yaml
# seeds/windows.yaml
example_ext_downloads:
  - {_hosts: ws-01, ts: "{{ago:2h}}", user: j.doe, bytes: "250000"}
  - {_hosts: ws-01, ts: "{{ago:1h}}", user: svc-backup, bytes: "4000000"}
```

Columns a seed row has but the schema doesn't are added as `text`.

## Computed tables: `_views`

Some extension tables don't store rows; they compute them from their inputs,
for example a summary filtered by a threshold or the folders below a given
folder. In osquery the inputs are constraints in the query
(`WHERE user = 'j.doe' AND min_bytes = 1000000`). phantomfleet answers such a
table with a view: a SQL `SELECT` defined in the seeds under the reserved
`_views` key, evaluated on the host for each statement.

```yaml
# seeds/all.yaml
_views:
  example_ext_download_summary: |
    WITH args AS (SELECT :user AS u, COALESCE(:min_bytes, 0) AS m)
    SELECT d.user AS user, args.m AS min_bytes, d.source_host AS source_host,
           COUNT(*) AS downloads, SUM(d.bytes) AS total_bytes
    FROM example_ext_downloads d JOIN args
    WHERE (args.u IS NULL OR d.user = args.u) AND d.bytes >= args.m
    GROUP BY d.user, d.source_host
```

Rules:

- A view may only be defined for a table loaded with `--extra-schema`, and
  must be a single `SELECT` or `WITH ... SELECT` statement. Both are checked
  when the seeds load.
- **Inputs.** Each `:name` parameter in the view (`@name` and `$name` work
  too) is bound to the value of the first `name = literal` comparison in the
  statement being answered: a quoted string, an integer or a decimal. The
  column may be bare, double-quoted or alias-qualified (`s."user"`). A
  parameter the statement doesn't constrain is `NULL`, so use `COALESCE` for
  defaults. Only equality comparisons are inputs; `IN`, ranges and
  expressions are not.
- **Echo the inputs.** The statement's own `WHERE` still runs on the view's
  rows, so return each input as a column with the value it was given (as
  osquery tables do). Otherwise `WHERE min_bytes = 1000000` filters every row
  out.
- **Sources.** A view reads the host's tables: extension tables (their seed
  rows), core tables (the host's curated data) and other views (up to 8
  deep; a cycle is an error). `WITH RECURSIVE` works, which is how a hierarchy is
  walked; see `example_ext_folder_sizes` in the example.
- **Its own rows.** Inside a view, the view's own table name means that
  table's seed rows. A view can so post-process stored rows: derive a column,
  fill a default, rename a value. List the columns you return (SQLite has no
  `SELECT * EXCEPT`), and declare in the schema every column the view reads,
  so it exists on hosts whose rows don't set it:

  ```yaml
  _views:
    example_ext_downloads: |
      SELECT ts, user, source_host, file, folder_id, bytes, COALESCE(verdict, 'allowed') AS verdict
      FROM example_ext_downloads
  ```
- **Output.** Result columns are matched by name to the schema columns;
  schema columns the view doesn't return are `NULL` (reported as `""`), and
  extra result columns are added as `text`. At most 5000 rows are kept.
- **Platforms.** A view in `all.yaml` applies to every platform; one in a
  platform file applies to that platform and replaces an `all.yaml` view of
  the same table. With several `--seeds-dir` layers, a later layer's view
  replaces an earlier one's.
- **Random nodes** never evaluate views; the table answers with no rows.
- A statement that references a view twice with different inputs sees one
  set of inputs (the first comparison found).

The SQLite engine includes the JSON functions (`json_group_object`,
`json_object`, ...) and window functions, useful for per-row summaries such as
the distinct verdicts of a group as a JSON array.

## Catalogs: `--catalog`

A catalog is a named list of coherent records. Seed templates draw from it
with `{{row:<catalog>.<field>}}`, so a padded row is a real-looking entry (a
service whose name, path and command line belong together) instead of random
words. The file maps catalog names to lists of records:

```yaml
example_linux_services:
  - {name: cron, path: /usr/sbin/cron, cmdline: /usr/sbin/cron -f, uid: "0"}
  - {name: rsyslogd, path: /usr/sbin/rsyslogd, cmdline: /usr/sbin/rsyslogd -n -iNONE, uid: "104"}
```

```yaml
# seeds/linux.yaml
processes:
  - pid: "{{int:300..65000}}"
    name: "{{row:example_linux_services.name}}"
    path: "{{row:example_linux_services.path}}"
    cmdline: "{{row:example_linux_services.cmdline}}"
    uid: "{{row:example_linux_services.uid}}"
```

- Catalog names match `[a-z0-9_]+`; field names are case-insensitive. Every
  value is converted to a string.
- Each catalog needs at least one entry, and no entry may be empty.
- A catalog defined by an earlier `--catalog` file is an error unless it is
  identical. A file with a clash merges nothing.
- No catalog is built in.

How `row:` tokens resolve:

- Every `row:` token of one seed row reads **the same entry**, so its fields
  stay together. A row can draw from several catalogs (one entry from each).
- A `row:` token makes a row a template, like a generator token.
- When a table is padded, each entry is used **at most once** per host and
  table, in a deterministic per-host order, and entries whose `name` an
  anchor row of the table already uses are skipped. When a template's catalog
  runs out, the template is retired, so a table padded only from catalogs
  stops at the catalog's size.
- Extension tables are never padded: each of their seed rows draws one entry
  at random.
- A row that names an unknown catalog is skipped while padding; elsewhere its
  `row:` tokens resolve to empty text.
