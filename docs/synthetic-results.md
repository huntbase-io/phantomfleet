# How synthetic results work

With `--fake-results` (on by default), a simulated node answers every distributed query
without running SQL. This page describes what happens to a query, in enough
detail to predict the answer and to know where the approximation ends.

The short version: each node has a deterministic **population** of rows per
table (seed rows first, padded to a per-table row count), and the query is a
**view** over that population. The SQL is taken apart with regular
expressions; it is never executed.

Two exceptions run real SQL on pinned hosts: statements that start with
`WITH`, and statements that read an extension table (`--extra-schema`). They
execute in an in-memory SQLite database loaded from the host's curated tables;
see [Real SQL for pinned hosts](../README.md#real-sql-for-pinned-hosts) and
[extensions.md](extensions.md). Before anything else, on a random node, a
query that names a table the node doesn't have (an unknown table, or another
platform's table such as `services` on Linux or `deb_packages` on Windows)
fails with `no such table: <name>`, and a query that names an extension table
answers with no rows. On a pinned host, another platform's table that the
host's seeds don't declare answers with no rows (osquery's `--enable_foreign`).
PAN-OS (`panos`) hosts also answer no rows for distro package tables unless
rows are seeded for that host.

Statements that use `EXISTS`, `pragma_*` functions or `osquery_registry`,
statements that read no table, and CTEs or computed SELECT lists over seeded
tables, run in SQLite on every node, random ones included. SQLite there has
osquery's extra SQL functions (`split`, `regex_match`, `concat_ws`, ...; see
[Real SQL for pinned hosts](../README.md#real-sql-for-pinned-hosts)).

## 1. Pre-processing

- Surrounding whitespace and a trailing `;` are removed.
- Every parenthesised `(SELECT ...)` is cut out and replaced by a placeholder
  column. Each one is answered separately later, as its own query, and its
  value is the first column of its first row (only when that row has exactly
  one column). This is what makes scalar subqueries such as
  `(SELECT hostname FROM system_info) AS hostname` work.
- Tables are read from the `FROM` clause, up to the first `WHERE`, `GROUP BY`,
  `ORDER BY`, `HAVING` or `LIMIT`. `JOIN` keywords (any kind) and commas
  separate tables; the first table is the driver.

## 2. Building the population

For each table, a node builds its population once per query.

**Platform profile.** The node's platform selects a seed profile: names
starting with `darwin` or containing `macos` (and `mac`) use `darwin`; names
starting with `windows` (and `win`) use `windows`; everything else uses
`linux`.

**Rows, in order:**

1. Identity rows (pinned nodes only) for `os_version`, `system_info` and
   `osquery_info`, built from the nodes file.
2. Seed rows restricted to this host with `_hosts`.
3. The profile's shared seed rows, minus any a host row replaces through
   `_key`.

**Row count.** The target size is drawn from the table's `[min, max]` in
`rowcounts.yaml` (`default` for unlisted tables, `[1, 8]` if there is no
default), capped at 5000, and never smaller than the number of identity and
host-specific rows. Shared seed rows beyond the target are dropped.

**Anchors and templates.** A seed row containing a generator token
(`{{int:..}}`, `{{choice:..}}`, `{{word}}`, ...) is a template. Rows without
generators are anchors and appear once. Identity tokens (`{{hostname}}`,
`{{ip}}`, `{{username}}`, ...) and `{{ago:..}}` do not make a row a template.

**Padding.** Until the target is reached, the node either clones a random
template (regenerating its tokens) or, if the table has no templates,
generates a row from schema column types.

**Columns.** A table's columns are its schema columns plus any extra column
that appears in its seed rows (treated as text). A seed row that leaves out a
column gets a generated value for it, except on pinned nodes (see below).

**Generated values** come from the column name first, then its osquery type:

| Column name pattern | Value |
|---|---|
| identity columns (`hostname`, `host`, `fqdn`, `computer_name`, `local_hostname`, `csname`, `device_name` outside `drivers`, `uuid`, `host_uuid`, `hardware_uuid`, `host_identifier`, `hardware_serial`, ...) | The node's own name, short name, identifier or serial |
| `uid`, `gid`, `euid`, `egid`, `*_uid`, `*_gid` | 0 to 2000 |
| `pid`, `ppid`, contains `pid` | 1 to 65535 |
| contains `port` | 1 to 65535 |
| MAC address columns | A MAC address |
| contains `address`, `ipv4`, `destination`, `gateway`, `netmask` | An IPv4 address |
| contains `interface` | `eth0`, `en0`, `wlan0`, `lo` or `ens33` |
| contains `cmdline`, `command` | A real binary path for the node's platform |
| contains `path`, `directory`, `cwd`, `source` | A real binary or file path for the node's platform |
| contains `username`, or `user`, `owner` | A username |
| contains `uuid`, `guid` | A random UUID |
| contains `version` | A version string |
| ends in `sha256`, `sha1`, `md5`; contains `hash` | Hex of the right length |
| contains `time`, `epoch`, `_at`, `seconds` | A Unix time between 2020 and 2025 |
| contains `size`, `bytes`, `memory`, `disk`, `space` | 0 to 1 GiB |
| `name`, `*_name` | An application-style name |
| contains `description`, `comment`, `summary`, `message` | A neutral phrase ("Vendor default") |
| `enabled`, `active`, `hidden`, `is_*`, ... | `0` or `1` |
| anything else | By type: `integer`, `bigint`, `double`, otherwise a word |

All values are strings, matching osquery's JSON result format.

**Determinism.** Every random choice is seeded from the node identifier, a
purpose and the table name, so the same node returns the same population for
the same table on every query and every run. Only `{{ago:..}}` values move,
by design, with the clock.

**Unknown tables.** A random node has the embedded osquery tables of its
platform, the `--extra-schema` tables (which have no rows on a random node)
and the tables its platform's seeds declare. A statement that names any other
table, including another platform's table such as `services` on Linux or
`rpm_packages` on Windows, fails with status `1` and the message
`no such table: <name>`, as on osquery. No rows are generated for it.

**Statements without a table.** A statement that reads no table (`SELECT 1`,
`SELECT sqrt(16)`) or only a table-valued function such as `json_each` runs
in SQLite, so its values are computed exactly.

## 3. Pinned (curated) nodes

Nodes loaded from a [nodes file](nodes-file.md) are treated as curated:

- If the node's platform profile declares a table (it has rows for any host,
  or an explicit empty list), the table is answered from seed rows only. It is
  padded by cloning the table's templates if there are any, and never with
  schema-generated rows. If the table has no templates, the seed rows are the
  whole answer (up to the table's row count; rows written for this host are
  always included).
- Columns a curated row leaves out are empty, unless they are identity columns,
  which carry the node's own values.
- User-like columns (`username`, `user`, `owner`, `user_name`, `login`) report
  the node's `primary_user`, or `Administrator` on Windows and `root`
  elsewhere when none is set. `installed_by` is `NT AUTHORITY\SYSTEM` on
  Windows.
- Joins are evaluated (section 5).

Tables the profile does not declare behave as for random nodes.

## 4. Applying the query

**WHERE.** The clause up to `GROUP BY`, `ORDER BY`, `HAVING` or `LIMIT` is
split on `OR`, and each part on `AND` (so `AND` binds tighter). Parentheses
are not understood. Each condition is one of:

- `col = v`, `col == v`, `col != v`, `col <> v`: case-insensitive string
  comparison.
- `col < v`, `>`, `<=`, `>=`: numeric if both sides parse as numbers, otherwise
  string comparison.
- `col LIKE p`, `col NOT LIKE p`: `%` and `_` wildcards, case-insensitive.
- `col IN (a, b)`, `col NOT IN (a, b)`: case-insensitive.

Values may be single- or double-quoted. A table alias or prefix on the column
(`p.name`) is ignored. A condition that does not match one of these shapes,
or names a column the row does not have, is treated as true, so a query is
never emptied by something the evaluator does not understand.

**Aggregates.** If any SELECT item is `count`, `sum`, `avg`, `min`, `max`,
`total` or `group_concat`, exactly one row is returned. `count(...)` is the
number of rows left after WHERE. The other aggregates are a deterministic
number between 0 and 1000. Non-aggregate items take the first remaining row's
value. `GROUP BY` and `HAVING` are ignored.

**LIMIT.** `LIMIT n` truncates the result. `OFFSET` is ignored.

**Projection.** `SELECT *` returns every column of the population. Otherwise
each SELECT item is reduced to a source column: the text after the last `(`
and the last `.`, so `p.name` reads `name` and `lower(name)` reads `name`.
Labels follow osquery: a bare or qualified column is labelled by its bare
name, an `AS` alias is used as-is, and expressions keep their text
(`count(*)`). A source column that does not exist yields an empty string.

`ORDER BY` and `DISTINCT` are ignored; rows come back in population order.

## 5. Joins

Every table in the `FROM` clause gets a population. They are combined
differently depending on the node.

**Random nodes: zip-merge.** Row *i* of the driver table is merged with row
*i* (modulo length) of each other table; on a column name collision, later
tables win. The result has as many rows as the driver. `ON` predicates are not
evaluated, so joined values do not correspond to each other.

**Pinned nodes: equality joins.** When every joined table has an `ON` clause
containing at least one `a = b` predicate (several may be combined with
`AND`), the join is evaluated as a nested loop: `INNER`/plain `JOIN` keeps
matching pairs, `LEFT JOIN` also keeps unmatched left rows. Comparisons are
case-insensitive. Each joined row carries both bare column names (later tables
win) and `alias.column` names. If any joined table lacks a usable `ON`
predicate (a comma join, `CROSS JOIN`, `USING`, or only non-equality
conditions), the whole query falls back to the zip-merge. `RIGHT` and `FULL`
joins are not supported.

Note that WHERE strips aliases, so in a join `WHERE u.uid = 0` tests the bare
`uid` column of the joined row, which is the last joined table's `uid`.

## 6. Response

The rows are posted to the distributed write endpoint with status `0` and an
empty message. The pattern answerer does not check SQL, so invalid SQL still
gets rows. There are three exceptions. When SQLite rejects a statement (one
a pinned host runs in SQLite, or an `EXISTS`, `pragma_*`,
`osquery_registry` or computed statement on any node), the node posts no
rows, status `1` and the error as the message, as osquery does. A query
on a table the node doesn't have (see the start of this page) gets status
`1` and `no such table: <name>`, and a query the pattern answerer cannot
handle also gets status `1`.

## Debugging with `--explain`

`--explain` prints one line per answered query:

```
[explain] finance-ws-12.corp.example.com/windows tables=services(seeded) population=58 afterWHERE=1 :: SELECT name, status FROM services WHERE name = 'WinDefend'
```

- node name and seed profile, plus `[join]` when more than one table is
  involved;
- each table and its source: `seeded` (the profile has rows for it),
  `schema/random` (schema only) or `unknown`;
- the population size and the number of rows left after WHERE;
- the query, collapsed to one line and truncated at 120 characters.

If a query returns more rows than you expect, check `afterWHERE`: a condition
the evaluator ignored leaves the population unfiltered.
