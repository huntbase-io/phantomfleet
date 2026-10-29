# Extension tables example

A two-host fleet showing phantomfleet's generic loaders with neutral, invented
data:

| File | Loaded with | What it shows |
|---|---|---|
| `schema.json` | `--extra-schema` | Four extension tables: `example_ext_downloads` and `example_ext_folders` (stored rows), `example_ext_download_summary` and `example_ext_folder_sizes` (computed). |
| `seeds/windows.yaml` | `--seeds-dir` | Folders and downloads on `ws-01` only, with `{{ago:...}}` timestamps. |
| `seeds/all.yaml` | `--seeds-dir` | `_views` computing a per-user download summary (inputs `user`, `min_bytes`) and folder sizes below a folder (inputs `folder`, `max_depth`). |
| `catalog.yaml` | `--catalog` | A small catalog of Linux services. |
| `seeds/linux.yaml` | `--seeds-dir` | A `processes` template padded from that catalog. |
| `nodes.yaml` | `--nodes-file` | `ws-01` (Windows) and `srv-01` (Ubuntu). |

```bash
export PHANTOMFLEET_SECRET="$ENROLL_SECRET"
phantomfleet --flavor generic --url https://fleet.example.com \
  --nodes-file examples/extension-tables/nodes.yaml --nodes 2 \
  --extra-schema examples/extension-tables/schema.json \
  --catalog examples/extension-tables/catalog.yaml \
  --seeds-dir examples/extension-tables/seeds \
  --state extension_tables_state.json
```

`--nodes 2` keeps the fleet to the two pinned hosts; with the default
`--nodes 5`, three random nodes would join them.

Then try, against `ws-01`:

```sql
SELECT verdict, count(*) FROM example_ext_downloads GROUP BY verdict;
SELECT source_host, downloads, total_bytes, verdicts FROM example_ext_download_summary WHERE user = 'j.doe';
SELECT name, level, own_bytes, total_bytes, subfolders FROM example_ext_folder_sizes WHERE folder = 'f-1' AND max_depth = 1;
```

`srv-01` has no stored rows, so the same statements return no rows
there, as do random nodes. On `srv-01`, `SELECT name, path, cmdline FROM
processes` lists catalog services alongside the built-in seeds.

See [docs/extensions.md](../../docs/extensions.md) for the formats.
