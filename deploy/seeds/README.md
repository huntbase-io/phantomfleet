# Extra seed data (no rebuild required)

Drop YAML files here to add fake data on top of the image's built-in seeds. This
folder is bind-mounted into the container at `/seeds` and loaded at startup
(`--seeds-dir=/seeds`). Changes take effect on the next `up -d` / restart — no rebuild.

Recognised file names (only `*.yaml` is read; this `.md` is ignored):

- `all.yaml` — rows added to **every** platform profile
- `linux.yaml` / `darwin.yaml` / `windows.yaml` — rows added to that platform
- `rowcounts.yaml` — per-table `[min, max]` row counts, overriding the built-ins

Merging is **additive**: your rows are appended to the matching table, so the built-in
anchors/templates remain. Values can be fixed strings, `{{token}}` patterns, or a mix.

Example `linux.yaml`:

```yaml
processes:
  - pid: "31337"
    name: my-agent
    path: /opt/acme/bin/agent
  # patterned template — padding clones it with fresh values
  - pid: "{{int:300..65000}}"
    name: "{{choice:acme-worker|acme-sync|acme-scan}}"
    path: "/opt/acme/bin/{{word}}"

my_custom_table:
  - id: "1"
    label: "{{choice:prod|staging}}"
    address: "{{ipv4}}"
```

Tokens: `{{hostname}}` `{{shorthost}}` `{{ip}}` `{{uuid}}` `{{version}}`
`{{username}}` `{{ago:DURATION}}` (identity and time);
`{{int:MIN..MAX}}` `{{float:MIN..MAX}}` `{{choice:a|b|c}}` `{{ipv4}}` `{{mac}}`
`{{uuid4}}` `{{hex:N}}` `{{word}}` `{{words}}` `{{semver}}` `{{bool}}`
`{{unixtime[:MIN..MAX]}}` `{{date}}` (generators); `{{row:CATALOG.FIELD}}`
(with `--catalog`). See [docs/seeds.md](../../docs/seeds.md) for each one.

A file that isn't valid YAML stops phantomfleet at start-up with an error
naming the file.

Add `<table>: [min, max]` to `rowcounts.yaml` here to control how many rows a new or
existing table reports.
