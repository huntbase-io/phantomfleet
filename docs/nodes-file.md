# Nodes file reference

`--nodes-file` loads a YAML file that pins node identities: hostnames,
platforms, IPs, OS and hardware details, and stable identifiers. Pinned nodes
look the same on every run, so the server keeps the same hosts, and their
answers are curated for consistency across tables.

## Format

```yaml
namespace: 2b7c1e44-9d3a-5f1e-8c6b-4a0e9f3d7a11   # optional
nodes:
  - hostname: eng-ws-07.corp.example.com
    platform: darwin
    ip: 10.14.41.107
    uuid_seed: examplecorp/eng-ws-07
    osquery_version: "5.24.0"
    primary_user: m.delgado
    os:
      name: macOS
      version: "14.5"
      major: "14"
      minor: "5"
      patch: "0"
      build: 23F79
      platform: darwin
      platform_like: darwin
      arch: arm64
    hardware:
      vendor: Apple Inc.
      model: Mac15,3
      serial: C02EXC07MBP
      cpu_brand: Apple M3
      cpu_cores: 8
      physical_memory: 25769803776
```

### Top level

| Key | Description |
|---|---|
| `namespace` | UUID used as the UUIDv5 namespace for `uuid_seed` and hostnames. Optional; a fixed built-in namespace is used when omitted. |
| `nodes` | List of node entries. |

### Node entry

| Key | Required | Description |
|---|---|---|
| `hostname` | yes | Fully qualified hostname. The first label is the short name. |
| `platform` | yes | Platform name, lower-cased. Selects the seed profile (`darwin*`/`macos` to darwin, `windows*` to windows, anything else to linux) and the enrollment `platform_type`. |
| `ip` | no | The address the host reports (`{{ip}}` in seeds, `interface_addresses`); sent as `X-Real-IP` with `--spoof-real-ip`. |
| `uuid` | no | Explicit host identifier (any UUID). |
| `uuid_seed` | no | String to derive the identifier from. |
| `osquery_version` | no | Reported osquery version. Default `5.24.0`, the embedded schema's version. |
| `primary_user` | no | The host's main user. Fills `{{username}}` and user-like columns. Default: `Administrator` on Windows, `root` elsewhere. |
| `os` | no | What the host reports in `os_version` and at enrollment. Fields: `name`, `version`, `major`, `minor`, `patch`, `build`, `codename`, `platform`, `platform_like`, `arch` (default `x86_64`). Without it, enrollment uses a generic default for the platform. |
| `hardware` | no | What the host reports in `system_info` and at enrollment. Fields: `vendor`, `model`, `version`, `serial`, `cpu_brand`, `cpu_cores` (logical cores; physical cores are reported as half), `physical_memory` (bytes). |

Quote values YAML might reinterpret, such as versions (`"14.5"`) and numeric
strings (`"04"`).

## Identifiers

The host identifier is, in order of preference:

1. `uuid`, if set;
2. UUIDv5(`namespace`, `uuid_seed`), if `uuid_seed` is set;
3. UUIDv5(`namespace`, `hostname`).

Identifiers are reported upper-case. Two entries resolving to the same
identifier are rejected at startup.

Because identifiers are derived, renaming a host without a `uuid_seed` changes
its identifier, and the server sees a new host. Set `uuid_seed` (or `uuid`) on
every entry if hostnames might change. Changing `namespace` changes every
derived identifier.

## What pinned nodes report

- **Enrollment** sends the pinned OS and hardware, with `computer_name` and
  `local_hostname` set to the short name.
- **`os_version`, `system_info`, `osquery_info`** answer from the nodes file:
  one row each, with the identifier as `uuid`, the hardware serial as
  `hardware_serial`, and so on.
- **Identity columns** in every table carry the node's own values (hostname,
  short name, identifier, serial). User-like columns carry `primary_user`.
- **Curated tables**: a table the platform profile declares is answered from
  seed rows only, with no schema-generated rows, and columns a seed row
  omits are empty. See [synthetic results](synthetic-results.md#3-pinned-curated-nodes).
- **Joins** with equality `ON` predicates are evaluated rather than
  zip-merged.

Pinned nodes still use the shared platform seeds. To make a host report
exactly what you wrote, combine the nodes file with a `--seeds-dir` that uses
`_hosts` rows and `_replace` (see [seeds](seeds.md)).

## Interaction with `--nodes` and `--state`

- The fleet size is the larger of `--nodes` and the number of pinned nodes.
  Pinned nodes come first, in file order; any remainder is random nodes. With
  the default `--nodes 5`, a 15-entry file runs exactly 15 nodes.
- On restart, each pinned node takes its enrollment key from the state file
  (matched by identifier), so it is not re-enrolled. Its other fields are
  refreshed from the nodes file, so you can edit OS, hardware or users between
  runs.
- Random nodes saved in the state are kept, up to the fleet size.
- Removing an entry from the file stops simulating that host; the server still
  has its record.

## Validating a file

Run phantomfleet with the file and `--mode verbose` against a test server, or
check the startup line `Loaded N pinned node(s) from <file>`. Parse errors name
the entry number and hostname.
