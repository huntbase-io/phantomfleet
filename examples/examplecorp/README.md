# Example Corp sample fleet

Example Corp is a fictional 15-host company for demos, query development and
end-to-end tests. Every host is pinned (stable hostname, IP, OS, hardware and
UUID), and the seed data gives the estate vulnerable software, ordinary
business inventory and one intrusion story to work through.

All names, addresses, serials, keys and indicators are invented. The domain is
`corp.example.com`, internal addresses are in `10.14.0.0/16`, and external
indicators use reserved documentation ranges (`203.0.113.0/24`, `*.test`).

## Files

| File | Purpose |
|---|---|
| `nodes.yaml` | The 15 pinned hosts (`--nodes-file`). |
| `seeds/linux.yaml` | Linux hosts and the PAN-OS appliances. |
| `seeds/windows.yaml` | Windows servers and workstations, including the intrusion story. |
| `seeds/darwin.yaml` | macOS workstations. |
| `seeds/rowcounts.yaml` | Row counts for the tables these seeds add. |

## Run it

```bash
export PHANTOMFLEET_SECRET="$ENROLL_SECRET"

# osctrl
phantomfleet \
  --url https://osctrl-tls.example.com --env "$ENV_UUID" \
  --nodes-file examples/examplecorp/nodes.yaml \
  --seeds-dir examples/examplecorp/seeds \
  --state examplecorp_state.json

# Fleet or another standard server
phantomfleet --flavor generic \
  --url https://fleet.example.com \
  --nodes-file examples/examplecorp/nodes.yaml \
  --seeds-dir examples/examplecorp/seeds \
  --state examplecorp_state.json
```

Both files are needed: the nodes file without the seeds gives you the right
hosts with generic platform data. With the default `--nodes 5`, exactly the 15
pinned hosts run. Use a dedicated `--state` file so Example Corp's enrollment
keys don't mix with other runs. A Compose setup is in [`deploy/`](../../deploy/).

Host UUIDs are derived from the file's `namespace` and each host's
`uuid_seed`, so they are identical everywhere this example runs.

## The estate

| Host | Role | Platform | OS | IP | Primary user |
|---|---|---|---|---|---|
| `web-prod-01` | Web / payment portal | ubuntu | Ubuntu 22.04.4 LTS | 10.14.22.31 | svc_deploy |
| `web-prod-02` | Web | ubuntu | Ubuntu 22.04.4 LTS | 10.14.22.32 | svc_deploy |
| `db-primary` | PostgreSQL 14 | ubuntu | Ubuntu 22.04.4 LTS | 10.14.30.10 | svc_backup |
| `build-runner-03` | CI runner | ubuntu | Ubuntu 24.04 LTS | 10.14.50.13 | svc_deploy |
| `jump-01` | SSH bastion | ubuntu | Ubuntu 22.04.4 LTS | 10.14.2.5 | (root) |
| `fw-edge-01` | Edge firewall | panos | PAN-OS 11.1.0 | 10.14.1.1 | (root) |
| `vpn-gw-01` | GlobalProtect VPN | panos | PAN-OS 11.1.0 | 10.14.1.20 | (root) |
| `dc-01` | Domain controller | windows | Windows Server 2022 | 10.14.5.10 | (Administrator) |
| `file-srv-01` | File server | windows | Windows Server 2022 | 10.14.5.40 | svc_backup |
| `finance-ws-12` | Finance workstation | windows | Windows 11 Enterprise 23H2 | 10.14.40.112 | a.harper |
| `finance-ws-13` | Finance workstation | windows | Windows 11 Enterprise 23H2 | 10.14.40.113 | s.novak |
| `hr-ws-03` | HR workstation | windows | Windows 11 Enterprise 23H2 | 10.14.42.103 | j.chen |
| `sales-ws-21` | Sales workstation | windows | Windows 11 Enterprise 23H2 | 10.14.43.121 | p.ivanova |
| `eng-ws-07` | Engineering laptop | darwin | macOS 14.5 (arm64) | 10.14.41.107 | m.delgado |
| `eng-ws-22` | Engineering laptop | darwin | macOS 14.5 (arm64) | 10.14.41.122 | r.okonkwo |

All hostnames end in `.corp.example.com`. Users in parentheses are the platform
default reported when no `primary_user` is set. The PAN-OS appliances are
enrolled as osquery hosts so they appear in the fleet; their platform is not
macOS or Windows, so they answer from the Linux seed profile. Hardware
ranges from VMware VMs to Dell, Lenovo and HP laptops, Apple M3 MacBooks and
Palo Alto PA-3220 appliances.

The seeds use `_replace` for identity tables (`users`, `groups`,
`user_groups`, `logged_in_users`, `interface_addresses`, `usb_devices`,
`chrome_extensions`, `platform_info`, `last`, and `patches` on Windows), so
those tables report exactly the curated rows: local accounts and logins that
match each host's users, interfaces on the pinned IPs, and so on.

## Vulnerable software

| Host(s) | Finding | Where to look |
|---|---|---|
| `web-prod-01` | log4j-core 2.14.1 in `/opt/payment-portal/lib` (CVE-2021-44228) | `deb_packages`, `file`, `processes` |
| `web-prod-01`, `web-prod-02` | nginx 1.24.0 (CVE-2023-44487) | `deb_packages`, `processes`, `listening_ports` |
| `fw-edge-01`, `vpn-gw-01` | PAN-OS 11.1.0 with GlobalProtect (CVE-2024-3400) | `os_version`, `processes`, `listening_ports` |
| `eng-ws-07`, `eng-ws-22` | Google Chrome 116.0.5845.96, bundled libwebp (CVE-2023-4863) | `apps` |
| `eng-ws-07`, `eng-ws-22` | Homebrew `webp` 1.3.1 (CVE-2023-4863) | `homebrew_packages` |
| `sales-ws-21` | An unwanted browser toolbar ("Search Toolbar Plus") | `programs` |

Other details worth finding: an AWS credentials file in the deploy
account's home directory on `build-runner-03`, the database backup cron job on `db-primary`, and an SSH key
on `jump-01` belonging to an engineer's laptop.

## The story: driver in the finance wing

`finance-ws-12` (user `a.harper`) shows a bring-your-own-vulnerable-driver
intrusion. Event timestamps use `{{ago:..}}`, so the story always happened
about a day before you query it.

1. `Invoice_0921.zip` lands in the user's Downloads and is extracted; the user
   opens `Invoice_0921.lnk`.
2. A hidden, encoded PowerShell process (`powershell.exe -NoP -W Hidden -Enc ...`,
   child of `explorer.exe`) downloads a payload from `update.example-c2.test`
   (`203.0.113.42`) to `%TEMP%\rtc.sys`.
3. `sc.exe` registers and starts `rtc.sys` as the `RTCore64` kernel driver
   service, a signed but vulnerable MSI Afterburner driver known from
   LOLDrivers.
4. Microsoft Defender services (`WinDefend`, `Sense`, `WdNisSvc`) are stopped on
   this host only; every other Windows host still runs `WinDefend`.
5. The host opens an SMB connection to `file-srv-01` (`10.14.5.40:445`) and
   starts renaming files on the `D:\Shares\finance` share. The bulk rename is
   blocked, leaving one spreadsheet renamed to
   `Vendor_Payments_Sep.xlsx.locked` next to untouched files.

Tables involved: `processes`, `process_events`, `file`, `hash`, `drivers`,
`services`, `socket_events`, `listening_ports`.

## Queries to try

```sql
-- Which Windows hosts have Defender stopped?
SELECT name, status, start_type FROM services WHERE name = 'WinDefend';

-- Encoded PowerShell
SELECT pid, parent, name, cmdline FROM processes WHERE cmdline LIKE '%-Enc%';

-- Kernel drivers loaded from user-writable paths
SELECT device_name, image, provider, signed FROM drivers WHERE image LIKE '%\Temp\%';

-- Hash the dropped driver
SELECT path, sha256 FROM hash WHERE path LIKE '%rtc.sys';

-- Outbound connections from PowerShell
SELECT pid, path, remote_address, remote_port FROM socket_events WHERE path LIKE '%powershell%';

-- Vulnerable Chrome on macOS
SELECT name, bundle_short_version FROM apps WHERE bundle_identifier = 'com.google.Chrome';

-- log4j on disk
SELECT path, size FROM file WHERE path LIKE '%log4j-core%';

-- Who is logged in where (scalar subqueries are supported)
SELECT user, (SELECT hostname FROM system_info) AS hostname FROM logged_in_users;
```

Remember that answers are synthetic and SQL support is heuristic; see
[docs/synthetic-results.md](../../docs/synthetic-results.md).

## Customising

- Keep `nodes.yaml` and the seeds in step: the seeds name hosts by short name
  in `_hosts`, and their identity tables reflect each host's users and IPs.
- To add a host, add an entry to `nodes.yaml` with its own `uuid_seed`, then
  add `_hosts` rows for it to the seed file of its platform.
- To add story events, prefer `{{ago:..}}` timestamps and `_hosts` rows on the
  hosts involved; use `_key` to replace a row every host has (as the stopped
  `WinDefend` does).
