# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/huntbase-io/phantomfleet/security/advisories/new)
("Report a vulnerability" on the repository's **Security** tab). Do not open a
public issue, pull request or discussion for a suspected vulnerability.

Include the phantomfleet version (`phantomfleet --version`), how you ran it,
and steps to reproduce. We will acknowledge the report, keep you updated while
we look into it, and credit you in the advisory unless you prefer otherwise.

Security fixes are made on the latest release only.

## Scope

phantomfleet is a client: it enrolls simulated hosts into an osquery TLS
server and talks to it over HTTP(S). In scope are issues in phantomfleet
itself, for example:

- a server being able to make phantomfleet do something beyond what is
  documented below (for example, run commands while `--fake-results` is on,
  or read or write files other than its state file and `http_errors.log`);
- secrets (enroll secret, node keys) leaking into output or files beyond what
  is documented;
- vulnerabilities in the published binaries or container image.

Issues in osquery TLS servers themselves (osctrl, Fleet and others) should be
reported to those projects.

## Using phantomfleet safely

phantomfleet is a testing and demo tool. Keep these properties in mind.

**Only point it at servers you operate or are authorised to test.** It creates
hosts and generates load: in the README's [Scale](README.md#scale)
measurements, one process enrolled 5,000 nodes in about 6 seconds against
osctrl v0.6.2 with its enroll rate limit raised (osctrl's default allows 20
enrollments per minute per source address). Prefer
non-production servers. Simulated hosts in a production tenant can be mistaken
for real machines, skew inventories and alerts, and count against licences.

**Leave `--fake-results` on (the default) unless you mean otherwise.** With
`--fake-results=false`, every
distributed query the server sends is executed on the machine running
phantomfleet with `osqueryi`, once per simulated node. Anyone who can schedule
queries on that server can then read data from your machine. The container
image does not include `osqueryi`.

**`--insecure` disables TLS certificate verification** for every request,
including enrollment, which carries the enroll secret, and all subsequent
requests, which carry node keys. Use it only against lab servers with
self-signed certificates on networks you trust. Prefer adding the server's CA
to the system trust store instead.

**Treat the enroll secret as a credential.** Anyone holding it can enroll
hosts into that environment. Pass it from an environment variable or secret
store rather than typing it into shared shell history, use a dedicated
environment or secret for simulated fleets where your server supports it, and
rotate it when you are done if it was shared.

**Protect the state file.** `phantomfleet_state.json` (or your `--state` path)
contains every simulated node's node key, which authenticates as that node to
the server. It is written atomically with mode 0600 (an existing file with
wider permissions is replaced), and a state file that can't be parsed stops
the run rather than being overwritten; keep it out of version control and
shared volumes. Delete it, and remove the hosts on the server, when a
simulated fleet is retired.

**Output and logs.** The enroll secret and every node key are masked in
verbose output and `http_errors.log`, in JSON and non-JSON bodies alike
(every known secret value is replaced wherever it appears). Those still
contain hostnames, queries and server responses.

**Server-supplied SQL.** With `--fake-results` on, some statements are
answered by running them in an in-memory SQLite database that holds only
synthetic data (see the README's security notes for which). Only one
`SELECT` or `WITH` statement runs: SQLite's own tokenizer decides where it
ends and anything after it is refused. The connection allows no attached
databases (so no `ATTACH` or `VACUUM INTO`), never enables extension
loading, runs the statement with `query_only` on, and limits value size,
statement length, compound SELECTs, expression depth and run time.

**Don't impersonate real hosts.** A nodes file can pin any hostname, UUID or
serial number. Use invented identities; a simulated host that shadows a real
one can hide it or corrupt its inventory and alert history.

**`--spoof-real-ip` is off by default.** With it, every request carries the
node's simulated address in `X-Real-IP`, and servers that trust that header
(directly or behind a proxy) record it as the host's source address. Use it
only on servers you operate.

**Seed and nodes files are trusted input.** They are read from paths you pass
on the command line; don't load files from untrusted sources without reviewing
them.
