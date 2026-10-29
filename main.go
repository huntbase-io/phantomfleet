// Command phantomfleet simulates a fleet of osquery hosts against an osquery
// TLS server: each simulated host enrolls, polls for config, sends status and
// result logs, and answers distributed queries (optionally with realistic,
// schema-aware synthetic rows).
package main

import "github.com/huntbase-io/phantomfleet/internal/cli"

// version is set at build time with -ldflags "-X main.version=...". Builds
// without it (go install module@version) report the module version instead;
// see cli's buildVersion.
var version = "dev"

func main() {
	cli.Main(version)
}
