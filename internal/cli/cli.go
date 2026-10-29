// Package cli is the phantomfleet command line: flags, usage, validation and
// the enroll secret, then hands the configured fleet to agent.Run.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/huntbase-io/phantomfleet/internal/agent"
	"github.com/huntbase-io/phantomfleet/internal/protocol"
	"github.com/huntbase-io/phantomfleet/internal/stats"
	"github.com/huntbase-io/phantomfleet/internal/synth"
)

// version is what -h and --version print. Main sets it to the ldflags value
// (main.version) and, once the flags are parsed, resolves it with
// buildVersion.
var version string

// largeFleet is the fleet size above which --allow-large-fleet is required.
// validateConfig checks --nodes early; agent.Run checks the final count
// (pinned and resumed nodes included).
const largeFleet = agent.LargeFleet

const (
	defaultURL = "http://localhost:9000/"

	LOG_INTERVAL        = 60
	CONFIG_INTERVAL     = 45
	QUERY_READ_INTERVAL = 30

	STATE_JSON = "phantomfleet_state.json"
)

// secretEnv names the environment variable that can carry the enroll secret.
const secretEnv = "PHANTOMFLEET_SECRET"

// cliOptions are the parsed flags that are not part of Config itself.
type cliOptions struct {
	outputMode  string
	showVersion bool
}

// registerFlags defines every command-line flag (and its short alias) on fs.
func registerFlags(fs *flag.FlagSet, config *agent.Config, opts *cliOptions) {
	fs.StringVar(&config.URL, "url", defaultURL, "Base URL of the osquery TLS server")
	fs.StringVar(&config.URL, "u", defaultURL, "Base URL of the osquery TLS server")
	fs.StringVar(&config.Flavor, "flavor", protocol.FlavorOsctrl, "Server flavor: osctrl (environment-scoped URLs, needs --env) or generic (standard osquery TLS paths, e.g. Fleet)")
	fs.StringVar(&config.Env, "env", "", "Environment UUID (required with --flavor osctrl, ignored with generic)")
	fs.StringVar(&config.Paths.Enroll, "enroll-path", "", "Override the enroll endpoint path (appended to --url)")
	fs.StringVar(&config.Paths.Config, "config-path", "", "Override the config endpoint path (appended to --url)")
	fs.StringVar(&config.Paths.Log, "log-path", "", "Override the log endpoint path (appended to --url)")
	fs.StringVar(&config.Paths.Read, "read-path", "", "Override the distributed read endpoint path (appended to --url)")
	fs.StringVar(&config.Paths.Write, "write-path", "", "Override the distributed write endpoint path (appended to --url)")
	fs.StringVar(&config.Secret, "secret", "", "Enroll secret for the osquery TLS server (visible in the process list; prefer --secret-file or $"+secretEnv+")")
	fs.StringVar(&config.Secret, "s", "", "Shorthand for --secret")
	fs.StringVar(&config.SecretFile, "secret-file", "", "File holding the enroll secret (surrounding whitespace is trimmed)")
	fs.IntVar(&config.Nodes, "nodes", 5, "Number of nodes to simulate (with --nodes-file: the fleet size, pinned nodes first, the rest random)")
	fs.IntVar(&config.Nodes, "n", 5, "Shorthand for --nodes")
	fs.IntVar(&config.StatusInterval, "status", LOG_INTERVAL, "Interval in seconds for status log requests")
	fs.IntVar(&config.StatusInterval, "S", LOG_INTERVAL, "Interval in seconds for status log requests")
	fs.IntVar(&config.ResultInterval, "result", LOG_INTERVAL, "Interval in seconds for result log requests")
	fs.IntVar(&config.ResultInterval, "R", LOG_INTERVAL, "Interval in seconds for result log requests")
	fs.IntVar(&config.ConfigInterval, "config", CONFIG_INTERVAL, "Interval in seconds for config requests")
	fs.IntVar(&config.ConfigInterval, "c", CONFIG_INTERVAL, "Interval in seconds for config requests")
	fs.IntVar(&config.QueryInterval, "query", QUERY_READ_INTERVAL, "Interval in seconds for distributed query read requests")
	fs.IntVar(&config.QueryInterval, "q", QUERY_READ_INTERVAL, "Interval in seconds for distributed query read requests")
	fs.BoolVar(&config.Insecure, "insecure", false, "Skip TLS certificate verification")
	fs.BoolVar(&config.FakeResults, "fake-results", true, "Answer distributed queries with synthetic rows. Set --fake-results=false to run them through osqueryi instead, which lets the server run arbitrary osquery SQL on this machine")
	fs.BoolVar(&config.FakeResults, "f", true, "Shorthand for --fake-results")
	fs.BoolVar(&config.Explain, "explain", false, "Log how each fake-result query is decomposed (tables, seeding, row counts)")
	fs.IntVar(&config.EnrollConcurrency, "enroll-concurrency", 50, "Number of nodes to enroll in parallel at startup")
	fs.Var((*stringList)(&config.SeedsDirs), "seeds-dir", "Directory of extra seed YAML to layer over the built-in fake data (additive); repeatable, layered in the order given")
	fs.StringVar(&config.NodesFile, "nodes-file", "", "YAML file pinning node identities (hostname, platform, OS, IP, uuid); the fleet size is the larger of --nodes and the pinned count")
	fs.Var((*stringList)(&config.ExtraSchemas), "extra-schema", "JSON file of extension tables in the shape of the embedded osquery schema ({\"table\": [{\"name\", \"type\"}]}); repeatable")
	fs.Var((*stringList)(&config.Catalogs), "catalog", "YAML file of row catalogs for {{row:<catalog>.<field>}} seed tokens; repeatable")
	fs.BoolVar(&config.SpoofRealIP, "spoof-real-ip", false, "Send each node's simulated IP in an X-Real-IP header, so servers that trust the header record it (only for servers you operate)")
	fs.BoolVar(&config.AllowLargeFleet, "allow-large-fleet", false, fmt.Sprintf("Allow a fleet of more than %d nodes (counting random, pinned and resumed nodes)", largeFleet))
	fs.BoolVar(&config.Verbose, "verbose", false, "Enable verbose output")
	fs.BoolVar(&config.Verbose, "v", false, "Enable verbose output")
	fs.StringVar(&config.StateFile, "state", STATE_JSON, "JSON file to persist and resume node state (empty to disable)")
	fs.StringVar(&opts.outputMode, "mode", "summary", "Output mode: quiet, summary, verbose, dashboard, json")
	fs.IntVar(&config.SummaryInterval, "summary-interval", 30, "Interval in seconds for summary reports")
	fs.BoolVar(&opts.showVersion, "version", false, "Print the version and exit")
}

// usage prints the command synopsis followed by the flag defaults.
func usage(fs *flag.FlagSet) func() {
	return func() {
		out := fs.Output()
		fmt.Fprintf(out, "phantomfleet %s - simulate a fleet of osquery hosts against an osquery TLS server\n\n", version)
		fmt.Fprintf(out, "Usage:\n")
		fmt.Fprintf(out, "  phantomfleet --url https://tls.example.com --env <uuid> --secret-file <file> [flags]   (osctrl)\n")
		fmt.Fprintf(out, "  phantomfleet --flavor generic --url https://fleet.example.com --secret-file <file> [flags]\n\n")
		fmt.Fprintf(out, "The enroll secret comes from --secret-file, $%s or --secret (visible to other local users).\n\n", secretEnv)
		fmt.Fprintf(out, "Flags:\n")
		fs.PrintDefaults()
	}
}

// parseOutputMode maps a --mode value to an OutputMode.
func parseOutputMode(mode string) (stats.OutputMode, error) {
	switch strings.ToLower(mode) {
	case "quiet":
		return stats.QuietMode, nil
	case "summary":
		return stats.SummaryMode, nil
	case "verbose":
		return stats.VerboseMode, nil
	case "dashboard":
		return stats.DashboardMode, nil
	case "json":
		return stats.JSONMode, nil
	default:
		return 0, fmt.Errorf("invalid output mode %q; valid modes: quiet, summary, verbose, dashboard, json", mode)
	}
}

// Main runs phantomfleet. ldflagsVersion is main.version, set at build time
// with -ldflags "-X main.version=...".
func Main(ldflagsVersion string) {
	version = ldflagsVersion
	var config agent.Config
	var opts cliOptions
	fs := flag.CommandLine
	registerFlags(fs, &config, &opts)
	fs.Usage = usage(fs)
	flag.Parse()
	version = buildVersion(version)

	if opts.showVersion {
		fmt.Printf("phantomfleet %s\n", version)
		return
	}

	mode, err := parseOutputMode(opts.outputMode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	config.OutputMode = mode
	if config.Verbose {
		config.OutputMode = stats.VerboseMode
	}

	if err := validateConfig(config); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	secret, err := resolveSecret(config.Secret, config.SecretFile, os.Getenv(secretEnv))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
		fs.Usage()
		os.Exit(1)
	}
	config.Secret = secret

	urls, err := protocol.BuildEndpoints(config.URL, config.Flavor, config.Env, config.Paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
		fs.Usage()
		os.Exit(1)
	}
	config.Flavor = strings.ToLower(strings.TrimSpace(config.Flavor))
	if config.Flavor == protocol.FlavorGeneric && config.Env != "" {
		fmt.Printf("Note: --env is ignored with --flavor %s\n", protocol.FlavorGeneric)
	}

	fmt.Printf("phantomfleet %s (flavor %s)\n", version, config.Flavor)
	printEndpoints(os.Stdout, urls)
	if !config.FakeResults {
		fmt.Println("Warning: --fake-results=false; distributed queries from the server run on this machine via osqueryi")
	}

	// Enable query decomposition logging for --fake-results when requested.
	synth.SetExplain(config.Explain)

	if err := synth.LoadData(config.ExtraSchemas, config.Catalogs, config.SeedsDirs, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	agent.Run(config, urls, protocol.UserAgent(version))
}

// buildVersion returns the ldflags version when set, else the module version
// recorded by `go install github.com/huntbase-io/phantomfleet@vX.Y.Z`, else
// "dev" (a local `go build` of a working tree).
func buildVersion(ldflagsVersion string) string {
	if ldflagsVersion != "" && ldflagsVersion != "dev" {
		return ldflagsVersion
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		if v := bi.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	return "dev"
}

// validateConfig rejects settings that would panic or misbehave later:
// non-positive intervals, a negative node count and, without
// --allow-large-fleet, a --nodes value above largeFleet (the final fleet size
// is checked again once the nodes file and state are loaded).
func validateConfig(c agent.Config) error {
	for _, iv := range []struct {
		name string
		v    int
	}{
		{"--status", c.StatusInterval}, {"--result", c.ResultInterval}, {"--config", c.ConfigInterval},
		{"--query", c.QueryInterval}, {"--summary-interval", c.SummaryInterval},
	} {
		if iv.v <= 0 {
			return fmt.Errorf("%s must be a positive number of seconds, got %d", iv.name, iv.v)
		}
	}
	if c.Nodes < 0 {
		return fmt.Errorf("--nodes must not be negative, got %d", c.Nodes)
	}
	if c.Nodes > largeFleet && !c.AllowLargeFleet {
		return fmt.Errorf("--nodes %d is above %d; add --allow-large-fleet if you mean it, and only against a server you operate", c.Nodes, largeFleet)
	}
	return nil
}

// resolveSecret picks the enroll secret from --secret, --secret-file or the
// environment, in that order of precedence. Giving both flags is an error.
func resolveSecret(flagSecret, secretFile, envSecret string) (string, error) {
	if flagSecret != "" && secretFile != "" {
		return "", errors.New("use only one of --secret and --secret-file")
	}
	if flagSecret != "" {
		return flagSecret, nil
	}
	if secretFile != "" {
		// #nosec G304 -- operator-supplied secret file path.
		raw, err := os.ReadFile(filepath.Clean(secretFile))
		if err != nil {
			return "", fmt.Errorf("--secret-file: %w", err)
		}
		s := strings.TrimSpace(string(raw))
		if s == "" {
			return "", fmt.Errorf("--secret-file %s is empty", secretFile)
		}
		return s, nil
	}
	if s := strings.TrimSpace(envSecret); s != "" {
		return s, nil
	}
	return "", fmt.Errorf("an enroll secret is required: set $%s, --secret-file or --secret", secretEnv)
}

// printEndpoints lists the resolved endpoint URLs in a stable order.
func printEndpoints(w io.Writer, urls map[string]string) {
	for _, ep := range []struct{ name, key string }{
		{"enroll", protocol.EndpointEnroll}, {"config", protocol.EndpointConfig}, {"log", protocol.EndpointLog}, {"read", protocol.EndpointRead}, {"write", protocol.EndpointWrite},
	} {
		fmt.Fprintf(w, "  %-7s %s\n", ep.name, urls[ep.key])
	}
}

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}
