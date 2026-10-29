package cli

import (
	"flag"
	"io"
	"strings"
	"testing"

	"github.com/huntbase-io/phantomfleet/internal/agent"
	"github.com/huntbase-io/phantomfleet/internal/protocol"
)

func TestFlagsAndAliases(t *testing.T) {
	var cfg agent.Config
	var opts cliOptions
	fs := flag.NewFlagSet("phantomfleet", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	registerFlags(fs, &cfg, &opts)
	err := fs.Parse([]string{
		"-u", "https://tls.example.com", "-s", "sekrit", "-n", "7", "-S", "11", "-R", "12",
		"-c", "13", "-q", "14", "-f", "-v", "--flavor", "generic", "--read-path", "/r", "--version",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.URL != "https://tls.example.com" || cfg.Secret != "sekrit" || cfg.Nodes != 7 ||
		cfg.StatusInterval != 11 || cfg.ResultInterval != 12 || cfg.ConfigInterval != 13 || cfg.QueryInterval != 14 ||
		!cfg.FakeResults || !cfg.Verbose || cfg.Flavor != protocol.FlavorGeneric || cfg.Paths.Read != "/r" || !opts.showVersion {
		t.Fatalf("unexpected config: %+v %+v", cfg, opts)
	}

	var defCfg agent.Config
	var defOpts cliOptions
	fs = flag.NewFlagSet("phantomfleet", flag.ContinueOnError)
	registerFlags(fs, &defCfg, &defOpts)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if defCfg.Flavor != protocol.FlavorOsctrl || defCfg.StateFile != "phantomfleet_state.json" || defOpts.outputMode != "summary" {
		t.Fatalf("unexpected defaults: %+v %+v", defCfg, defOpts)
	}
}

func TestValidateConfig(t *testing.T) {
	ok := agent.Config{Nodes: 5, StatusInterval: 1, ResultInterval: 1, ConfigInterval: 1, QueryInterval: 1, SummaryInterval: 1}
	if err := validateConfig(ok); err != nil {
		t.Fatal(err)
	}
	bad := ok
	bad.QueryInterval = 0
	if err := validateConfig(bad); err == nil {
		t.Error("a zero interval was accepted")
	}
	big := ok
	big.Nodes = largeFleet + 1
	if err := validateConfig(big); err == nil || !strings.Contains(err.Error(), "--allow-large-fleet") {
		t.Errorf("large fleet without the flag: %v", err)
	}
	big.AllowLargeFleet = true
	if err := validateConfig(big); err != nil {
		t.Errorf("large fleet with the flag: %v", err)
	}
}

func TestBuildVersionPrefersLdflags(t *testing.T) {
	if v := buildVersion("v1.2.3"); v != "v1.2.3" {
		t.Errorf("buildVersion(v1.2.3) = %s", v)
	}
	// In a test binary the main module version is "(devel)" or empty.
	if v := buildVersion("dev"); v == "" {
		t.Error("empty version")
	}
}

func TestSeedsDirFlagRepeats(t *testing.T) {
	var cfg agent.Config
	var opts cliOptions
	fs := flag.NewFlagSet("pf", flag.ContinueOnError)
	registerFlags(fs, &cfg, &opts)
	if err := fs.Parse([]string{"--seeds-dir", "base", "--seeds-dir=estate"}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(cfg.SeedsDirs, ",") != "base,estate" {
		t.Fatalf("seeds dirs = %v", cfg.SeedsDirs)
	}
}

func TestLoaderFlagsRepeat(t *testing.T) {
	var cfg agent.Config
	var opts cliOptions
	fs := flag.NewFlagSet("pf", flag.ContinueOnError)
	registerFlags(fs, &cfg, &opts)
	err := fs.Parse([]string{"--extra-schema", "a.json", "--extra-schema=b.json", "--catalog", "c.yaml", "--catalog", "d.yaml", "--secret-file", "s"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(cfg.ExtraSchemas, ",") != "a.json,b.json" || strings.Join(cfg.Catalogs, ",") != "c.yaml,d.yaml" || cfg.SecretFile != "s" {
		t.Fatalf("parsed %+v", cfg)
	}
}
