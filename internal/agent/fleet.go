package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/huntbase-io/phantomfleet/internal/host"
	"github.com/huntbase-io/phantomfleet/internal/protocol"
	"github.com/huntbase-io/phantomfleet/internal/stats"
	"github.com/huntbase-io/phantomfleet/internal/synth"
)

// Config holds the command-line configuration.
type Config struct {
	URL               string
	Flavor            string
	Env               string
	Paths             protocol.EndpointPaths
	Secret            string
	Nodes             int
	StatusInterval    int
	ResultInterval    int
	ConfigInterval    int
	QueryInterval     int
	Verbose           bool
	Insecure          bool
	OutputMode        stats.OutputMode
	SummaryInterval   int
	StateFile         string
	FakeResults       bool
	Explain           bool
	EnrollConcurrency int
	SeedsDirs         []string
	NodesFile         string
	SecretFile        string
	ExtraSchemas      []string
	Catalogs          []string
	SpoofRealIP       bool
	AllowLargeFleet   bool
}

// LargeFleet is the fleet size above which --allow-large-fleet is required:
// a guard against a typo, a state file or a nodes file turning a test into a
// flood.
const LargeFleet = 1000

// loadStateFile reads the state file. A missing file is not an error (nil
// nodes); a file that exists but cannot be read or parsed is, so a truncated
// or corrupt state never silently becomes a new fleet that re-enrolls every
// host and overwrites the old keys.
func loadStateFile(filename string) ([]host.Node, error) {
	nodes, err := host.LoadState(filename)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("state file %s cannot be loaded (%w); fix it or move it aside to start a new fleet", filename, err)
	}
	return nodes, nil
}

// buildNodes loads or generates the fleet: pinned nodes (--nodes-file) first,
// then nodes resumed from the state file, then random nodes up to --nodes.
// It refuses a fleet above LargeFleet without --allow-large-fleet, whatever
// made it that large.
func buildNodes(config Config, r *rand.Rand) ([]host.Node, error) {
	var nodes []host.Node
	var state []host.Node
	if config.StateFile != "" {
		var err error
		if state, err = loadStateFile(config.StateFile); err != nil {
			return nil, err
		}
	}

	switch {
	case config.NodesFile != "":
		// Pinned nodes come first; the state only contributes their
		// enrollment keys and any random nodes --nodes still asks for.
		pinned, err := host.LoadNodesFile(config.NodesFile)
		if err != nil {
			return nil, fmt.Errorf("--nodes-file %s: %w", config.NodesFile, err)
		}
		fmt.Printf("Loaded %d pinned node(s) from %s\n", len(pinned), config.NodesFile)
		total := max(config.Nodes, len(pinned))
		nodes = host.MergePinned(pinned, state, total)
		if extra := total - len(nodes); extra > 0 {
			fmt.Printf("Requested %d nodes; generating %d random node(s) beyond the pinned ones\n", total, extra)
			nodes = append(nodes, host.RandomNodes(extra, r, nodes, synth.ProfileOS)...)
		}
	case config.StateFile != "":
		fmt.Printf("Attempting to resume state from %s\n", config.StateFile)
		if len(state) > 0 {
			nodes = state
			fmt.Printf("Resumed %d nodes from state\n", len(nodes))
			// Scale up to the requested count without losing already-enrolled nodes.
			if extra := config.Nodes - len(nodes); extra > 0 {
				fmt.Printf("Requested %d nodes; generating %d more\n", config.Nodes, extra)
				nodes = append(nodes, host.RandomNodes(extra, r, nodes, synth.ProfileOS)...)
			}
		} else {
			fmt.Printf("No saved state found, generating %d nodes\n", config.Nodes)
			nodes = host.RandomNodes(config.Nodes, r, nil, synth.ProfileOS)
		}
	default:
		nodes = host.RandomNodes(config.Nodes, r, nil, synth.ProfileOS)
	}

	if len(nodes) > LargeFleet && !config.AllowLargeFleet {
		return nil, fmt.Errorf("the fleet has %d nodes (from --nodes, --nodes-file and the state file), above %d; add --allow-large-fleet if you mean it, and only against a server you operate", len(nodes), LargeFleet)
	}
	return nodes, nil
}

// redactedNodes returns a copy of nodes with their node keys masked, for printing.
func redactedNodes(nodes []host.Node) []host.Node {
	out := make([]host.Node, len(nodes))
	copy(out, nodes)
	for i := range out {
		if out[i].Key != "" {
			out[i].Key = "****"
		}
	}
	return out
}

// Run loads or generates the simulated nodes, enrolls them and runs their
// request loops until the process is interrupted. urls are the endpoint URLs
// from protocol.BuildEndpoints; userAgent is sent with every request.
func Run(config Config, urls map[string]string, userAgent string) {
	// #nosec G404 -- non-cryptographic randomness used only to simulate fake
	// node telemetry/timing.
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	nodes, err := buildNodes(config, r)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	upgradeLegacyNodes(nodes)

	// Mask the enroll secret and every known node key in anything printed or
	// logged from a server response (keys enrolled later register themselves).
	protocol.RegisterSecret(config.Secret)
	for _, n := range nodes {
		protocol.RegisterSecret(n.Key)
	}

	if config.Verbose {
		prettyJSON, _ := json.MarshalIndent(redactedNodes(nodes), "", "  ")
		fmt.Printf("%s\n", string(prettyJSON))
	}

	// Ctrl-C / SIGTERM (e.g. docker stop) cancels ctx; state is saved on the way out.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// One lock per node: its four request loops share the node's key and may
	// re-enroll it, and the state saver reads it.
	locks := make([]sync.Mutex, len(nodes))

	// Create HTTP client
	client := protocol.NewHTTPClient(config.Verbose, config.Insecure)
	client.SetUserAgent(userAgent)

	// Enroll nodes that have no key yet, using a bounded worker pool so large
	// cold starts (thousands of nodes) complete quickly instead of one-at-a-time.
	var toEnroll []int
	for i := range nodes {
		if nodes[i].Key == "" {
			toEnroll = append(toEnroll, i)
		}
	}
	if len(toEnroll) > 0 {
		workers := config.EnrollConcurrency
		if workers < 1 {
			workers = 1
		}
		if workers > len(toEnroll) {
			workers = len(toEnroll)
		}
		fmt.Printf("Enrolling %d nodes (%d in parallel)...\n", len(toEnroll), workers)

		enrolled := enrollNodes(ctx, client, nodes, toEnroll, workers, urls[protocol.EndpointEnroll], config)
		if ctx.Err() != nil {
			fmt.Printf("Interrupted during enrollment (%d of %d enrolled)\n", enrolled, len(toEnroll))
			saveState(nodes, locks, config.StateFile)
			return
		}
		if enrolled == len(toEnroll) {
			fmt.Printf("Enrollment complete: %d nodes\n", enrolled)
		} else {
			fmt.Printf("Enrollment complete: %d of %d nodes enrolled\n", enrolled, len(toEnroll))
		}
		// Persist the new keys now rather than waiting for the first periodic save.
		saveState(nodes, locks, config.StateFile)
	}

	// Periodically save state if state file is specified
	if config.StateFile != "" {
		go func(ctx context.Context) {
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					saveState(nodes, locks, config.StateFile)
				}
			}
		}(ctx)
	}

	// Set node counts in global stats
	stats.SetNodeCounts(len(nodes), len(nodes))

	// Start monitoring goroutines based on output mode
	switch config.OutputMode {
	case stats.SummaryMode:
		go stats.SummaryReporter(ctx, time.Duration(config.SummaryInterval)*time.Second)
	case stats.DashboardMode:
		go stats.DashboardReporter(ctx, 2*time.Second) // Update every 2 seconds
	case stats.JSONMode:
		go stats.JSONReporter(ctx, time.Duration(config.SummaryInterval)*time.Second)
	}

	// Start each node's request loops
	for i := range nodes {
		runNode(ctx, client, &nodes[i], &locks[i], urls, config)
	}

	// Print startup message based on output mode
	switch config.OutputMode {
	case stats.QuietMode:
		fmt.Printf("Started %d nodes in quiet mode. Press Ctrl+C to stop.\n", len(nodes))
	case stats.SummaryMode:
		fmt.Printf("Started %d nodes with summary reports every %d seconds. Press Ctrl+C to stop.\n", len(nodes), config.SummaryInterval)
	case stats.VerboseMode:
		fmt.Println("Started concurrent traffic simulation with verbose output. Press Ctrl+C to stop.")
	case stats.DashboardMode:
		fmt.Printf("Started %d nodes with real-time dashboard. Press Ctrl+C to stop.\n", len(nodes))
	case stats.JSONMode:
		fmt.Printf("Started %d nodes with JSON output every %d seconds. Press Ctrl+C to stop.\n", len(nodes), config.SummaryInterval)
	}

	<-ctx.Done()
	stop()
	if config.StateFile != "" {
		saveState(nodes, locks, config.StateFile)
		fmt.Printf("\nStopped; state saved to %s\n", config.StateFile)
	} else {
		fmt.Println("\nStopped")
	}
}

// saveState writes every node (keys included) to the state file, taking each
// node's lock so a key being replaced by re-enrollment is never torn. A blank
// filename disables state.
func saveState(nodes []host.Node, locks []sync.Mutex, filename string) {
	if filename == "" {
		return
	}
	snap := make([]host.Node, len(nodes))
	for i := range nodes {
		snap[i] = snapshot(&nodes[i], &locks[i])
	}
	if err := host.SaveState(snap, filename); err != nil {
		fmt.Printf("Failed to save state: %v\n", err)
	}
}

// upgradeLegacyNodes gives random nodes from an older state file (which had no
// OS of their own) the OS of their seed profile, so their os_version answers
// match what they report when they next enroll.
func upgradeLegacyNodes(nodes []host.Node) {
	for i := range nodes {
		if !nodes[i].Pinned && nodes[i].OS == nil {
			nodes[i].OS = synth.ProfileOS(nodes[i].Target)
		}
	}
}

// enrollNodes enrolls nodes[i] for every i in toEnroll with a pool of
// workers, storing each key in the node, and returns how many enrolled (got
// a key). Once ctx is done the remaining nodes are skipped.
func enrollNodes(ctx context.Context, client *protocol.HTTPClient, nodes []host.Node, toEnroll []int, workers int, enrollURL string, config Config) int {
	idxCh := make(chan int, len(toEnroll))
	for _, i := range toEnroll {
		idxCh <- i
	}
	close(idxCh)

	var wg sync.WaitGroup
	var attempted, enrolled int64
	var warnThrottle sync.Once
	throttledOnce := func(wait time.Duration) {
		warnThrottle.Do(func() {
			fmt.Printf("The server is rate-limiting enrollment (HTTP 429/503); retrying as it allows (first wait %s). Raise the server's enroll rate limit to enroll faster.\n", wait)
		})
	}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Each worker owns distinct indices, so writing nodes[i].Key is race-free.
			for i := range idxCh {
				if ctx.Err() != nil {
					continue // interrupted: drain without enrolling
				}
				nodes[i].Key = enrollWithBackoff(ctx, client, nodes[i], config.Secret, enrollURL, config, throttledOnce)
				if nodes[i].Key != "" {
					atomic.AddInt64(&enrolled, 1)
					if config.OutputMode == stats.VerboseMode {
						fmt.Printf("Enrolled %s as %s\n", nodes[i].Target, nodes[i].Name)
					}
				}
				if n := atomic.AddInt64(&attempted, 1); n%500 == 0 {
					fmt.Printf("  attempted %d/%d, enrolled %d\n", n, len(toEnroll), atomic.LoadInt64(&enrolled))
				}
			}
		}()
	}
	wg.Wait()
	return int(atomic.LoadInt64(&enrolled))
}
