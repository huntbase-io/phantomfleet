package agent

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"time"
)

// OSQUERYI is the osqueryi binary run for --fake-results=false.
const OSQUERYI = "osqueryi"

// osqueryTimeout bounds a single osqueryi run.
const osqueryTimeout = 60 * time.Second

// osqueryCommand builds the osqueryi invocation for a distributed query.
//
// The query text comes from the remote TLS server, so it is fed to osqueryi on
// stdin rather than as an argument: a query beginning with "-" must never be
// parsed as an osqueryi flag.
func osqueryCommand(ctx context.Context, query string) *exec.Cmd {
	q := strings.TrimSpace(query)
	if !strings.HasSuffix(q, ";") {
		q += ";"
	}
	cmd := exec.CommandContext(ctx, OSQUERYI, "--json") // #nosec G204 -- fixed binary and arguments; the query is passed on stdin
	cmd.Stdin = strings.NewReader(q + "\n")
	return cmd
}

// executeOSQuery runs a distributed query with the local osqueryi binary.
//
// SECURITY: this is only used without --fake-results. In that mode the TLS
// server can run arbitrary osquery SQL on the machine running phantomfleet,
// exactly as it could against a real osquery agent. Only point it at servers
// you trust.
func executeOSQuery(query string) ([]map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), osqueryTimeout)
	defer cancel()
	output, err := osqueryCommand(ctx, query).Output()
	if err != nil {
		return nil, err
	}

	var results []map[string]interface{}
	if err := json.Unmarshal(output, &results); err != nil {
		return nil, err
	}

	return results, nil
}
