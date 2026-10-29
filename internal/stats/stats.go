package stats

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// OutputMode defines the output verbosity level
type OutputMode int

const (
	QuietMode OutputMode = iota
	SummaryMode
	VerboseMode
	DashboardMode
	JSONMode
)

// OperationType represents different types of operations
type OperationType int

const (
	EnrollOp OperationType = iota
	StatusOp
	ResultOp
	ConfigOp
	QueryReadOp
	QueryWriteOp
)

// LatencyStats tracks latency statistics for an operation type
type LatencyStats struct {
	mu           sync.RWMutex
	latencies    []time.Duration
	min          time.Duration
	max          time.Duration
	total        time.Duration
	count        int64
	successCount int64
	failCount    int64
}

// OperationStats tracks statistics for all operation types
type OperationStats struct {
	enroll     LatencyStats
	status     LatencyStats
	result     LatencyStats
	config     LatencyStats
	queryRead  LatencyStats
	queryWrite LatencyStats
}

// URLStats tracks statistics per URL endpoint
type URLStats struct {
	mu    sync.RWMutex
	stats map[string]*LatencyStats
}

// GlobalStats holds global statistics
type GlobalStats struct {
	mu          sync.RWMutex
	operations  OperationStats
	urls        URLStats
	startTime   time.Time
	totalNodes  int
	activeNodes int
	lastUpdate  time.Time
}

// globalStats is the process-wide statistics instance.
var globalStats = &GlobalStats{
	startTime: time.Now(),
	urls: URLStats{
		stats: make(map[string]*LatencyStats),
	},
}

// AddLatency adds a latency measurement to the statistics
func (ls *LatencyStats) AddLatency(latency time.Duration, success bool) {
	ls.mu.Lock()
	defer ls.mu.Unlock()

	ls.latencies = append(ls.latencies, latency)
	ls.count++

	if success {
		ls.successCount++
	} else {
		ls.failCount++
	}

	ls.total += latency

	if ls.count == 1 {
		ls.min = latency
		ls.max = latency
	} else {
		if latency < ls.min {
			ls.min = latency
		}
		if latency > ls.max {
			ls.max = latency
		}
	}

	// Keep only last 1000 measurements for percentile calculations
	if len(ls.latencies) > 1000 {
		ls.latencies = ls.latencies[len(ls.latencies)-1000:]
	}
}

// GetStats returns current statistics
func (ls *LatencyStats) GetStats() (min, max, avg time.Duration, p95, p99 time.Duration, count, successCount, failCount int64) {
	ls.mu.RLock()
	defer ls.mu.RUnlock()

	if ls.count == 0 {
		return 0, 0, 0, 0, 0, 0, 0, 0
	}

	min = ls.min
	max = ls.max
	avg = ls.total / time.Duration(ls.count)
	count = ls.count
	successCount = ls.successCount
	failCount = ls.failCount

	// Calculate percentiles
	if len(ls.latencies) > 0 {
		sorted := make([]time.Duration, len(ls.latencies))
		copy(sorted, ls.latencies)
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i] < sorted[j]
		})

		p95Idx := int(float64(len(sorted)) * 0.95)
		p99Idx := int(float64(len(sorted)) * 0.99)

		if p95Idx < len(sorted) {
			p95 = sorted[p95Idx]
		}
		if p99Idx < len(sorted) {
			p99 = sorted[p99Idx]
		}
	}

	return
}

// GetOperationStats returns statistics for a specific operation type
func (gs *GlobalStats) GetOperationStats(opType OperationType) *LatencyStats {
	gs.mu.RLock()
	defer gs.mu.RUnlock()

	switch opType {
	case EnrollOp:
		return &gs.operations.enroll
	case StatusOp:
		return &gs.operations.status
	case ResultOp:
		return &gs.operations.result
	case ConfigOp:
		return &gs.operations.config
	case QueryReadOp:
		return &gs.operations.queryRead
	case QueryWriteOp:
		return &gs.operations.queryWrite
	default:
		return nil
	}
}

// RecordOperation records an operation with its latency and success status
func (gs *GlobalStats) RecordOperation(opType OperationType, latency time.Duration, success bool) {
	stats := gs.GetOperationStats(opType)
	if stats != nil {
		stats.AddLatency(latency, success)
	}

	gs.mu.Lock()
	gs.lastUpdate = time.Now()
	gs.mu.Unlock()
}

// RecordURLOperation records an operation for a specific URL
func (gs *GlobalStats) RecordURLOperation(url string, latency time.Duration, success bool) {
	gs.mu.Lock()
	gs.urls.mu.Lock()

	if gs.urls.stats[url] == nil {
		gs.urls.stats[url] = &LatencyStats{}
	}
	gs.urls.stats[url].AddLatency(latency, success)
	gs.lastUpdate = time.Now()

	gs.urls.mu.Unlock()
	gs.mu.Unlock()
}

// GetURLStats returns statistics for all URLs
func (gs *GlobalStats) GetURLStats() map[string]*LatencyStats {
	gs.urls.mu.RLock()
	defer gs.urls.mu.RUnlock()

	result := make(map[string]*LatencyStats)
	for url, stats := range gs.urls.stats {
		result[url] = stats
	}
	return result
}

// GetUptime returns the uptime since start
func (gs *GlobalStats) GetUptime() time.Duration {
	gs.mu.RLock()
	defer gs.mu.RUnlock()
	return time.Since(gs.startTime)
}

// SetNodeCounts sets the total and active node counts
func (gs *GlobalStats) SetNodeCounts(total, active int) {
	gs.mu.Lock()
	defer gs.mu.Unlock()
	gs.totalNodes = total
	gs.activeNodes = active
}

// SetNodeCounts records the fleet size shown in reports.
func SetNodeCounts(total, active int) {
	globalStats.SetNodeCounts(total, active)
}

// printSummary prints a summary of statistics
func printSummary() {
	uptime := globalStats.GetUptime()

	fmt.Printf("\n%s\n", strings.Repeat("=", 80))
	fmt.Printf("PHANTOMFLEET - PERFORMANCE SUMMARY\n")
	fmt.Printf("Uptime: %s\n", uptime.Round(time.Second))
	fmt.Printf("%s\n", strings.Repeat("=", 80))

	operations := []struct {
		name string
		op   OperationType
	}{
		{"Enroll", EnrollOp},
		{"Status", StatusOp},
		{"Result", ResultOp},
		{"Config", ConfigOp},
		{"Query Read", QueryReadOp},
		{"Query Write", QueryWriteOp},
	}

	for _, op := range operations {
		stats := globalStats.GetOperationStats(op.op)
		min, max, avg, p95, p99, count, success, _ := stats.GetStats()

		if count > 0 {
			successRate := float64(success) / float64(count) * 100
			fmt.Printf("%-12s | Count: %6d | Success: %5.1f%% | Min: %4dms | Avg: %4dms | Max: %4dms | P95: %4dms | P99: %4dms\n",
				op.name, count, successRate, min.Milliseconds(), avg.Milliseconds(), max.Milliseconds(), p95.Milliseconds(), p99.Milliseconds())
		}
	}

	// Print URL statistics
	fmt.Printf("%s\n", strings.Repeat("=", 80))
	fmt.Printf("URL STATISTICS - ABSOLUTE NUMBERS\n")
	fmt.Printf("%s\n", strings.Repeat("=", 80))

	urlStats := globalStats.GetURLStats()
	if len(urlStats) > 0 {
		fmt.Printf("%-50s | %8s | %8s | %8s | %8s\n", "URL", "Total", "Success", "Failed", "Success%")
		fmt.Printf("%s\n", strings.Repeat("-", 80))

		for url, stats := range urlStats {
			_, _, _, _, _, count, success, fail := stats.GetStats()
			if count > 0 {
				successRate := float64(success) / float64(count) * 100
				fmt.Printf("%-50s | %8d | %8d | %8d | %7.1f%%\n",
					url, count, success, fail, successRate)
			}
		}
	}
	fmt.Printf("%s\n\n", strings.Repeat("=", 80))
}

// printDashboard prints a real-time dashboard
func printDashboard() {
	// Clear screen and move cursor to top
	fmt.Print("\033[2J\033[H")

	uptime := globalStats.GetUptime()

	fmt.Printf("PHANTOMFLEET - REAL-TIME DASHBOARD\n")
	fmt.Printf("Uptime: %s | Last Update: %s\n", uptime.Round(time.Second), time.Now().Format("15:04:05"))
	fmt.Printf("%s\n", strings.Repeat("-", 100))

	operations := []struct {
		name string
		op   OperationType
	}{
		{"Enroll", EnrollOp},
		{"Status", StatusOp},
		{"Result", ResultOp},
		{"Config", ConfigOp},
		{"Query Read", QueryReadOp},
		{"Query Write", QueryWriteOp},
	}

	fmt.Printf("%-12s | %8s | %8s | %8s | %8s | %8s | %8s | %8s\n",
		"Operation", "Count", "Success%", "Min(ms)", "Avg(ms)", "Max(ms)", "P95(ms)", "P99(ms)")
	fmt.Printf("%s\n", strings.Repeat("-", 100))

	for _, op := range operations {
		stats := globalStats.GetOperationStats(op.op)
		min, max, avg, p95, p99, count, success, _ := stats.GetStats()

		if count > 0 {
			successRate := float64(success) / float64(count) * 100
			fmt.Printf("%-12s | %8d | %7.1f%% | %8d | %8d | %8d | %8d | %8d\n",
				op.name, count, successRate, min.Milliseconds(), avg.Milliseconds(), max.Milliseconds(), p95.Milliseconds(), p99.Milliseconds())
		} else {
			fmt.Printf("%-12s | %8d | %7s | %8s | %8s | %8s | %8s | %8s\n",
				op.name, 0, "-", "-", "-", "-", "-", "-")
		}
	}
	fmt.Printf("%s\n", strings.Repeat("-", 100))

	// Print URL statistics section
	fmt.Printf("\nURL STATISTICS - ABSOLUTE NUMBERS\n")
	fmt.Printf("%s\n", strings.Repeat("-", 100))
	fmt.Printf("%-50s | %8s | %8s | %8s | %8s\n", "URL", "Total", "Success", "Failed", "Success%")
	fmt.Printf("%s\n", strings.Repeat("-", 100))

	urlStats := globalStats.GetURLStats()
	if len(urlStats) > 0 {
		for url, stats := range urlStats {
			_, _, _, _, _, count, success, fail := stats.GetStats()
			if count > 0 {
				successRate := float64(success) / float64(count) * 100
				fmt.Printf("%-50s | %8d | %8d | %8d | %7.1f%%\n",
					url, count, success, fail, successRate)
			}
		}
	} else {
		fmt.Printf("%-50s | %8s | %8s | %8s | %8s\n", "No data yet", "-", "-", "-", "-")
	}
	fmt.Printf("%s\n", strings.Repeat("-", 100))
}

// printJSONStats prints statistics in JSON format
func printJSONStats() {
	stats := make(map[string]interface{})
	stats["uptime_seconds"] = globalStats.GetUptime().Seconds()
	stats["timestamp"] = time.Now().Unix()

	operations := make(map[string]interface{})
	opTypes := []struct {
		name string
		op   OperationType
	}{
		{"enroll", EnrollOp},
		{"status", StatusOp},
		{"result", ResultOp},
		{"config", ConfigOp},
		{"query_read", QueryReadOp},
		{"query_write", QueryWriteOp},
	}

	for _, op := range opTypes {
		opStats := globalStats.GetOperationStats(op.op)
		min, max, avg, p95, p99, count, success, fail := opStats.GetStats()

		opData := make(map[string]interface{})
		opData["count"] = count
		opData["success_count"] = success
		opData["fail_count"] = fail
		if count > 0 {
			opData["success_rate"] = float64(success) / float64(count) * 100
		} else {
			opData["success_rate"] = 0.0
		}
		opData["min_ms"] = min.Milliseconds()
		opData["avg_ms"] = avg.Milliseconds()
		opData["max_ms"] = max.Milliseconds()
		opData["p95_ms"] = p95.Milliseconds()
		opData["p99_ms"] = p99.Milliseconds()

		operations[op.name] = opData
	}

	stats["operations"] = operations

	// Add URL statistics
	urlStats := globalStats.GetURLStats()
	urls := make(map[string]interface{})
	for url, urlStat := range urlStats {
		_, _, _, _, _, count, success, fail := urlStat.GetStats()

		urlData := make(map[string]interface{})
		urlData["count"] = count
		urlData["success_count"] = success
		urlData["fail_count"] = fail
		if count > 0 {
			urlData["success_rate"] = float64(success) / float64(count) * 100
		} else {
			urlData["success_rate"] = 0.0
		}

		urls[url] = urlData
	}
	stats["urls"] = urls

	jsonData, _ := json.MarshalIndent(stats, "", "  ")
	fmt.Printf("%s\n", string(jsonData))
}

// Log records an operation in the global statistics and, in verbose mode,
// prints it.
func Log(opType OperationType, nodeName string, url string, latency time.Duration, success bool, mode OutputMode) {
	// Record the operation in both operation and URL statistics
	globalStats.RecordOperation(opType, latency, success)
	globalStats.RecordURLOperation(url, latency, success)

	// Output based on mode
	switch mode {
	case QuietMode:
		// No output
		return
	case SummaryMode:
		// Only periodic summaries (handled by summary goroutine)
		return
	case VerboseMode:
		// Original verbose output
		opNames := map[OperationType]string{
			EnrollOp:     "enroll",
			StatusOp:     "status",
			ResultOp:     "result",
			ConfigOp:     "config",
			QueryReadOp:  "query_read",
			QueryWriteOp: "query_write",
		}
		status := "✓"
		if !success {
			status = "✗"
		}
		fmt.Printf("⏰ %d ms %s %s from %s to %s\n", latency.Milliseconds(), status, opNames[opType], nodeName, url)
	case DashboardMode:
		// Real-time dashboard (handled by dashboard goroutine)
		return
	case JSONMode:
		// JSON output (handled by JSON goroutine)
		return
	}
}

// SummaryReporter runs periodic summary reports
func SummaryReporter(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			printSummary()
		}
	}
}

// DashboardReporter runs real-time dashboard updates
func DashboardReporter(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			printDashboard()
		}
	}
}

// JSONReporter runs periodic JSON output
func JSONReporter(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			printJSONStats()
		}
	}
}
