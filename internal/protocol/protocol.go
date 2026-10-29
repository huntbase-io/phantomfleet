// Package protocol speaks the osquery TLS remote API: the wire types, plain
// request builders, endpoint URLs for each server flavor and the HTTP client.
package protocol

import (
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/huntbase-io/phantomfleet/internal/host"
)

// SystemInfo represents system information for enrollment
type SystemInfo struct {
	ComputerName     string `json:"computer_name"`
	CPUBrand         string `json:"cpu_brand"`
	CPULogicalCores  string `json:"cpu_logical_cores"`
	CPUPhysicalCores string `json:"cpu_physical_cores"`
	CPUSubtype       string `json:"cpu_subtype"`
	CPUType          string `json:"cpu_type"`
	HardwareModel    string `json:"hardware_model"`
	Hostname         string `json:"hostname"`
	LocalHostname    string `json:"local_hostname"`
	PhysicalMemory   string `json:"physical_memory"`
	UUID             string `json:"uuid"`
}

// OSQueryInfo represents osquery information
type OSQueryInfo struct {
	BuildDistro   string `json:"build_distro"`
	BuildPlatform string `json:"build_platform"`
	ConfigHash    string `json:"config_hash"`
	ConfigValid   string `json:"config_valid"`
	Extensions    string `json:"extensions"`
	InstanceID    string `json:"instance_id"`
	PID           string `json:"pid"`
	StartTime     string `json:"start_time"`
	UUID          string `json:"uuid"`
	Version       string `json:"version"`
	Watcher       string `json:"watcher"`
}

// OSVersion represents OS version information
type OSVersion struct {
	ID           string `json:"_id,omitempty"`
	Codename     string `json:"codename,omitempty"`
	Build        string `json:"build,omitempty"`
	Major        string `json:"major"`
	Minor        string `json:"minor"`
	Name         string `json:"name"`
	Patch        string `json:"patch"`
	Platform     string `json:"platform"`
	PlatformLike string `json:"platform_like,omitempty"`
	Version      string `json:"version"`
	InstallDate  string `json:"install_date,omitempty"`
}

// HostDetails represents host details for enrollment
type HostDetails struct {
	OSVersion   OSVersion   `json:"os_version"`
	OSQueryInfo OSQueryInfo `json:"osquery_info"`
	SystemInfo  SystemInfo  `json:"system_info"`
}

// EnrollRequest represents enrollment request
type EnrollRequest struct {
	EnrollSecret   string      `json:"enroll_secret"`
	HostIdentifier string      `json:"host_identifier"`
	PlatformType   string      `json:"platform_type"`
	HostDetails    HostDetails `json:"host_details"`
}

// EnrollResponse represents enrollment response
type EnrollResponse struct {
	NodeKey string `json:"node_key"`
}

// LogRequest represents log request
type LogRequest struct {
	NodeKey string      `json:"node_key"`
	LogType string      `json:"log_type"`
	Data    interface{} `json:"data"`
}

// ConfigRequest represents config request
type ConfigRequest struct {
	NodeKey string `json:"node_key"`
}

// QueryReadRequest represents query read request
type QueryReadRequest struct {
	NodeKey string `json:"node_key"`
}

// QueryWriteRequest represents query write request
type QueryWriteRequest struct {
	NodeKey  string                 `json:"node_key"`
	Queries  map[string]interface{} `json:"queries"`
	Statuses map[string]int         `json:"statuses"`
	Messages map[string]string      `json:"messages"`
}

// StatusLog represents a status log entry
type StatusLog struct {
	HostIdentifier string `json:"hostIdentifier"`
	CalendarTime   string `json:"calendarTime"`
	UnixTime       string `json:"unixTime"`
	Severity       string `json:"severity"`
	Filename       string `json:"filename"`
	Line           string `json:"line"`
	Message        string `json:"message"`
	Version        string `json:"version"`
}

// ResultLog represents a result log entry
type ResultLog struct {
	Name           string            `json:"name"`
	HostIdentifier string            `json:"hostIdentifier"`
	CalendarTime   string            `json:"calendarTime"`
	UnixTime       string            `json:"unixTime"`
	Epoch          int               `json:"epoch"`
	Counter        int               `json:"counter"`
	Numerics       bool              `json:"numerics"`
	Decorations    map[string]string `json:"decorations"`
	Columns        map[string]string `json:"columns"`
	Action         string            `json:"action"`
}

// NewSystemInfo generates system info for a node
func NewSystemInfo(name, uuid string) SystemInfo {
	return SystemInfo{
		ComputerName:     name,
		CPUBrand:         "Intel(R) Core(TM) i7-7920HQ CPU @ 3.10GHz",
		CPULogicalCores:  "4",
		CPUPhysicalCores: "4",
		CPUSubtype:       "158",
		CPUType:          "x86_64",
		HardwareModel:    "",
		Hostname:         name,
		LocalHostname:    name,
		PhysicalMemory:   "2095869952",
		UUID:             uuid,
	}
}

// NewOSQueryInfo generates osquery info for a node
func NewOSQueryInfo(uuidStr, version string) OSQueryInfo {
	return OSQueryInfo{
		BuildDistro:   "build_distro",
		BuildPlatform: "build_platform",
		ConfigHash:    "",
		ConfigValid:   "0",
		Extensions:    "active",
		InstanceID:    uuid.New().String(),
		PID:           "11",
		StartTime:     "1564800635",
		UUID:          uuidStr,
		Version:       version,
		Watcher:       "9",
	}
}

// NewConfigRequest generates config request
func NewConfigRequest(nodeKey string) ConfigRequest {
	return ConfigRequest{NodeKey: nodeKey}
}

// NewQueryReadRequest generates query read request
func NewQueryReadRequest(nodeKey string) QueryReadRequest {
	return QueryReadRequest{NodeKey: nodeKey}
}

// NewStatusLog generates status log
func NewStatusLog(node host.Node) LogRequest {
	status := StatusLog{
		HostIdentifier: node.Identifier,
		CalendarTime:   time.Now().Format(time.RFC1123),
		UnixTime:       strconv.FormatInt(time.Now().Unix(), 10),
		Severity:       "0",
		Filename:       "phantomfleet",
		Line:           "255",
		Message:        "phantomfleet simulated status log",
		Version:        node.Version,
	}
	return LogRequest{
		NodeKey: node.Key,
		LogType: "status",
		Data:    []StatusLog{status},
	}
}

// NewResultLog generates result log
func NewResultLog(node host.Node) LogRequest {
	result := ResultLog{
		Name:           "uptime",
		HostIdentifier: node.Identifier,
		CalendarTime:   time.Now().Format(time.RFC1123),
		UnixTime:       strconv.FormatInt(time.Now().Unix(), 10),
		Epoch:          0,
		Counter:        0,
		Numerics:       false,
		Decorations: map[string]string{
			"config_hash":     "7155bb2b98162fa5641d340e03a38d0502df34f0",
			"hostname":        node.Name,
			"local_hostname":  node.Name,
			"osquery_md5":     "8e2490cb34e32cb33d6326ca30763167",
			"osquery_user":    "root",
			"osquery_version": node.Version,
			"username":        "user (console)",
		},
		Columns: map[string]string{
			"days":          "0",
			"hours":         "1",
			"minutes":       "2",
			"seconds":       "3",
			"total_seconds": "123456",
		},
		Action: "added",
	}
	return LogRequest{
		NodeKey: node.Key,
		LogType: "result",
		Data:    []ResultLog{result},
	}
}
