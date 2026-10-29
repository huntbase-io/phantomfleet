package synth

import (
	"strconv"
	"strings"

	"github.com/huntbase-io/phantomfleet/internal/host"
	"github.com/huntbase-io/phantomfleet/internal/protocol"
)

// shortHostname is the first label of a hostname.
func shortHostname(name string) string {
	if i := strings.IndexByte(name, '.'); i > 0 {
		return name[:i]
	}
	return name
}

// osVersionFor returns what a node reports at enrollment: its pinned OS when
// set, else the platform default.
func osVersionFor(node host.Node) protocol.OSVersion {
	v := node.OS
	if v == nil {
		v = ProfileOS(node.Target)
	}
	return protocol.OSVersion{
		Codename:     v.Codename,
		Build:        v.Build,
		Major:        v.Major,
		Minor:        v.Minor,
		Name:         v.Name,
		Patch:        v.Patch,
		Platform:     v.Platform,
		PlatformLike: v.PlatformLike,
		Version:      v.Version,
	}
}

// systemInfoFor returns what a node reports at enrollment, honoring pinned hardware.
func systemInfoFor(node host.Node) protocol.SystemInfo {
	info := protocol.NewSystemInfo(node.Name, node.Identifier)
	// Start from the platform profile's system_info row, so a node reports the
	// hardware at enrollment that it answers with later.
	if raw, ok := seedRowsRaw(profileForPlatform(node.Target), "system_info"); ok {
		for _, row := range raw {
			if _, hostOnly := row[hostsColumn]; hostOnly {
				continue
			}
			set := func(dst *string, col string) {
				if v := row[col]; v != "" && !strings.Contains(v, "{{") {
					*dst = v
				}
			}
			set(&info.CPUBrand, "cpu_brand")
			set(&info.CPUType, "cpu_type")
			set(&info.CPULogicalCores, "cpu_logical_cores")
			set(&info.CPUPhysicalCores, "cpu_physical_cores")
			set(&info.PhysicalMemory, "physical_memory")
			set(&info.HardwareModel, "hardware_model")
			break
		}
	}
	if node.Pinned {
		info.ComputerName = shortHostname(node.Name)
		info.LocalHostname = shortHostname(node.Name)
	}
	if hw := node.Hardware; hw != nil {
		if hw.CPUBrand != "" {
			info.CPUBrand = hw.CPUBrand
		}
		if hw.CPUCores > 0 {
			info.CPULogicalCores = strconv.Itoa(hw.CPUCores)
			info.CPUPhysicalCores = strconv.Itoa(max(1, hw.CPUCores/2))
		}
		if hw.Model != "" {
			info.HardwareModel = hw.Model
		}
		if hw.PhysicalMemory > 0 {
			info.PhysicalMemory = strconv.FormatInt(hw.PhysicalMemory, 10)
		}
	}
	return info
}

// identityRows are the rows a node reports for its identity tables, so
// `SELECT * FROM os_version` on finance-ws-12 answers Windows 11 Enterprise, not
// the platform profile's generic row. Returned rows go ahead of every seed row;
// for singleton tables they are the whole population. (The pinned IP needs no
// row here: the platform profiles' interface_addresses rows use {{ip}}.)
func identityRows(node host.Node, table string) []map[string]string {
	// Every node, pinned or random, reports the tables it has and the OS it
	// enrolled with.
	switch table {
	case "osquery_registry":
		return registryRows(node)
	case "os_version":
		if node.OS == nil {
			return nil
		}
		return []map[string]string{{
			"name":          node.OS.Name,
			"version":       node.OS.Version,
			"major":         node.OS.Major,
			"minor":         node.OS.Minor,
			"patch":         node.OS.Patch,
			"build":         node.OS.Build,
			"codename":      node.OS.Codename,
			"platform":      node.OS.Platform,
			"platform_like": node.OS.PlatformLike,
			"arch":          firstNonEmpty(node.OS.Arch, "x86_64"),
		}}
	}
	if !node.Pinned {
		return nil
	}
	switch table {
	case "system_info":
		info := systemInfoFor(node)
		row := map[string]string{
			"hostname":           node.Name,
			"uuid":               node.Identifier,
			"computer_name":      info.ComputerName,
			"local_hostname":     info.LocalHostname,
			"cpu_brand":          info.CPUBrand,
			"cpu_type":           "x86_64",
			"cpu_physical_cores": info.CPUPhysicalCores,
			"cpu_logical_cores":  info.CPULogicalCores,
			"physical_memory":    info.PhysicalMemory,
		}
		if hw := node.Hardware; hw != nil {
			row["hardware_vendor"] = hw.Vendor
			row["hardware_model"] = hw.Model
			row["hardware_version"] = hw.Version
			row["hardware_serial"] = hw.Serial
		}
		return []map[string]string{row}
	case "osquery_info":
		return []map[string]string{{
			"uuid":         node.Identifier,
			"instance_id":  node.Identifier,
			"version":      node.Version,
			"config_valid": "1",
		}}
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// defaultOSUser is the account a pinned node without a primary user reports in
// user-like columns: the platform's administrator.
func defaultOSUser(node host.Node) string {
	switch profileForPlatform(node.Target) {
	case "windows":
		return "Administrator"
	default:
		return "root"
	}
}

// resolveIdentity expands only the per-node identity tokens of a seed value
// (hostname, shorthost, ip, uuid, version, username), leaving generators as-is.
func resolveIdentity(s string, node host.Node) string {
	if !strings.Contains(s, "{{") {
		return s
	}
	return reToken.ReplaceAllStringFunc(s, func(tok string) string {
		switch strings.ToLower(strings.TrimSpace(tok[2 : len(tok)-2])) {
		case "hostname":
			return node.Name
		case "shorthost":
			return shortHostname(node.Name)
		case "ip":
			return node.IP
		case "uuid":
			return node.Identifier
		case "version":
			return node.Version
		case "username":
			return nodeUsername(node)
		}
		return tok
	})
}

// identityValue is the node's own value for an identity-like column, or ""
// with ok=false when the column is not one. Pinned or not, these columns never
// carry random words: a hostname column names this host, a serial its serial.
func identityValue(node host.Node, table, column string) (string, bool) {
	n := strings.ToLower(column)
	switch n {
	case "hostname", "host", "host_name", "fqdn":
		return node.Name, true
	case "csname", "computer_name", "local_hostname", "computername", "machine_name":
		return shortHostname(node.Name), true
	case "device_name":
		if table == "drivers" {
			return "", false // a driver's name, not the host's
		}
		return shortHostname(node.Name), true
	case "uuid", "host_uuid", "hardware_uuid", "host_identifier", "hostidentifier", "node_uuid":
		return node.Identifier, true
	case "hardware_serial", "serial_number", "board_serial":
		if node.Hardware != nil && node.Hardware.Serial != "" {
			return node.Hardware.Serial, true
		}
		return "", node.Pinned
	case "installed_by":
		if profileForPlatform(node.Target) == "windows" {
			return "NT AUTHORITY\\SYSTEM", true
		}
		return nodeUsername(node), node.Pinned
	case "username", "user", "owner", "user_name", "login":
		// Random nodes keep their random users; pinned hosts report real ones.
		return nodeUsername(node), node.Pinned
	}
	return "", false
}

// ProfileOS is the OS a random node of target reports: the first shared
// os_version row of its seed profile (built in, or replaced with
// --seeds-dir), so enrollment and later os_version answers agree.
func ProfileOS(target string) *host.NodeOS {
	profile := profileForPlatform(target)
	if raw, ok := seedRowsRaw(profile, "os_version"); ok {
		for _, row := range raw {
			if _, hostOnly := row[hostsColumn]; hostOnly {
				continue
			}
			return &host.NodeOS{
				Name: row["name"], Version: row["version"], Major: row["major"],
				Minor: row["minor"], Patch: row["patch"], Build: row["build"],
				Codename: row["codename"], Platform: row["platform"],
				PlatformLike: row["platform_like"], Arch: row["arch"],
			}
		}
	}
	return fallbackOS(profile)
}

// fallbackOS is used only when a seed layer removed a profile's os_version.
func fallbackOS(profile string) *host.NodeOS {
	switch profile {
	case "windows":
		return &host.NodeOS{Name: "Microsoft Windows 11 Pro", Version: "10.0.26100", Major: "10", Minor: "0", Patch: "0",
			Build: "26100", Platform: "windows", PlatformLike: "windows", Arch: "x86_64"}
	case "darwin":
		return &host.NodeOS{Name: "macOS", Version: "15.6.1", Major: "15", Minor: "6", Patch: "1",
			Build: "24G90", Platform: "darwin", PlatformLike: "darwin", Arch: "arm64"}
	default:
		return &host.NodeOS{Name: "Ubuntu", Version: "24.04.3 LTS (Noble Numbat)", Major: "24", Minor: "04", Patch: "0",
			Codename: "noble", Platform: "ubuntu", PlatformLike: "debian", Arch: "x86_64"}
	}
}

// getPlatformType returns the osquery platform_type bitmask string for a
// node's platform.
func getPlatformType(platform string) string {
	if strings.HasPrefix(strings.ToLower(platform), "freebsd") {
		return "37"
	}
	switch profileForPlatform(platform) {
	case "darwin":
		return "21"
	case "windows":
		return "2"
	default:
		return "9"
	}
}

// EnrollRequest generates enrollment request for a node
func EnrollRequest(node host.Node, secret string) protocol.EnrollRequest {
	return protocol.EnrollRequest{
		EnrollSecret:   secret,
		HostIdentifier: node.Identifier,
		PlatformType:   getPlatformType(node.Target),
		HostDetails: protocol.HostDetails{
			OSVersion:   osVersionFor(node),
			OSQueryInfo: protocol.NewOSQueryInfo(node.Identifier, node.Version),
			SystemInfo:  systemInfoFor(node),
		},
	}
}
