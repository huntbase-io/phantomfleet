package synth

import (
	_ "embed"
	"encoding/json"
	"sort"
	"strings"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/huntbase-io/phantomfleet/internal/host"
)

// osqueryPlatformsJSON maps each embedded osquery table to the platforms it
// exists on ("darwin", "linux", "windows"), from the same osquery schema
// release as osquery_schema.json.
//
//go:embed osquery_platforms.json
var osqueryPlatformsJSON []byte

// tablePlatforms is the parsed osquery_platforms.json.
var tablePlatforms = map[string][]string{}

func init() {
	if err := json.Unmarshal(osqueryPlatformsJSON, &tablePlatforms); err != nil {
		tablePlatforms = map[string][]string{}
	}
}

// Platform-specific osquery tables. Real osquery fails a query that names
// another platform's table, so a host never reports rows for one unless its
// seeds deliberately declare the table. Without this, a Linux host answered
// `services` with schema-generated Windows-looking values.
var (
	windowsOnlyTables = setOf(
		"appcompat_shims", "authenticode", "autoexec", "background_activities_moderator",
		"bitlocker_info", "chocolatey_packages", "default_environment", "drivers",
		"hvci_status", "ie_extensions", "kva_speculative_info", "logical_drives",
		"logon_sessions", "ntdomains", "office_mru", "patches", "physical_disk_performance",
		"pipes", "powershell_events", "prefetch", "programs", "registry", "scheduled_tasks",
		"services", "shellbags", "shimcache", "userassist", "video_info",
	)
	linuxOnlyTables = setOf(
		"apparmor_events", "apparmor_profiles", "apt_sources", "deb_packages", "iptables",
		"kernel_modules", "md_devices", "memory_info", "process_namespaces", "rpm_packages",
		"seccomp_events", "selinux_events", "selinux_settings", "shadow", "systemd_units",
		"yum_sources",
	)
	darwinOnlyTables = setOf(
		"account_policy_data", "alf", "alf_exceptions", "alf_explicit_auths", "apps",
		"asl", "authorization_mechanisms", "authorizations", "gatekeeper", "homebrew_packages",
		"kernel_extensions", "keychain_acls", "keychain_items", "launchd", "launchd_overrides",
		"location_services", "managed_policies", "mdm", "nvram", "package_bom",
		"package_receipts", "plist", "preferences", "quicklook_cache", "safari_extensions",
		"sandboxes", "sharing_preferences", "signature", "sip_config", "system_extensions",
		"unified_log",
	)
	// Distro package managers. A network appliance shares the linux profile
	// but has none of these, so the profile's distro package rows must not
	// reach it.
	distroPackageTables   = setOf("apt_sources", "deb_packages", "rpm_packages", "yum_sources")
	platformTablePrefixes = map[string][]string{
		"windows": {"windows_", "wmi_", "ntfs_"},
		"darwin":  {"xprotect_", "time_machine_", "wifi_"},
	}
)

// applianceTarget reports whether an osquery platform is a network appliance
// OS (PAN-OS) rather than a general-purpose Linux distribution.
func applianceTarget(platform string) bool {
	return strings.EqualFold(strings.TrimSpace(platform), "panos")
}

func setOf(items ...string) map[string]bool {
	s := make(map[string]bool, len(items))
	for _, i := range items {
		s[i] = true
	}
	return s
}

// tablePlatform is the only platform profile a table exists on, or "" for a
// cross-platform (or unknown) table.
func tablePlatform(table string) string {
	t := strings.ToLower(table)
	switch {
	case windowsOnlyTables[t]:
		return "windows"
	case linuxOnlyTables[t]:
		return "linux"
	case darwinOnlyTables[t]:
		return "darwin"
	}
	for platform, prefixes := range platformTablePrefixes {
		for _, p := range prefixes {
			if strings.HasPrefix(t, p) {
				return platform
			}
		}
	}
	return ""
}

// onPlatform reports whether table exists on a platform profile. Tables in the
// osquery platform data use it; others fall back to the hand-kept lists above
// (cross-platform unless listed).
func onPlatform(table, platform string) bool {
	t := strings.ToLower(table)
	if ps, ok := tablePlatforms[t]; ok {
		for _, p := range ps {
			if p == platform {
				return true
			}
		}
		return false
	}
	owner := tablePlatform(t)
	return owner == "" || owner == platform
}

// foreignTable reports whether table belongs to another platform than the
// node's and the node's seeds don't declare it anyway.
func foreignTable(node host.Node, table string) bool {
	// Appliances (PAN-OS) answer from the linux profile, but they have no
	// distro package manager: only rows seeded for that host may answer.
	if applianceTarget(node.Target) && distroPackageTables[strings.ToLower(table)] {
		hostRows, _ := seedRowsSplit(node, table)
		return len(hostRows) == 0
	}
	platform := profileForPlatform(node.Target)
	if onPlatform(table, platform) {
		return false
	}
	if tableDeclared(platform, table) || len(identityRows(node, table)) > 0 {
		return false
	}
	hostRows, _ := seedRowsSplit(node, table)
	return len(hostRows) == 0
}

// Realistic fallbacks for schema-generated path/command/description columns,
// per platform profile, instead of dictionary words that read as suspicious.
var (
	linuxPaths = []string{
		"/usr/sbin/sshd", "/usr/sbin/cron", "/usr/sbin/rsyslogd", "/usr/bin/dbus-daemon",
		"/usr/lib/systemd/systemd-journald", "/usr/lib/systemd/systemd-logind",
		"/usr/bin/containerd", "/usr/bin/dockerd", "/usr/lib/snapd/snapd", "/usr/bin/python3.10",
		"/usr/libexec/polkitd", "/usr/sbin/irqbalance", "/usr/bin/vmtoolsd", "/usr/sbin/nginx",
		"/etc/ssh/sshd_config", "/etc/hosts", "/var/log/syslog", "/var/log/auth.log",
	}
	windowsPaths = []string{
		"C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System32\\lsass.exe",
		"C:\\Windows\\System32\\services.exe", "C:\\Windows\\System32\\winlogon.exe",
		"C:\\Windows\\System32\\csrss.exe", "C:\\Windows\\explorer.exe",
		"C:\\Windows\\System32\\SearchIndexer.exe", "C:\\Windows\\System32\\spoolsv.exe",
		"C:\\Windows\\System32\\taskhostw.exe", "C:\\Windows\\System32\\RuntimeBroker.exe",
		"C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe",
		"C:\\Program Files\\osquery\\osqueryd\\osqueryd.exe",
	}
	darwinPaths = []string{
		"/usr/sbin/cfprefsd", "/usr/libexec/trustd", "/usr/libexec/logd",
		"/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder",
		"/System/Library/CoreServices/Dock.app/Contents/MacOS/Dock",
		"/usr/libexec/syspolicyd", "/usr/sbin/mDNSResponder", "/usr/libexec/opendirectoryd",
		"/Applications/Safari.app/Contents/MacOS/Safari", "/usr/local/bin/osqueryd",
	}
	neutralDescriptions = []string{
		"Installed by the operating system", "Managed by IT", "Standard configuration",
		"Vendor default", "Created during provisioning",
	}
)

func platformPaths(node host.Node) []string {
	switch profileForPlatform(node.Target) {
	case "windows":
		return windowsPaths
	case "darwin":
		return darwinPaths
	default:
		return linuxPaths
	}
}

func pickString(f *gofakeit.Faker, opts []string) string {
	return opts[f.Number(0, len(opts)-1)]
}

// registryRows are a node's osquery_registry rows: one "table" plugin per
// table the node has (the embedded tables of its platform, the tables its
// seeds declare and every --extra-schema table), plus the TLS plugins a
// remote-managed osquery runs. Servers probe this table before sending
// platform- or extension-specific queries (Fleet's discovery queries), so it
// must agree with what the node answers.
func registryRows(node host.Node) []map[string]string {
	platform := profileForPlatform(node.Target)
	names := map[string]bool{}
	for t := range osquerySchema {
		if isExtensionTable(t) || !foreignTable(node, t) {
			names[t] = true
		}
	}
	for t := range seedProfiles[platform] {
		names[t] = true
	}
	sorted := make([]string, 0, len(names))
	for t := range names {
		if reIdent.MatchString(t) {
			sorted = append(sorted, t)
		}
	}
	sort.Strings(sorted)
	rows := make([]map[string]string, 0, len(sorted)+4)
	for _, p := range []string{"config", "logger", "distributed", "enroll"} {
		rows = append(rows, map[string]string{"registry": p, "name": "tls", "owner_uuid": "0", "internal": "0", "active": "1"})
	}
	for _, t := range sorted {
		owner := "0"
		if isExtensionTable(t) {
			owner = "1"
		}
		rows = append(rows, map[string]string{"registry": "table", "name": t, "owner_uuid": owner, "internal": "0", "active": "1"})
	}
	return rows
}
