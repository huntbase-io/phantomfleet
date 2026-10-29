package protocol

import (
	"fmt"
	"net/url"
	"strings"
)

// Server flavors select how endpoint URLs are built from --url.
const (
	// FlavorOsctrl targets osctrl-tls, whose endpoints are scoped by
	// environment: <url>/<env>/{enroll,config,log,read,write}.
	FlavorOsctrl = "osctrl"
	// FlavorGeneric targets any server that serves osquery's standard TLS
	// endpoint paths (Fleet and most other osquery TLS servers).
	FlavorGeneric = "generic"
)

// Keys of the endpoint map returned by BuildEndpoints.
const (
	EndpointEnroll = "enroll"
	EndpointConfig = "config"
	EndpointLog    = "log"
	EndpointRead   = "query"
	EndpointWrite  = "write"
)

// EndpointPaths holds a path for each osquery TLS endpoint. An empty field
// means "use the flavor's default".
type EndpointPaths struct {
	Enroll string
	Config string
	Log    string
	Read   string
	Write  string
}

// genericPaths are osquery's standard TLS endpoint defaults
// (--enroll_tls_endpoint, --config_tls_endpoint, --logger_tls_endpoint,
// --distributed_tls_read_endpoint, --distributed_tls_write_endpoint).
var genericPaths = EndpointPaths{
	Enroll: "/api/v1/osquery/enroll",
	Config: "/api/v1/osquery/config",
	Log:    "/api/v1/osquery/log",
	Read:   "/api/v1/osquery/distributed/read",
	Write:  "/api/v1/osquery/distributed/write",
}

// osctrlPaths returns osctrl-tls's environment-scoped endpoint paths.
func osctrlPaths(env string) EndpointPaths {
	return EndpointPaths{
		Enroll: "/" + env + "/enroll",
		Config: "/" + env + "/config",
		Log:    "/" + env + "/log",
		Read:   "/" + env + "/read",
		Write:  "/" + env + "/write",
	}
}

// joinURL appends path to base with exactly one slash between them,
// regardless of trailing/leading slashes on either side.
func joinURL(base, path string) string {
	base = strings.TrimRight(base, "/")
	path = strings.Trim(strings.TrimSpace(path), "/")
	if path == "" {
		return base
	}
	return base + "/" + path
}

// BuildEndpoints resolves the full URL of every osquery TLS endpoint.
//
// baseURL is --url. In the osctrl flavor a base URL that already ends in
// /<env> is accepted (the environment is not appended twice). Override paths
// are appended to the base URL as-is; in the osctrl flavor an override
// replaces the whole /<env>/<endpoint> path.
func BuildEndpoints(baseURL, flavor, env string, overrides EndpointPaths) (map[string]string, error) {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("invalid --url %q: %w", baseURL, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid --url %q: must be an absolute http(s) URL, e.g. https://tls.example.com", baseURL)
	}

	var defaults EndpointPaths
	switch strings.ToLower(strings.TrimSpace(flavor)) {
	case FlavorOsctrl:
		env = strings.Trim(strings.TrimSpace(env), "/")
		if env == "" {
			return nil, fmt.Errorf("--env (environment UUID) is required with --flavor %s; use --flavor %s for servers that serve the standard osquery paths", FlavorOsctrl, FlavorGeneric)
		}
		// Tolerate --url values that already include the environment.
		base = strings.TrimSuffix(base, "/"+env)
		defaults = osctrlPaths(env)
	case FlavorGeneric:
		defaults = genericPaths
	default:
		return nil, fmt.Errorf("invalid --flavor %q: valid flavors are %s, %s", flavor, FlavorOsctrl, FlavorGeneric)
	}

	pick := func(override, def string) string {
		if strings.Trim(strings.TrimSpace(override), "/") != "" {
			return joinURL(base, override)
		}
		return joinURL(base, def)
	}
	return map[string]string{
		EndpointEnroll: pick(overrides.Enroll, defaults.Enroll),
		EndpointConfig: pick(overrides.Config, defaults.Config),
		EndpointLog:    pick(overrides.Log, defaults.Log),
		EndpointRead:   pick(overrides.Read, defaults.Read),
		EndpointWrite:  pick(overrides.Write, defaults.Write),
	}, nil
}
