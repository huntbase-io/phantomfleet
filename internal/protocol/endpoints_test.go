package protocol

import (
	"strings"
	"testing"
)

const testEnv = "0b6a5c1e-1f2d-4e3c-9a8b-7c6d5e4f3a2b"

func TestBuildEndpointsOsctrl(t *testing.T) {
	want := map[string]string{
		EndpointEnroll: "https://tls.example.com/" + testEnv + "/enroll",
		EndpointConfig: "https://tls.example.com/" + testEnv + "/config",
		EndpointLog:    "https://tls.example.com/" + testEnv + "/log",
		EndpointRead:   "https://tls.example.com/" + testEnv + "/read",
		EndpointWrite:  "https://tls.example.com/" + testEnv + "/write",
	}
	for _, base := range []string{
		"https://tls.example.com",
		"https://tls.example.com/",
		"https://tls.example.com//",
		"https://tls.example.com/" + testEnv, // env already in --url
		"https://tls.example.com/" + testEnv + "/",
		"  https://tls.example.com/  ",
	} {
		got, err := BuildEndpoints(base, FlavorOsctrl, testEnv, EndpointPaths{})
		if err != nil {
			t.Fatalf("%q: %v", base, err)
		}
		assertEndpoints(t, base, got, want)
	}
}

func TestBuildEndpointsOsctrlRequiresEnv(t *testing.T) {
	if _, err := BuildEndpoints("https://tls.example.com", FlavorOsctrl, "", EndpointPaths{}); err == nil {
		t.Fatal("osctrl flavor without --env should fail")
	}
	if _, err := BuildEndpoints("https://tls.example.com", FlavorOsctrl, " / ", EndpointPaths{}); err == nil {
		t.Fatal("osctrl flavor with a blank --env should fail")
	}
}

func TestBuildEndpointsGeneric(t *testing.T) {
	want := map[string]string{
		EndpointEnroll: "https://fleet.example.com:8080/api/v1/osquery/enroll",
		EndpointConfig: "https://fleet.example.com:8080/api/v1/osquery/config",
		EndpointLog:    "https://fleet.example.com:8080/api/v1/osquery/log",
		EndpointRead:   "https://fleet.example.com:8080/api/v1/osquery/distributed/read",
		EndpointWrite:  "https://fleet.example.com:8080/api/v1/osquery/distributed/write",
	}
	for _, env := range []string{"", testEnv} { // --env is ignored
		for _, base := range []string{"https://fleet.example.com:8080", "https://fleet.example.com:8080/"} {
			got, err := BuildEndpoints(base, "GENERIC", env, EndpointPaths{})
			if err != nil {
				t.Fatalf("%q: %v", base, err)
			}
			assertEndpoints(t, base, got, want)
		}
	}
}

func TestBuildEndpointsGenericKeepsBasePrefix(t *testing.T) {
	got, err := BuildEndpoints("http://localhost:9000/osquery-proxy/", FlavorGeneric, "", EndpointPaths{})
	if err != nil {
		t.Fatal(err)
	}
	if want := "http://localhost:9000/osquery-proxy/api/v1/osquery/enroll"; got[EndpointEnroll] != want {
		t.Fatalf("enroll = %q, want %q", got[EndpointEnroll], want)
	}
}

func TestBuildEndpointsOverrides(t *testing.T) {
	overrides := EndpointPaths{
		Enroll: "custom/enroll",   // no leading slash
		Config: "/custom/config/", // trailing slash
		Read:   "//q/read",
		Write:  "   ", // blank means "use the default"
	}

	got, err := BuildEndpoints("https://tls.example.com/", FlavorOsctrl, testEnv, overrides)
	if err != nil {
		t.Fatal(err)
	}
	// In the osctrl flavor an override replaces the whole /<env>/<endpoint> path.
	assertEndpoints(t, "osctrl", got, map[string]string{
		EndpointEnroll: "https://tls.example.com/custom/enroll",
		EndpointConfig: "https://tls.example.com/custom/config",
		EndpointLog:    "https://tls.example.com/" + testEnv + "/log",
		EndpointRead:   "https://tls.example.com/q/read",
		EndpointWrite:  "https://tls.example.com/" + testEnv + "/write",
	})

	got, err = BuildEndpoints("https://fleet.example.com", FlavorGeneric, "", overrides)
	if err != nil {
		t.Fatal(err)
	}
	assertEndpoints(t, "generic", got, map[string]string{
		EndpointEnroll: "https://fleet.example.com/custom/enroll",
		EndpointConfig: "https://fleet.example.com/custom/config",
		EndpointLog:    "https://fleet.example.com/api/v1/osquery/log",
		EndpointRead:   "https://fleet.example.com/q/read",
		EndpointWrite:  "https://fleet.example.com/api/v1/osquery/distributed/write",
	})
}

func TestBuildEndpointsRejectsBadInput(t *testing.T) {
	for _, tc := range []struct{ url, flavor string }{
		{"https://tls.example.com", "fleet"},
		{"tls.example.com", FlavorGeneric},
		{"ftp://tls.example.com", FlavorGeneric},
		{"https://", FlavorGeneric},
		{"", FlavorGeneric},
	} {
		if _, err := BuildEndpoints(tc.url, tc.flavor, testEnv, EndpointPaths{}); err == nil {
			t.Errorf("BuildEndpoints(%q, %q) should fail", tc.url, tc.flavor)
		}
	}
}

func TestJoinURL(t *testing.T) {
	for _, tc := range []struct{ base, path, want string }{
		{"http://h", "/a", "http://h/a"},
		{"http://h/", "a", "http://h/a"},
		{"http://h//", "//a/b//", "http://h/a/b"},
		{"http://h/p", "", "http://h/p"},
	} {
		if got := joinURL(tc.base, tc.path); got != tc.want {
			t.Errorf("joinURL(%q, %q) = %q, want %q", tc.base, tc.path, got, tc.want)
		}
	}
}

func assertEndpoints(t *testing.T, label string, got, want map[string]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: got %d endpoints, want %d", label, len(got), len(want))
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: %s = %q, want %q", label, k, got[k], w)
		}
	}
	for _, u := range got {
		if strings.Contains(strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://"), "//") {
			t.Errorf("%s: double slash in %q", label, u)
		}
	}
}
