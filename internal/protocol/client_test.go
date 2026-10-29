package protocol

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRedactJSON(t *testing.T) {
	isolateSecrets(t)
	body := []byte(`{"enroll_secret":"topsecret","node_key":"abcd1234","host_identifier":"h1",` +
		`"nested":[{"Node_Key":"zzz"}],"node_invalid":false}`)
	got := redactJSON(body)
	for _, leak := range []string{"topsecret", "abcd1234", "zzz"} {
		if strings.Contains(got, leak) {
			t.Fatalf("redactJSON leaked %q: %s", leak, got)
		}
	}
	for _, keep := range []string{`"host_identifier":"h1"`, `"enroll_secret":"****"`, `"node_key":"****"`, `"node_invalid":false`} {
		if !strings.Contains(got, keep) {
			t.Fatalf("redactJSON lost %s: %s", keep, got)
		}
	}

	if got := RedactedIndent(map[string]interface{}{"node_key": "abcd1234", "queries": map[string]interface{}{}}); strings.Contains(got, "abcd1234") {
		t.Fatalf("RedactedIndent leaked the node key: %s", got)
	}

	long := strings.Repeat("x", maxRawBody+100)
	if got := redactJSON([]byte(long)); len(got) > maxRawBody+40 {
		t.Fatalf("non-JSON body not truncated: %d bytes", len(got))
	}
}

// captureStdout runs fn with os.Stdout redirected and returns what it printed.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	defer func() { os.Stdout = old }()
	fn()
	_ = w.Close()
	os.Stdout = old
	return <-done
}

func TestEchoedCredentialsAreRedactedFromPlainTextErrors(t *testing.T) {
	t.Chdir(t.TempDir()) // http_errors.log is written to the working directory
	// A proxy or WAF error page that echoes the request, as plain text.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprintf(w, "oops, bad request: %s", b)
	}))
	defer srv.Close()

	const secret, key = "ENROLL-SECRET-plain-1", "NODEKEY-plain-2"
	c := NewHTTPClient(true, false)
	out := captureStdout(t, func() {
		_, _, _ = c.Post(srv.URL, map[string]string{"enroll_secret": secret, "host_identifier": "h"}, nil)
		_, _, _ = c.Post(srv.URL, map[string]string{"node_key": key}, nil)
	})
	logged, err := os.ReadFile("http_errors.log")
	if err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{"stdout": out, "http_errors.log": string(logged)} {
		if !strings.Contains(text, "oops, bad request") {
			t.Fatalf("%s lacks the error body:\n%s", name, text)
		}
		for _, leak := range []string{secret, key} {
			if strings.Contains(text, leak) {
				t.Errorf("%s leaked %q:\n%s", name, leak, text)
			}
		}
	}
}

// isolateSecrets empties the credential registry for one test and restores
// it afterwards, so values other tests register (such as a one-letter node
// key) don't mask parts of this test's text.
func isolateSecrets(t *testing.T) {
	t.Helper()
	secrets.Lock()
	saved := secrets.set
	secrets.set, secrets.replacer = map[string]bool{}, nil
	secrets.Unlock()
	t.Cleanup(func() {
		secrets.Lock()
		secrets.set, secrets.replacer = saved, nil
		secrets.Unlock()
	})
}

func TestRedactMasksRegisteredValues(t *testing.T) {
	isolateSecrets(t)
	RegisterSecret("s3cr3t-value", "")
	if got := Redact(`<html>key=s3cr3t-value</html>`); got != `<html>key=****</html>` {
		t.Fatalf("Redact = %q", got)
	}
	if got := redactJSON([]byte(`{"error":"bad key s3cr3t-value"}`)); strings.Contains(got, "s3cr3t-value") {
		t.Fatalf("redactJSON leaked a registered value: %s", got)
	}
	// A node key received in a response is registered too.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"node_key":"fresh-key-from-server"}`)
	}))
	defer srv.Close()
	if _, _, err := NewHTTPClient(false, false).Post(srv.URL, map[string]string{}, nil); err != nil {
		t.Fatal(err)
	}
	if got := Redact("x fresh-key-from-server y"); got != "x **** y" {
		t.Fatalf("received node key not registered: %q", got)
	}
}

func TestCrossOriginRedirectsAreRefused(t *testing.T) {
	var hits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/same" {
			http.Redirect(w, r, "/ok", http.StatusTemporaryRedirect)
			return
		}
		if r.URL.Path == "/ok" {
			_, _ = io.WriteString(w, `{"node_key":"node-key-from-test-server"}`)
			return
		}
		http.Redirect(w, r, other.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()

	c := NewHTTPClient(false, false)
	if _, _, err := c.Post(srv.URL+"/away", map[string]string{"enroll_secret": "x"}, nil); err == nil || !strings.Contains(err.Error(), "refusing redirect") {
		t.Fatalf("cross-host redirect: err = %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("the request was re-sent to another host")
	}
	code, resp, err := c.Post(srv.URL+"/same", map[string]string{}, nil)
	if err != nil || code != http.StatusOK || resp["node_key"] != "node-key-from-test-server" {
		t.Fatalf("same-origin redirect: %d %v %v", code, resp, err)
	}
}

func TestOversizedResponsesAreRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte(" "), maxResponseBody+1))
	}))
	defer srv.Close()
	if _, _, err := NewHTTPClient(false, false).Post(srv.URL, map[string]string{}, nil); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("oversized body: err = %v", err)
	}
}
