package protocol

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// secrets holds every credential value this process has sent or received
// (the enroll secret, every node key). Anything printed or logged from a
// server response passes through Redact, so a server or proxy that echoes
// the request in an error page cannot put a credential in stdout or
// http_errors.log, whatever the content type.
var secrets = struct {
	sync.RWMutex
	set      map[string]bool
	replacer *strings.Replacer // rebuilt lazily after set changes
}{set: map[string]bool{}}

// RegisterSecret adds credential values that Redact must mask. Empty values
// are ignored.
func RegisterSecret(values ...string) {
	secrets.RLock()
	missing := false
	for _, v := range values {
		if v != "" && !secrets.set[v] {
			missing = true
			break
		}
	}
	secrets.RUnlock()
	if !missing {
		return
	}
	secrets.Lock()
	defer secrets.Unlock()
	for _, v := range values {
		if v != "" && !secrets.set[v] {
			secrets.set[v] = true
			secrets.replacer = nil
		}
	}
}

// Redact replaces every registered credential value in s with ****.
func Redact(s string) string {
	secrets.RLock()
	r, n := secrets.replacer, len(secrets.set)
	secrets.RUnlock()
	if n == 0 {
		return s
	}
	if r == nil {
		secrets.Lock()
		if secrets.replacer == nil {
			pairs := make([]string, 0, 2*len(secrets.set))
			for v := range secrets.set {
				pairs = append(pairs, v, "****")
			}
			secrets.replacer = strings.NewReplacer(pairs...)
		}
		r = secrets.replacer
		secrets.Unlock()
	}
	return r.Replace(s)
}

// registerSecretsIn registers the values of sensitive keys found anywhere in
// a decoded JSON value.
func registerSecretsIn(v interface{}) {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, val := range t {
			if s, ok := val.(string); ok && sensitiveKeys[strings.ToLower(k)] {
				RegisterSecret(s)
				continue
			}
			registerSecretsIn(val)
		}
	case []interface{}:
		for _, val := range t {
			registerSecretsIn(val)
		}
	}
}

// sensitiveKeys are JSON object keys whose values are credentials and must
// never be printed or logged.
var sensitiveKeys = map[string]bool{
	"enroll_secret": true,
	"node_key":      true,
}

// redactValue returns a copy of a decoded JSON value with every sensitive key's
// value masked, at any depth.
func redactValue(v interface{}) interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(t))
		for k, val := range t {
			if sensitiveKeys[strings.ToLower(k)] {
				out[k] = maskSecret(val)
				continue
			}
			out[k] = redactValue(val)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(t))
		for i, val := range t {
			out[i] = redactValue(val)
		}
		return out
	default:
		return v
	}
}

// maskSecret replaces a credential with a fixed mask, keeping only whether it
// was set.
func maskSecret(v interface{}) interface{} {
	if s, ok := v.(string); ok && s == "" {
		return ""
	}
	return "****"
}

// maxRawBody caps how much of a non-JSON body (an HTML 404 page, a proxy
// error) is echoed, which is usually enough to diagnose a wrong --flavor/path.
const maxRawBody = 512

// redactJSON returns a JSON document with sensitive values masked. Bodies that
// are not JSON are truncated. Either way, every registered credential value
// is masked wherever it appears (see Redact).
func redactJSON(raw []byte) string {
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		text := Redact(strings.TrimSpace(string(raw)))
		if len(text) > maxRawBody {
			text = text[:maxRawBody] + fmt.Sprintf("... (%d bytes total)", len(raw))
		}
		return text
	}
	out, err := json.Marshal(redactValue(v))
	if err != nil {
		return "<unprintable body>"
	}
	return Redact(string(out))
}

// RedactedIndent pretty-prints a decoded JSON value with sensitive values masked.
func RedactedIndent(v interface{}) string {
	out, err := json.MarshalIndent(redactValue(v), "", "  ")
	if err != nil {
		return "<unprintable body>"
	}
	return Redact(string(out))
}

// HTTPClient wraps http.Client with custom configuration
type HTTPClient struct {
	client    *http.Client
	debug     bool
	userAgent string
}

// UserAgent identifies phantomfleet traffic, so server operators can
// recognize, filter or block simulated fleets.
func UserAgent(version string) string {
	return "phantomfleet/" + version + " (+https://github.com/huntbase-io/phantomfleet)"
}

// maxResponseBody bounds how much of a response is read: the largest
// legitimate answers (a config with many packs, a distributed read with many
// queries) are far smaller.
const maxResponseBody = 16 << 20

// checkRedirect refuses a redirect to another scheme or host: the request
// body (the enroll secret or a node key) would be sent there again. Redirects
// within the same origin are followed, up to 10.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	orig := via[0].URL
	if req.URL.Scheme != orig.Scheme || req.URL.Host != orig.Host {
		return fmt.Errorf("refusing redirect from %s://%s to %s://%s: the request carries credentials", orig.Scheme, orig.Host, req.URL.Scheme, req.URL.Host)
	}
	return nil
}

// NewHTTPClient creates a new HTTP client
func NewHTTPClient(debug bool, insecure bool) *HTTPClient {
	tr := &http.Transport{
		// Certificates are verified by default; skipping verification requires
		// the explicit --insecure flag (default false) for self-signed dev stacks.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure, MinVersion: tls.VersionTLS12}, // #nosec G402 -- opt-in via --insecure (default false), dev load generator only
		Proxy:           http.ProxyFromEnvironment,
		// Every simulated node talks to the same server: keep enough idle
		// connections for them to be reused instead of opening (and leaving
		// in TIME_WAIT) a new one per request.
		// MaxConnsPerHost bounds open sockets: a burst beyond it waits for a
		// free connection instead of exhausting local ports.
		MaxIdleConns:        1024,
		MaxIdleConnsPerHost: 1024,
		MaxConnsPerHost:     1024,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	return &HTTPClient{
		client: &http.Client{
			Transport:     tr,
			Timeout:       30 * time.Second,
			CheckRedirect: checkRedirect,
		},
		debug: debug,
	}
}

// SetUserAgent sets the User-Agent header sent with every request.
func (c *HTTPClient) SetUserAgent(ua string) {
	c.userAgent = ua
}

// Debug reports whether the client prints requests and responses.
func (c *HTTPClient) Debug() bool {
	return c.debug
}

// Post sends a POST request and returns status code and parsed response
func (c *HTTPClient) Post(url string, data interface{}, headers map[string]string) (int, map[string]interface{}, error) {
	code, result, _, err := c.PostWithRetryAfter(url, data, headers)
	return code, result, err
}

// Throttled reports whether a status asks the client to slow down and retry.
func Throttled(code int) bool {
	return code == http.StatusTooManyRequests || code == http.StatusServiceUnavailable
}

// retryAfter parses a Retry-After header given in seconds, bounded to
// [1s, 5m]; zero when absent or unparsable.
func retryAfter(h http.Header) time.Duration {
	s := strings.TrimSpace(h.Get("Retry-After"))
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return min(max(time.Duration(n)*time.Second, time.Second), 5*time.Minute)
}

// PostWithRetryAfter is Post that also returns the server's Retry-After
// delay for throttled (429/503) responses.
func (c *HTTPClient) PostWithRetryAfter(url string, data interface{}, headers map[string]string) (int, map[string]interface{}, time.Duration, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return 0, nil, 0, err
	}
	// Whatever credential this request carries is masked in anything
	// printed from now on.
	var sent interface{}
	if json.Unmarshal(jsonData, &sent) == nil {
		registerSecretsIn(sent)
	}

	if c.debug {
		fmt.Printf("POST to %s\n", url)
		fmt.Printf("DATA: %s\n", redactJSON(jsonData))
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewBuffer(jsonData))
	if err != nil {
		return 0, nil, 0, err
	}

	req.Header.Set("Content-Type", "application/json")
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, nil, 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody+1))
	if err != nil {
		return resp.StatusCode, nil, 0, err
	}
	if len(body) > maxResponseBody {
		return resp.StatusCode, nil, 0, fmt.Errorf("response from %s is larger than %d MiB", url, maxResponseBody>>20)
	}

	if c.debug {
		fmt.Printf("HTTP %d\n", resp.StatusCode)
	}

	var result map[string]interface{}
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(body, &result); err != nil {
			return resp.StatusCode, nil, 0, err
		}
		registerSecretsIn(result)
		if c.debug {
			fmt.Printf("%s\n", RedactedIndent(result))
		}
	} else {
		// Keep the parsed body when there is one: an error response can carry
		// node_invalid (Fleet answers 401 with it). Non-JSON bodies are fine.
		_ = json.Unmarshal(body, &result)
		if Throttled(resp.StatusCode) && !c.debug {
			// Rate limiting is expected when a whole fleet shares one source
			// address; the caller backs off. Not worth a line per request.
			return resp.StatusCode, result, retryAfter(resp.Header), nil
		}
		// Print error and output when not 200
		fmt.Printf("HTTP request to %s returned status %d\n", url, resp.StatusCode)
		fmt.Printf("Response body: %s\n", redactJSON(body))
		// Write error to external file
		f, ferr := os.OpenFile("http_errors.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if ferr == nil {
			logLine := fmt.Sprintf("%s | %s | HTTP %d\n%s\n\n", time.Now().Format(time.RFC3339), url, resp.StatusCode, redactJSON(body))
			_, _ = f.WriteString(logLine)
			_ = f.Close()
		}
	}

	return resp.StatusCode, result, retryAfter(resp.Header), nil
}
