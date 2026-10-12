package server

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/amamus/ocis-ftp-bridge/pkg/config"
	bridgehttp "github.com/amamus/ocis-ftp-bridge/pkg/http"
	"github.com/amamus/ocis-ftp-bridge/pkg/observability"
)

// noopObs is a no-op observability.Client for tests.
type noopObs struct{}

func (noopObs) Start() error                  { return nil }
func (noopObs) Stop() error                   { return nil }
func (noopObs) Logger() *observability.Logger { return nil }
func (noopObs) Log(level, message string)     {}
func (noopObs) Debug(msg string, args ...any) {}
func (noopObs) Info(msg string, args ...any)  {}
func (noopObs) Warn(msg string, args ...any)  {}
func (noopObs) Error(msg string, args ...any) {}
func (noopObs) Metric(name, value string)     {}
func (noopObs) Trace(name string) observability.Context {
	return noopTrace{}
}

type noopTrace struct{}

func (noopTrace) Finish() {}

// testConfig returns a minimal valid configuration with the spool directory
// pointed at a temporary directory and the operations server on an ephemeral
// loopback port.
func testConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := config.New()
	cfg.Server.TLS.Enabled = false
	cfg.Spool.Directory = t.TempDir()
	cfg.HTTP.Address = "127.0.0.1:0"
	return cfg
}

// startOperationsServer constructs the service and starts only its operations
// HTTP server, returning the bound base URL.
func startOperationsServer(t *testing.T, cfg *config.Config) string {
	t.Helper()

	svc, err := New(cfg, noopObs{})
	if err != nil {
		t.Fatalf("failed to construct service: %v", err)
	}
	s, ok := svc.(*service)
	if !ok {
		t.Fatalf("expected *service, got %T", svc)
	}
	ops, ok := s.httpServer.(*bridgehttp.OperationsServer)
	if !ok {
		t.Fatalf("expected *http.OperationsServer, got %T", s.httpServer)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := ops.Run(ctx); err != nil {
		t.Fatalf("failed to start operations server: %v", err)
	}
	t.Cleanup(func() { ops.Stop() })

	// The listener binds asynchronously; wait for the actual address.
	addr := ""
	for i := 0; i < 100; i++ {
		if addr = ops.Addr(); addr != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if addr == "" {
		t.Fatal("operations server did not bind a listener")
	}
	return "http://" + addr
}

// getStatus performs a GET request, retrying briefly while the listener
// accepts connections but is not yet serving.
func getStatus(t *testing.T, client *http.Client, base, path, user, pass string) int {
	t.Helper()
	var code int
	var err error
	for i := 0; i < 20; i++ {
		req, reqErr := http.NewRequest(http.MethodGet, base+path, nil)
		if reqErr != nil {
			t.Fatalf("failed to build request: %v", reqErr)
		}
		if user != "" || pass != "" {
			req.SetBasicAuth(user, pass)
		}
		var resp *http.Response
		resp, err = client.Do(req)
		if err == nil {
			code = resp.StatusCode
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			return code
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("GET %s failed: %v", path, err)
	return 0
}

// TestOperationsEndpointsRequireAuth guards SEC-001: with http.auth enabled,
// the operations endpoints /readyz and /metrics must reject unauthenticated
// or wrongly-authenticated requests, while /healthz (liveness, consumed by
// docker/k8s probes) stays reachable without credentials.
func TestOperationsEndpointsRequireAuth(t *testing.T) {
	cfg := testConfig(t)
	cfg.HTTP.Auth = config.HTTPAuthConfig{
		Enabled:  true,
		Method:   "basic",
		Username: "admin",
		Password: "test-secret",
	}
	base := startOperationsServer(t, cfg)
	client := &http.Client{Timeout: 10 * time.Second}

	if code := getStatus(t, client, base, "/readyz", "", ""); code != http.StatusUnauthorized {
		t.Errorf("GET /readyz without credentials = %d, want 401 (SEC-001)", code)
	}
	if code := getStatus(t, client, base, "/metrics", "", ""); code != http.StatusUnauthorized {
		t.Errorf("GET /metrics without credentials = %d, want 401 (SEC-001)", code)
	}
	if code := getStatus(t, client, base, "/healthz", "", ""); code != http.StatusOK {
		t.Errorf("GET /healthz without credentials = %d, want 200 (liveness probe)", code)
	}
	if code := getStatus(t, client, base, "/readyz", "admin", "wrong-password"); code != http.StatusUnauthorized {
		t.Errorf("GET /readyz with wrong password = %d, want 401 (SEC-001)", code)
	}
	// Valid credentials must pass the auth gate. The handler itself may
	// return 503 when oCIS is unreachable in the test environment.
	if code := getStatus(t, client, base, "/readyz", "admin", "test-secret"); code == http.StatusUnauthorized {
		t.Error("GET /readyz with valid credentials = 401, want auth to pass (SEC-001)")
	}
}

// TestGeneratedAuthPasswordWhenUnset verifies that a random password is
// generated when http.auth is enabled with method basic but no password is
// configured, so the operations endpoints are protected out of the box
// (SEC-001).
func TestGeneratedAuthPasswordWhenUnset(t *testing.T) {
	cfg := testConfig(t)
	cfg.HTTP.Auth = config.HTTPAuthConfig{
		Enabled:  true,
		Method:   "basic",
		Username: "admin",
		// no password: must be generated at startup
	}

	if _, err := New(cfg, noopObs{}); err != nil {
		t.Fatalf("failed to construct service: %v", err)
	}
	if cfg.HTTP.Auth.Password == "" {
		t.Error("http.auth.password was not generated for enabled basic auth (SEC-001)")
	}
}
