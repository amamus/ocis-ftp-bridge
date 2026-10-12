package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

	// Run binds the listener synchronously; poll briefly anyway so the test
	// does not depend on that timing detail.
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

// writeTestCertificate generates a self-signed certificate with an RSA key of
// the given size and writes the cert/key PEM files into dir.
func writeTestCertificate(t *testing.T, dir string, keyBits int) (certPath, keyPath string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ocis-ftp-bridge-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	certOut, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("failed to create certificate file: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		certOut.Close()
		t.Fatalf("failed to encode certificate: %v", err)
	}
	certOut.Close()

	keyOut, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("failed to create key file: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		keyOut.Close()
		t.Fatalf("failed to encode key: %v", err)
	}
	keyOut.Close()

	return certPath, keyPath
}

// TestNewValidatesTLSConfig guards QLT-003: server.New must validate the TLS
// configuration at startup so a missing, unreadable, expired, or weak-key
// certificate fails fast instead of when the first FTPS connection arrives.
func TestNewValidatesTLSConfig(t *testing.T) {
	t.Run("missing certificate file", func(t *testing.T) {
		cfg := testConfig(t)
		cfg.Server.TLS.Enabled = true
		cfg.Server.TLS.Cert = filepath.Join(t.TempDir(), "does-not-exist.pem")
		cfg.Server.TLS.Key = filepath.Join(t.TempDir(), "does-not-exist-key.pem")

		if _, err := New(cfg, noopObs{}); err == nil {
			t.Error("New with TLS enabled but missing certificate files = nil error, want error (QLT-003)")
		}
	})

	t.Run("weak RSA key", func(t *testing.T) {
		dir := t.TempDir()
		certPath, keyPath := writeTestCertificate(t, dir, 1024)

		cfg := testConfig(t)
		cfg.Server.TLS.Enabled = true
		cfg.Server.TLS.Cert = certPath
		cfg.Server.TLS.Key = keyPath

		if _, err := New(cfg, noopObs{}); err == nil {
			t.Error("New with TLS enabled and a 1024-bit RSA key = nil error, want error (QLT-003)")
		}
	})

	t.Run("valid certificate", func(t *testing.T) {
		dir := t.TempDir()
		certPath, keyPath := writeTestCertificate(t, dir, 2048)

		cfg := testConfig(t)
		cfg.Server.TLS.Enabled = true
		cfg.Server.TLS.Cert = certPath
		cfg.Server.TLS.Key = keyPath

		if _, err := New(cfg, noopObs{}); err != nil {
			t.Errorf("New with TLS enabled and a valid certificate = %v, want nil (QLT-003)", err)
		}
	})
}

// freeLoopbackAddr returns a loopback host:port with a currently free port.
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve a port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// getMetricsBody fetches /metrics and returns the response body, or an empty
// string while the server is not yet accepting connections.
func getMetricsBody(client *http.Client, base string) string {
	resp, err := client.Get(base + "/metrics")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return string(b)
}

// hasSpoolCapacity reports whether the metrics body contains the spool
// capacity gauge set to want.
func hasSpoolCapacity(body string, want float64) bool {
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "ocis_ftp_spool_capacity_bytes ") {
			fields := strings.Fields(line)
			if len(fields) != 2 {
				return false
			}
			got, err := strconv.ParseFloat(fields[1], 64)
			return err == nil && got == want
		}
	}
	return false
}

// TestRunStartsSpoolMonitor guards QLT-003: the spool monitor must be started
// with the service lifecycle so the spool metrics are registered on /metrics
// and the capacity gauge reflects the configured spool size.
func TestRunStartsSpoolMonitor(t *testing.T) {
	cfg := testConfig(t)
	cfg.HTTP.Auth.Enabled = false
	cfg.Server.Listen = freeLoopbackAddr(t)
	cfg.Spool.Monitoring.CheckInterval = 50 * time.Millisecond

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
	runErr := make(chan error, 1)
	go func() { runErr <- svc.Run(ctx) }()

	addr := ""
	for i := 0; i < 100; i++ {
		if addr = ops.Addr(); addr != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if addr == "" {
		cancel()
		<-runErr
		t.Fatal("operations server did not bind a listener")
	}

	// Poll /metrics until the spool monitor has published the configured
	// capacity. The monitor sets the capacity gauge on Start, so this proves
	// the monitor is wired into the service lifecycle.
	client := &http.Client{Timeout: 10 * time.Second}
	base := "http://" + addr
	var body string
	deadline := time.Now().Add(3 * time.Second)
	for {
		body = getMetricsBody(client, base)
		if hasSpoolCapacity(body, float64(cfg.Spool.MaxSize)) {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-runErr
			t.Fatalf("spool capacity metric did not appear on /metrics (QLT-003); last body:\n%s", body)
		}
		time.Sleep(25 * time.Millisecond)
	}

	for _, name := range []string{
		"ocis_ftp_spool_size_bytes",
		"ocis_ftp_spool_file_count",
		"ocis_ftp_spool_usage_percent",
		"ocis_ftp_spool_capacity_exceeded_total",
	} {
		if !strings.Contains(body, name) {
			t.Errorf("/metrics missing %q (QLT-003)", name)
		}
	}

	cancel()
	if err := <-runErr; err != nil {
		t.Errorf("Run returned error: %v", err)
	}
}

// TestNewNilConfig verifies that server.New rejects a nil configuration
// instead of panicking (config→server wiring, TST-001).
func TestNewNilConfig(t *testing.T) {
	if _, err := New(nil, noopObs{}); err == nil {
		t.Error("New(nil, ...) = nil error, want ErrInvalidConfig")
	}
}

// TestNewInvalidConfig verifies that an invalid configuration fails
// construction with ErrInvalidConfig (config→server wiring, TST-001).
func TestNewInvalidConfig(t *testing.T) {
	cfg := testConfig(t)
	cfg.Server.Listen = "not-an-address"

	_, err := New(cfg, noopObs{})
	if err == nil {
		t.Fatal("New with invalid server.listen = nil error, want error")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("New with invalid config = %v, want it to wrap ErrInvalidConfig", err)
	}
}

// TestNewSpoolInitFailure verifies that a spool directory that cannot be
// created fails construction instead of starting a broken service
// (TST-001).
func TestNewSpoolInitFailure(t *testing.T) {
	// A regular file where the spool directory tree should be created.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0600); err != nil {
		t.Fatalf("failed to create blocker file: %v", err)
	}

	cfg := testConfig(t)
	cfg.Spool.Directory = filepath.Join(blocker, "spool")

	_, err := New(cfg, noopObs{})
	if err == nil {
		t.Fatal("New with an uncreatable spool directory = nil error, want error")
	}
	if !strings.Contains(err.Error(), "spool") {
		t.Errorf("New error = %v, want it to mention the spool initialization", err)
	}
}

// TestStopFTPSServerShutsDownFTPDriver verifies that stopping the FTP server
// also shuts down the FTP driver, cancelling its lifecycle context so that
// in-flight uploads are aborted during service shutdown instead of surviving
// until the client disconnects (QLT-011).
func TestStopFTPSServerShutsDownFTPDriver(t *testing.T) {
	srv, err := New(testConfig(t), noopObs{})
	if err != nil {
		t.Fatalf("failed to construct service: %v", err)
	}
	svc, ok := srv.(*service)
	if !ok {
		t.Fatalf("expected *service, got %T", srv)
	}

	// Stop returns ErrNotListening because no listener was started in this
	// test; the driver shutdown must still have happened.
	_ = svc.stopFTPServer()

	if !svc.ftpDriver.IsShuttingDown() {
		t.Error("stopFTPServer did not shut down the FTP driver (QLT-011)")
	}
}
