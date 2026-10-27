package http

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestOperationsServer_Creation(t *testing.T) {
	t.Run("create server with default address", func(t *testing.T) {
		server := NewOperationsServer(":9200", AuthConfig{}, HealthCheckConfig{CheckTimeout: 5 * time.Second})
		if server == nil {
			t.Fatal("Expected non-nil server")
		}

		if server.Addr() != "" {
			t.Errorf("Expected empty address before start, got %q", server.Addr())
		}
	})

	t.Run("create server with random port", func(t *testing.T) {
		server := NewOperationsServer(":0", AuthConfig{}, HealthCheckConfig{CheckTimeout: 5 * time.Second})
		if server == nil {
			t.Fatal("Expected non-nil server")
		}
	})
}

func TestOperationsServer_StartStop(t *testing.T) {
	t.Run("start and stop without error", func(t *testing.T) {
		server := NewOperationsServer(":0", AuthConfig{}, HealthCheckConfig{CheckTimeout: 5 * time.Second})

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Start the server
		if err := server.Run(ctx); err != nil {
			t.Fatalf("Failed to start HTTP server: %v", err)
		}

		// Give server time to start
		time.Sleep(50 * time.Millisecond)

		// Check that server is healthy and ready
		if !server.IsHealthy() {
			t.Error("Expected server to be healthy after start")
		}
		if !server.IsReady() {
			t.Error("Expected server to be ready after start")
		}

		// Check that address is set
		addr := server.Addr()
		if addr == "" {
			t.Error("Expected non-empty address after start")
		}

		// Stop the server
		if err := server.Stop(); err != nil {
			t.Fatalf("Failed to stop HTTP server: %v", err)
		}
	})

	t.Run("double start returns error", func(t *testing.T) {
		server := NewOperationsServer(":0", AuthConfig{}, HealthCheckConfig{CheckTimeout: 5 * time.Second})

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Start the server
		if err := server.Run(ctx); err != nil {
			t.Fatalf("Failed to start HTTP server: %v", err)
		}

		// Give server time to start
		time.Sleep(50 * time.Millisecond)

		// Try to start again
		err := server.Run(ctx)
		if err == nil {
			t.Error("Expected error when starting server twice")
		}
	})

	t.Run("double stop is safe", func(t *testing.T) {
		server := NewOperationsServer(":0", AuthConfig{}, HealthCheckConfig{CheckTimeout: 5 * time.Second})

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Start the server
		if err := server.Run(ctx); err != nil {
			t.Fatalf("Failed to start HTTP server: %v", err)
		}

		// Give server time to start
		time.Sleep(50 * time.Millisecond)

		// Stop the server
		if err := server.Stop(); err != nil {
			t.Fatalf("Failed to stop HTTP server: %v", err)
		}

		// Stop again - should be safe
		if err := server.Stop(); err != nil {
			t.Fatalf("Failed to stop HTTP server second time: %v", err)
		}
	})
}

func TestOperationsServer_HealthState(t *testing.T) {
	t.Run("health state management", func(t *testing.T) {
		server := NewOperationsServer(":0", AuthConfig{}, HealthCheckConfig{CheckTimeout: 5 * time.Second})

		// Initially healthy
		if !server.IsHealthy() {
			t.Error("Expected server to be healthy initially")
		}

		// Set to unhealthy
		server.SetHealthy(false)
		if server.IsHealthy() {
			t.Error("Expected server to be unhealthy after SetHealthy(false)")
		}

		// Set back to healthy
		server.SetHealthy(true)
		if !server.IsHealthy() {
			t.Error("Expected server to be healthy after SetHealthy(true)")
		}
	})

	t.Run("ready state management", func(t *testing.T) {
		server := NewOperationsServer(":0", AuthConfig{}, HealthCheckConfig{CheckTimeout: 5 * time.Second})

		// Initially ready
		if !server.IsReady() {
			t.Error("Expected server to be ready initially")
		}

		// Set to not ready
		server.SetReady(false)
		if server.IsReady() {
			t.Error("Expected server to be not ready after SetReady(false)")
		}

		// Set back to ready
		server.SetReady(true)
		if !server.IsReady() {
			t.Error("Expected server to be ready after SetReady(true)")
		}
	})
}

func TestOperationsServer_Metrics(t *testing.T) {
	t.Run("metrics methods do not panic", func(t *testing.T) {
		server := NewOperationsServer(":0", AuthConfig{}, HealthCheckConfig{CheckTimeout: 5 * time.Second})

		// These should not panic
		server.IncrementFTPSessionTotal("success")
		server.IncrementFTPSessionTotal("failure")

		server.SetFTPActiveSessions(5)

		server.IncrementUploadsTotal("success")
		server.IncrementUploadsTotal("failure")

		server.IncrementUploadFailuresTotal("timeout")
		server.IncrementUploadFailuresTotal("permission_denied")

		server.AddUploadBytes(1024)

		server.ObserveUploadDuration(1*time.Second, "success")

		server.IncrementOcisRequestsTotal("graph", "success")
		server.IncrementOcisRequestsTotal("webdav", "failure")
	})
}

// TestOperationsServer_ReadHeaderTimeout verifies that the HTTP server is
// configured with a ReadHeaderTimeout to mitigate Slowloris attacks.
func TestOperationsServer_ReadHeaderTimeout(t *testing.T) {
	server := NewOperationsServer(":0", AuthConfig{}, HealthCheckConfig{CheckTimeout: 5 * time.Second})
	if server.server == nil {
		t.Fatal("expected underlying http.Server to be initialized")
	}
	if server.server.ReadHeaderTimeout != 10*time.Second {
		t.Fatalf("expected ReadHeaderTimeout of 10s, got %v", server.server.ReadHeaderTimeout)
	}
}

// waitForAddr polls until the server reports its bound address.
func waitForAddr(t *testing.T, server *OperationsServer) string {
	t.Helper()
	for i := 0; i < 100; i++ {
		if addr := server.Addr(); addr != "" {
			return "http://" + addr
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("operations server did not bind a listener")
	return ""
}

// TestOperationsServer_RunFailsOnBusyPort guards SEC-009: Run must return an
// error when the operations port is already in use instead of silently
// leaving the bridge running without an operations server.
func TestOperationsServer_RunFailsOnBusyPort(t *testing.T) {
	// Occupy a port so the operations server cannot bind it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to occupy test port: %v", err)
	}
	defer ln.Close()

	server := NewOperationsServer(ln.Addr().String(), AuthConfig{}, HealthCheckConfig{CheckTimeout: 5 * time.Second})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := server.Run(ctx); err == nil {
		t.Error("Run on a busy port returned nil error, want listen error (SEC-009)")
		_ = server.Stop()
	}

	// A failed Run must leave Stop as a safe no-op.
	if err := server.Stop(); err != nil {
		t.Errorf("Stop after failed Run = %v, want nil", err)
	}
}

// TestOperationsServer_ReadyzCachesHealthChecks guards SEC-010: /readyz must
// not run outbound health checks on every request; results are cached for a
// short TTL so probe hammering does not amplify into oCIS/WebDAV traffic.
func TestOperationsServer_ReadyzCachesHealthChecks(t *testing.T) {
	var statusCalls int32
	ocis := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/status" {
			atomic.AddInt32(&statusCalls, 1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ocis.Close()

	server := NewOperationsServer("127.0.0.1:0", AuthConfig{}, HealthCheckConfig{
		OCISURL:        ocis.URL,
		WebDAVURL:      ocis.URL,
		SpoolDirectory: t.TempDir(),
		CheckTimeout:   5 * time.Second,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := server.Run(ctx); err != nil {
		t.Fatalf("Failed to start HTTP server: %v", err)
	}
	defer server.Stop()

	base := waitForAddr(t, server)

	client := &http.Client{Timeout: 10 * time.Second}
	for i := 0; i < 2; i++ {
		resp, err := client.Get(base + "/readyz")
		if err != nil {
			t.Fatalf("GET /readyz failed: %v", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /readyz = %d, want 200 (all checks pass against the test server)", resp.StatusCode)
		}
	}

	if got := atomic.LoadInt32(&statusCalls); got != 1 {
		t.Errorf("oCIS /status called %d times for 2 rapid /readyz requests, want 1 (cached, SEC-010)", got)
	}
}

// TestOperationsServer_ReadyzDoesNotMutateReadiness guards SEC-010: a failing
// /readyz response is computed per request and must not mutate the server's
// global readiness state (probe-induced readiness flapping drains pods).
func TestOperationsServer_ReadyzDoesNotMutateReadiness(t *testing.T) {
	server := NewOperationsServer("127.0.0.1:0", AuthConfig{}, HealthCheckConfig{
		OCISURL:        "http://127.0.0.1:1", // nothing listens here: connection refused
		WebDAVURL:      "http://127.0.0.1:1",
		SpoolDirectory: t.TempDir(),
		CheckTimeout:   time.Second,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := server.Run(ctx); err != nil {
		t.Fatalf("Failed to start HTTP server: %v", err)
	}
	defer server.Stop()

	base := waitForAddr(t, server)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(base + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz failed: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("GET /readyz with unreachable oCIS = %d, want 503", resp.StatusCode)
	}

	if !server.IsReady() {
		t.Error("global readiness was mutated by the /readyz handler; probes must not change it (SEC-010)")
	}
}
