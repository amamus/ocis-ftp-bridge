package http

import (
	"context"
	"testing"
	"time"
)

func TestOperationsServer_Creation(t *testing.T) {
	t.Run("create server with default address", func(t *testing.T) {
		server := NewOperationsServer(":9200")
		if server == nil {
			t.Fatal("Expected non-nil server")
		}
		
		if server.Addr() != "" {
			t.Errorf("Expected empty address before start, got %q", server.Addr())
		}
	})

	t.Run("create server with random port", func(t *testing.T) {
		server := NewOperationsServer(":0")
		if server == nil {
			t.Fatal("Expected non-nil server")
		}
	})
}

func TestOperationsServer_StartStop(t *testing.T) {
	t.Run("start and stop without error", func(t *testing.T) {
		server := NewOperationsServer(":0")

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
		server := NewOperationsServer(":0")

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
		server := NewOperationsServer(":0")

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
		server := NewOperationsServer(":0")

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
		server := NewOperationsServer(":0")

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
		server := NewOperationsServer(":0")

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