package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	"github.com/amamus/ocis-ftp-bridge/pkg/config"
	"github.com/amamus/ocis-ftp-bridge/pkg/observability"
	"github.com/amamus/ocis-ftp-bridge/pkg/server"
)

func main() {
	// Load configuration
	cfg := config.New()

	// Initialize observability
	obsCfg := observability.Config{
		Debug: cfg.Observability.Debug,
	}
	obs, err := observability.New(obsCfg)
	if err != nil {
		log.Fatalf("failed to initialize observability: %v", err)
	}
	defer obs.Stop()

	// Create context for graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Create and run server
	srv, err := server.New(cfg, obs)
	if err != nil {
		log.Fatalf("failed to create server: %v", err)
	}

	// Start server
	if err := srv.Run(ctx); err != nil {
		log.Fatalf("server failed: %v", err)
	}

	log.Println("Server shut down gracefully")
}