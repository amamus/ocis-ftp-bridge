package main

import (
	"context"
	"flag"
	"log"
	"os/signal"
	"syscall"

	"github.com/amamus/ocis-ftp-bridge/pkg/config"
	"github.com/amamus/ocis-ftp-bridge/pkg/observability"
	"github.com/amamus/ocis-ftp-bridge/pkg/server"
)

func main() {
	configPath := flag.String("config", "", "path to ocis-ftp-bridge YAML configuration")
	flag.Parse()
	if *configPath == "" {
		log.Fatal("-config is required")
	}

	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		log.Fatalf("failed to load configuration: %v", err)
	}

	obs, err := observability.New(observability.Config{Debug: cfg.Observability.Debug})
	if err != nil {
		log.Fatalf("failed to initialize observability: %v", err)
	}
	defer obs.Stop()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv, err := server.New(cfg, obs)
	if err != nil {
		log.Fatalf("failed to create server: %v", err)
	}
	if err := srv.Run(ctx); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
