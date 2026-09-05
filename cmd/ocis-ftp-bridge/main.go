// Package main is the entry point for the ocis-ftp-bridge service.
//
// This service provides FTP protocol support for printer/scanner ingestion
// into oCIS via LibreGraph and WebDAV.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/amamus/ocis-ftp-bridge/pkg/config"
	"github.com/amamus/ocis-ftp-bridge/pkg/observability"
	"github.com/amamus/ocis-ftp-bridge/pkg/server"
)

// Version information - set at build time via ldflags
var (
	Version   = "1.0.0-dev"
	CommitSHA = "unknown"
	BuildDate = "unknown"
)

func main() {
	configPath := flag.String("config", "", "path to ocis-ftp-bridge YAML configuration")
	versionFlag := flag.Bool("version", false, "print version information and exit")
	flag.Parse()

	// Print version information if requested
	if *versionFlag {
		fmt.Printf("%s version %s\n", os.Args[0], Version)
		fmt.Printf("commit: %s\n", CommitSHA)
		fmt.Printf("built: %s\n", BuildDate)
		os.Exit(0)
	}

	if *configPath == "" {
		log.Fatal("-config is required")
	}

	// Log version information at startup
	log.Printf("Starting %s version %s (commit: %s, built: %s)", os.Args[0], Version, CommitSHA, BuildDate)

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
