// Package main is the entry point for the ocis-ftp-bridge service.
//
// This service provides FTP protocol support for printer/scanner ingestion
// into oCIS via LibreGraph and WebDAV.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
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
		fmt.Fprintf(os.Stderr, "Error: -config is required\n")
		os.Exit(1)
	}

	// Create observability with default logger config
	// We need to load config first to get logging configuration
	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Create observability client with logging configuration
	obsConfig := observability.Config{
		Debug:  cfg.Observability.Debug,
		Logger: cfg.Observability.Logger,
	}
	
	obs, err := observability.New(obsConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to initialize observability: %v\n", err)
		os.Exit(1)
	}
	defer obs.Stop()

	// Get the structured logger
	logger := obs.Logger()

	// Log version information at startup with structured fields
	logger.Info("Starting service",
		slog.String("version", Version),
		slog.String("commit", CommitSHA),
		slog.String("built", BuildDate),
		slog.String("config_path", *configPath),
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger.Info("Initializing server...")

	srv, err := server.New(cfg, obs)
	if err != nil {
		logger.Error("Failed to create server",
			slog.String("error", err.Error()),
		)
		os.Exit(1)
	}

	logger.Info("Server initialized, starting...")

	if err := srv.Run(ctx); err != nil {
		logger.Error("Server failed",
			slog.String("error", err.Error()),
		)
		os.Exit(1)
	}

	logger.Info("Server shutdown complete")
}
