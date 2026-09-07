// Package server provides the service lifecycle for ocis-ftp-bridge.
//
// Issue #1 deliberately does not start a production FTP listener. The FTP protocol
// implementation is selected in pkg/ftp and real account/driver wiring is introduced
// by the later FTP implementation issue.
package server

import (
	"context"
	"fmt"
	"sync"

	"github.com/amamus/ocis-ftp-bridge/pkg/config"
	"github.com/amamus/ocis-ftp-bridge/pkg/ftp"
	"github.com/amamus/ocis-ftp-bridge/pkg/graph"
	"github.com/amamus/ocis-ftp-bridge/pkg/http"
	"github.com/amamus/ocis-ftp-bridge/pkg/observability"
	"github.com/amamus/ocis-ftp-bridge/pkg/spool"
	"github.com/amamus/ocis-ftp-bridge/pkg/webdav"
)

// Server is the main service lifecycle surface.
type Server interface {
	Run(ctx context.Context) error
}

type service struct {
	cfg            *config.Config
	obs            observability.Client
	spoolManager   spool.Manager
	graphClient    graph.Client
	webdavClient   webdav.Client
	ftpServer      ftp.Server
	httpServer     http.Server
	wg             sync.WaitGroup
}

// New validates configuration and constructs the issue #1 service foundation.
func New(cfg *config.Config, obs observability.Client) (Server, error) {
	if cfg == nil {
		return nil, ErrInvalidConfig
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	
	// Validate TLS configuration at startup
	// This ensures that if TLS is enabled, the certificates are valid
	if err := cfg.ValidateTLSConfig(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}

	spoolMgr, err := initializeSpool(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize spool: %w", err)
	}

	if err := obs.Start(); err != nil {
		return nil, fmt.Errorf("failed to start observability: %w", err)
	}

	// Create graph client with placeholder credentials (will be configured per-account)
	graphClient := graph.NewClient(cfg.OCIS.GraphURL, "placeholder-token")

	// Create webdav client with placeholder credentials (will be configured per-account)
	webdavClient := webdav.NewClient(cfg.OCIS.WebDAVURL, "placeholder-token")

	// Initialize FTP server
	ftpDriver := ftp.NewBridgeDriver(cfg, obs, spoolMgr, graphClient)
	ftpServer := ftp.NewServer(ftpDriver)

	// Initialize HTTP operations server
	httpServer := http.NewOperationsServer(cfg.HTTP.Address)

	return &service{
		cfg:            cfg,
		obs:            obs,
		spoolManager:   spoolMgr,
		graphClient:    graphClient,
		webdavClient:   webdavClient,
		ftpServer:      ftpServer,
		httpServer:     httpServer,
	}, nil
}

func initializeSpool(cfg *config.Config) (spool.Manager, error) {
	mgr, err := spool.NewManager(cfg.Spool.Directory, cfg.Spool.MaxSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create spool manager: %w", err)
	}

	if err := mgr.Cleanup(30); err != nil {
		return nil, fmt.Errorf("failed to clean spool: %w", err)
	}

	return mgr, nil
}

// Run starts the FTP and HTTP servers and keeps the service alive until shutdown is requested.
func (s *service) Run(ctx context.Context) error {
	s.obs.Log("info", fmt.Sprintf("starting ocis-ftp-bridge on %s with passive ports %d-%d",
		s.cfg.Server.Listen, s.cfg.Server.Passive.MinPort, s.cfg.Server.Passive.MaxPort))

	// Start FTP server in a goroutine
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.runFTPServer(ctx); err != nil {
			s.obs.Log("error", fmt.Sprintf("FTP server failed: %v", err))
		}
	}()

	// Start HTTP operations server in a goroutine
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.runHTTPServer(ctx); err != nil {
			s.obs.Log("error", fmt.Sprintf("HTTP server failed: %v", err))
		}
	}()

	// Log service startup info
	s.obs.Log("info", fmt.Sprintf("HTTP operations server started on %s", s.cfg.HTTP.Address))
	s.obs.Log("info", "Endpoints available: /healthz, /readyz, /metrics")

	// Wait for shutdown
	<-ctx.Done()

	s.obs.Log("info", "shutting down ocis-ftp-bridge")

	// Shutdown FTP server
	if err := s.stopFTPServer(); err != nil {
		s.obs.Log("error", fmt.Sprintf("FTP server shutdown error: %v", err))
	}

	// Shutdown HTTP server
	if err := s.stopHTTPServer(); err != nil {
		s.obs.Log("error", fmt.Sprintf("HTTP server shutdown error: %v", err))
	}

	// Wait for all servers to stop
	s.wg.Wait()

	if err := s.obs.Stop(); err != nil {
		return fmt.Errorf("failed to stop observability: %w", err)
	}
	return nil
}

// runFTPServer runs the FTP server on the configured address.
func (s *service) runFTPServer(ctx context.Context) error {
	// The FTP server will use the ListenAddr from GetSettings()
	s.obs.Log("info", fmt.Sprintf("FTP server starting on %s", s.cfg.Server.Listen))

	// Start serving FTP connections
	err := s.ftpServer.ListenAndServe()
	if err != nil {
		return fmt.Errorf("FTP server failed: %w", err)
	}

	return nil
}

// runHTTPServer runs the HTTP operations server
func (s *service) runHTTPServer(ctx context.Context) error {
	s.obs.Log("info", fmt.Sprintf("HTTP operations server starting on %s", s.cfg.HTTP.Address))
	return s.httpServer.Run(ctx)
}

// stopHTTPServer stops the HTTP operations server
func (s *service) stopHTTPServer() error {
	return s.httpServer.Stop()
}

// stopFTPServer stops the FTP server.
func (s *service) stopFTPServer() error {
	return s.ftpServer.Stop()
}

type ServerError struct {
	msg string
}

func (e *ServerError) Error() string {
	return fmt.Sprintf("server error: %s", e.msg)
}

var (
	ErrInvalidConfig    = &ServerError{msg: "invalid server config"}
	ErrServerNotRunning = &ServerError{msg: "server not running"}
	ErrShutdownFailed   = &ServerError{msg: "server shutdown failed"}
)
