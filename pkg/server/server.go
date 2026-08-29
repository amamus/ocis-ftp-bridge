// Package server provides the main server implementation for ocis-ftp-bridge.
//
// It ties together all components (FTP, auth, spool, graph, webdav)
// and manages the service lifecycle.
package server

import (
	"context"
	"fmt"

	"github.com/amamus/ocis-ftp-bridge/pkg/auth"
	"github.com/amamus/ocis-ftp-bridge/pkg/config"
	"github.com/amamus/ocis-ftp-bridge/pkg/ftp"
	"github.com/amamus/ocis-ftp-bridge/pkg/graph"
	"github.com/amamus/ocis-ftp-bridge/pkg/observability"
	"github.com/amamus/ocis-ftp-bridge/pkg/spool"
	"github.com/amamus/ocis-ftp-bridge/pkg/webdav"
)

// Server is the main service server
type Server interface {
	// Run starts the server and blocks until ctx is done
	Run(ctx context.Context) error
}

// service is the default implementation of Server
type service struct {
	cfg          *config.Config
	obs          observability.Client
	spoolManager  spool.Manager
	graphClient  graph.Client
	webdavClient webdav.Client
	ftpAuth      ftp.Authenticator
	authMapper   auth.AccountMapper
	ftpServer    ftp.Server
}

// New creates a new server instance
func New(cfg *config.Config, obs observability.Client) (Server, error) {
	// Validate config
	if cfg == nil {
		return nil, ErrInvalidConfig
	}

	// Initialize spool manager
	spoolMgr, err := initializeSpool(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize spool: %w", err)
	}

	// Initialize observability
	if err := obs.Start(); err != nil {
		return nil, fmt.Errorf("failed to start observability: %w", err)
	}

	graphCli := graph.NewClient(cfg.OCIS.GraphURL, "placeholder-token")
	
	// Initialize WebDAV client
	webdavCli := webdav.NewClient(cfg.OCIS.WebDAVURL, "placeholder-token")

	// Initialize FTP authenticator (placeholder)
	ftpAuth := ftp.NewAuthenticator(map[string]string{ /* config */ })

	// Initialize auth mapper
	authMapp := auth.NewAccountMapper(ftpAuth)

	// Create FTP server (interface only)
	// In production, this would create an actual FTP server
	ftpSrv := &defaultFTPServer{started: false}

	return &service{
		cfg:          cfg,
		obs:          obs,
		spoolManager:  spoolMgr,
		graphClient:  graphCli,
		webdavClient: webdavCli,
		ftpAuth:      ftpAuth,
		authMapper:   authMapp,
		ftpServer:    ftpSrv,
	}, nil
}

// defaultFTPServer is a mock FTP server for testing
// In production, this would be replaced with a real FTP server implementation
type defaultFTPServer struct {
	started bool
}

func (s *defaultFTPServer) Start() error {
	s.started = true
	fmt.Println("FTP server started")
	return nil
}

func (s *defaultFTPServer) Stop() error {
	s.started = false
	fmt.Println("FTP server stopped")
	return nil
}

func (s *defaultFTPServer) ListenAndServe() error {
	fmt.Println("FTP server listening and serving")
	return nil
}

func (s *defaultFTPServer) SetHandler(ftp.Handler) error {
	fmt.Println("FTP handler set")
	return nil
}

// initializeSpool initializes the spool manager
func initializeSpool(cfg *config.Config) (spool.Manager, error) {
	mgr, err := spool.NewManager(cfg.Spool.Directory, cfg.Spool.MaxSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create spool manager: %w", err)
	}
	
	// Cleanup old files
	if err := mgr.Cleanup(30); err != nil {
		fmt.Printf("Warning: spool cleanup failed: %v\n", err)
	}
	
	return mgr, nil
}

// Run starts the server and blocks until context is done
func (s *service) Run(ctx context.Context) error {
	s.obs.Log("info", "starting ocis-ftp-bridge")

	fmt.Printf("Configuration: Debug=%v, FTP=%s, HTTP=%s\n",
		s.cfg.Observability.Debug, s.cfg.FTP.Address, s.cfg.HTTP.Address)

	// In production, this would start the actual FTP server
	fmt.Println("Server running (FTP uploads not implemented)")

	// Block until context is done
	<-ctx.Done()

	s.obs.Log("info", "shutting down ocis-ftp-bridge")

	// Stop observability
	if err := s.obs.Stop(); err != nil {
		fmt.Printf("Warning: failed to stop observability: %v\n", err)
	}

	s.obs.Log("info", "shutdown complete")

	return nil
}

// Errors
type ServerError struct {
	msg string
}

func (e *ServerError) Error() string {
	return fmt.Sprintf("server error: %s", e.msg)
}

var (
	ErrInvalidConfig     = &ServerError{msg: "invalid server config"}
	ErrServerNotRunning  = &ServerError{msg: "server not running"}
	ErrShutdownFailed    = &ServerError{msg: "server shutdown failed"}
)
