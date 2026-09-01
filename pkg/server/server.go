// Package server provides the service lifecycle for ocis-ftp-bridge.
//
// Issue #1 deliberately does not start a production FTP listener. The FTP protocol
// implementation is selected in pkg/ftp and real account/driver wiring is introduced
// by the later FTP implementation issue.
package server

import (
	"context"
	"fmt"

	"github.com/amamus/ocis-ftp-bridge/pkg/config"
	"github.com/amamus/ocis-ftp-bridge/pkg/graph"
	"github.com/amamus/ocis-ftp-bridge/pkg/observability"
	"github.com/amamus/ocis-ftp-bridge/pkg/spool"
	"github.com/amamus/ocis-ftp-bridge/pkg/webdav"
)

// Server is the main service lifecycle surface.
type Server interface {
	Run(ctx context.Context) error
}

type service struct {
	cfg          *config.Config
	obs          observability.Client
	spoolManager spool.Manager
	graphClient  graph.Client
	webdavClient webdav.Client
}

// New validates configuration and constructs the issue #1 service foundation.
func New(cfg *config.Config, obs observability.Client) (Server, error) {
	if cfg == nil {
		return nil, ErrInvalidConfig
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}

	spoolMgr, err := initializeSpool(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize spool: %w", err)
	}

	if err := obs.Start(); err != nil {
		return nil, fmt.Errorf("failed to start observability: %w", err)
	}

	return &service{
		cfg:          cfg,
		obs:          obs,
		spoolManager: spoolMgr,
		graphClient:  graph.NewClient(cfg.OCIS.GraphURL, "placeholder-token"),
		webdavClient: webdav.NewClient(cfg.OCIS.WebDAVURL, "placeholder-token"),
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

// Run keeps the service foundation alive until shutdown is requested.
// Real FTP listener wiring is intentionally deferred to issue #6.
func (s *service) Run(ctx context.Context) error {
	s.obs.Log("info", "starting ocis-ftp-bridge")
	<-ctx.Done()
	s.obs.Log("info", "shutting down ocis-ftp-bridge")

	if err := s.obs.Stop(); err != nil {
		return fmt.Errorf("failed to stop observability: %w", err)
	}
	return nil
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
