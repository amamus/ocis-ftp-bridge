// Package spool provides local file spool functionality for ocis-ftp-bridge.
package spool

import (
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/amamus/ocis-ftp-bridge/pkg/config"
	"github.com/amamus/ocis-ftp-bridge/pkg/http"
)

// Monitor provides spool monitoring functionality.
type Monitor struct {
	// spoolDir is the spool directory to monitor
	spoolDir string
	// maxSize is the maximum spool size in bytes
	maxSize uint64
	// config contains monitoring configuration
	config config.MonitoringConfig
	// server is the HTTP server for metrics
	server *http.OperationsServer
	// logger for logging messages
	logger *slog.Logger
	// stopChan for stopping the monitor
	stopChan chan struct{}
	// doneChan signals when monitoring has stopped
	doneChan chan struct{}
}

// NewMonitor creates a new spool monitor.
func NewMonitor(spoolDir string, maxSize uint64, cfg config.MonitoringConfig, server *http.OperationsServer) *Monitor {
	return &Monitor{
		spoolDir:  spoolDir,
		maxSize:   maxSize,
		config:    cfg,
		server:    server,
		logger:    slog.Default(),
		stopChan:  make(chan struct{}),
		doneChan:  make(chan struct{}),
	}
}

// Start starts the spool monitoring loop.
func (m *Monitor) Start() {
	if !m.config.Enabled {
		if m.logger != nil {
			m.logger.Info("Spool monitoring is disabled")
		}
		close(m.doneChan)
		return
	}

	if m.logger != nil {
		m.logger.Info("Starting spool monitoring",
			"spool_directory", m.spoolDir,
			"max_size", m.maxSize,
			"check_interval", m.config.CheckInterval,
			"warning_threshold", m.config.WarningThreshold,
			"critical_threshold", m.config.CriticalThreshold)
	}

	// Set initial capacity metric
	if m.server != nil {
		m.server.SetSpoolCapacityBytes(m.maxSize)
	}

	// Start the monitoring loop
	go m.monitorLoop()
}

// Stop stops the spool monitoring loop.
func (m *Monitor) Stop() {
	close(m.stopChan)
	<-m.doneChan
}

// monitorLoop is the main monitoring loop.
func (m *Monitor) monitorLoop() {
	defer close(m.doneChan)

	ticker := time.NewTicker(m.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			if m.logger != nil {
				m.logger.Info("Stopping spool monitoring")
			}
			return
		case <-ticker.C:
			m.checkSpoolUsage()
		}
	}
}

// checkSpoolUsage checks the current spool usage and updates metrics.
func (m *Monitor) checkSpoolUsage() {
	// Get current usage
	usedBytes, fileCount, err := m.calculateCurrentUsage()
	if err != nil {
		m.logger.Error("Failed to calculate spool usage", "error", err)
		return
	}

	// Calculate usage percentage
	usagePercent := float64(0)
	if m.maxSize > 0 {
		usagePercent = float64(usedBytes) / float64(m.maxSize) * 100
	}

	// Update metrics if server is available
	if m.server != nil {
		m.server.SetSpoolSizeBytes(usedBytes)
		m.server.SetSpoolFileCount(fileCount)
		m.server.SetSpoolCapacityBytes(m.maxSize)
		m.server.SetSpoolUsagePercent(usagePercent)
	}

	if m.logger != nil {
		m.logger.Debug("Spool usage",
			"used_bytes", usedBytes,
			"file_count", fileCount,
			"capacity_bytes", m.maxSize,
			"usage_percent", usagePercent)

		// Check for warning threshold
		if usagePercent >= m.config.WarningThreshold {
			m.logger.Warn("Spool usage warning threshold exceeded",
				"usage_percent", usagePercent,
				"threshold", m.config.WarningThreshold,
				"used_bytes", usedBytes,
				"capacity_bytes", m.maxSize)
		}

		// Check for critical threshold
		if usagePercent >= m.config.CriticalThreshold {
			m.logger.Error("Spool usage critical threshold exceeded",
				"usage_percent", usagePercent,
				"threshold", m.config.CriticalThreshold,
				"used_bytes", usedBytes,
				"capacity_bytes", m.maxSize)
		}
	}
}

// calculateCurrentUsage calculates the current spool usage by scanning the directory.
func (m *Monitor) calculateCurrentUsage() (usedBytes uint64, fileCount uint64, err error) {
	var totalBytes uint64
	var totalFiles uint64

	err = filepath.Walk(m.spoolDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Skip directories we can't access, but continue with others
			if os.IsPermission(err) {
				if m.logger != nil {
					m.logger.Warn("Permission denied accessing path", "path", path)
				}
				return nil
			}
			return err
		}

		// Skip directories and temporary files
		if info.IsDir() {
			return nil
		}

		// Skip temporary files
		if len(info.Name()) > 0 && (info.Name()[0] == '.' || filepath.Ext(info.Name()) == ".tmp") {
			return nil
		}

		totalBytes += uint64(info.Size())
		totalFiles++

		return nil
	})

	return totalBytes, totalFiles, err
}

// CapacityExceeded is called when spool capacity is exceeded to update metrics.
func (m *Monitor) CapacityExceeded() {
	if m.server != nil {
		m.server.IncrementSpoolCapacityExceededTotal()
	}
	if m.logger != nil {
		m.logger.Warn("Spool capacity exceeded")
	}
}

// SpoolMonitor provides an interface for spool monitoring.
type SpoolMonitor interface {
	Start()
	Stop()
	CapacityExceeded()
}

// StartSpoolMonitor starts a spool monitor with the given configuration.
func StartSpoolMonitor(spoolDir string, maxSize uint64, cfg config.MonitoringConfig, server *http.OperationsServer) SpoolMonitor {
	monitor := NewMonitor(spoolDir, maxSize, cfg, server)
	monitor.Start()
	return monitor
}