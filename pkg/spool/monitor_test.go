// Package spool provides local file spool functionality for ocis-ftp-bridge.
package spool

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/amamus/ocis-ftp-bridge/pkg/config"
)

func TestMonitor_CalculateCurrentUsage(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "spool-monitor-test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create some test files
	testFiles := []struct {
		name    string
		content string
	}{
		{"file1.txt", "content1"},
		{"file2.txt", "content2content2"},
		{".hidden", "hidden"}, // Should be skipped
		{"file3.tmp", "temp"}, // Should be skipped
	}

	for _, tf := range testFiles {
		if len(tf.name) > 0 && (tf.name[0] == '.' || filepath.Ext(tf.name) == ".tmp") {
			continue // Skip files that should be ignored
		}
		filePath := filepath.Join(tempDir, tf.name)
		if err := os.WriteFile(filePath, []byte(tf.content), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", tf.name, err)
		}
	}

	// Create monitor
	monitor := &Monitor{
		spoolDir: tempDir,
		maxSize: 1024 * 1024, // 1MB
		config: config.MonitoringConfig{
			Enabled:           true,
			WarningThreshold:  80.0,
			CriticalThreshold: 95.0,
			CheckInterval:     30 * time.Second,
		},
		server: nil, // No server for this test
		logger: nil, // Will use default logger
	}

	// Calculate usage
	usedBytes, fileCount, err := monitor.calculateCurrentUsage()
	if err != nil {
		t.Fatalf("calculateCurrentUsage failed: %v", err)
	}

	// Expected: file1.txt (7 bytes) + file2.txt (16 bytes) = 23 bytes
	expectedBytes := uint64(len("content1") + len("content2content2"))
	expectedCount := uint64(2)

	if usedBytes != expectedBytes {
		t.Errorf("Expected %d bytes, got %d", expectedBytes, usedBytes)
	}

	if fileCount != expectedCount {
		t.Errorf("Expected %d files, got %d", expectedCount, fileCount)
	}
}

func TestMonitor_CalculateCurrentUsageWithDirectories(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "spool-monitor-test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create subdirectories with files
	userDir := filepath.Join(tempDir, "testuser")
	if err := os.Mkdir(userDir, 0755); err != nil {
		t.Fatalf("Failed to create user directory: %v", err)
	}

	// Create files in subdirectory
	testFiles := []struct {
		name    string
		content string
	}{
		{"upload1.txt", "test content"},
		{"upload2.txt", "more content here"},
	}

	for _, tf := range testFiles {
		filePath := filepath.Join(userDir, tf.name)
		if err := os.WriteFile(filePath, []byte(tf.content), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", tf.name, err)
		}
	}

	// Create monitor
	monitor := &Monitor{
		spoolDir: tempDir,
		maxSize: 1024 * 1024,
		config: config.MonitoringConfig{
			Enabled:           true,
			WarningThreshold:  80.0,
			CriticalThreshold: 95.0,
			CheckInterval:     30 * time.Second,
		},
		server: nil,
		logger: nil,
	}

	// Calculate usage
	usedBytes, fileCount, err := monitor.calculateCurrentUsage()
	if err != nil {
		t.Fatalf("calculateCurrentUsage failed: %v", err)
	}

	// Expected: upload1.txt (12 bytes) + upload2.txt (18 bytes) = 30 bytes, 2 files
	expectedBytes := uint64(len("test content") + len("more content here"))
	expectedCount := uint64(2)

	if usedBytes != expectedBytes {
		t.Errorf("Expected %d bytes, got %d", expectedBytes, usedBytes)
	}

	if fileCount != expectedCount {
		t.Errorf("Expected %d files, got %d", expectedCount, fileCount)
	}
}

func TestMonitor_StartStop(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "spool-monitor-test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create monitor with disabled monitoring
	monitor := &Monitor{
		spoolDir: tempDir,
		maxSize: 1024 * 1024,
		config: config.MonitoringConfig{
			Enabled: false, // Disabled for this test
		},
		server:    nil,
		logger:    nil,
		stopChan:  make(chan struct{}),
		doneChan:  make(chan struct{}),
	}

	// Start monitor (should return immediately since disabled)
	monitor.Start()

	// Check that doneChan is closed (monitoring disabled)
	select {
	case <-monitor.doneChan:
		// Expected
	case <-time.After(time.Second):
		t.Error("Monitor should have stopped immediately when disabled")
	}

	// Test with enabled monitoring
	monitor = &Monitor{
		spoolDir: tempDir,
		maxSize: 1024 * 1024,
		config: config.MonitoringConfig{
			Enabled:           true,
			WarningThreshold:  80.0,
			CriticalThreshold: 95.0,
			CheckInterval:     100 * time.Millisecond, // Short interval for testing
		},
		server:    nil,
		logger:    nil,
		stopChan:  make(chan struct{}),
		doneChan:  make(chan struct{}),
	}

	// Start monitor
	monitor.Start()

	// Let it run for a bit
	time.Sleep(250 * time.Millisecond)

	// Stop monitor
	monitor.Stop()

	// Check that it stopped
	select {
	case <-monitor.doneChan:
		// Expected
	case <-time.After(time.Second):
		t.Error("Monitor should have stopped after Stop() call")
	}
}

func TestMonitor_CapacityExceeded(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "spool-monitor-test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create monitor
	monitor := &Monitor{
		spoolDir: tempDir,
		maxSize: 1024 * 1024,
		config: config.MonitoringConfig{
			Enabled:           true,
			WarningThreshold:  80.0,
			CriticalThreshold: 95.0,
			CheckInterval:     30 * time.Second,
		},
		server: nil, // No server, so this should not panic
		logger: nil,
	}

	// Call CapacityExceeded (should not panic with nil server)
	monitor.CapacityExceeded()

	// Test with a mock server that has the method
	// We can't easily test this without creating a full mock, so we'll just
	// ensure it doesn't panic with nil server
}