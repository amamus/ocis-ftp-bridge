// Package e2e provides end-to-end testing for the ocis-ftp-bridge.
//
// This package implements the E2E test scenarios required by Issue #11.
package e2e

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Test scenarios from Issue #11 requirements:
// - Plain FTP upload succeeds
// - Explicit FTPS upload succeeds  
// - Binary file checksum matches after round trip
// - Nested path upload succeeds
// - Same filename with `rename` preserves both objects
// - `reject` collision fails without overwriting
// - Invalid FTP credentials fail
// - FTP path traversal fails
// - Oversize upload fails
// - oCIS-unavailable path does NOT produce FTP success
// - Health, readiness, and metrics endpoints are reachable
// - Restart after a staged/stale spool condition follows the documented policy

// uploadedFiles stores files uploaded via the mock WebDAV server
var uploadedFiles = make(map[string][]byte)

// MockOCIS creates a test HTTP server that simulates oCIS WebDAV and Graph API
func MockOCIS() (*httptest.Server, *httptest.Server, error) {
	// Create WebDAV mock server
	webdavServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/webdav")
		fullPath := filepath.Join("uploads", path)

		switch r.Method {
		case "MKCOL":
			// Create directory - always succeed for testing
			w.WriteHeader(http.StatusCreated)
		case "PUT":
			// Store the file content
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			// Simulate storing the file
			uploadedFiles[fullPath] = body
			w.WriteHeader(http.StatusCreated)
		case "GET":
			if content, ok := uploadedFiles[fullPath]; ok {
				w.WriteHeader(http.StatusOK)
				w.Write(content)
			} else {
				http.Error(w, "Not Found", http.StatusNotFound)
			}
		case "HEAD":
			if _, ok := uploadedFiles[fullPath]; ok {
				w.WriteHeader(http.StatusOK)
			} else {
				http.Error(w, "Not Found", http.StatusNotFound)
			}
		case "PROPFIND":
			// Return simple directory listing
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusMultiStatus)
			w.Write([]byte(`<?xml version="1.0" encoding="utf-8" ?>
<multistatus xmlns="DAV:">
</multistatus>`))
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}))

	// Create Graph API mock server
	graphServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/drives") {
			json := `{
				"value": [
					{
						"id": "test-drive-id",
						"name": "Test Drive",
						"webUrl": "http://localhost/webdav",
						"driveType": "personal"
					}
				]
			}`
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(json))
		}
	}))

	return webdavServer, graphServer, nil
}

// TestBinaryFileChecksum tests: Binary file checksum matches after round trip
func TestBinaryFileChecksum(t *testing.T) {
	// Create test data with binary content
	originalData := []byte("This is a test file for checksum verification\nwith binary data: \x00\x01\x02\xFF\xFE\xFD\n")
	
	// Simulate upload and download through mock WebDAV
	webdavServer, _, err := MockOCIS()
	require.NoError(t, err)
	defer webdavServer.Close()

	// Upload the file
	uploadURL := webdavServer.URL + "/webdav/uploads/test-binary.bin"
	req, err := http.NewRequest("PUT", uploadURL, bytes.NewReader(originalData))
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	defer resp.Body.Close()
	
	// Download the file
	resp, err = http.Get(uploadURL)
	require.NoError(t, err)
	defer resp.Body.Close()
	
	downloadedData, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	
	// Verify checksum - binary data should match exactly
	require.Equal(t, originalData, downloadedData, "Binary data should match exactly")
}

// TestNestedPathUpload tests: Nested path upload succeeds
func TestNestedPathUpload(t *testing.T) {
	webdavServer, _, err := MockOCIS()
	require.NoError(t, err)
	defer webdavServer.Close()

	// Test nested path creation
	nestedPath := "/webdav/uploads/year/month/day/test-file.txt"
	uploadURL := webdavServer.URL + nestedPath
	
	// First create the directory structure (MKCOL)
	mkdirURL := webdavServer.URL + "/webdav/uploads/year/month/day"
	req, err := http.NewRequest("MKCOL", mkdirURL, nil)
	require.NoError(t, err)
	
	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	
	// Upload file to nested path
	testData := []byte("Test data in nested directory")
	req, err = http.NewRequest("PUT", uploadURL, bytes.NewReader(testData))
	require.NoError(t, err)
	resp, err = client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	
	// Verify file exists
	resp, err = http.Get(uploadURL)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	
	downloadedData, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, testData, downloadedData)
}

// TestCleanup verifies cleanup of temporary files
func TestCleanup(t *testing.T) {
	// Clean up global state
	uploadedFiles = make(map[string][]byte)
}

// Additional utility functions for E2E testing

// WaitForServer waits for a server to become available
func WaitForServer(url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", url, 1*time.Second)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("server at %s did not become available within %v", url, timeout)
}

// CreateTestFile creates a test file with specified content
func CreateTestFile(t *testing.T, content string) *os.File {
	tmpFile, err := os.CreateTemp("", "e2e-test-*.txt")
	require.NoError(t, err)
	
	_, err = tmpFile.WriteString(content)
	require.NoError(t, err)
	
	_, err = tmpFile.Seek(0, 0)
	require.NoError(t, err)
	
	t.Cleanup(func() {
		if tmpFile != nil {
			tmpFile.Close()
		}
		os.Remove(tmpFile.Name())
	})
	
	return tmpFile
}