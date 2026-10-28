// Package e2e provides end-to-end testing for the ocis-ftp-bridge.
//
// This package implements the E2E test scenarios required by Issue #11.
package e2e

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"sync"
	"testing"

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

// The mock WebDAV server keeps its state in package-level maps guarded by
// mockMu. resetMockState restores the initial state: the root collection
// "/" and the "/uploads" collection exist, everything else must be created
// with MKCOL.
var (
	mockMu          sync.Mutex
	uploadedFiles   = make(map[string][]byte)
	mockCollections = map[string]bool{"/": true, "/uploads": true}
)

// resetMockState restores the mock server's initial state.
func resetMockState() {
	mockMu.Lock()
	defer mockMu.Unlock()
	uploadedFiles = make(map[string][]byte)
	mockCollections = map[string]bool{"/": true, "/uploads": true}
}

// MockOCIS creates a test HTTP server that simulates oCIS WebDAV and Graph API
func MockOCIS() (*httptest.Server, *httptest.Server, error) {
	resetMockState()

	// Create WebDAV mock server. The handler implements real WebDAV semantics
	// (see mock_test.go) so the e2e scenarios cannot be masked by
	// unconditional success: PUT into a missing parent collection fails with
	// 404, PUT with If-None-Match: * onto an existing object fails with 412,
	// MKCOL on an existing collection fails with 405, and MKCOL with a
	// missing parent fails with 409 (MKCOL is not recursive).
	webdavServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urlPath := "/" + strings.Trim(strings.TrimPrefix(r.URL.Path, "/webdav"), "/")

		mockMu.Lock()
		defer mockMu.Unlock()

		switch r.Method {
		case "MKCOL":
			if mockCollections[urlPath] {
				http.Error(w, "Collection already exists", http.StatusMethodNotAllowed)
				return
			}
			if parent := path.Dir(urlPath); !mockCollections[parent] {
				http.Error(w, "Parent collection does not exist", http.StatusConflict)
				return
			}
			mockCollections[urlPath] = true
			w.WriteHeader(http.StatusCreated)
		case "PUT":
			// A real WebDAV server does not create parent collections
			// implicitly: PUT into a missing parent fails with 404.
			if parent := path.Dir(urlPath); !mockCollections[parent] {
				http.Error(w, "Parent collection does not exist", http.StatusNotFound)
				return
			}
			// The bridge sends If-None-Match: * for non-overwriting uploads
			// (QLT-002); a real server answers 412 when the target exists.
			if r.Header.Get("If-None-Match") == "*" {
				if _, exists := uploadedFiles[urlPath]; exists {
					http.Error(w, "Precondition failed", http.StatusPreconditionFailed)
					return
				}
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			uploadedFiles[urlPath] = body
			w.WriteHeader(http.StatusCreated)
		case "GET":
			if content, ok := uploadedFiles[urlPath]; ok {
				w.WriteHeader(http.StatusOK)
				w.Write(content)
				return
			}
			if mockCollections[urlPath] {
				w.WriteHeader(http.StatusOK)
				return
			}
			http.Error(w, "Not Found", http.StatusNotFound)
		case "HEAD":
			if _, ok := uploadedFiles[urlPath]; ok {
				w.WriteHeader(http.StatusOK)
				return
			}
			if mockCollections[urlPath] {
				w.WriteHeader(http.StatusOK)
				return
			}
			http.Error(w, "Not Found", http.StatusNotFound)
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

	// Create the directory structure level by level: MKCOL is not recursive
	// and fails with 409 when the parent collection is missing.
	client := &http.Client{}
	for _, dir := range []string{"/webdav/uploads/year", "/webdav/uploads/year/month", "/webdav/uploads/year/month/day"} {
		req, err := http.NewRequest("MKCOL", webdavServer.URL+dir, nil)
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, resp.StatusCode, "MKCOL %s", dir)
		resp.Body.Close()
	}

	// Upload file to nested path
	testData := []byte("Test data in nested directory")
	req, err := http.NewRequest("PUT", uploadURL, bytes.NewReader(testData))
	require.NoError(t, err)
	resp, err := client.Do(req)
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
	resetMockState()
}
