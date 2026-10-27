// Package webdav provides WebDAV client for upload operations in ocis-ftp-bridge.
//
// This file implements the concrete WebDAV client using Go's standard net/http package.
package webdav

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
	"unicode/utf8"
)

// Path validation constants
const (
	// MaxPathLength is the maximum allowed length for WebDAV paths in bytes
	MaxPathLength = 4096
	// MaxFilenameLength is the maximum allowed length for filenames in bytes
	MaxFilenameLength = 255
)

// webdavClient is the concrete implementation of Client.
type webdavClient struct {
	baseURL    string
	username   string
	token      string
	httpClient *http.Client
}

// NewWebDAVClient creates a new WebDAV client.
// baseURL is the base URL for the WebDAV API (e.g., "https://ocis.example.com/webdav").
// username and token are used for authentication.
func NewWebDAVClient(baseURL, username, token string) Client {
	return NewWebDAVClientWithHTTP(baseURL, username, token, nil)
}

// NewWebDAVClientWithHTTP creates a new WebDAV client with a custom HTTP client.
func NewWebDAVClientWithHTTP(baseURL, username, token string, httpClient *http.Client) Client {
	if httpClient == nil {
		// Use reasonable defaults for production use. There is deliberately
		// no total Timeout: it would bound the ENTIRE request including a
		// 50 MiB upload body and abort large transfers mid-upload (PERF-001).
		// ResponseHeaderTimeout and IdleConnTimeout remain as hang guards, and
		// control operations get a per-call deadline (see withControlDeadline).
		httpClient = &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:          10,
				MaxIdleConnsPerHost:   10,
				IdleConnTimeout:       90 * time.Second,
				ResponseHeaderTimeout: 10 * time.Second,
			},
			// Disable redirects to prevent credential leakage
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	// Ensure baseURL ends with exactly one slash
	baseURL = strings.TrimRight(baseURL, "/")

	return &webdavClient{
		baseURL:    baseURL,
		username:   username,
		token:      token,
		httpClient: httpClient,
	}
}

// Upload uploads a file to the specified path.
func (c *webdavClient) Upload(ctx context.Context, path string, data []byte, overwrite bool) error {
	if path == "" {
		return ErrInvalidPath
	}

	if len(data) == 0 {
		return ErrEmptyData
	}

	// Create a reader from the byte slice
	reader := bytes.NewReader(data)
	return c.UploadStream(ctx, path, reader, int64(len(data)), overwrite)
}

const (
	// uploadMaxAttempts bounds retries of a WebDAV upload on temporary
	// (5xx) server failures.
	uploadMaxAttempts = 3
	// uploadRetryBaseDelay is the backoff before the first retry; it doubles
	// with each subsequent attempt.
	uploadRetryBaseDelay = 250 * time.Millisecond
)

// controlOpTimeout bounds WebDAV control operations (MKCOL, HEAD, DELETE,
// PROPFIND) when the caller's context carries no deadline. Uploads are
// deliberately not bounded by it: their duration scales with the file size
// (PERF-001).
var controlOpTimeout = 30 * time.Second

// withControlDeadline returns ctx bounded by controlOpTimeout unless the
// caller already set a deadline.
func withControlDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, controlOpTimeout)
}

// UploadStream uploads a file from an io.Reader to the specified path.
// Temporary (5xx) server failures are retried with bounded backoff; the body
// must implement io.ReadSeeker so it can be rewound between attempts.
func (c *webdavClient) UploadStream(ctx context.Context, path string, reader io.Reader, size int64, overwrite bool) error {
	if path == "" {
		return ErrInvalidPath
	}

	if reader == nil {
		return ErrEmptyData
	}

	// Normalize the path to prevent traversal
	normalizedPath, err := c.normalizePath(path)
	if err != nil {
		return err
	}

	// Construct the full URL
	fullURL, err := url.Parse(c.baseURL + "/" + strings.TrimLeft(normalizedPath, "/"))
	if err != nil {
		return fmt.Errorf("failed to construct WebDAV URL for path %q: %w", path, err)
	}

	// A retry resends the body, so only rewindable readers can be retried.
	seeker, rewindable := reader.(io.ReadSeeker)

	var lastErr error
	for attempt := 1; attempt <= uploadMaxAttempts; attempt++ {
		if attempt > 1 {
			if !rewindable {
				return lastErr
			}
			if _, err := seeker.Seek(0, io.SeekStart); err != nil {
				return fmt.Errorf("failed to rewind upload body for retry: %w", err)
			}
			// Bounded exponential backoff between attempts
			select {
			case <-ctx.Done():
				return fmt.Errorf("upload aborted while waiting to retry: %w", ctx.Err())
			case <-time.After(uploadRetryBaseDelay << (attempt - 2)):
			}
		}

		lastErr = c.doUpload(ctx, fullURL.String(), reader, size, overwrite, normalizedPath)
		if lastErr == nil {
			return nil
		}
		// Only temporary server failures are retried; everything else (auth,
		// conflict, size limits, ...) fails immediately.
		if !errors.Is(lastErr, ErrTemporaryFailure) {
			return lastErr
		}
	}
	return fmt.Errorf("upload failed after %d attempts: %w", uploadMaxAttempts, lastErr)
}

// doUpload performs a single WebDAV PUT for an upload.
func (c *webdavClient) doUpload(ctx context.Context, fullURL string, reader io.Reader, size int64, overwrite bool, normalizedPath string) error {
	// Create the request
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, fullURL, reader)
	if err != nil {
		return fmt.Errorf("failed to create WebDAV upload request: %w", err)
	}

	// Set ContentLength on the request itself. Go's HTTP transport ignores
	// the Content-Length header; req.ContentLength must be set explicitly.
	// Without this, non-seekable readers (e.g. *os.File) produce chunked
	// transfer encoding, which oCIS rejects with 400. See issue #106.
	if size == 0 {
		// For zero-byte uploads, ContentLength=0 with a non-nil Body means
		// "unknown length" (chunked) in Go. Use http.NoBody to send
		// Content-Length: 0 with an empty body.
		req.ContentLength = 0
		req.Body = http.NoBody
	} else {
		req.ContentLength = size
	}

	// Set headers
	req.Header.Set("Content-Type", "application/octet-stream")

	// Set conditional headers for overwrite protection
	if !overwrite {
		req.Header.Set("If-None-Match", "*")
	}

	// Add authentication
	c.addAuth(req)

	// Execute the request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("WebDAV upload failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle the response
	return c.handleUploadResponse(resp, normalizedPath)
}

// CreateDirectory creates a directory at the specified path.
func (c *webdavClient) CreateDirectory(ctx context.Context, path string) error {
	ctx, cancel := withControlDeadline(ctx)
	defer cancel()

	if path == "" {
		return ErrInvalidPath
	}

	// Normalize the path to prevent traversal
	normalizedPath, err := c.normalizePath(path)
	if err != nil {
		return err
	}

	// Ensure the path ends with a slash for directory creation
	if !strings.HasSuffix(normalizedPath, "/") {
		normalizedPath += "/"
	}

	// Construct the full URL
	fullURL, err := url.Parse(c.baseURL + "/" + strings.TrimLeft(normalizedPath, "/"))
	if err != nil {
		return fmt.Errorf("failed to construct WebDAV URL for directory %q: %w", path, err)
	}

	// Create the request
	req, err := http.NewRequestWithContext(ctx, "MKCOL", fullURL.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create WebDAV MKCOL request: %w", err)
	}

	// Add authentication
	c.addAuth(req)

	// Execute the request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("WebDAV MKCOL failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle the response
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil // Success
	}

	// Check for specific error conditions
	if resp.StatusCode == http.StatusConflict || resp.StatusCode == http.StatusMethodNotAllowed {
		// Directory already exists, that's fine for idempotent creation
		return nil
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return ErrUnauthorized
	}

	if resp.StatusCode == http.StatusForbidden {
		return ErrForbidden
	}

	if resp.StatusCode == http.StatusNotFound {
		// Parent path doesn't exist
		return ErrPathNotFound
	}

	// Read the response body for error details
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("MKCOL failed with status %d: %s", resp.StatusCode, string(body))
}

// CheckPathExistence checks if a path exists.
func (c *webdavClient) CheckPathExistence(ctx context.Context, path string) (bool, error) {
	ctx, cancel := withControlDeadline(ctx)
	defer cancel()

	if path == "" {
		return false, ErrInvalidPath
	}

	// Normalize the path
	normalizedPath, err := c.normalizePath(path)
	if err != nil {
		return false, err
	}

	// Construct the full URL
	fullURL, err := url.Parse(c.baseURL + "/" + strings.TrimLeft(normalizedPath, "/"))
	if err != nil {
		return false, fmt.Errorf("failed to construct WebDAV URL for path %q: %w", path, err)
	}

	// Create a HEAD request to check existence without downloading the body
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, fullURL.String(), nil)
	if err != nil {
		return false, fmt.Errorf("failed to create WebDAV HEAD request: %w", err)
	}

	// Add authentication
	c.addAuth(req)

	// Execute the request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("WebDAV HEAD failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle the response
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		return true, nil
	}

	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return false, ErrUnauthorized
	}

	if resp.StatusCode == http.StatusForbidden {
		return false, ErrForbidden
	}

	// For other status codes, consider it as not existing to be safe
	// But return the error for debugging
	body, _ := io.ReadAll(resp.Body)
	return false, fmt.Errorf("path existence check failed with status %d: %s", resp.StatusCode, string(body))
}

// DeleteFile deletes a file at the specified path.
func (c *webdavClient) DeleteFile(ctx context.Context, path string) error {
	ctx, cancel := withControlDeadline(ctx)
	defer cancel()

	if path == "" {
		return ErrInvalidPath
	}

	// Normalize the path
	normalizedPath, err := c.normalizePath(path)
	if err != nil {
		return err
	}

	// Construct the full URL
	fullURL, err := url.Parse(c.baseURL + "/" + strings.TrimLeft(normalizedPath, "/"))
	if err != nil {
		return fmt.Errorf("failed to construct WebDAV URL for path %q: %w", path, err)
	}

	// Create the request
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, fullURL.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create WebDAV DELETE request: %w", err)
	}

	// Add authentication
	c.addAuth(req)

	// Execute the request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("WebDAV DELETE failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle the response
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil // Success
	}

	if resp.StatusCode == http.StatusNotFound {
		return ErrPathNotFound
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return ErrUnauthorized
	}

	if resp.StatusCode == http.StatusForbidden {
		return ErrForbidden
	}

	// Read the response body for error details
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("DELETE failed with status %d: %s", resp.StatusCode, string(body))
}

// GetFileInfo gets information about a file.
func (c *webdavClient) GetFileInfo(ctx context.Context, path string) (FileInfo, error) {
	ctx, cancel := withControlDeadline(ctx)
	defer cancel()

	if path == "" {
		return FileInfo{}, ErrInvalidPath
	}

	// Normalize the path
	normalizedPath, err := c.normalizePath(path)
	if err != nil {
		return FileInfo{}, err
	}

	// Construct the full URL
	fullURL, err := url.Parse(c.baseURL + "/" + strings.TrimLeft(normalizedPath, "/"))
	if err != nil {
		return FileInfo{}, fmt.Errorf("failed to construct WebDAV URL for path %q: %w", path, err)
	}

	// Create a PROPFIND request to get file information
	req, err := http.NewRequestWithContext(ctx, "PROPFIND", fullURL.String(), nil)
	if err != nil {
		return FileInfo{}, fmt.Errorf("failed to create WebDAV PROPFIND request: %w", err)
	}

	// Set PROPFIND headers
	req.Header.Set("Depth", "0")

	// Add authentication
	c.addAuth(req)

	// Execute the request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return FileInfo{}, fmt.Errorf("WebDAV PROPFIND failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle the response
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusMultiStatus {
		// Parse the PROPFIND response (simplified for now)
		// In a full implementation, we would parse the XML response
		// For now, return basic info
		return FileInfo{
			Path:          path,
			IsDirectory:   strings.HasSuffix(normalizedPath, "/"),
			LastModified: time.Now().UTC().Format(time.RFC3339),
		}, nil
	}

	if resp.StatusCode == http.StatusNotFound {
		return FileInfo{}, ErrPathNotFound
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return FileInfo{}, ErrUnauthorized
	}

	if resp.StatusCode == http.StatusForbidden {
		return FileInfo{}, ErrForbidden
	}

	// For other status codes, return a generic error
	body, _ := io.ReadAll(resp.Body)
	return FileInfo{}, fmt.Errorf("PROPFIND failed with status %d: %s", resp.StatusCode, string(body))
}

// ValidateConfiguration validates that the WebDAV client can connect to the API.
func (c *webdavClient) ValidateConfiguration(ctx context.Context) error {
	// Try to check if the root path exists
	_, err := c.CheckPathExistence(ctx, "/")
	if err != nil {
		return fmt.Errorf("WebDAV configuration validation failed: %w", err)
	}
	return nil
}

// addAuth adds authentication headers to the request.
func (c *webdavClient) addAuth(req *http.Request) {
	// Use BasicAuth as the primary authentication method
	// WebDAV typically uses BasicAuth over HTTPS
	req.SetBasicAuth(c.username, c.token)
}

// normalizePath normalizes the path to prevent traversal and ensure proper formatting.
func (c *webdavClient) normalizePath(p string) (string, error) {
	if p == "" {
		return "", ErrInvalidPath
	}

	// Validate path length to prevent buffer overflow attacks
	if len(p) > MaxPathLength {
		return "", fmt.Errorf("%w: path length %d exceeds maximum of %d", ErrInvalidPath, len(p), MaxPathLength)
	}

	// Validate UTF-8 encoding
	if !utf8.ValidString(p) {
		return "", fmt.Errorf("%w: path contains invalid UTF-8 sequences", ErrInvalidPath)
	}

	// Prevent path traversal by checking for various traversal patterns
	if strings.Contains(p, "..") {
		return "", ErrPathTraversal
	}

	// Check for Windows-specific traversal patterns
	if strings.Contains(p, "\\..\\") || strings.Contains(p, "\\..") || strings.Contains(p, "..\\") {
		return "", ErrPathTraversal
	}

	// Check for drive letters (Windows)
	if len(p) >= 2 && p[1] == ':' {
		return "", fmt.Errorf("%w: absolute Windows paths not allowed", ErrInvalidPath)
	}

	// Check for null bytes and control characters
	for _, r := range p {
		if r == 0 || (r < 32 && r != '/' && r != '.' && r != '_' && r != '-') {
			return "", fmt.Errorf("%w: path contains invalid control characters", ErrInvalidPath)
		}
	}

	// Clean the path to remove . components and normalize slashes
	cleanPath := path.Clean(p)

	// Double-check that the cleaned path doesn't start with .. (shouldn't happen if input was clean)
	if strings.HasPrefix(cleanPath, "..") {
		return "", ErrPathTraversal
	}

	// Ensure the path starts with a slash for absolute paths
	if !strings.HasPrefix(cleanPath, "/") {
		cleanPath = "/" + cleanPath
	}

	// Final length check after normalization
	if len(cleanPath) > MaxPathLength {
		return "", fmt.Errorf("%w: normalized path length %d exceeds maximum of %d", ErrInvalidPath, len(cleanPath), MaxPathLength)
	}

	// URL encode the path components properly
	// Split into components and encode each one
	parts := strings.Split(cleanPath, "/")
	for i, part := range parts {
		if part != "" {
			parts[i] = url.PathEscape(part)
		}
	}

	return strings.Join(parts, "/"), nil
}

// handleUploadResponse handles the response from a WebDAV upload request.
func (c *webdavClient) handleUploadResponse(resp *http.Response, path string) error {
	// Check for success status codes
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	// Handle specific error conditions
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return ErrUnauthorized

	case http.StatusForbidden:
		return ErrForbidden

	case http.StatusNotFound:
		// Parent path doesn't exist
		return ErrPathNotFound

	case http.StatusConflict:
		// File already exists and we didn't want to overwrite
		return ErrUploadConflict

	case http.StatusPreconditionFailed: // 412 - Conditional request failed
		// This happens when If-None-Match fails (file already exists)
		return ErrUploadConflict

	case http.StatusRequestEntityTooLarge: // 413
		return ErrFileTooLarge

	case http.StatusTooManyRequests: // 429
		return ErrRateLimited

	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout: // 5xx
		return ErrTemporaryFailure

	default:
		// Read the response body for error details
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload failed with status %d for path %q: %s", resp.StatusCode, path, string(body))
	}
}