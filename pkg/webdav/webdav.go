// Package webdav provides WebDAV client for upload operations in ocis-ftp-bridge.
//
// It defines interfaces for interacting with the oCIS WebDAV API
// to upload files to drives or spaces.
package webdav

import (
	"context"
	"fmt"
	"io"
)

// Client is the interface for WebDAV upload operations.
type Client interface {
	// Upload uploads a file to the specified path.
	Upload(ctx context.Context, path string, data []byte, overwrite bool) error

	// UploadStream uploads a file from an io.Reader to the specified path.
	// This allows for streaming large files without loading them entirely into memory.
	UploadStream(ctx context.Context, path string, reader io.Reader, size int64, overwrite bool) error

	// CreateDirectory creates a directory at the specified path.
	CreateDirectory(ctx context.Context, path string) error

	// CheckPathExistence checks if a path exists.
	CheckPathExistence(ctx context.Context, path string) (bool, error)

	// DeleteFile deletes a file at the specified path.
	DeleteFile(ctx context.Context, path string) error

	// GetFileInfo gets information about a file.
	GetFileInfo(ctx context.Context, path string) (FileInfo, error)

	// ValidateConfiguration validates that the WebDAV client can connect to the API.
	ValidateConfiguration(ctx context.Context) error
}

// FileInfo represents information about a file.
type FileInfo struct {
	// Path is the path to the file.
	Path string

	// Size is the size of the file in bytes.
	Size int64

	// LastModified is the last modification time.
	LastModified string

	// IsDirectory indicates if the path is a directory.
	IsDirectory bool
}

// NewClient creates a new WebDAV client.
// This function creates a client that uses the standard HTTP client.
// For backward compatibility, it still returns the Client interface.
func NewClient(baseURL, token string) Client {
	return NewWebDAVClient(baseURL, "", token)
}

// NewClientWithCredentials creates a new WebDAV client with username and token.
// This is the preferred method for authentication.
func NewClientWithCredentials(baseURL, username, token string) Client {
	return NewWebDAVClient(baseURL, username, token)
}

// Errors
// WebDAVError represents an error during WebDAV operations.
type WebDAVError struct {
	msg string
}

func (e *WebDAVError) Error() string {
	return fmt.Sprintf("webdav error: %s", e.msg)
}

var (
	ErrInvalidPath        = &WebDAVError{msg: "invalid path"}
	ErrEmptyData          = &WebDAVError{msg: "empty data"}
	ErrNotImplemented      = &WebDAVError{msg: "operation not implemented"}
	ErrUploadFailed        = &WebDAVError{msg: "upload failed"}
	ErrPathNotFound       = &WebDAVError{msg: "path not found"}
	ErrUnauthorized       = &WebDAVError{msg: "unauthorized"}
	ErrForbidden          = &WebDAVError{msg: "forbidden"}
	ErrWebDAVAPIError     = &WebDAVError{msg: "WebDAV API error"}
	ErrPathTraversal      = &WebDAVError{msg: "path traversal"}
	ErrUploadConflict     = &WebDAVError{msg: "upload conflict - file already exists"}
	ErrFileTooLarge       = &WebDAVError{msg: "file too large"}
	ErrRateLimited        = &WebDAVError{msg: "rate limited"}
	ErrTemporaryFailure   = &WebDAVError{msg: "temporary server failure"}
)