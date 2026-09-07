// Package transfer provides path mapping, directory creation, and collision handling
// for the ocis-ftp-bridge upload pipeline.
//
// This package implements the business logic for mapping FTP upload requests
// to oCIS WebDAV targets with proper collision handling and directory management.
package transfer

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/amamus/ocis-ftp-bridge/pkg/webdav"
)

// CollisionPolicy defines how to handle filename collisions
type CollisionPolicy string

const (
	// CollisionPolicyRename renames the file to avoid conflicts
	CollisionPolicyRename CollisionPolicy = "rename"
	// CollisionPolicyReject fails the upload if a file already exists
	CollisionPolicyReject CollisionPolicy = "reject"
	// CollisionPolicyOverwrite replaces existing files
	CollisionPolicyOverwrite CollisionPolicy = "overwrite"
)

// TargetConfig contains the configuration for a transfer target
type TargetConfig struct {
	// DriveID is the oCIS drive ID (authoritative if set)
	DriveID string
	// Drive is the oCIS drive name (used if DriveID is not set)
	Drive string
	// Root is the base path in the drive for uploads
	Root string
	// CollisionPolicy defines how to handle filename conflicts
	CollisionPolicy CollisionPolicy
	// MaxSize is the maximum file size allowed
	MaxSize uint64
}

// TransferRequest represents an upload request from an FTP client
type TransferRequest struct {
	// UserID is the FTP user/account identifier
	UserID string
	// Filename is the original filename from the FTP client
	Filename string
	// Path is the FTP path provided by the client (may be empty)
	Path string
	// Size is the expected size of the upload
	Size int64
	// Data is the file content (for non-streaming uploads)
	Data []byte
	// Reader is the data source (for streaming uploads)
	Reader io.Reader
}

// TransferResult contains the result of a transfer operation
type TransferResult struct {
	// TargetPath is the full oCIS WebDAV path for the file
	TargetPath string
	// Filename is the final filename (may be modified due to collision handling)
	Filename string
	// Size is the actual size of the transferred file
	Size int64
	// Success indicates whether the transfer was successful
	Success bool
	// Error contains any error that occurred
	Error error
}

// TransferManager handles path mapping and collision resolution
type TransferManager struct {
	mu             sync.Mutex
	targetConfigs  map[string]TargetConfig
	uploadCounters map[string]uint64
	webdavClient   webdav.Client
	context        context.Context
}

// NewTransferManager creates a new transfer manager
func NewTransferManager() *TransferManager {
	return &TransferManager{
		targetConfigs:  make(map[string]TargetConfig),
		uploadCounters: make(map[string]uint64),
		context:        context.Background(),
	}
}

// NewTransferManagerWithWebDAV creates a new transfer manager with WebDAV client
func NewTransferManagerWithWebDAV(ctx context.Context, client webdav.Client) *TransferManager {
	return &TransferManager{
		targetConfigs:  make(map[string]TargetConfig),
		uploadCounters: make(map[string]uint64),
		webdavClient:   client,
		context:        ctx,
	}
}

// SetWebDAVClient sets the WebDAV client for the transfer manager
func (tm *TransferManager) SetWebDAVClient(client webdav.Client) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.webdavClient = client
}

// AddTarget adds a target configuration for a user
func (tm *TransferManager) AddTarget(userID string, config TargetConfig) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.targetConfigs[userID] = config
}

// GetTarget gets the target configuration for a user
func (tm *TransferManager) GetTarget(userID string) (TargetConfig, bool) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	config, exists := tm.targetConfigs[userID]
	return config, exists
}

// CalculateTargetPath calculates the final WebDAV target path for an upload
// This implements the path mapping logic:
// - Combines the account's target root with the FTP path
// - Handles path normalization and traversal prevention
// - Preserves Unicode filenames
func (tm *TransferManager) CalculateTargetPath(userID, ftpPath, filename string) (string, error) {
	config, exists := tm.GetTarget(userID)
	if !exists {
		return "", fmt.Errorf("no target configuration for user %s", userID)
	}

	// Start with the target root
	targetPath := config.Root

	// Add the FTP path if provided
	if ftpPath != "" && ftpPath != "." && ftpPath != "/" {
		// Normalize and validate the FTP path
		normalizedPath, err := tm.normalizeFTPPath(ftpPath)
		if err != nil {
			return "", err
		}
		// Join with target root
		targetPath = filepath.Join(targetPath, normalizedPath)
	}

	// Add the filename
	if filename != "" {
		// Sanitize the filename
		safeFilename, err := tm.sanitizeFilename(filename)
		if err != nil {
			return "", err
		}
		targetPath = filepath.Join(targetPath, safeFilename)
	}

	// Final validation
	if err := tm.validateTargetPath(targetPath, config.Root); err != nil {
		return "", err
	}

	return targetPath, nil
}

// normalizeFTPPath normalizes an FTP path and prevents traversal.
// This function validates that the path does not contain directory traversal
// sequences and returns a clean, normalized path.
func (tm *TransferManager) normalizeFTPPath(path string) (string, error) {
	// Handle empty or root paths
	if path == "" || path == "." || path == "/" {
		return "", nil
	}

	// Check for path traversal in original path (various patterns)
	traversalPatterns := []string{"..", "/..", "../", "\\..\\", "..\\"}
	for _, pattern := range traversalPatterns {
		if strings.Contains(path, pattern) {
			return "", fmt.Errorf("path traversal not allowed: %s", path)
		}
	}

	// Check for absolute paths (Unix and Windows)
	if strings.HasPrefix(path, "/") || strings.HasPrefix(path, "\\") {
		return "", fmt.Errorf("absolute paths not allowed: %s", path)
	}

	// Check for drive letters (Windows)
	if len(path) >= 2 && path[1] == ':' {
		return "", fmt.Errorf("drive letters not allowed: %s", path)
	}

	// Remove leading slashes for normalization
	path = strings.TrimLeft(path, "/\\")

	// Handle case where we end up with empty string after trimming
	if path == "" {
		return "", nil
	}

	// Clean the path - this resolves . and .. if they somehow got through
	cleanPath := filepath.Clean(path)

	// After cleaning, the path should not contain ..
	if strings.Contains(cleanPath, "..") {
		return "", fmt.Errorf("path traversal not allowed: %s", path)
	}

	// Validate that the cleaned path is still a relative path
	if filepath.IsAbs(cleanPath) {
		return "", fmt.Errorf("path resolved to absolute path: %s", path)
	}

	// Check length limits
	const maxPathLength = 4096
	if len(cleanPath) > maxPathLength {
		return "", fmt.Errorf("path too long: %d characters (max %d)", len(cleanPath), maxPathLength)
	}

	return cleanPath, nil
}

// sanitizeFilename sanitizes a filename to prevent security issues
// while preserving Unicode characters.
// This function validates that the filename does not contain path traversal
// sequences and removes or replaces dangerous characters.
func (tm *TransferManager) sanitizeFilename(filename string) (string, error) {
	if filename == "" {
		return "", fmt.Errorf("filename cannot be empty")
	}

	// Store original for error messages
	originalFilename := filename

	// Check for absolute paths (Unix and Windows)
	if strings.HasPrefix(filename, "/") || strings.HasPrefix(filename, "\\") {
		return "", fmt.Errorf("filename cannot be absolute path: %s", originalFilename)
	}

	// Check for drive letters (Windows) - e.g., "C:" or "C:filename"
	if len(filename) >= 2 && filename[1] == ':' {
		return "", fmt.Errorf("filename cannot contain drive letter: %s", originalFilename)
	}

	// Check for path traversal sequences BEFORE extracting base
	// This catches attempts like "../secret.txt" or "path/../file.txt"
	// We need to check the original filename for these patterns
	if strings.Contains(originalFilename, "/..") || strings.Contains(originalFilename, "\\..") {
		return "", fmt.Errorf("filename contains path traversal: %s", originalFilename)
	}

	// Check for leading ".." patterns
	if strings.HasPrefix(originalFilename, "../") || strings.HasPrefix(originalFilename, "..\\") {
		return "", fmt.Errorf("filename contains path traversal: %s", originalFilename)
	}

	// Check for ".." followed by path separator at any position
	// This catches patterns like "foo/../bar" but not "...test.txt"
	for i := 0; i < len(originalFilename)-2; i++ {
		if originalFilename[i] == '.' && originalFilename[i+1] == '.' {
			// Check if followed by a path separator
			if i+2 < len(originalFilename) {
				nextChar := originalFilename[i+2]
				if nextChar == '/' || nextChar == '\\' {
					return "", fmt.Errorf("filename contains path traversal: %s", originalFilename)
				}
			}
			// Check if preceded by a path separator (for patterns like "/..file")
			if i > 0 {
				prevChar := originalFilename[i-1]
				if prevChar == '/' || prevChar == '\\' {
					return "", fmt.Errorf("filename contains path traversal: %s", originalFilename)
				}
			}
		}
	}

	// Extract the base filename (removes any directory components)
	filename = filepath.Base(filename)

	// After Base(), check for ".." as the ENTIRE filename (not as part of it)
	if filename == ".." || filename == "." {
		return "", fmt.Errorf("filename contains path traversal: %s", originalFilename)
	}

	// Remove control characters but preserve Unicode
	// This allows Unicode filenames while removing problematic characters
	var safeFilename strings.Builder
	for _, r := range filename {
		// Allow printable characters (including Unicode)
		// Block control characters (0-31), DEL (127), and null bytes
		if r >= 32 && r != 127 {
			safeFilename.WriteRune(r)
		} else {
			// Replace control characters with underscore
			safeFilename.WriteRune('_')
		}
	}

	result := safeFilename.String()

	// If we ended up with an empty string, use a default
	if result == "" {
		return "unnamed", nil
	}

	// Check length limits to prevent denial of service
	const maxFilenameLength = 255
	if len(result) > maxFilenameLength {
		return "", fmt.Errorf("filename too long: %d characters (max %d)", len(result), maxFilenameLength)
	}

	return result, nil
}

// validateTargetPath ensures the target path stays within the target root
// This prevents directory traversal attacks by verifying the resolved path
// is contained within the target root directory.
func (tm *TransferManager) validateTargetPath(targetPath, targetRoot string) error {
	// Normalize both paths using filepath.Clean
	cleanRoot := filepath.Clean(targetRoot)
	cleanPath := filepath.Clean(targetPath)

	// Ensure both paths are absolute for comparison
	if !filepath.IsAbs(cleanRoot) {
		cleanRoot = "/" + cleanRoot
	}
	if !filepath.IsAbs(cleanPath) {
		cleanPath = "/" + cleanPath
	}

	// Handle the case where targetPath equals targetRoot exactly
	if cleanPath == cleanRoot {
		return nil
	}

	// Add trailing separator to root to ensure proper prefix matching
	// This prevents cases where /root matches /root2 or /root-foo
	if !strings.HasSuffix(cleanRoot, "/") {
		cleanRoot += "/"
	}

	// Check if the target path is within the target root
	// The path must start with root (which now has a trailing separator)
	if !strings.HasPrefix(cleanPath, cleanRoot) {
		return fmt.Errorf("target path %s is outside target root %s", targetPath, targetRoot)
	}

	// Additional check: ensure no parent directory escape after the root
	// This catches edge cases like /root/../attack or /root/foo/../../bar
	relPath, err := filepath.Rel(cleanRoot, cleanPath)
	if err != nil {
		// If Rel returns an error, the paths are on different drives (Windows) or invalid
		return fmt.Errorf("target path %s is invalid or outside target root %s", targetPath, targetRoot)
	}
	// Only reject if relPath starts with "../" or is exactly ".."
	// This allows filenames that start with ".." like "...test.txt" or "..file.txt"
	if relPath == ".." || strings.HasPrefix(relPath, "../") || strings.HasPrefix(relPath, "..\\") {
		return fmt.Errorf("target path %s escapes target root %s", targetPath, targetRoot)
	}

	return nil
}

// GenerateUniqueFilename generates a unique filename for collision avoidance
// This implements the rename collision policy
func (tm *TransferManager) GenerateUniqueFilename(basePath, filename string) string {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Extract extension
	ext := filepath.Ext(filename)
	base := strings.TrimSuffix(filename, ext)

	// Generate timestamp suffix
	timestamp := time.Now().UTC().Format("20060102-150405")

	// Try the original filename first (for testing)
	fullPath := filepath.Join(basePath, filename)
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		return filename
	}

	// Generate unique filename with timestamp
	newFilename := fmt.Sprintf("%s-%s%s", base, timestamp, ext)
	fullPath = filepath.Join(basePath, newFilename)
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		return newFilename
	}

	// If that also exists, add a counter
	counter := tm.uploadCounters[basePath] + 1
	tm.uploadCounters[basePath] = counter
	newFilename = fmt.Sprintf("%s-%s-%d%s", base, timestamp, counter, ext)

	return newFilename
}

// CheckCollision checks if a file already exists at the target path
func (tm *TransferManager) CheckCollision(targetPath string) (bool, error) {
	// Use WebDAV client to check if the path exists
	if tm.webdavClient == nil {
		// Fallback: assume file doesn't exist
		return false, nil
	}

	// Check if the path exists using WebDAV
	exists, err := tm.webdavClient.CheckPathExistence(tm.context, targetPath)
	if err != nil {
		// If we can't check, assume it doesn't exist to avoid blocking uploads
		// This is a safe default for the bridge
		return false, nil
	}

	return exists, nil
}

// ResolveCollision resolves a filename collision based on the collision policy
func (tm *TransferManager) ResolveCollision(basePath, filename string, policy CollisionPolicy) (string, error) {
	switch policy {
	case CollisionPolicyOverwrite:
		// Allow overwriting - return original filename
		return filename, nil

	case CollisionPolicyReject:
		// Check if file exists
		fullPath := filepath.Join(basePath, filename)
		exists, err := tm.CheckCollision(fullPath)
		if err != nil {
			return "", err
		}
		if exists {
			return "", fmt.Errorf("file already exists: %s", filename)
		}
		return filename, nil

	case CollisionPolicyRename:
		// Generate unique filename
		return tm.GenerateUniqueFilename(basePath, filename), nil

	default:
		return "", fmt.Errorf("unknown collision policy: %s", policy)
	}
}

// EnsureParentDirectories creates all parent directories for a given path
func (tm *TransferManager) EnsureParentDirectories(targetPath string) error {
	if tm.webdavClient == nil {
		// Without WebDAV client, we can't create directories
		return nil
	}

	// Get the parent directory
	parentDir := filepath.Dir(targetPath)
	if parentDir == "." || parentDir == "/" {
		// Root directory, no need to create
		return nil
	}

	// Check if parent directory exists
	exists, err := tm.webdavClient.CheckPathExistence(tm.context, parentDir)
	if err != nil {
		// If we can't check, try to create anyway
		return tm.webdavClient.CreateDirectory(tm.context, parentDir)
	}

	if !exists {
		// Create the parent directory (and any missing parents)
		return tm.createParentDirectoriesRecursive(parentDir)
	}

	return nil
}

// createParentDirectoriesRecursive creates all parent directories recursively
func (tm *TransferManager) createParentDirectoriesRecursive(path string) error {
	if tm.webdavClient == nil {
		return nil
	}

	// Get the parent of this path
	parentDir := filepath.Dir(path)
	if parentDir == "." || parentDir == "/" {
		// We're at the root, create the current directory
		return tm.webdavClient.CreateDirectory(tm.context, path)
	}

	// Recursively create parent first
	err := tm.createParentDirectoriesRecursive(parentDir)
	if err != nil {
		return err
	}

	// Then create the current directory
	return tm.webdavClient.CreateDirectory(tm.context, path)
}

// ProcessUpload handles the complete upload processing pipeline
// This includes path mapping, collision resolution, and directory creation
func (tm *TransferManager) ProcessUpload(request TransferRequest) TransferResult {
	// Get target configuration for this user
	config, exists := tm.GetTarget(request.UserID)
	if !exists {
		return TransferResult{
			Success: false,
			Error:   fmt.Errorf("no target configuration for user %s", request.UserID),
		}
	}

	// Calculate the base target path (without filename)
	basePath, err := tm.CalculateTargetPath(request.UserID, request.Path, "")
	if err != nil {
		return TransferResult{
			Success: false,
			Error:   fmt.Errorf("failed to calculate target path: %w", err),
		}
	}

	// Handle collision based on policy
	finalFilename := request.Filename
	if request.Filename != "" {
		finalFilename, err = tm.ResolveCollision(basePath, request.Filename, config.CollisionPolicy)
		if err != nil {
			return TransferResult{
				Success: false,
				Error:   fmt.Errorf("collision resolution failed: %w", err),
			}
		}
	}

	// Calculate final target path with resolved filename
	finalPath, err := tm.CalculateTargetPath(request.UserID, request.Path, finalFilename)
	if err != nil {
		return TransferResult{
			Success: false,
			Error:   fmt.Errorf("failed to calculate final target path: %w", err),
		}
	}

	// Ensure parent directories exist
	err = tm.EnsureParentDirectories(finalPath)
	if err != nil {
		return TransferResult{
			Success: false,
			Error:   fmt.Errorf("failed to ensure parent directories: %w", err),
		}
	}

	return TransferResult{
		TargetPath: finalPath,
		Filename:   finalFilename,
		Size:       request.Size,
		Success:    true,
	}
}

// Path validation helpers

// isSafePath checks if a path contains only safe characters
func isSafePath(path string) bool {
	// Allow alphanumeric, spaces, common punctuation, and Unicode
	safePattern := regexp.MustCompile(`^[\w\s\-.~/]+$`)
	return safePattern.MatchString(path)
}

// Extract components from a path
func extractPathComponents(path string) []string {
	if path == "" || path == "." || path == "/" {
		return []string{}
	}

	// Remove leading/trailing slashes and split
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return []string{}
	}

	return strings.Split(trimmed, "/")
}