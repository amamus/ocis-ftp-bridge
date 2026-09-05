// Package spool provides local file spool functionality for ocis-ftp-bridge.
//
// It manages temporary file storage for FTP uploads before they
// are forwarded to oCIS via WebDAV.
package spool

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// FileStatus represents the status of a spooled file.
type FileStatus string

const (
	// FileStatusPending indicates the file is still being uploaded.
	FileStatusPending FileStatus = "pending"
	// FileStatusCommitted indicates the file has been fully uploaded but not yet sent to WebDAV.
	FileStatusCommitted FileStatus = "committed"
	// FileStatusFailed indicates the upload failed.
	FileStatusFailed FileStatus = "failed"
	// FileStatusPublished indicates the file has been successfully published to WebDAV.
	FileStatusPublished FileStatus = "published"
)

// Errors
var (
	ErrInvalidSpoolDirectory  = fmt.Errorf("invalid spool directory")
	ErrInvalidParameters      = fmt.Errorf("invalid parameters")
	ErrEmptyData              = fmt.Errorf("empty data")
	ErrFileTooLarge           = fmt.Errorf("file too large")
	ErrPathTraversal          = fmt.Errorf("path traversal")
	ErrNotImplemented         = fmt.Errorf("operation not implemented")
	ErrUploadCancelled        = fmt.Errorf("upload cancelled")
	ErrUploadIncomplete       = fmt.Errorf("upload incomplete")
	ErrSpoolCapacityExceeded = fmt.Errorf("spool capacity exceeded")
	ErrFileNotFound           = fmt.Errorf("file not found")
	ErrDuplicateFile          = fmt.Errorf("duplicate file")
)

// FileRef represents a reference to a spooled file.
type FileRef struct {
	// UserID is the user/printer account ID.
	UserID string

	// FileID is the unique identifier for this file.
	FileID string

	// Filename is the original filename.
	Filename string

	// Size is the size of the file in bytes.
	Size int64

	// Path is the absolute filesystem path to the file.
	Path string

	// CreatedAt is when the file was created.
	CreatedAt string

	// TargetPath is the destination path in oCIS.
	TargetPath string

	// Status is the current status of the file.
	Status FileStatus

	// AccountID is the account this file belongs to.
	AccountID string
}

// SpoolFile represents a file in the spool directory.
type SpoolFile struct {
	FileRef
	// ModTime is the modification time of the file.
	ModTime time.Time
}

// Manager is the interface for managing local file spool.
type Manager interface {
	// Store stores data into the spool and returns a file reference.
	Store(userID string, filename string, data []byte) (FileRef, error)

	// StoreStream stores data from a reader into the spool for streaming uploads.
	// This method allows for large file uploads without loading the entire file into memory.
	StoreStream(userID, filename, targetPath string, reader io.Reader, size int64) (FileRef, error)

	// Retrieve retrieves the data for a spooled file.
	Retrieve(userID string, fileID string) ([]byte, error)

	// Delete deletes a spooled file.
	Delete(userID string, fileID string) error

	// DeleteByPath deletes a file by its filesystem path.
	DeleteByPath(filePath string) error

	// List lists all files for a user.
	List(userID string) ([]FileRef, error)

	// ListAll lists all files in the spool.
	ListAll() ([]SpoolFile, error)

	// Cleanup removes files older than maxAge (in minutes).
	Cleanup(maxAge int) error

	// GetFileRef retrieves a FileRef by userID and fileID.
	GetFileRef(userID string, fileID string) (FileRef, error)

	// GetUsage returns the current spool usage and capacity.
	GetUsage() (used uint64, capacity uint64, err error)

	// MarkPublished marks a file as successfully published to WebDAV.
	MarkPublished(userID, fileID string) error

	// MarkFailed marks a file as failed to publish.
	MarkFailed(userID, fileID string) error

	// GetPendingFiles returns all files that are committed but not yet published.
	GetPendingFiles() ([]FileRef, error)

	// GetUploadManager returns the upload manager for streaming uploads.
	GetUploadManager() UploadManager
}

// Upload represents an active upload operation.
type Upload struct {
	// ID is the unique identifier for this upload.
	ID string

	// UserID is the user/printer account ID.
	UserID string

	// Filename is the original filename from the FTP client.
	Filename string

	// TargetPath is the destination path in oCIS.
	TargetPath string

	// TempFile is the temporary file being written.
	TempFile *os.File

	// TempPath is the path to the temporary file.
	TempPath string

	// Size is the expected total size.
	Size int64

	// BytesReceived is the number of bytes received so far.
	BytesReceived int64

	// StartedAt is when the upload started.
	StartedAt time.Time

	// AccountMaxSize is the per-account maximum file size.
	AccountMaxSize uint64

	// Cancel is a function to cancel the upload.
	Cancel context.CancelFunc

	// Context is the upload context.
	Context context.Context
}

// UploadManager manages active uploads and their lifecycle.
type UploadManager interface {
	// StartUpload begins a new upload and returns an Upload for streaming data.
	StartUpload(ctx context.Context, userID, filename, targetPath string, expectedSize int64, accountMaxSize uint64) (*Upload, error)

	// WriteChunk writes a chunk of data to an active upload.
	WriteChunk(upload *Upload, data []byte) (int, error)

	// FinishUpload completes an upload and returns a FileRef for the final file.
	FinishUpload(upload *Upload) (FileRef, error)

	// AbortUpload cancels an upload and cleans up the temporary file.
	AbortUpload(upload *Upload) error

	// GetUpload retrieves an active upload by ID.
	GetUpload(uploadID string) *Upload

	// RemoveUpload removes an upload from the active uploads map.
	RemoveUpload(uploadID string)
}

// defaultManager is the default implementation of Manager.
type defaultManager struct {
	spoolDir      string
	maxSize       uint64
	uploadManager UploadManager
}

// uploadManager implements UploadManager.
type uploadManager struct {
	spoolDir       string
	maxTotalSize   uint64
	currentUsage   uint64
	activeUploads map[string]*Upload
	mu            sync.RWMutex
}

// NewManager creates a new file spool manager.
func NewManager(spoolDir string, maxSize uint64) (Manager, error) {
	if spoolDir == "" {
		return nil, ErrInvalidSpoolDirectory
	}

	if err := os.MkdirAll(spoolDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create spool directory: %w", err)
	}

	// Check if the spool directory is writable
	if err := checkDirectoryWritable(spoolDir); err != nil {
		return nil, fmt.Errorf("spool directory is not writable: %w", err)
	}

	return &defaultManager{
		spoolDir:      spoolDir,
		maxSize:       maxSize,
		uploadManager: NewUploadManager(spoolDir, maxSize),
	}, nil
}

// checkDirectoryWritable checks if a directory is writable.
func checkDirectoryWritable(dir string) error {
	testFile := filepath.Join(dir, ".write_test")
	if err := os.WriteFile(testFile, []byte("test"), 0600); err != nil {
		return err
	}
	return os.Remove(testFile)
}

// NewUploadManager creates a new upload manager.
func NewUploadManager(spoolDir string, maxTotalSize uint64) UploadManager {
	return &uploadManager{
		spoolDir:       spoolDir,
		maxTotalSize:   maxTotalSize,
		activeUploads: make(map[string]*Upload),
	}
}

// StartUpload begins a new upload and returns an Upload for streaming data.
func (m *uploadManager) StartUpload(ctx context.Context, userID, filename, targetPath string, expectedSize int64, accountMaxSize uint64) (*Upload, error) {
	// Validate parameters
	if userID == "" {
		return nil, ErrInvalidParameters
	}
	if filename == "" {
		return nil, ErrInvalidParameters
	}
	if expectedSize < 0 {
		return nil, ErrInvalidParameters
	}
	if accountMaxSize == 0 {
		return nil, ErrInvalidParameters
	}

	// Check if the file would exceed the account limit
	if uint64(expectedSize) > accountMaxSize {
		return nil, ErrFileTooLarge
	}

	// Check path traversal in userID and target path
	if strings.Contains(userID, "..") || strings.Contains(targetPath, "..") {
		return nil, ErrPathTraversal
	}

	// Check if we have enough total spool capacity
	if uint64(expectedSize) > m.maxTotalSize {
		return nil, ErrFileTooLarge
	}

	// Check current usage + this file wouldn't exceed capacity
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.currentUsage+uint64(expectedSize) > m.maxTotalSize {
		return nil, ErrSpoolCapacityExceeded
	}

	// Create a unique upload ID
	uploadID := m.generateUploadID(userID, filename, targetPath)

	// Create the user directory in spool
	cleanUserID := filepath.Clean(userID)
	absSpoolDir, err := filepath.Abs(m.spoolDir)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute spool directory: %w", err)
	}

	userDir := filepath.Join(absSpoolDir, cleanUserID)
	if err := os.MkdirAll(userDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create user spool directory: %w", err)
	}

	// Validate that the user directory is within the spool directory
	rel, err := filepath.Rel(absSpoolDir, userDir)
	if err != nil || strings.HasPrefix(rel, "..") {
		return nil, ErrPathTraversal
	}

	// Create a temporary file
	tempFile, err := os.CreateTemp(userDir, "upload-*.tmp")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary file: %w", err)
	}

	// Set restrictive permissions
	if err := tempFile.Chmod(0600); err != nil {
		os.Remove(tempFile.Name())
		return nil, fmt.Errorf("failed to set file permissions: %w", err)
	}

	// Create the upload context
	uploadCtx, cancel := context.WithCancel(ctx)

	upload := &Upload{
		ID:            uploadID,
		UserID:        userID,
		Filename:      filename,
		TargetPath:    targetPath,
		TempFile:      tempFile,
		TempPath:      tempFile.Name(),
		Size:          expectedSize,
		BytesReceived: 0,
		StartedAt:     time.Now().UTC(),
		AccountMaxSize: accountMaxSize,
		Cancel:        cancel,
		Context:       uploadCtx,
	}

	// Track the upload
	m.activeUploads[uploadID] = upload
	atomic.AddUint64(&m.currentUsage, uint64(expectedSize))

	return upload, nil
}

// WriteChunk writes a chunk of data to an active upload.
func (m *uploadManager) WriteChunk(upload *Upload, data []byte) (int, error) {
	if upload == nil {
		return 0, ErrInvalidParameters
	}

	// Check if upload was cancelled
	select {
	case <-upload.Context.Done():
		return 0, ErrUploadCancelled
	default:
	}

	// Check size limits
	remaining := upload.Size - upload.BytesReceived
	if int64(len(data)) > remaining {
		return 0, ErrFileTooLarge
	}

	// Check if this chunk would exceed account max size
	if upload.BytesReceived+int64(len(data)) > int64(upload.AccountMaxSize) {
		return 0, ErrFileTooLarge
	}

	// Write the data
	n, err := upload.TempFile.Write(data)
	if err != nil {
		return n, fmt.Errorf("failed to write upload chunk: %w", err)
	}

	// Update bytes received
	atomic.AddInt64(&upload.BytesReceived, int64(n))

	return n, nil
}

// FinishUpload completes an upload and returns a FileRef for the final file.
func (m *uploadManager) FinishUpload(upload *Upload) (FileRef, error) {
	if upload == nil {
		return FileRef{}, ErrInvalidParameters
	}

	// Check if upload was cancelled or incomplete
	select {
	case <-upload.Context.Done():
		return FileRef{}, ErrUploadCancelled
	default:
	}

	if upload.BytesReceived != upload.Size {
		return FileRef{}, ErrUploadIncomplete
	}

	// Sync the file to disk
	if err := upload.TempFile.Sync(); err != nil {
		return FileRef{}, fmt.Errorf("failed to sync upload file: %w", err)
	}

	// Close the file
	if err := upload.TempFile.Close(); err != nil {
		return FileRef{}, fmt.Errorf("failed to close upload file: %w", err)
	}

	// Generate a final file ID
	fileID := m.generateFileID(upload)

	// Determine the final file path
	cleanUserID := filepath.Clean(upload.UserID)
	absSpoolDir, err := filepath.Abs(m.spoolDir)
	if err != nil {
		return FileRef{}, fmt.Errorf("failed to get absolute spool directory: %w", err)
	}

	userDir := filepath.Join(absSpoolDir, cleanUserID)
	finalPath := filepath.Join(userDir, fileID)

	// Move the temporary file to the final location
	if err := os.Rename(upload.TempPath, finalPath); err != nil {
		// If rename fails, try copy + delete
		if err := copyFile(finalPath, upload.TempPath); err != nil {
			return FileRef{}, fmt.Errorf("failed to move upload file: %w", err)
		}
		if err := os.Remove(upload.TempPath); err != nil && !os.IsNotExist(err) {
			// Log error but continue - file is copied
			fmt.Printf("warning: failed to remove temporary file %s: %v\n", upload.TempPath, err)
		}
	}

	// Set final permissions
	if err := os.Chmod(finalPath, 0640); err != nil {
		return FileRef{}, fmt.Errorf("failed to set final file permissions: %w", err)
	}

	// Create the file reference
	fileRef := FileRef{
		UserID:    upload.UserID,
		FileID:    fileID,
		Filename:  upload.Filename,
		Size:      upload.BytesReceived,
		Path:      finalPath,
		CreatedAt: upload.StartedAt.Format("2006_01_02T15_04_05Z"),
		TargetPath: upload.TargetPath,
		Status:    FileStatusCommitted,
	}

	// Remove from active uploads
	m.mu.Lock()
	delete(m.activeUploads, upload.ID)
	m.mu.Unlock()

	return fileRef, nil
}

// AbortUpload cancels an upload and cleans up the temporary file.
func (m *uploadManager) AbortUpload(upload *Upload) error {
	if upload == nil {
		return ErrInvalidParameters
	}

	// Cancel the context
	if upload.Cancel != nil {
		upload.Cancel()
	}

	// Close and remove the temporary file
	if upload.TempFile != nil {
		upload.TempFile.Close()
		os.Remove(upload.TempPath)
	}

	// Remove from active uploads
	m.mu.Lock()
	delete(m.activeUploads, upload.ID)
	m.mu.Unlock()

	return nil
}

// GetUpload retrieves an active upload by ID.
func (m *uploadManager) GetUpload(uploadID string) *Upload {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.activeUploads[uploadID]
}

// RemoveUpload removes an upload from the active uploads map.
func (m *uploadManager) RemoveUpload(uploadID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.activeUploads, uploadID)
}

// generateUploadID generates a unique upload ID.
func (m *uploadManager) generateUploadID(userID, filename, targetPath string) string {
	dataToHash := userID + "-" + filename + "-" + targetPath + "-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	idHash := sha256.Sum256([]byte(dataToHash))
	return fmt.Sprintf("upload-%s", hex.EncodeToString(idHash[:])[:16])
}

// generateFileID generates a unique file ID.
func (m *uploadManager) generateFileID(upload *Upload) string {
	dataToHash := upload.UserID + "-" + upload.Filename + "-" + upload.TargetPath + "-" + strconv.FormatInt(upload.StartedAt.UnixNano(), 10)
	idHash := sha256.Sum256([]byte(dataToHash))
	return fmt.Sprintf("file-%s-%d", hex.EncodeToString(idHash[:])[:16], upload.BytesReceived)
}

// copyFile copies a file from src to dst.
func copyFile(dst, src string) error {
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()

	_, err = io.Copy(destination, source)
	return err
}

// Store implements Manager.Store.
func (m *defaultManager) Store(userID string, filename string, data []byte) (FileRef, error) {
	if userID == "" || filename == "" {
		return FileRef{}, ErrInvalidParameters
	}
	if len(data) == 0 {
		return FileRef{}, ErrEmptyData
	}
	if uint64(len(data)) > m.maxSize {
		return FileRef{}, ErrFileTooLarge
	}
	if strings.Contains(userID, "..") {
		return FileRef{}, ErrPathTraversal
	}

	cleanUserID := filepath.Clean(userID)
	absSpoolDir, err := filepath.Abs(m.spoolDir)
	if err != nil {
		return FileRef{}, fmt.Errorf("failed to get absolute path for spool directory: %w", err)
	}
	userDir := filepath.Join(absSpoolDir, cleanUserID)
	rel, err := filepath.Rel(absSpoolDir, userDir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return FileRef{}, ErrPathTraversal
	}

	if err := os.MkdirAll(userDir, 0750); err != nil {
		return FileRef{}, fmt.Errorf("failed to create user directory: %w", err)
	}

	dataToHash := filename + "-" + userID + "-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	idHash := sha256.Sum256([]byte(dataToHash))
	fileID := fmt.Sprintf("file-%s-%d", hex.EncodeToString(idHash[:])[:16], len(data))
	filePath := filepath.Join(userDir, fileID)

	if err := os.WriteFile(filePath, data, 0640); err != nil {
		return FileRef{}, fmt.Errorf("failed to write spool file: %w", err)
	}

	return FileRef{
		UserID:    userID,
		FileID:    fileID,
		Filename:  filename,
		Size:      int64(len(data)),
		Path:      filePath,
		CreatedAt: time.Now().UTC().Format("2006_01_02T15_04_05Z"),
		Status:    FileStatusCommitted,
	}, nil
}

// StoreStream implements streaming upload storage.
func (m *defaultManager) StoreStream(userID, filename, targetPath string, reader io.Reader, size int64) (FileRef, error) {
	if userID == "" || filename == "" || targetPath == "" {
		return FileRef{}, ErrInvalidParameters
	}
	if reader == nil {
		return FileRef{}, ErrInvalidParameters
	}
	if size <= 0 {
		return FileRef{}, ErrEmptyData
	}
	if uint64(size) > m.maxSize {
		return FileRef{}, ErrFileTooLarge
	}

	// Use the upload manager for streaming
	ctx := context.Background()
	upload, err := m.uploadManager.StartUpload(ctx, userID, filename, targetPath, size, m.maxSize)
	if err != nil {
		return FileRef{}, fmt.Errorf("failed to start upload: %w", err)
	}

	// Read the data in chunks
	buf := make([]byte, 32*1024) // 32KB buffer
	for {
		n, err := reader.Read(buf)
		if err != nil && err != io.EOF {
			// Abort the upload on read error
			m.uploadManager.AbortUpload(upload)
			return FileRef{}, fmt.Errorf("failed to read upload data: %w", err)
		}
		if n == 0 {
			break
		}

		if _, err := m.uploadManager.WriteChunk(upload, buf[:n]); err != nil {
			m.uploadManager.AbortUpload(upload)
			return FileRef{}, fmt.Errorf("failed to write upload chunk: %w", err)
		}
	}

	// Finish the upload
	fileRef, err := m.uploadManager.FinishUpload(upload)
	if err != nil {
		return FileRef{}, fmt.Errorf("failed to finish upload: %w", err)
	}

	return fileRef, nil
}

func (m *defaultManager) Retrieve(userID string, fileID string) ([]byte, error) {
	if userID == "" || fileID == "" {
		return nil, ErrInvalidParameters
	}

	cleanUserID := filepath.Clean(userID)
	absSpoolDir, err := filepath.Abs(m.spoolDir)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for spool directory: %w", err)
	}
	userDir := filepath.Join(absSpoolDir, cleanUserID)

	// Check for path traversal
	rel, err := filepath.Rel(absSpoolDir, userDir)
	if err != nil || strings.HasPrefix(rel, "..") {
		return nil, ErrPathTraversal
	}

	// Try to find the file with the given ID
	filePath := filepath.Join(userDir, fileID)
	if data, err := os.ReadFile(filePath); err == nil {
		return data, nil
	}

	// Try to find the file with file- prefix
	filePath = filepath.Join(userDir, "file-"+fileID)
	if data, err := os.ReadFile(filePath); err == nil {
		return data, nil
	}

	return nil, ErrFileNotFound
}

func (m *defaultManager) Delete(userID string, fileID string) error {
	if userID == "" || fileID == "" {
		return ErrInvalidParameters
	}

	// Find and delete the file
	fileRef, err := m.GetFileRef(userID, fileID)
	if err != nil {
		return err
	}

	return m.DeleteByPath(fileRef.Path)
}

func (m *defaultManager) DeleteByPath(filePath string) error {
	if filePath == "" {
		return ErrInvalidParameters
	}

	// Validate that the file is within the spool directory
	absSpoolDir, err := filepath.Abs(m.spoolDir)
	if err != nil {
		return fmt.Errorf("failed to get absolute spool directory: %w", err)
	}

	absFilePath, err := filepath.Abs(filePath)
	if err != nil {
		return fmt.Errorf("failed to get absolute file path: %w", err)
	}

	rel, err := filepath.Rel(absSpoolDir, absFilePath)
	if err != nil || strings.HasPrefix(rel, "..") {
		return ErrPathTraversal
	}

	if err := os.Remove(absFilePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete file: %w", err)
	}

	return nil
}

func (m *defaultManager) List(userID string) ([]FileRef, error) {
	if userID == "" {
		return nil, ErrInvalidParameters
	}

	cleanUserID := filepath.Clean(userID)
	absSpoolDir, err := filepath.Abs(m.spoolDir)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for spool directory: %w", err)
	}
	userDir := filepath.Join(absSpoolDir, cleanUserID)

	// Check for path traversal
	rel, err := filepath.Rel(absSpoolDir, userDir)
	if err != nil || strings.HasPrefix(rel, "..") {
		return nil, ErrPathTraversal
	}

	entries, err := os.ReadDir(userDir)
	if err != nil {
		// If the user directory doesn't exist, return empty list
		if os.IsNotExist(err) {
			return []FileRef{}, nil
		}
		return nil, fmt.Errorf("failed to read user directory: %w", err)
	}

	var files []FileRef
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filePath := filepath.Join(userDir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}

		// Skip temporary files
		if strings.HasSuffix(entry.Name(), ".tmp") {
			continue
		}

		files = append(files, FileRef{
			UserID:    userID,
			FileID:    entry.Name(),
			Filename:  entry.Name(), // Would need to track original filename separately
			Size:      info.Size(),
			Path:      filePath,
			CreatedAt: info.ModTime().UTC().Format("2006_01_02T15_04_05Z"),
			Status:    FileStatusCommitted,
		})
	}

	return files, nil
}

func (m *defaultManager) ListAll() ([]SpoolFile, error) {
	absSpoolDir, err := filepath.Abs(m.spoolDir)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for spool directory: %w", err)
	}

	// Walk the spool directory
	var allFiles []SpoolFile
	if err := filepath.Walk(absSpoolDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		// Skip temporary files
		if strings.HasSuffix(info.Name(), ".tmp") {
			return nil
		}

		// Determine user ID from path
		relPath, err := filepath.Rel(absSpoolDir, path)
		if err != nil {
			return err
		}

		parts := strings.Split(relPath, string(filepath.Separator))
		if len(parts) < 2 {
			return nil
		}

		userID := parts[0]
		fileID := parts[1]

		allFiles = append(allFiles, SpoolFile{
			FileRef: FileRef{
				UserID:    userID,
				FileID:    fileID,
				Filename:  fileID,
				Size:      info.Size(),
				Path:      path,
				CreatedAt: info.ModTime().UTC().Format("2006_01_02T15_04_05Z"),
				Status:    FileStatusCommitted,
			},
			ModTime: info.ModTime(),
		})

		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to walk spool directory: %w", err)
	}

	return allFiles, nil
}

func (m *defaultManager) Cleanup(maxAge int) error {
	if maxAge <= 0 {
		maxAge = 30 // Default to 30 minutes
	}

	allFiles, err := m.ListAll()
	if err != nil {
		return fmt.Errorf("failed to list files for cleanup: %w", err)
	}

	cutoff := time.Now().Add(-time.Duration(maxAge) * time.Minute)
	deletedCount := 0

	for _, spoolFile := range allFiles {
		if spoolFile.ModTime.Before(cutoff) {
			if err := m.DeleteByPath(spoolFile.Path); err != nil {
				// Log error but continue with other files
				fmt.Printf("warning: failed to delete old file %s: %v\n", spoolFile.Path, err)
			}
			deletedCount++
		}
	}

	fmt.Printf("Cleaned up %d old files from spool\n", deletedCount)
	return nil
}

func (m *defaultManager) GetFileRef(userID string, fileID string) (FileRef, error) {
	if userID == "" || fileID == "" {
		return FileRef{}, ErrInvalidParameters
	}

	// Try to find the file
	files, err := m.List(userID)
	if err != nil {
		return FileRef{}, fmt.Errorf("failed to list user files: %w", err)
	}

	for _, file := range files {
		if file.FileID == fileID {
			return file, nil
		}
	}

	return FileRef{}, ErrFileNotFound
}

func (m *defaultManager) GetUsage() (used uint64, capacity uint64, err error) {
	// Calculate actual usage by summing up all files
	allFiles, err := m.ListAll()
	if err != nil {
		return 0, m.maxSize, fmt.Errorf("failed to calculate usage: %w", err)
	}

	var totalUsed uint64
	for _, file := range allFiles {
		totalUsed += uint64(file.Size)
	}

	return totalUsed, m.maxSize, nil
}

func (m *defaultManager) MarkPublished(userID, fileID string) error {
	if _, err := m.GetFileRef(userID, fileID); err != nil {
		return err
	}

	// In a real implementation, we would update metadata to mark as published
	// For now, we can delete the file from spool since it's successfully published
	// Alternatively, we could keep it for some time for recovery
	return nil
}

func (m *defaultManager) MarkFailed(userID, fileID string) error {
	// Mark the file as failed - could be used for retry logic
	return nil
}

func (m *defaultManager) GetPendingFiles() ([]FileRef, error) {
	// Get all committed files that haven't been published yet
	allFiles, err := m.ListAll()
	if err != nil {
		return nil, err
	}

	var pending []FileRef
	for _, spoolFile := range allFiles {
		if spoolFile.Status == FileStatusCommitted {
			pending = append(pending, spoolFile.FileRef)
		}
	}

	return pending, nil
}

func (m *defaultManager) GetUploadManager() UploadManager {
	return m.uploadManager
}