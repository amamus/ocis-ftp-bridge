// Package spool provides local file spool functionality for ocis-ftp-bridge.
//
// It manages temporary file storage for FTP uploads before they
// are forwarded to oCIS via WebDAV.
package spool

import (
	"fmt"
	"os"
	"path/filepath"
)

// Manager is the interface for managing local file spool.
type Manager interface {
		// Store stores data in the spool.
		Store(userID string, filename string, data []byte) (FileRef, error)
		
		// Retrieve retrieves data from the spool.
		Retrieve(userID string, fileID string) ([]byte, error)
		
		// Delete deletes a file from the spool.
		Delete(userID string, fileID string) error
		
		// List lists all files in the spool for a user.
		List(userID string) ([]FileRef, error)
		
		// Cleanup cleans up old files from the spool.
		Cleanup(maxAge int) error
		
		// GetFileRef gets a file reference by userID and fileID.
		GetFileRef(userID string, fileID string) (FileRef, error)
		
		// GetUsage returns current usage and capacity information.
		GetUsage() (used, capacity uint64, err error)
	}

// FileRef represents a reference to a spooled file.
type FileRef struct {
	// UserID is the user who owns the file.
	UserID string
	
	// FileID is the unique identifier for the file.
	FileID string
	
	// Filename is the original filename.
	Filename string
	
	// Size is the size of the file in bytes.
	Size int64
	
	// Path is the full path to the file.
	Path string
	
	// CreatedAt is when the file was created.
	CreatedAt string
}

// NewManager creates a new file spool manager.
func NewManager(spoolDir string, maxSize uint64) (Manager, error) {
	if spoolDir == "" {
		return nil, ErrInvalidSpoolDirectory
	}
	
	// Create spool directory if it doesn't exist
	err := os.MkdirAll(spoolDir, 0750)
	if err != nil {
		return nil, fmt.Errorf("failed to create spool directory: %w", err)
	}
	
	return &defaultManager{spoolDir: spoolDir, maxSize: maxSize}, nil
}

// defaultManager is the default implementation of Manager.
type defaultManager struct {
	spoolDir string
	maxSize  uint64
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
	
	// Create user directory
	userDir := filepath.Join(m.spoolDir, userID)
	err := os.MkdirAll(userDir, 0750)
	if err != nil {
		return FileRef{}, fmt.Errorf("failed to create user directory: %w", err)
	}
	
	// Generate file ID (in production, use UUID)
	fileID := fmt.Sprintf("%d", len(data))
	filePath := filepath.Join(userDir, fileID)
	
	// Write file
	err = os.WriteFile(filePath, data, 0640)
	if err != nil {
		return FileRef{}, fmt.Errorf("failed to write spool file: %w", err)
	}
	
	return FileRef{
		UserID:   userID,
		FileID:   fileID,
		Filename: filename,
		Size:     int64(len(data)),
		Path:     filePath,
		CreatedAt: "2024-01-01T00:00:00Z", // placeholder
	}, nil
}

// Retrieve implements Manager.Retrieve.
func (m *defaultManager) Retrieve(userID string, fileID string) ([]byte, error) {
	if userID == "" || fileID == "" {
		return nil, ErrInvalidParameters
	}
	
	filePath := filepath.Join(m.spoolDir, userID, fileID)
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrFileNotFound
		}
		return nil, fmt.Errorf("failed to read spool file: %w", err)
	}
	
	return data, nil
}

// Delete implements Manager.Delete.
func (m *defaultManager) Delete(userID string, fileID string) error {
	if userID == "" || fileID == "" {
		return ErrInvalidParameters
	}
	
	filePath := filepath.Join(m.spoolDir, userID, fileID)
	err := os.Remove(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return ErrFileNotFound
		}
		return fmt.Errorf("failed to delete spool file: %w", err)
	}
	
	return nil
}

// List implements Manager.List.
func (m *defaultManager) List(userID string) ([]FileRef, error) {
	if userID == "" {
		return nil, ErrInvalidParameters
	}
	
	userDir := filepath.Join(m.spoolDir, userID)
	ents, err := os.ReadDir(userDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []FileRef{}, nil
		}
		return nil, fmt.Errorf("failed to read user directory: %w", err)
	}
	
	var files []FileRef
	for _, ent := range ents {
		if ent.IsDir() {
			continue
		}
		
		filePath := filepath.Join(userDir, ent.Name())
		info, err := ent.Info()
		if err != nil {
			continue
		}
		
		files = append(files, FileRef{
			UserID:   userID,
			FileID:   ent.Name(),
			Filename: "unknown.txt", // placeholder
			Size:     info.Size(),
			Path:     filePath,
			CreatedAt: "2024-01-01T00:00:00Z", // placeholder
		})
	}
	
	return files, nil
}

// Cleanup implements Manager.Cleanup.
func (m *defaultManager) Cleanup(maxAge int) error {
	// In production, this would delete files older than maxAge
	fmt.Printf("Cleanup with maxAge=%d - NOT IMPLEMENTED\n", maxAge)
	return nil
}

// GetUsage returns current usage and capacity information.
func (m *defaultManager) GetUsage() (used, capacity uint64, err error) {
	// For now, return placeholder values
	used = 0
	capacity = m.maxSize
	return used, capacity, nil
}

// GetFileRef implements Manager.GetFileRef.
func (m *defaultManager) GetFileRef(userID string, fileID string) (FileRef, error) {
	if userID == "" || fileID == "" {
		return FileRef{}, ErrInvalidParameters
	}
	
	filePath := filepath.Join(m.spoolDir, userID, fileID)
	info, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return FileRef{}, ErrFileNotFound
		}
		return FileRef{}, fmt.Errorf("failed to stat spool file: %w", err)
	}
	
	return FileRef{
		UserID:   userID,
		FileID:   fileID,
		Filename: "unknown.txt", // placeholder
		Size:     info.Size(),
		Path:     filePath,
		CreatedAt: "2024-01-01T00:00:00Z", // placeholder
	}, nil
}

// Errors
type SpoolError struct {
	msg string
}

func (e *SpoolError) Error() string {
	return fmt.Sprintf("spool error: %s", e.msg)
}

var (
	ErrInvalidSpoolDirectory = &SpoolError{msg: "invalid spool directory"}
	ErrInvalidParameters     = &SpoolError{msg: "invalid parameters"}
	ErrEmptyData             = &SpoolError{msg: "empty data"}
	ErrFileTooLarge          = &SpoolError{msg: "file too large"}
	ErrFileNotFound          = &SpoolError{msg: "file not found"}
	ErrSpoolFull             = &SpoolError{msg: "spool directory full"}
	ErrPermissionDenied      = &SpoolError{msg: "permission denied"}
)