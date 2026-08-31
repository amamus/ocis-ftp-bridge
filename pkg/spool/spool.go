// Package spool provides local file spool functionality for ocis-ftp-bridge.
//
// It manages temporary file storage for FTP uploads before they
// are forwarded to oCIS via WebDAV.
package spool

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Errors
var (
	ErrInvalidSpoolDirectory = fmt.Errorf("invalid spool directory")
	ErrInvalidParameters     = fmt.Errorf("invalid parameters")
	ErrEmptyData             = fmt.Errorf("empty data")
	ErrFileTooLarge          = fmt.Errorf("file too large")
	ErrPathTraversal         = fmt.Errorf("path traversal")
	ErrNotImplemented        = fmt.Errorf("operation not implemented")
)

// Manager is the interface for managing local file spool.
type Manager interface {
	Store(userID string, filename string, data []byte) (FileRef, error)
	Retrieve(userID string, fileID string) ([]byte, error)
	Delete(userID string, fileID string) error
	List(userID string) ([]FileRef, error)
	Cleanup(maxAge int) error
	GetFileRef(userID string, fileID string) (FileRef, error)
	GetUsage() (used uint64, capacity uint64, err error)
}

// FileRef represents a reference to a spooled file.
type FileRef struct {
	UserID    string
	FileID    string
	Filename  string
	Size      int64
	Path      string
	CreatedAt string
}

// NewManager creates a new file spool manager.
func NewManager(spoolDir string, maxSize uint64) (Manager, error) {
	if spoolDir == "" {
		return nil, ErrInvalidSpoolDirectory
	}

	if err := os.MkdirAll(spoolDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create spool directory: %w", err)
	}

	return &defaultManager{spoolDir: spoolDir, maxSize: maxSize}, nil
}

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
	if strings.HasPrefix(userID, "..") || strings.Contains(userID, "..") {
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
	fileID := fmt.Sprintf("%s-%d", hex.EncodeToString(idHash[:])[:16], len(data))
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
	}, nil
}

func (m *defaultManager) Retrieve(userID string, fileID string) ([]byte, error) {
	_ = userID
	_ = fileID
	return nil, ErrNotImplemented
}

func (m *defaultManager) Delete(userID string, fileID string) error {
	_ = userID
	_ = fileID
	return ErrNotImplemented
}

func (m *defaultManager) List(userID string) ([]FileRef, error) {
	_ = userID
	return nil, ErrNotImplemented
}

func (m *defaultManager) Cleanup(maxAge int) error {
	_ = maxAge
	return nil
}

func (m *defaultManager) GetFileRef(userID string, fileID string) (FileRef, error) {
	_ = userID
	_ = fileID
	return FileRef{}, ErrNotImplemented
}

func (m *defaultManager) GetUsage() (used uint64, capacity uint64, err error) {
	return 0, m.maxSize, nil
}
