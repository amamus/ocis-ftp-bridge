package spool

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewManager(t *testing.T) {
	t.Parallel()

	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "spool-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Test with valid parameters
	manager, err := NewManager(tempDir, 1024*1024)
	require.NoError(t, err)
	require.NotNil(t, manager)

	// Test GetUploadManager
	uploadManager := manager.GetUploadManager()
	require.NotNil(t, uploadManager)

	// Test GetUsage
	used, capacity, err := manager.GetUsage()
	require.NoError(t, err)
	assert.Equal(t, uint64(0), used)
	assert.Equal(t, uint64(1024*1024), capacity)
}

func TestNewManager_InvalidDirectory(t *testing.T) {
	t.Parallel()

	// Test with empty directory
	_, err := NewManager("", 1024)
	require.Error(t, err)
	assert.Equal(t, ErrInvalidSpoolDirectory, err)

	// Test with non-existent directory (should be created)
	tempDir, err := os.MkdirTemp("", "spool-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	nonExistentDir := filepath.Join(tempDir, "nonexistent")
	manager, err := NewManager(nonExistentDir, 1024)
	require.NoError(t, err)
	require.NotNil(t, manager)
}

func TestNewManager_ReadOnlyDirectory(t *testing.T) {
	t.Parallel()

	// Create a read-only directory
	tempDir, err := os.MkdirTemp("", "spool-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Make it read-only
	readOnlyDir := filepath.Join(tempDir, "readonly")
	err = os.Mkdir(readOnlyDir, 0555)
	require.NoError(t, err)

	// Try to create manager in read-only directory
	_, err = NewManager(readOnlyDir, 1024)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not writable")
}

func TestStoreAndRetrieve(t *testing.T) {
	t.Parallel()

	tempDir, err := os.MkdirTemp("", "spool-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	manager, err := NewManager(tempDir, 1024*1024)
	require.NoError(t, err)

	// Test storing data
	testData := []byte("test data for spool")
	fileRef, err := manager.Store("testuser", "testfile.txt", testData)
	require.NoError(t, err)
	assert.Equal(t, "testuser", fileRef.UserID)
	assert.Equal(t, "testfile.txt", fileRef.Filename)
	assert.Equal(t, int64(len(testData)), fileRef.Size)
	assert.NotEmpty(t, fileRef.FileID)
	assert.NotEmpty(t, fileRef.Path)
	assert.Equal(t, FileStatusCommitted, fileRef.Status)

	// Test retrieving data
	retrievedData, err := manager.Retrieve("testuser", fileRef.FileID)
	require.NoError(t, err)
	assert.Equal(t, testData, retrievedData)

	// Test retrieving with wrong user ID
	_, err = manager.Retrieve("wronguser", fileRef.FileID)
	require.Error(t, err)
	assert.Equal(t, ErrFileNotFound, err)

	// Test retrieving with wrong file ID
	_, err = manager.Retrieve("testuser", "nonexistent")
	require.Error(t, err)
	assert.Equal(t, ErrFileNotFound, err)
}

func TestStore_InvalidParameters(t *testing.T) {
	t.Parallel()

	tempDir, err := os.MkdirTemp("", "spool-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	manager, err := NewManager(tempDir, 1024*1024)
	require.NoError(t, err)

	// Test with empty user ID
	_, err = manager.Store("", "testfile.txt", []byte("data"))
	require.Error(t, err)
	assert.Equal(t, ErrInvalidParameters, err)

	// Test with empty filename
	_, err = manager.Store("testuser", "", []byte("data"))
	require.Error(t, err)
	assert.Equal(t, ErrInvalidParameters, err)

	// Test with empty data
	_, err = manager.Store("testuser", "testfile.txt", []byte{})
	require.Error(t, err)
	assert.Equal(t, ErrEmptyData, err)

	// Test with nil data
	_, err = manager.Store("testuser", "testfile.txt", nil)
	require.Error(t, err)
	assert.Equal(t, ErrEmptyData, err)

	// Test with file too large
	largeData := make([]byte, 2*1024*1024) // 2MB
	_, err = manager.Store("testuser", "largefile.txt", largeData)
	require.Error(t, err)
	assert.Equal(t, ErrFileTooLarge, err)
}

func TestStore_PathTraversal(t *testing.T) {
	t.Parallel()

	tempDir, err := os.MkdirTemp("", "spool-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	manager, err := NewManager(tempDir, 1024*1024)
	require.NoError(t, err)

	// Test path traversal in user ID
	_, err = manager.Store("../testuser", "testfile.txt", []byte("data"))
	require.Error(t, err)
	assert.Equal(t, ErrPathTraversal, err)

	// Test path traversal in user ID
	_, err = manager.Store("testuser/..", "testfile.txt", []byte("data"))
	require.Error(t, err)
	assert.Equal(t, ErrPathTraversal, err)
}

func TestStoreStream(t *testing.T) {
	t.Parallel()

	tempDir, err := os.MkdirTemp("", "spool-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	manager, err := NewManager(tempDir, 1024*1024)
	require.NoError(t, err)

	// Test streaming upload
	testData := []byte("test data for streaming upload")
	reader := bytes.NewReader(testData)

	fileRef, err := manager.StoreStream("testuser", "streamfile.txt", "/target/path", reader, int64(len(testData)))
	require.NoError(t, err)
	assert.Equal(t, "testuser", fileRef.UserID)
	assert.Equal(t, "streamfile.txt", fileRef.Filename)
	assert.Equal(t, "/target/path", fileRef.TargetPath)
	assert.Equal(t, int64(len(testData)), fileRef.Size)
	assert.Equal(t, FileStatusCommitted, fileRef.Status)

	// Verify the file was written correctly
	retrievedData, err := manager.Retrieve("testuser", fileRef.FileID)
	require.NoError(t, err)
	assert.Equal(t, testData, retrievedData)
}

func TestStoreStream_InvalidParameters(t *testing.T) {
	t.Parallel()

	tempDir, err := os.MkdirTemp("", "spool-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	manager, err := NewManager(tempDir, 1024*1024)
	require.NoError(t, err)

	// Test with empty user ID
	_, err = manager.StoreStream("", "testfile.txt", "/target", bytes.NewReader([]byte("data")), 4)
	require.Error(t, err)
	assert.Equal(t, ErrInvalidParameters, err)

	// Test with empty filename
	_, err = manager.StoreStream("testuser", "", "/target", bytes.NewReader([]byte("data")), 4)
	require.Error(t, err)
	assert.Equal(t, ErrInvalidParameters, err)

	// Test with empty target path
	_, err = manager.StoreStream("testuser", "testfile.txt", "", bytes.NewReader([]byte("data")), 4)
	require.Error(t, err)
	assert.Equal(t, ErrInvalidParameters, err)

	// Test with nil reader
	_, err = manager.StoreStream("testuser", "testfile.txt", "/target", nil, 4)
	require.Error(t, err)
	assert.Equal(t, ErrInvalidParameters, err)

	// Test with zero size
	_, err = manager.StoreStream("testuser", "testfile.txt", "/target", bytes.NewReader([]byte("data")), 0)
	require.Error(t, err)
	assert.Equal(t, ErrEmptyData, err)
}

func TestDelete(t *testing.T) {
	t.Parallel()

	tempDir, err := os.MkdirTemp("", "spool-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	manager, err := NewManager(tempDir, 1024*1024)
	require.NoError(t, err)

	// Store a file
	_, err = manager.Store("testuser", "testfile.txt", []byte("data"))
	require.NoError(t, err)

	// List files to get the file ID
	files, err := manager.List("testuser")
	require.NoError(t, err)
	require.Len(t, files, 1)

	// Delete the file
	err = manager.Delete("testuser", files[0].FileID)
	require.NoError(t, err)

	// Verify the file is gone
	files, err = manager.List("testuser")
	require.NoError(t, err)
	assert.Len(t, files, 0)

	// Test deleting non-existent file
	err = manager.Delete("testuser", "nonexistent")
	require.Error(t, err)
	assert.Equal(t, ErrFileNotFound, err)
}

func TestDeleteByPath(t *testing.T) {
	t.Parallel()

	tempDir, err := os.MkdirTemp("", "spool-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	manager, err := NewManager(tempDir, 1024*1024)
	require.NoError(t, err)

	// Store a file
	fileRef, err := manager.Store("testuser", "testfile.txt", []byte("data"))
	require.NoError(t, err)

	// Delete by path
	err = manager.DeleteByPath(fileRef.Path)
	require.NoError(t, err)

	// Test deleting with path outside spool directory
	err = manager.DeleteByPath("/etc/passwd")
	require.Error(t, err)
	assert.Equal(t, ErrPathTraversal, err)
}

func TestList(t *testing.T) {
	t.Parallel()

	tempDir, err := os.MkdirTemp("", "spool-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	manager, err := NewManager(tempDir, 1024*1024)
	require.NoError(t, err)

	// Store multiple files
	_, err = manager.Store("testuser", "file1.txt", []byte("data1"))
	require.NoError(t, err)
	_, err = manager.Store("testuser", "file2.txt", []byte("data2"))
	require.NoError(t, err)
	_, err = manager.Store("testuser", "file3.txt", []byte("data3"))
	require.NoError(t, err)

	// List files for user
	files, err := manager.List("testuser")
	require.NoError(t, err)
	assert.Len(t, files, 3)

	// List files for different user (should be empty)
	files, err = manager.List("otheruser")
	require.NoError(t, err)
	assert.Len(t, files, 0)

	// List files for non-existent user
	files, err = manager.List("nonexistent")
	require.NoError(t, err)
	assert.Len(t, files, 0)

	// Test invalid user ID
	_, err = manager.List("")
	require.Error(t, err)
	assert.Equal(t, ErrInvalidParameters, err)
}

func TestListAll(t *testing.T) {
	t.Parallel()

	tempDir, err := os.MkdirTemp("", "spool-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	manager, err := NewManager(tempDir, 1024*1024)
	require.NoError(t, err)

	// Store files for multiple users
	_, err = manager.Store("user1", "file1.txt", []byte("data1"))
	require.NoError(t, err)
	_, err = manager.Store("user2", "file2.txt", []byte("data2"))
	require.NoError(t, err)

	// List all files
	allFiles, err := manager.ListAll()
	require.NoError(t, err)
	assert.Len(t, allFiles, 2)

	// Verify user IDs are correct
	foundUser1 := false
	foundUser2 := false
	for _, file := range allFiles {
		if file.UserID == "user1" {
			foundUser1 = true
		}
		if file.UserID == "user2" {
			foundUser2 = true
		}
	}
	assert.True(t, foundUser1)
	assert.True(t, foundUser2)
}

func TestCleanup(t *testing.T) {
	t.Parallel()

	tempDir, err := os.MkdirTemp("", "spool-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	manager, err := NewManager(tempDir, 1024*1024)
	require.NoError(t, err)

	// Store a file
	_, err = manager.Store("testuser", "testfile.txt", []byte("data"))
	require.NoError(t, err)

	// Modify the file's modification time to make it old
	files, err := manager.List("testuser")
	require.NoError(t, err)
	require.Len(t, files, 1)

	// Set the file's modification time to 1 hour ago
	oldTime := time.Now().Add(-2 * time.Hour)
	err = os.Chtimes(files[0].Path, oldTime, oldTime)
	require.NoError(t, err)

	// Run cleanup with 1 hour max age
	err = manager.Cleanup(60)
	require.NoError(t, err)

	// Verify the file was cleaned up
	files, err = manager.List("testuser")
	require.NoError(t, err)
	assert.Len(t, files, 0)

	// Test with invalid max age (should use default)
	err = manager.Cleanup(0)
	require.NoError(t, err)
}

func TestGetFileRef(t *testing.T) {
	t.Parallel()

	tempDir, err := os.MkdirTemp("", "spool-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	manager, err := NewManager(tempDir, 1024*1024)
	require.NoError(t, err)

	// Store a file
	fileRef, err := manager.Store("testuser", "testfile.txt", []byte("data"))
	require.NoError(t, err)

	// Get the file reference
	retrievedRef, err := manager.GetFileRef("testuser", fileRef.FileID)
	require.NoError(t, err)
	assert.Equal(t, fileRef.UserID, retrievedRef.UserID)
	assert.Equal(t, fileRef.FileID, retrievedRef.FileID)

	// Test with non-existent file
	_, err = manager.GetFileRef("testuser", "nonexistent")
	require.Error(t, err)
	assert.Equal(t, ErrFileNotFound, err)
}

func TestGetUsage(t *testing.T) {
	t.Parallel()

	tempDir, err := os.MkdirTemp("", "spool-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	manager, err := NewManager(tempDir, 1024*1024)
	require.NoError(t, err)

	// Initially should be 0 usage
	used, capacity, err := manager.GetUsage()
	require.NoError(t, err)
	assert.Equal(t, uint64(0), used)
	assert.Equal(t, uint64(1024*1024), capacity)

	// Store some files
	_, err = manager.Store("testuser", "file1.txt", []byte("data1"))
	require.NoError(t, err)
	_, err = manager.Store("testuser", "file2.txt", []byte("data2data2"))
	require.NoError(t, err)

	// Check usage
	used, _, err = manager.GetUsage()
	require.NoError(t, err)
	assert.Equal(t, uint64(15), used) // 5 + 10 bytes (data1 + data2data2)
}

func TestUploadManager(t *testing.T) {
	t.Parallel()

	tempDir, err := os.MkdirTemp("", "spool-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	manager, err := NewManager(tempDir, 1024*1024)
	require.NoError(t, err)

	uploadManager := manager.GetUploadManager()

	// Test starting an upload
	ctx := context.Background()
	upload, err := uploadManager.StartUpload(ctx, "testuser", "testfile.txt", "/target", 100, 1024*1024)
	require.NoError(t, err)
	assert.NotNil(t, upload)
	assert.NotEmpty(t, upload.ID)
	assert.Equal(t, "testuser", upload.UserID)
	assert.Equal(t, "testfile.txt", upload.Filename)
	assert.Equal(t, "/target", upload.TargetPath)
	assert.Equal(t, int64(100), upload.Size)
	assert.Equal(t, int64(0), upload.BytesReceived)

	// Test writing chunks
	n, err := uploadManager.WriteChunk(upload, []byte("chunk1"))
	require.NoError(t, err)
	assert.Equal(t, 6, n)

	n, err = uploadManager.WriteChunk(upload, []byte("chunk2"))
	require.NoError(t, err)
	assert.Equal(t, 6, n)

	// Test GetUpload
	retrievedUpload := uploadManager.GetUpload(upload.ID)
	require.NotNil(t, retrievedUpload)
	assert.Equal(t, upload.ID, retrievedUpload.ID)

	// Test AbortUpload
	err = uploadManager.AbortUpload(upload)
	require.NoError(t, err)

	// Verify upload was removed
	retrievedUpload = uploadManager.GetUpload(upload.ID)
	assert.Nil(t, retrievedUpload)
}

func TestUploadManager_SizeLimits(t *testing.T) {
	t.Parallel()

	tempDir, err := os.MkdirTemp("", "spool-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	manager, err := NewManager(tempDir, 1024*1024)
	require.NoError(t, err)

	uploadManager := manager.GetUploadManager()
	ctx := context.Background()

	// Test file too large for account
	_, err = uploadManager.StartUpload(ctx, "testuser", "largefile.txt", "/target", 2000, 1000)
	require.Error(t, err)
	assert.Equal(t, ErrFileTooLarge, err)

	// Test file too large for total spool capacity
	_, err = uploadManager.StartUpload(ctx, "testuser", "file.txt", "/target", 2*1024*1024, 2*1024*1024)
	require.Error(t, err)
	assert.Equal(t, ErrFileTooLarge, err)

	// Test chunk exceeding remaining size
	upload, err := uploadManager.StartUpload(ctx, "testuser", "file.txt", "/target", 100, 1024*1024)
	require.NoError(t, err)

	// Write up to the limit
	_, err = uploadManager.WriteChunk(upload, make([]byte, 50))
	require.NoError(t, err)

	// Try to write more than remaining
	_, err = uploadManager.WriteChunk(upload, make([]byte, 100))
	require.Error(t, err)
	assert.Equal(t, ErrFileTooLarge, err)

	// Abort the upload
	uploadManager.AbortUpload(upload)
}

func TestUploadManager_Cancellation(t *testing.T) {
	t.Parallel()

	tempDir, err := os.MkdirTemp("", "spool-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	manager, err := NewManager(tempDir, 1024*1024)
	require.NoError(t, err)

	uploadManager := manager.GetUploadManager()

	// Create a context that can be cancelled
	ctx, cancel := context.WithCancel(context.Background())

	// Start an upload
	upload, err := uploadManager.StartUpload(ctx, "testuser", "file.txt", "/target", 100, 1024*1024)
	require.NoError(t, err)

	// Write some data
	_, err = uploadManager.WriteChunk(upload, []byte("test"))
	require.NoError(t, err)

	// Cancel the context
	cancel()

	// Try to write more data (should fail)
	_, err = uploadManager.WriteChunk(upload, []byte("test2"))
	require.Error(t, err)
	assert.Equal(t, ErrUploadCancelled, err)

	// Abort the upload
	uploadManager.AbortUpload(upload)
}

func TestFinishUpload(t *testing.T) {
	t.Parallel()

	tempDir, err := os.MkdirTemp("", "spool-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	manager, err := NewManager(tempDir, 1024*1024)
	require.NoError(t, err)

	uploadManager := manager.GetUploadManager()
	ctx := context.Background()

	// Start an upload
	upload, err := uploadManager.StartUpload(ctx, "testuser", "testfile.txt", "/target", 10, 1024*1024)
	require.NoError(t, err)

	// Write all the data
	_, err = uploadManager.WriteChunk(upload, []byte("1234567890"))
	require.NoError(t, err)

	// Finish the upload
	fileRef, err := uploadManager.FinishUpload(upload)
	require.NoError(t, err)
	assert.Equal(t, "testuser", fileRef.UserID)
	assert.Equal(t, "testfile.txt", fileRef.Filename)
	assert.Equal(t, int64(10), fileRef.Size)
	assert.Equal(t, FileStatusCommitted, fileRef.Status)

	// Verify the file exists and has correct content
	data, err := os.ReadFile(fileRef.Path)
	require.NoError(t, err)
	assert.Equal(t, []byte("1234567890"), data)

	// Verify upload was removed from active uploads
	retrievedUpload := uploadManager.GetUpload(upload.ID)
	assert.Nil(t, retrievedUpload)

	// Clean up the file
	manager.DeleteByPath(fileRef.Path)
}

func TestFinishUpload_Incomplete(t *testing.T) {
	t.Parallel()

	tempDir, err := os.MkdirTemp("", "spool-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	manager, err := NewManager(tempDir, 1024*1024)
	require.NoError(t, err)

	uploadManager := manager.GetUploadManager()
	ctx := context.Background()

	// Start an upload
	upload, err := uploadManager.StartUpload(ctx, "testuser", "file.txt", "/target", 100, 1024*1024)
	require.NoError(t, err)

	// Write only part of the data
	_, err = uploadManager.WriteChunk(upload, []byte("test"))
	require.NoError(t, err)

	// Try to finish (should fail)
	_, err = uploadManager.FinishUpload(upload)
	require.Error(t, err)
	assert.Equal(t, ErrUploadIncomplete, err)

	// Abort the upload
	uploadManager.AbortUpload(upload)
}

func TestStoreStream_LargeFile(t *testing.T) {
	t.Parallel()

	tempDir, err := os.MkdirTemp("", "spool-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	manager, err := NewManager(tempDir, 10*1024*1024) // 10MB
	require.NoError(t, err)

	// Create a large file (1MB)
	largeData := make([]byte, 1024*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	reader := bytes.NewReader(largeData)
	fileRef, err := manager.StoreStream("testuser", "largefile.bin", "/target", reader, int64(len(largeData)))
	require.NoError(t, err)
	assert.Equal(t, int64(len(largeData)), fileRef.Size)

	// Verify the file was written correctly
	retrievedData, err := manager.Retrieve("testuser", fileRef.FileID)
	require.NoError(t, err)
	assert.Equal(t, largeData, retrievedData)
}

func TestConcurrentUploads(t *testing.T) {
	t.Parallel()

	tempDir, err := os.MkdirTemp("", "spool-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	manager, err := NewManager(tempDir, 100*1024*1024) // 100MB
	require.NoError(t, err)

	uploadManager := manager.GetUploadManager()
	ctx := context.Background()

	// Start multiple concurrent uploads
	uploadCount := 10
	uploads := make([]*Upload, uploadCount)

	for i := 0; i < uploadCount; i++ {
		upload, err := uploadManager.StartUpload(ctx, "testuser", 
			fmt.Sprintf("file%d.txt", i), "/target", 1000, 10*1024*1024)
		require.NoError(t, err)
		uploads[i] = upload
	}

	// Write to all uploads - write the full expected size
	for i := 0; i < uploadCount; i++ {
		// Write enough data to meet the expected size
		data := make([]byte, 1000)
		for j := range data {
			data[j] = byte(j % 256)
		}
		_, err := uploadManager.WriteChunk(uploads[i], data)
		require.NoError(t, err)
	}

	// Finish all uploads
	for i := 0; i < uploadCount; i++ {
		_, err := uploadManager.FinishUpload(uploads[i])
		require.NoError(t, err)
	}

	// Verify all files exist
	files, err := manager.List("testuser")
	require.NoError(t, err)
	assert.Len(t, files, uploadCount)
}

func TestPathTraversalInSpool(t *testing.T) {
	t.Parallel()

	tempDir, err := os.MkdirTemp("", "spool-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	manager, err := NewManager(tempDir, 1024*1024)
	require.NoError(t, err)

	// Test path traversal in various operations
	testCases := []struct {
		userID    string
		shouldErr bool
	}{
		{"../etc/passwd", true},
		{"testuser/../etc/passwd", true},
		{"..", true},
		{"./testuser", false}, // This is actually valid - path.Clean removes the ./
		{"testuser", false},    // This is valid
	}

	for _, tc := range testCases {
		t.Run(tc.userID, func(t *testing.T) {
			t.Parallel()
			_, err := manager.Store(tc.userID, "testfile.txt", []byte("data"))
			if tc.shouldErr {
				require.Error(t, err)
				assert.Equal(t, ErrPathTraversal, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSpoolDirectoryStructure(t *testing.T) {
	t.Parallel()

	tempDir, err := os.MkdirTemp("", "spool-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	manager, err := NewManager(tempDir, 1024*1024)
	require.NoError(t, err)

	// Store files for multiple users
	_, err = manager.Store("user1", "file1.txt", []byte("data1"))
	require.NoError(t, err)
	_, err = manager.Store("user2", "file2.txt", []byte("data2"))
	require.NoError(t, err)

	// Verify the directory structure
	// Should have: tempDir/user1/file1-*.txt and tempDir/user2/file2-*.txt
	user1Dir := filepath.Join(tempDir, "user1")
	user2Dir := filepath.Join(tempDir, "user2")

	_, err = os.Stat(user1Dir)
	require.NoError(t, err)

	_, err = os.Stat(user2Dir)
	require.NoError(t, err)

	// Verify files exist
	user1Files, err := os.ReadDir(user1Dir)
	require.NoError(t, err)
	assert.Len(t, user1Files, 1)

	user2Files, err := os.ReadDir(user2Dir)
	require.NoError(t, err)
	assert.Len(t, user2Files, 1)
}

func TestFilePermissions(t *testing.T) {
	t.Parallel()

	tempDir, err := os.MkdirTemp("", "spool-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	manager, err := NewManager(tempDir, 1024*1024)
	require.NoError(t, err)

	// Store a file
	fileRef, err := manager.Store("testuser", "testfile.txt", []byte("data"))
	require.NoError(t, err)

	// Check file permissions (should be 0640)
	info, err := os.Stat(fileRef.Path)
	require.NoError(t, err)

	// On Unix systems, check the permissions
	if !strings.HasPrefix(fileRef.Path, "C:") { // Skip on Windows
		mode := info.Mode().Perm()
		// The file should have read/write for owner and read for group
		assert.True(t, mode&0600 == 0600, "File should have owner read/write")
	}
}

func TestGetPendingFiles(t *testing.T) {
	t.Parallel()

	tempDir, err := os.MkdirTemp("", "spool-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	manager, err := NewManager(tempDir, 1024*1024)
	require.NoError(t, err)

	// Store some files
	_, err = manager.Store("testuser", "file1.txt", []byte("data1"))
	require.NoError(t, err)
	_, err = manager.Store("testuser", "file2.txt", []byte("data2"))
	require.NoError(t, err)

	// Get pending files
	pending, err := manager.GetPendingFiles()
	require.NoError(t, err)
	assert.Len(t, pending, 2)

	// All files should have committed status
	for _, file := range pending {
		assert.Equal(t, FileStatusCommitted, file.Status)
	}
}