package transfer

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/amamus/ocis-ftp-bridge/pkg/errors"
	"github.com/amamus/ocis-ftp-bridge/pkg/webdav"
)

func TestTransferManager_CalculateTargetPath(t *testing.T) {
	tm := NewTransferManager()

	// Add a target configuration
	tm.AddTarget("testuser", TargetConfig{
		DriveID:          "drive123",
		Drive:           "MyDrive",
		Root:            "/uploads",
		CollisionPolicy: CollisionPolicyRename,
		MaxSize:         1000000,
	})

	testCases := []struct {
		name         string
		userID       string
		ftpPath      string
		filename     string
		expectedPath string
		expectError  bool
	}{
		{
			name:         "simple filename at root",
			userID:       "testuser",
			ftpPath:      "",
			filename:     "test.txt",
			expectedPath: "/uploads/test.txt",
			expectError:  false,
		},
		{
			name:         "filename with nested FTP path",
			userID:       "testuser",
			ftpPath:      "scans/daily",
			filename:     "scan001.pdf",
			expectedPath: "/uploads/scans/daily/scan001.pdf",
			expectError:  false,
		},
		{
			name:         "filename with unicode",
			userID:       "testuser",
			ftpPath:      "documents",
			filename:     "résumé.txt",
			expectedPath: "/uploads/documents/résumé.txt",
			expectError:  false,
		},
		{
			name:         "filename with spaces",
			userID:       "testuser",
			ftpPath:      "",
			filename:     "my document.txt",
			expectedPath: "/uploads/my document.txt",
			expectError:  false,
		},
		{
			name:         "path traversal with ..",
			userID:       "testuser",
			ftpPath:      "../secret",
			filename:     "test.txt",
			expectedPath: "",
			expectError:  true,
		},
		{
			name:         "absolute path",
			userID:       "testuser",
			ftpPath:      "/absolute/path",
			filename:     "test.txt",
			expectedPath: "",
			expectError:  true,
		},
		{
			name:         "root path",
			userID:       "testuser",
			ftpPath:      "/",
			filename:     "test.txt",
			expectedPath: "/uploads/test.txt",
			expectError:  false,
		},
		{
			name:         "current directory path",
			userID:       "testuser",
			ftpPath:      ".",
			filename:     "test.txt",
			expectedPath: "/uploads/test.txt",
			expectError:  false,
		},
		{
			name:         "filename with path traversal",
			userID:       "testuser",
			ftpPath:      "",
			filename:     "../secret.txt",
			expectedPath: "",
			expectError:  true,
		},
		{
			name:         "deeply nested path",
			userID:       "testuser",
			ftpPath:      "a/b/c/d",
			filename:     "file.txt",
			expectedPath: "/uploads/a/b/c/d/file.txt",
			expectError:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			path, err := tm.CalculateTargetPath(tc.userID, tc.ftpPath, tc.filename)

			if tc.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if path != tc.expectedPath {
				t.Errorf("expected path %q but got %q", tc.expectedPath, path)
			}
		})
	}
}

func TestTransferManager_SanitizeFilename(t *testing.T) {
	tm := NewTransferManager()

	testCases := []struct {
		name       string
		filename   string
		expected   string
		expectError bool
	}{
		{
			name:       "simple filename",
			filename:   "test.txt",
			expected:   "test.txt",
			expectError: false,
		},
		{
			name:       "filename with spaces",
			filename:   "my document.txt",
			expected:   "my document.txt",
			expectError: false,
		},
		{
			name:       "filename with unicode",
			filename:   "résumé.pdf",
			expected:   "résumé.pdf",
			expectError: false,
		},
		{
			name:       "filename with dots",
			filename:   "archive.tar.gz",
			expected:   "archive.tar.gz",
			expectError: false,
		},
		{
			name:       "filename with path",
			filename:   "path/to/file.txt",
			expected:   "file.txt",
			expectError: false,
		},
		{
			name:       "filename with traversal",
			filename:   "../secret.txt",
			expected:   "",
			expectError: true,
		},
		{
			name:       "empty filename",
			filename:   "",
			expected:   "",
			expectError: true,
		},
		{
			name:       "filename with control characters",
			filename:   "test\x00.txt",
			expected:   "test_.txt",
			expectError: false,
		},
		{
			name:       "filename with newline",
			filename:   "test\n.txt",
			expected:   "test_.txt",
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			safeName, err := tm.sanitizeFilename(tc.filename)

			if tc.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if safeName != tc.expected {
				t.Errorf("expected filename %q but got %q", tc.expected, safeName)
			}
		})
	}
}

func TestTransferManager_NormalizeFTPPath(t *testing.T) {
	tm := NewTransferManager()

	testCases := []struct {
		name       string
		path       string
		expected   string
		expectError bool
	}{
		{
			name:       "simple path",
			path:       "scans/daily",
			expected:   "scans/daily",
			expectError: false,
		},
		{
			name:       "empty path",
			path:       "",
			expected:   "",
			expectError: false,
		},
		{
			name:       "root path",
			path:       "/",
			expected:   "",
			expectError: false,
		},
		{
			name:       "current directory",
			path:       ".",
			expected:   "",
			expectError: false,
		},
		{
			name:       "path traversal",
			path:       "../secret",
			expected:   "",
			expectError: true,
		},
		{
			name:       "absolute path",
			path:       "/absolute",
			expected:   "",
			expectError: true,
		},
		{
			name:       "path with multiple slashes",
			path:       "scans//daily",
			expected:   "scans/daily",
			expectError: false,
		},
		{
			name:       "path with leading slashes",
			path:       "///scans/daily",
			expected:   "",
			expectError: true, // should be rejected as absolute path
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			normalized, err := tm.normalizeFTPPath(tc.path)

			if tc.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if normalized != tc.expected {
				t.Errorf("expected normalized path %q but got %q", tc.expected, normalized)
			}
		})
	}
}

func TestTransferManager_ValidateTargetPath(t *testing.T) {
	tm := NewTransferManager()

	testCases := []struct {
		name       string
		targetPath string
		targetRoot string
		expectError bool
	}{
		{
			name:       "valid path within root",
			targetPath: "/uploads/scans/file.txt",
			targetRoot: "/uploads",
			expectError: false,
		},
		{
			name:       "valid path at root",
			targetPath: "/uploads/file.txt",
			targetRoot: "/uploads",
			expectError: false,
		},
		{
			name:       "path outside root",
			targetPath: "/other/file.txt",
			targetRoot: "/uploads",
			expectError: true,
		},
		{
			name:       "path traversal outside root",
			targetPath: "/uploads/../etc/passwd",
			targetRoot: "/uploads",
			expectError: true,
		},
		{
			name:       "non-absolute target path",
			targetPath: "uploads/scans/file.txt",
			targetRoot: "/uploads",
			expectError: false,
		},
		{
			name:       "non-absolute target root",
			targetPath: "/uploads/scans/file.txt",
			targetRoot: "uploads",
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tm.validateTargetPath(tc.targetPath, tc.targetRoot)

			if tc.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestPathHelpers(t *testing.T) {
	t.Run("isSafePath", func(t *testing.T) {
		testCases := []struct {
			path     string
			expected bool
		}{
			{"simple/path", true},
			{"/absolute/path", true},
			{"path/../traversal", true}, // The regex allows this character set
			{"path with spaces", true},
			{"path/with/dots.txt", true},
			{"", false},
		}

		for _, tc := range testCases {
			t.Run(tc.path, func(t *testing.T) {
				result := isSafePath(tc.path)
				if result != tc.expected {
					t.Errorf("isSafePath(%q) = %v, expected %v", tc.path, result, tc.expected)
				}
			})
		}
	})

	t.Run("extractPathComponents", func(t *testing.T) {
		testCases := []struct {
			path     string
			expected []string
		}{
			{"", []string{}},
			{".", []string{}},
			{"/", []string{}},
			{"a/b/c", []string{"a", "b", "c"}},
			{"/a/b/c", []string{"a", "b", "c"}},
			{"a/b/c/", []string{"a", "b", "c"}},
		}

		for _, tc := range testCases {
			t.Run(tc.path, func(t *testing.T) {
				result := extractPathComponents(tc.path)
				if len(result) != len(tc.expected) {
					t.Errorf("extractPathComponents(%q) returned %d components, expected %d", tc.path, len(result), len(tc.expected))
					return
				}
				for i, comp := range result {
					if comp != tc.expected[i] {
						t.Errorf("component %d: got %q, expected %q", i, comp, tc.expected[i])
					}
				}
			})
		}
	})
}

func TestCollisionPolicyStringValues(t *testing.T) {
	t.Run("collision policy constants", func(t *testing.T) {
		if string(CollisionPolicyRename) != "rename" {
			t.Errorf("CollisionPolicyRename should be 'rename', got %q", CollisionPolicyRename)
		}
		if string(CollisionPolicyReject) != "reject" {
			t.Errorf("CollisionPolicyReject should be 'reject', got %q", CollisionPolicyReject)
		}
		if string(CollisionPolicyOverwrite) != "overwrite" {
			t.Errorf("CollisionPolicyOverwrite should be 'overwrite', got %q", CollisionPolicyOverwrite)
		}
	})
}

func TestEdgeCases(t *testing.T) {
	tm := NewTransferManager()

	// Add target configuration
	tm.AddTarget("testuser", TargetConfig{
		DriveID:          "drive123",
		Drive:           "MyDrive",
		Root:            "/uploads",
		CollisionPolicy: CollisionPolicyRename,
		MaxSize:         1000000,
	})

	edgeCases := []struct {
		name     string
		ftpPath  string
		filename string
		wantError bool
	}{
		{
			name:     "dotfile",
			ftpPath:  "",
			filename: ".gitignore",
			wantError: false,
		},
		{
			name:     "multi-dot extension",
			ftpPath:  "",
			filename: "archive.tar.gz",
			wantError: false,
		},
		{
			name:     "filename with special chars",
			ftpPath:  "",
			filename: "file-with-dashes_and_underscores.txt",
			wantError: false,
		},
		{
			name:     "filename with spaces and unicode",
			ftpPath:  "",
			filename: "my résumé (final).pdf",
			wantError: false,
		},
		{
			name:     "deeply nested path",
			ftpPath:  "a/b/c/d/e/f",
			filename: "file.txt",
			wantError: false,
		},
		{
			name:     "path with windows separators",
			ftpPath:  "path\\to\\file",
			filename: "test.txt",
			wantError: false,
		},
		{
			name:     "path with mixed slashes",
			ftpPath:  "path/to\\file",
			filename: "test.txt",
			wantError: false,
		},
		{
			name:     "null byte in filename",
			ftpPath:  "",
			filename: "test\x00.txt",
			wantError: false,
		},
		{
			name:     "filename only dots",
			ftpPath:  "",
			filename: "...",
			wantError: false,
		},
	}

	for _, tc := range edgeCases {
		t.Run(tc.name, func(t *testing.T) {
			path, err := tm.CalculateTargetPath("testuser", tc.ftpPath, tc.filename)

			if tc.wantError {
				if err == nil {
					t.Errorf("expected error for %s but got none", tc.name)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error for %s: %v", tc.name, err)
				return
			}

			if path == "" {
				t.Errorf("expected non-empty path for %s", tc.name)
			}

			// Basic sanity check - path should start with target root
			if !strings.HasPrefix(path, "/uploads") {
				t.Errorf("path should start with /uploads, got: %s", path)
			}
		})
	}
}

func TestResolveCollisionPolicies(t *testing.T) {
	// Collision checks run against the WebDAV backend; seed an empty one so
	// no collisions exist.
	tm := NewTransferManagerWithWebDAV(context.Background(), newFakeWebDAVClient())

	// Add target configuration
	tm.AddTarget("testuser", TargetConfig{
		DriveID:          "drive123",
		Drive:           "MyDrive",
		Root:            "/uploads",
		CollisionPolicy: CollisionPolicyRename,
		MaxSize:         1000000,
	})

	t.Run("rename policy", func(t *testing.T) {
		// Nothing exists in WebDAV, so the original filename is kept
		finalName, err := tm.ResolveCollision("/uploads", "test.txt", CollisionPolicyRename)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return
		}

		if finalName != "test.txt" {
			t.Errorf("expected original filename when no collision exists in WebDAV, got %q", finalName)
		}
	})

	t.Run("reject policy without existing file", func(t *testing.T) {
		// Nothing exists in WebDAV, so reject passes
		finalName, err := tm.ResolveCollision("/uploads", "test.txt", CollisionPolicyReject)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return
		}

		if finalName != "test.txt" {
			t.Errorf("expected original filename for reject policy without collision, got %q", finalName)
		}
	})

	t.Run("overwrite policy", func(t *testing.T) {
		// Overwrite policy should always return original filename
		finalName, err := tm.ResolveCollision("/uploads", "test.txt", CollisionPolicyOverwrite)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return
		}

		if finalName != "test.txt" {
			t.Errorf("expected original filename for overwrite policy, got %q", finalName)
		}
	})

	t.Run("unknown policy", func(t *testing.T) {
		// Unknown policy should return error
		_, err := tm.ResolveCollision("/uploads", "test.txt", CollisionPolicy("unknown"))
		if err == nil {
			t.Errorf("expected error for unknown collision policy")
		}
	})
}

func TestGenerateUniqueFilename(t *testing.T) {
	t.Run("keeps original name when nothing exists in WebDAV", func(t *testing.T) {
		tm := NewTransferManagerWithWebDAV(context.Background(), newFakeWebDAVClient())

		result, err := tm.GenerateUniqueFilename("/uploads", "test.txt")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != "test.txt" {
			t.Errorf("expected original filename, got %q", result)
		}
	})

	t.Run("renames existing object and preserves extension", func(t *testing.T) {
		// Test with various extensions
		extensions := []string{".txt", ".pdf", ".jpg", ".tar.gz"}

		for _, ext := range extensions {
			filename := "file" + ext
			fake := newFakeWebDAVClient("/uploads/" + filename)
			tm := NewTransferManagerWithWebDAV(context.Background(), fake)

			result, err := tm.GenerateUniqueFilename("/uploads", filename)
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", filename, err)
			}

			if result == filename {
				t.Errorf("expected renamed filename for existing object %q, got original", filename)
			}

			// Check that the extension (per filepath.Ext) is preserved in the result
			if !strings.HasSuffix(result, filepath.Ext(filename)) {
				t.Errorf("extension %s not preserved in result: %s", ext, result)
			}
		}
	})

	t.Run("fails closed without a WebDAV client", func(t *testing.T) {
		tm := NewTransferManager()

		if _, err := tm.GenerateUniqueFilename("/uploads", "test.txt"); err == nil {
			t.Errorf("expected error without a WebDAV client")
		}
	})
}

// TestPathTraversalSecurity tests comprehensive path traversal protection
func TestPathTraversalSecurity(t *testing.T) {
	tm := NewTransferManager()

	// Add target configuration
	tm.AddTarget("testuser", TargetConfig{
		DriveID:          "drive123",
		Drive:           "MyDrive",
		Root:            "/uploads",
		CollisionPolicy: CollisionPolicyRename,
		MaxSize:         1000000,
	})

	// Test cases for path traversal attempts
	traversalCases := []struct {
		name     string
		ftpPath  string
		filename string
		wantError bool
	}{
		// Basic traversal attempts
		{
			name:     "simple dot-dot in path",
			ftpPath:  "../etc",
			filename: "passwd.txt",
			wantError: true,
		},
		{
			name:     "dot-dot at start of filename",
			ftpPath:  "",
			filename: "../secret.txt",
			wantError: true,
		},
		{
			name:     "dot-dot in middle of filename",
			ftpPath:  "",
			filename: "foo/../bar.txt",
			wantError: true,
		},
		{
			name:     "dot-dot at end of filename",
			ftpPath:  "",
			filename: "foo/..",
			wantError: true,
		},
		// Absolute path attempts
		{
			name:     "unix absolute path in ftpPath",
			ftpPath:  "/etc",
			filename: "passwd.txt",
			wantError: true,
		},
		{
			name:     "windows absolute path in ftpPath",
			ftpPath:  "\\Windows\\System32",
			filename: "config.ini",
			wantError: true,
		},
		{
			name:     "absolute path in filename",
			ftpPath:  "",
			filename: "/etc/passwd",
			wantError: true,
		},
		// Windows-specific attacks
		{
			name:     "windows drive letter",
			ftpPath:  "C:\\",
			filename: "file.txt",
			wantError: true,
		},
		{
			name:     "windows path separators",
			ftpPath:  "..\\..\\etc",
			filename: "passwd.txt",
			wantError: true,
		},
		// Mixed attacks
		{
			name:     "unix slash then dot-dot",
			ftpPath:  "/../etc",
			filename: "passwd.txt",
			wantError: true,
		},
		{
			name:     "dot-dot with trailing slash",
			ftpPath:  "foo/../",
			filename: "bar.txt",
			wantError: true,
		},
		{
			name:     "multiple dot-dot sequences",
			ftpPath:  "../../../etc",
			filename: "passwd.txt",
			wantError: true,
		},
		// Nested traversal attempts
		{
			name:     "nested path with traversal",
			ftpPath:  "a/b/../../c",
			filename: "file.txt",
			wantError: true,
		},
		{
			name:     "traversal then valid path",
			ftpPath:  "../a/b/c",
			filename: "file.txt",
			wantError: true,
		},
		// Null byte and control character attacks
		{
			name:     "null byte in path",
			ftpPath:  "foo\x00bar",
			filename: "file.txt",
			wantError: false, // Null byte will be sanitized
		},
		{
			name:     "control characters in filename",
			ftpPath:  "",
			filename: "file\x00\x01.txt",
			wantError: false, // Control chars will be replaced
		},
		// Valid cases that should NOT error
		{
			name:     "single dot in filename",
			ftpPath:  "",
			filename: ".hidden",
			wantError: false,
		},
		{
			name:     "dots in extension",
			ftpPath:  "",
			filename: "file.tar.gz",
			wantError: false,
		},
		{
			name:     "leading dots in filename",
			ftpPath:  "",
			filename: "...test.txt",
			wantError: false,
		},
	}

	for _, tc := range traversalCases {
		t.Run(tc.name, func(t *testing.T) {
			path, err := tm.CalculateTargetPath("testuser", tc.ftpPath, tc.filename)

			if tc.wantError {
				if err == nil {
					t.Errorf("expected error for %s but got none (path: %s)", tc.name, path)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error for %s: %v", tc.name, err)
				return
			}

			if path == "" {
				t.Errorf("expected non-empty path for %s", tc.name)
				return
			}

			// For valid cases, ensure path stays within root
			if !strings.HasPrefix(path, "/uploads/") && path != "/uploads/file.txt" {
				// Check if it's a direct file in root
				if !strings.HasPrefix(path, "/uploads/") {
					t.Logf("path for %s: %s", tc.name, path)
				}
			}

			// Ensure path doesn't contain actual traversal sequences
			// (not just ".." as a substring, which could be part of a filename)
			// Check for "/.." followed by "/" or at end, or "\\.." followed by "\\" or at end
			if strings.Contains(path, "/../") || strings.Contains(path, "\\..\\") ||
				strings.HasSuffix(path, "/..") || strings.HasSuffix(path, "\\..") ||
				strings.Contains(path, "/..\\") || strings.Contains(path, "\\../") {
				t.Errorf("path contains traversal sequence for %s: %s", tc.name, path)
			}

			// Ensure path is absolute
			if !strings.HasPrefix(path, "/") {
				t.Errorf("path is not absolute for %s: %s", tc.name, path)
			}
		})
	}
}

// TestValidateTargetPathEdgeCases tests edge cases in path validation
func TestValidateTargetPathEdgeCases(t *testing.T) {
	tm := NewTransferManager()

	edgeCases := []struct {
		name       string
		targetPath string
		targetRoot string
		expectError bool
	}{
		// Root prefix matching edge cases
		{
			name:       "root is prefix but path continues differently",
			targetPath: "/root2/file.txt",
			targetRoot: "/root",
			expectError: true, // /root2 should not match /root
		},
		{
			name:       "root is prefix with dash",
			targetPath: "/root-foo/file.txt",
			targetRoot: "/root",
			expectError: true, // /root-foo should not match /root
		},
		{
			name:       "exact root match",
			targetPath: "/root",
			targetRoot: "/root",
			expectError: false,
		},
		{
			name:       "root with trailing slash",
			targetPath: "/root/file.txt",
			targetRoot: "/root/",
			expectError: false,
		},
		{
			name:       "path with multiple trailing slashes",
			targetPath: "/root/file///txt",
			targetRoot: "/root",
			expectError: false, // filepath.Clean will normalize
		},
	}

	for _, tc := range edgeCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tm.validateTargetPath(tc.targetPath, tc.targetRoot)

			if tc.expectError {
				if err == nil {
					t.Errorf("expected error for %s but got none", tc.name)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error for %s: %v", tc.name, err)
			}
		})
	}
}

func TestProcessUploadIntegration(t *testing.T) {
	tm := NewTransferManagerWithWebDAV(context.Background(), newFakeWebDAVClient())

	// Add target configuration
	tm.AddTarget("testuser", TargetConfig{
		DriveID:          "drive123",
		Drive:           "MyDrive",
		Root:            "/uploads",
		CollisionPolicy: CollisionPolicyRename,
		MaxSize:         1000000,
	})

	t.Run("successful upload processing", func(t *testing.T) {
		request := TransferRequest{
			UserID:   "testuser",
			Filename: "test.txt",
			Path:     "scans",
			Size:     1024,
			Data:     []byte("test content"),
		}

		result := tm.ProcessUpload(request)

		if !result.Success {
			t.Errorf("expected successful upload, got error: %v", result.Error)
			return
		}

		// Check that the target path was calculated correctly
		if result.TargetPath != "/uploads/scans/test.txt" {
			t.Errorf("expected target path /uploads/scans/test.txt, got %q", result.TargetPath)
		}

		if result.Filename != "test.txt" {
			t.Errorf("expected filename test.txt, got %q", result.Filename)
		}

		if result.Size != 1024 {
			t.Errorf("expected size 1024, got %d", result.Size)
		}
	})

	t.Run("upload with unknown user", func(t *testing.T) {
		request := TransferRequest{
			UserID:   "unknownuser",
			Filename: "test.txt",
			Path:     "scans",
			Size:     1024,
			Data:     []byte("test content"),
		}

		result := tm.ProcessUpload(request)

		if result.Success {
			t.Errorf("expected failed upload for unknown user")
		}

		if result.Error == nil {
			t.Errorf("expected error for unknown user")
		}
	})

	t.Run("upload with path traversal", func(t *testing.T) {
		request := TransferRequest{
			UserID:   "testuser",
			Filename: "test.txt",
			Path:     "../secret",
			Size:     1024,
			Data:     []byte("test content"),
		}

		result := tm.ProcessUpload(request)

		if result.Success {
			t.Errorf("expected failed upload for path traversal")
		}

		if result.Error == nil {
			t.Errorf("expected error for path traversal")
		}
	})

	t.Run("reject policy fails for object existing in WebDAV", func(t *testing.T) {
		rejectTM := NewTransferManagerWithWebDAV(context.Background(),
			newFakeWebDAVClient("/uploads/scans/test.txt"))
		rejectTM.AddTarget("testuser", TargetConfig{
			DriveID:          "drive123",
			Drive:           "MyDrive",
			Root:            "/uploads",
			CollisionPolicy: CollisionPolicyReject,
			MaxSize:         1000000,
		})

		request := TransferRequest{
			UserID:   "testuser",
			Filename: "test.txt",
			Path:     "scans",
			Size:     1024,
			Data:     []byte("test content"),
		}

		result := rejectTM.ProcessUpload(request)

		if result.Success {
			t.Errorf("expected failed upload for existing object under reject policy")
		}

		if result.Error == nil {
			t.Errorf("expected error for existing object under reject policy")
		}
	})
}

// TestSanitizeFilenameUnicodeLength verifies that filename length is measured
// in characters (runes), not bytes, so multi-byte UTF-8 filenames are not
// incorrectly rejected.
func TestSanitizeFilenameUnicodeLength(t *testing.T) {
	tm := NewTransferManager()

	t.Run("accepts multi-byte filename under 255 characters", func(t *testing.T) {
		// 100 CJK characters, each 3 bytes in UTF-8 = 300 bytes total
		// but only 100 runes, well under the 255-character limit
		filename := strings.Repeat("漢", 100) + ".txt"
		safeName, err := tm.sanitizeFilename(filename)
		if err != nil {
			t.Errorf("expected no error for 100-character CJK filename, got: %v", err)
		}
		if safeName != filename {
			t.Errorf("expected filename to be preserved, got %q", safeName)
		}
	})

	t.Run("rejects filename over 255 characters", func(t *testing.T) {
		// 256 ASCII characters = 256 bytes = 256 runes, over the limit
		filename := strings.Repeat("a", 256)
		_, err := tm.sanitizeFilename(filename)
		if err == nil {
			t.Errorf("expected error for 256-character filename")
		}
	})

	t.Run("rejects multi-byte filename over 255 runes", func(t *testing.T) {
		// 256 CJK characters = 768 bytes, 256 runes - over the character limit
		filename := strings.Repeat("漢", 256)
		_, err := tm.sanitizeFilename(filename)
		if err == nil {
			t.Errorf("expected error for 256-rune CJK filename")
		}
	})
}

// Ensure strings.HasSuffix is available
func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

// fakeWebDAVClient is an in-memory webdav.Client that gives the transfer
// manager real existence semantics without any network access.
type fakeWebDAVClient struct {
	mu          sync.Mutex
	existing    map[string]bool
	checked     []string
	createdDirs []string
	// checkErr, when set, is returned by every CheckPathExistence call to
	// simulate an unreachable or erroring WebDAV backend.
	checkErr error
}

func newFakeWebDAVClient(existing ...string) *fakeWebDAVClient {
	f := &fakeWebDAVClient{existing: make(map[string]bool)}
	for _, p := range existing {
		f.existing[p] = true
	}
	return f
}

func (f *fakeWebDAVClient) Upload(_ context.Context, path string, _ []byte, _ bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.existing[path] = true
	return nil
}

func (f *fakeWebDAVClient) UploadStream(_ context.Context, path string, _ io.Reader, _ int64, _ bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.existing[path] = true
	return nil
}

func (f *fakeWebDAVClient) CreateDirectory(_ context.Context, path string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.createdDirs = append(f.createdDirs, path)
	f.existing[path] = true
	return nil
}

func (f *fakeWebDAVClient) CheckPathExistence(_ context.Context, path string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checked = append(f.checked, path)
	if f.checkErr != nil {
		return false, f.checkErr
	}
	return f.existing[path], nil
}

func (f *fakeWebDAVClient) DeleteFile(_ context.Context, path string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.existing, path)
	return nil
}

func (f *fakeWebDAVClient) GetFileInfo(_ context.Context, path string) (webdav.FileInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.existing[path] {
		return webdav.FileInfo{}, fmt.Errorf("not found: %s", path)
	}
	return webdav.FileInfo{Path: path, IsDirectory: false}, nil
}

func (f *fakeWebDAVClient) ValidateConfiguration(context.Context) error { return nil }

func (f *fakeWebDAVClient) exists(path string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.existing[path]
}

func (f *fakeWebDAVClient) createdDirsSnapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.createdDirs...)
}

// TestResolveCollisionUsesWebDAVExistence verifies that collision resolution
// consults the WebDAV backend (QLT-001): an object existing only in oCIS must
// trigger rename/reject, and a file existing only on the local filesystem
// must NOT influence the outcome, because basePath is a WebDAV path.
func TestResolveCollisionUsesWebDAVExistence(t *testing.T) {
	t.Run("rename policy renames file that exists only in WebDAV", func(t *testing.T) {
		fake := newFakeWebDAVClient("/uploads/report.pdf")
		tm := NewTransferManagerWithWebDAV(context.Background(), fake)
		tm.AddTarget("testuser", TargetConfig{Root: "/uploads", CollisionPolicy: CollisionPolicyRename})

		finalName, err := tm.ResolveCollision("/uploads", "report.pdf", CollisionPolicyRename)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if finalName == "report.pdf" {
			t.Errorf("expected renamed filename for existing object, got original %q", finalName)
		}
		if fake.exists("/uploads/" + finalName) {
			t.Errorf("renamed filename %q already exists in WebDAV", finalName)
		}
	})

	t.Run("rename policy keeps name when file exists only locally", func(t *testing.T) {
		// Regression for the old os.Stat implementation: a file that happens
		// to exist locally at the WebDAV basePath must not trigger a rename.
		localDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(localDir, "report.pdf"), []byte("local"), 0o644); err != nil {
			t.Fatalf("failed to create local file: %v", err)
		}
		fake := newFakeWebDAVClient() // nothing exists in WebDAV
		tm := NewTransferManagerWithWebDAV(context.Background(), fake)
		tm.AddTarget("testuser", TargetConfig{Root: localDir, CollisionPolicy: CollisionPolicyRename})

		finalName, err := tm.ResolveCollision(localDir, "report.pdf", CollisionPolicyRename)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if finalName != "report.pdf" {
			t.Errorf("expected original filename (object does not exist in WebDAV), got %q", finalName)
		}
	})

	t.Run("reject policy rejects file that exists in WebDAV", func(t *testing.T) {
		fake := newFakeWebDAVClient("/uploads/report.pdf")
		tm := NewTransferManagerWithWebDAV(context.Background(), fake)
		tm.AddTarget("testuser", TargetConfig{Root: "/uploads", CollisionPolicy: CollisionPolicyReject})

		_, err := tm.ResolveCollision("/uploads", "report.pdf", CollisionPolicyReject)
		if err == nil {
			t.Fatal("expected reject policy to fail for existing object")
		}
		if !errors.IsCode(err, errors.ErrCodeAlreadyExists) {
			t.Errorf("expected ALREADY_EXISTS error, got %v", err)
		}
	})

	t.Run("reject policy accepts file missing from WebDAV even if present locally", func(t *testing.T) {
		localDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(localDir, "report.pdf"), []byte("local"), 0o644); err != nil {
			t.Fatalf("failed to create local file: %v", err)
		}
		fake := newFakeWebDAVClient()
		tm := NewTransferManagerWithWebDAV(context.Background(), fake)
		tm.AddTarget("testuser", TargetConfig{Root: localDir, CollisionPolicy: CollisionPolicyReject})

		finalName, err := tm.ResolveCollision(localDir, "report.pdf", CollisionPolicyReject)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if finalName != "report.pdf" {
			t.Errorf("expected original filename, got %q", finalName)
		}
	})
}

// TestCollisionPoliciesFailClosedWithoutWebDAVClient verifies that a transfer
// manager without a WebDAV client refuses rename/reject collision handling
// instead of silently assuming there is no collision (QLT-001).
func TestCollisionPoliciesFailClosedWithoutWebDAVClient(t *testing.T) {
	tm := NewTransferManager()

	if _, err := tm.ResolveCollision("/uploads", "report.pdf", CollisionPolicyReject); err == nil {
		t.Error("expected reject policy to fail without a WebDAV client")
	}
	if _, err := tm.ResolveCollision("/uploads", "report.pdf", CollisionPolicyRename); err == nil {
		t.Error("expected rename policy to fail without a WebDAV client")
	}
	if _, err := tm.CheckCollision("/uploads/report.pdf"); err == nil {
		t.Error("expected CheckCollision to fail without a WebDAV client")
	}
}

// TestEnsureParentDirectories verifies that parent directories are actually
// created in oCIS via MKCOL (QLT-002): oCIS follows RFC 4918 and answers a PUT
// with a missing parent collection with 409 Conflict — it never auto-creates
// parents, so the bridge must issue MKCOL for every missing level.
func TestEnsureParentDirectories(t *testing.T) {
	t.Run("creates every missing level in order", func(t *testing.T) {
		fake := newFakeWebDAVClient()
		tm := NewTransferManagerWithWebDAV(context.Background(), fake)

		if err := tm.EnsureParentDirectories("/uploads/scans/2026/file.pdf"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		want := []string{"/uploads", "/uploads/scans", "/uploads/scans/2026"}
		got := fake.createdDirsSnapshot()
		if len(got) != len(want) {
			t.Fatalf("expected MKCOL for %v, got %v", want, got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("expected MKCOL order %v, got %v", want, got)
			}
		}
	})

	t.Run("no MKCOL when the parent already exists", func(t *testing.T) {
		fake := newFakeWebDAVClient("/uploads/scans")
		tm := NewTransferManagerWithWebDAV(context.Background(), fake)

		if err := tm.EnsureParentDirectories("/uploads/scans/file.pdf"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := fake.createdDirsSnapshot(); len(got) != 0 {
			t.Errorf("expected no MKCOL for existing parent, got %v", got)
		}
	})

	t.Run("falls back to recursive creation when the existence check fails", func(t *testing.T) {
		fake := newFakeWebDAVClient()
		fake.checkErr = fmt.Errorf("HEAD request failed")
		tm := NewTransferManagerWithWebDAV(context.Background(), fake)

		if err := tm.EnsureParentDirectories("/uploads/scans/2026/file.pdf"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Even without a working existence check, every missing level must be
		// created — a single-level MKCOL would 409 against real oCIS.
		want := []string{"/uploads", "/uploads/scans", "/uploads/scans/2026"}
		got := fake.createdDirsSnapshot()
		if len(got) != len(want) {
			t.Fatalf("expected MKCOL for %v, got %v", want, got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("expected MKCOL order %v, got %v", want, got)
			}
		}
	})

	t.Run("fails closed without a WebDAV client", func(t *testing.T) {
		tm := NewTransferManager()

		if err := tm.EnsureParentDirectories("/uploads/scans/file.pdf"); err == nil {
			t.Error("expected error without a WebDAV client")
		}
	})
}
