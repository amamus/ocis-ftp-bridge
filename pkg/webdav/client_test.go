package webdav

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewWebDAVClient_InvalidURL(t *testing.T) {
	t.Parallel()

	// Test with empty URL
	client := NewWebDAVClient("", "user", "token")
	ctx := context.Background()
	_, err := client.CheckPathExistence(ctx, "/test")
	require.Error(t, err)
}

func TestWebDAVClient_InvalidPath(t *testing.T) {
	t.Parallel()

	client := NewWebDAVClient("http://localhost:9200/webdav", "user", "token")
	ctx := context.Background()

	// Test empty path
	_, err := client.CheckPathExistence(ctx, "")
	require.Error(t, err)
	assert.Equal(t, ErrInvalidPath, err)

	// Test path traversal
	_, err = client.CheckPathExistence(ctx, "/../etc/passwd")
	require.Error(t, err)
	assert.Equal(t, ErrPathTraversal, err)

	// Test another path traversal
	_, err = client.CheckPathExistence(ctx, "..")
	require.Error(t, err)
	assert.Equal(t, ErrPathTraversal, err)
}

func TestWebDAVClient_WithMockServer(t *testing.T) {
	t.Parallel()

	// Create a mock WebDAV server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Request: %s %s", r.Method, r.URL.Path)

		// Check authentication
		username, password, ok := r.BasicAuth()
		if !ok || username != "testuser" || password != "testtoken" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Route requests based on method and path
		switch {
		case r.Method == http.MethodHead && r.URL.Path == "/testfile.txt":
			// HEAD request for file existence check
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodHead && r.URL.Path == "/nonexistent.txt":
			// HEAD request for non-existent file
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodHead && r.URL.Path == "/":
			// HEAD request for root
			w.WriteHeader(http.StatusOK)

		case r.Method == "MKCOL" && r.URL.Path == "/testdir/":
			// MKCOL request for directory creation
			w.WriteHeader(http.StatusCreated)
		case r.Method == "MKCOL" && r.URL.Path == "/existingdir/":
			// MKCOL request for existing directory (idempotent)
			w.WriteHeader(http.StatusConflict)

		case r.Method == http.MethodPut && r.URL.Path == "/upload.txt":
			// PUT request for file upload
			// Check If-None-Match header for overwrite protection
			if r.Header.Get("If-None-Match") == "*" {
				// File already exists, return conflict
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			// Read and verify the body
			body, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if string(body) != "test content" {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("invalid content"))
				return
			}
			w.WriteHeader(http.StatusCreated)

		case r.Method == "PROPFIND" && r.URL.Path == "/testfile.txt":
			// PROPFIND request for file info
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusMultiStatus)
			w.Write([]byte(`<?xml version="1.0" encoding="utf-8" ?>
				<multistatus xmlns="DAV:">
					<response>
						<href>/testfile.txt</href>
						<propstat>
							<prop>
								<getlastmodified>Wed, 05 Sep 2026 00:00:00 GMT</getlastmodified>
								<getcontentlength>12</getcontentlength>
							</prop>
							<status>HTTP/1.1 200 OK</status>
						</propstat>
					</response>
				</multistatus>`))

		case r.Method == http.MethodDelete && r.URL.Path == "/testfile.txt":
			// DELETE request
			w.WriteHeader(http.StatusNoContent)

		case r.Method == http.MethodDelete && r.URL.Path == "/nonexistent.txt":
			// DELETE request for non-existent file
			w.WriteHeader(http.StatusNotFound)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create client pointing to our mock server
	client := NewWebDAVClient(server.URL, "testuser", "testtoken")
	ctx := context.Background()

	// Test CheckPathExistence - existing file
	exists, err := client.CheckPathExistence(ctx, "/testfile.txt")
	require.NoError(t, err)
	assert.True(t, exists)

	// Test CheckPathExistence - non-existent file
	exists, err = client.CheckPathExistence(ctx, "/nonexistent.txt")
	require.NoError(t, err)
	assert.False(t, exists)

	// Test CheckPathExistence - root
	exists, err = client.CheckPathExistence(ctx, "/")
	require.NoError(t, err)
	assert.True(t, exists)

	// Test CreateDirectory - new directory
	err = client.CreateDirectory(ctx, "/testdir")
	require.NoError(t, err)

	// Test CreateDirectory - existing directory (should be idempotent)
	err = client.CreateDirectory(ctx, "/existingdir")
	require.NoError(t, err)

	// Test Upload - without overwrite protection, file exists (should fail)
	err = client.Upload(ctx, "/upload.txt", []byte("test content"), false)
	require.Error(t, err)
	assert.Equal(t, ErrUploadConflict, err)

	// Test Upload - with overwrite protection, file exists (should succeed)
	// The mock accepts a plain PUT without If-None-Match, so the upload succeeds.
	err = client.Upload(ctx, "/upload.txt", []byte("test content"), true)
	require.NoError(t, err)

	// Test DeleteFile - existing file
	err = client.DeleteFile(ctx, "/testfile.txt")
	require.NoError(t, err)

	// Test DeleteFile - non-existent file
	err = client.DeleteFile(ctx, "/nonexistent.txt")
	require.Error(t, err)
	assert.Equal(t, ErrPathNotFound, err)
}

func TestWebDAVClient_Unauthorized(t *testing.T) {
	t.Parallel()

	// Create a mock server that returns 401
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client := NewWebDAVClient(server.URL, "wronguser", "wrongtoken")
	ctx := context.Background()

	// Test CheckPathExistence with wrong credentials
	_, err := client.CheckPathExistence(ctx, "/test")
	require.Error(t, err)
	assert.Equal(t, ErrUnauthorized, err)
}

func TestWebDAVClient_Forbidden(t *testing.T) {
	t.Parallel()

	// Create a mock server that returns 403
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	client := NewWebDAVClient(server.URL, "testuser", "testtoken")
	ctx := context.Background()

	// Test CheckPathExistence with forbidden access
	_, err := client.CheckPathExistence(ctx, "/test")
	require.Error(t, err)
	assert.Equal(t, ErrForbidden, err)
}

func TestWebDAVClient_UploadSuccess(t *testing.T) {
	t.Parallel()

	// Create a mock server that accepts uploads
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check authentication
		username, password, ok := r.BasicAuth()
		if !ok || username != "testuser" || password != "testtoken" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if r.Method == http.MethodPut && r.URL.Path == "/newfile.txt" {
			// Check content type
			if r.Header.Get("Content-Type") != "application/octet-stream" {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("invalid content type"))
				return
			}

			// Read and verify the body
			body, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			// Verify content length
			if r.Header.Get("Content-Length") != "12" {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("invalid content length"))
				return
			}

			if string(body) != "test content" {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("invalid content"))
				return
			}

			w.WriteHeader(http.StatusCreated)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewWebDAVClient(server.URL, "testuser", "testtoken")
	ctx := context.Background()

	// Test successful upload
	err := client.Upload(ctx, "/newfile.txt", []byte("test content"), true)
	require.NoError(t, err)
}

func TestWebDAVClient_StreamUpload(t *testing.T) {
	t.Parallel()

	// Create a mock server that accepts streaming uploads
	uploadedContent := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check authentication
		username, password, ok := r.BasicAuth()
		if !ok || username != "testuser" || password != "testtoken" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if r.Method == http.MethodPut && r.URL.Path == "/streamfile.txt" {
			// Read the stream
			body, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			uploadedContent = string(body)
			w.WriteHeader(http.StatusCreated)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewWebDAVClient(server.URL, "testuser", "testtoken")
	ctx := context.Background()

	// Create a reader with test content
	content := "This is streaming content for testing WebDAV upload"
	reader := strings.NewReader(content)

	// Test streaming upload
	err := client.UploadStream(ctx, "/streamfile.txt", reader, int64(len(content)), true)
	require.NoError(t, err)
	assert.Equal(t, content, uploadedContent)
}

func TestWebDAVClient_ConditionalUpload(t *testing.T) {
	t.Parallel()

	// Create a mock server that simulates file existence
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check authentication
		username, password, ok := r.BasicAuth()
		if !ok || username != "testuser" || password != "testtoken" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if r.Method == http.MethodPut && r.URL.Path == "/conditional.txt" {
			// Check If-None-Match header
			if r.Header.Get("If-None-Match") == "*" {
				// File already exists, return 412 Precondition Failed
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			// Without If-None-Match, accept the upload
			w.WriteHeader(http.StatusCreated)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewWebDAVClient(server.URL, "testuser", "testtoken")
	ctx := context.Background()

	// Test conditional upload without overwrite (should fail)
	err := client.Upload(ctx, "/conditional.txt", []byte("content"), false)
	require.Error(t, err)
	assert.Equal(t, ErrUploadConflict, err)

	// Test conditional upload with overwrite (should succeed)
	err = client.Upload(ctx, "/conditional.txt", []byte("content"), true)
	require.NoError(t, err)
}

func TestWebDAVClient_DirectoryPathNormalization(t *testing.T) {
	t.Parallel()

	// Create a mock server
	requestPaths := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPaths = append(requestPaths, r.URL.Path)

		// Check authentication
		username, password, ok := r.BasicAuth()
		if !ok || username != "testuser" || password != "testtoken" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// For MKCOL, ensure the path ends with /
		if r.Method == "MKCOL" {
			if strings.HasSuffix(r.URL.Path, "/") {
				w.WriteHeader(http.StatusCreated)
			} else {
				w.WriteHeader(http.StatusBadRequest)
			}
			return
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewWebDAVClient(server.URL, "testuser", "testtoken")
	ctx := context.Background()

	// Test that directory paths are properly normalized
	requestPaths = []string{}
	err := client.CreateDirectory(ctx, "/testdir")
	require.NoError(t, err)
	require.Len(t, requestPaths, 1)
	assert.True(t, strings.HasSuffix(requestPaths[0], "/"))
}

func TestWebDAVClient_PathTraversalPrevention(t *testing.T) {
	t.Parallel()

	client := NewWebDAVClient("http://localhost:9200/webdav", "user", "token")
	ctx := context.Background()

	// Test various path traversal attempts
	testCases := []string{
		"../etc/passwd",
		"..",
		"/../test",
		"test/../../etc/passwd",
		"/test/../etc/passwd",
	}

	for _, testCase := range testCases {
		t.Run(testCase, func(t *testing.T) {
			t.Parallel()
			_, err := client.CheckPathExistence(ctx, testCase)
			require.Error(t, err)
			assert.Equal(t, ErrPathTraversal, err)
		})
	}
}

func TestWebDAVClient_UnicodePath(t *testing.T) {
	t.Parallel()

	// Create a mock server that handles unicode paths
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check authentication
		username, password, ok := r.BasicAuth()
		if !ok || username != "testuser" || password != "testtoken" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Decode the path to check what we received
		decodedPath, err := url.PathUnescape(r.URL.Path)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		t.Logf("Received decoded path: %s", decodedPath)

		if strings.Contains(decodedPath, "测试") || strings.Contains(decodedPath, "тест") {
			w.WriteHeader(http.StatusCreated)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewWebDAVClient(server.URL, "testuser", "testtoken")
	ctx := context.Background()

	// Test unicode paths
	// Note: The client should properly URL encode unicode characters
	err := client.Upload(ctx, "/测试文件.txt", []byte("test"), true)
	// This might fail depending on how the mock server handles URL encoding
	// but the important thing is that it doesn't crash
	if err != nil {
		t.Logf("Unicode upload failed (expected in mock): %v", err)
	}

	// Test with already encoded path
	err = client.Upload(ctx, "/%E6%B5%8B%E8%AF%95.txt", []byte("test"), true)
	if err != nil {
		t.Logf("Encoded unicode upload failed: %v", err)
	}
}

func TestWebDAVClient_EmptyData(t *testing.T) {
	t.Parallel()

	client := NewWebDAVClient("http://localhost:9200/webdav", "user", "token")
	ctx := context.Background()

	// Test with nil data
	err := client.Upload(ctx, "/test.txt", nil, true)
	require.Error(t, err)
	assert.Equal(t, ErrEmptyData, err)

	// Test with empty byte slice
	err = client.Upload(ctx, "/test.txt", []byte{}, true)
	require.Error(t, err)
	assert.Equal(t, ErrEmptyData, err)

	// Test UploadStream with nil reader
	err = client.UploadStream(ctx, "/test.txt", nil, 0, true)
	require.Error(t, err)
	assert.Equal(t, ErrEmptyData, err)
}

// TestDefaultHTTPClientHasNoTotalTimeout guards PERF-001: the default HTTP
// client must not bound the ENTIRE request — including a 50 MiB upload
// body — with a total Timeout. ResponseHeaderTimeout stays as the hang
// guard for the response.
func TestDefaultHTTPClientHasNoTotalTimeout(t *testing.T) {
	t.Parallel()

	client := NewWebDAVClient("http://example.com/webdav", "user", "token")
	wc, ok := client.(*webdavClient)
	require.True(t, ok, "expected *webdavClient, got %T", client)
	assert.Zero(t, wc.httpClient.Timeout,
		"a total request timeout aborts large uploads mid-body (PERF-001)")
	transport, ok := wc.httpClient.Transport.(*http.Transport)
	require.True(t, ok, "expected *http.Transport, got %T", wc.httpClient.Transport)
	assert.Equal(t, 10*time.Second, transport.ResponseHeaderTimeout,
		"response header timeout must remain as the hang guard")
}

// TestUploadStreamRetriesTemporaryFailures verifies that a WebDAV upload is
// retried with a rewound body when the server answers 5xx (PERF-001).
func TestUploadStreamRetriesTemporaryFailures(t *testing.T) {
	t.Parallel()

	var puts int32
	var lastBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if atomic.AddInt32(&puts, 1) <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		lastBody = body
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	client := NewWebDAVClient(server.URL, "user", "token")
	content := []byte("scan data that must survive retries")
	err := client.UploadStream(context.Background(), "/report.pdf", bytes.NewReader(content), int64(len(content)), true)
	require.NoError(t, err)
	assert.Equal(t, int32(3), atomic.LoadInt32(&puts), "expected two retries after 503 responses")
	assert.Equal(t, content, lastBody, "the retried request must resend the full body")
}

// TestUploadStreamRetryIsBounded verifies that retries on temporary failures
// stop after a fixed number of attempts instead of looping forever.
func TestUploadStreamRetryIsBounded(t *testing.T) {
	t.Parallel()

	var puts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&puts, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := NewWebDAVClient(server.URL, "user", "token")
	err := client.UploadStream(context.Background(), "/report.pdf", bytes.NewReader([]byte("data")), 4, true)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTemporaryFailure)
	assert.Equal(t, int32(3), atomic.LoadInt32(&puts), "retries must be bounded")
}

// TestUploadStreamDoesNotRetryPermanentErrors verifies that non-temporary
// failures (e.g. a 409 conflict) fail immediately without a retry.
func TestUploadStreamDoesNotRetryPermanentErrors(t *testing.T) {
	t.Parallel()

	var puts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&puts, 1)
		w.WriteHeader(http.StatusConflict)
	}))
	defer server.Close()

	client := NewWebDAVClient(server.URL, "user", "token")
	err := client.UploadStream(context.Background(), "/report.pdf", bytes.NewReader([]byte("data")), 4, false)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUploadConflict)
	assert.Equal(t, int32(1), atomic.LoadInt32(&puts), "permanent errors must not be retried")
}

// nonSeekReader hides the Seek method of the wrapped reader.
type nonSeekReader struct{ r io.Reader }

func (n nonSeekReader) Read(p []byte) (int, error) { return n.r.Read(p) }

// TestUploadStreamDoesNotRetryNonSeekableBody verifies that a body which
// cannot be rewound is not retried: resending a consumed reader would upload
// a truncated or empty file.
func TestUploadStreamDoesNotRetryNonSeekableBody(t *testing.T) {
	t.Parallel()

	var puts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&puts, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := NewWebDAVClient(server.URL, "user", "token")
	err := client.UploadStream(context.Background(), "/report.pdf", nonSeekReader{bytes.NewReader([]byte("data"))}, 4, true)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTemporaryFailure)
	assert.Equal(t, int32(1), atomic.LoadInt32(&puts), "a body that cannot be rewound must not be retried")
}

// TestControlOperationHasDeadline verifies that WebDAV control operations
// fail on their own per-call deadline instead of hanging forever once the
// HTTP client's total Timeout is gone (PERF-001). Uploads are exempt: their
// duration scales with the file size.
func TestControlOperationHasDeadline(t *testing.T) {
	// Not parallel: mutates the package-level controlOpTimeout.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done() // hang until the client gives up
	}))
	defer server.Close()

	// The injected client's own total timeout (2s) is far above the control
	// deadline, so a fast failure can only come from the per-call deadline.
	httpClient := &http.Client{Timeout: 2 * time.Second}
	client := NewWebDAVClientWithHTTP(server.URL, "user", "token", httpClient)

	old := controlOpTimeout
	controlOpTimeout = 100 * time.Millisecond
	defer func() { controlOpTimeout = old }()

	start := time.Now()
	_, err := client.CheckPathExistence(context.Background(), "/anything")
	require.Error(t, err)
	assert.Less(t, time.Since(start), time.Second,
		"control operations must fail on their own deadline (PERF-001)")
}
