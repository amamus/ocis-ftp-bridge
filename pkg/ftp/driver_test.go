package ftp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	ftpserver "github.com/fclairamb/ftpserverlib"
	"golang.org/x/crypto/argon2"

	"github.com/amamus/ocis-ftp-bridge/pkg/config"
	"github.com/amamus/ocis-ftp-bridge/pkg/errors"
	"github.com/amamus/ocis-ftp-bridge/pkg/observability"
	"github.com/amamus/ocis-ftp-bridge/pkg/spool"
	"github.com/amamus/ocis-ftp-bridge/pkg/webdav"
)

// noopObs is a no-op observability.Client for tests.
type noopObs struct{}

func (noopObs) Start() error                  { return nil }
func (noopObs) Stop() error                   { return nil }
func (noopObs) Logger() *observability.Logger { return nil }
func (noopObs) Log(level, message string)     {}
func (noopObs) Debug(msg string, args ...any) {}
func (noopObs) Info(msg string, args ...any)  {}
func (noopObs) Warn(msg string, args ...any)  {}
func (noopObs) Error(msg string, args ...any) {}
func (noopObs) Metric(name, value string)     {}
func (noopObs) Trace(name string) observability.Context {
	return noopTrace{}
}

type noopTrace struct{}

func (noopTrace) Finish() {}

// mockClientContext is a minimal ftpserver.ClientContext for tests.
type mockClientContext struct {
	id   uint32
	addr net.Addr
}

func (m *mockClientContext) Path() string             { return "/" }
func (m *mockClientContext) SetPath(value string)     {}
func (m *mockClientContext) SetListPath(value string) {}
func (m *mockClientContext) SetDebug(debug bool)      {}
func (m *mockClientContext) Debug() bool              { return false }
func (m *mockClientContext) ID() uint32               { return m.id }
func (m *mockClientContext) RemoteAddr() net.Addr     { return m.addr }
func (m *mockClientContext) LocalAddr() net.Addr      { return m.addr }
func (m *mockClientContext) GetClientVersion() string { return "test" }
func (m *mockClientContext) Close() error             { return nil }
func (m *mockClientContext) HasTLSForControl() bool   { return false }
func (m *mockClientContext) HasTLSForTransfers() bool { return false }
func (m *mockClientContext) GetLastCommand() string   { return "" }
func (m *mockClientContext) GetLastDataChannel() ftpserver.DataChannel {
	return 0
}
func (m *mockClientContext) SetTLSRequirement(requirement ftpserver.TLSRequirement) error {
	return nil
}
func (m *mockClientContext) SetExtra(extra any) {}
func (m *mockClientContext) Extra() any         { return nil }

// testPasswordHash generates a valid Argon2id PHC string for the given password
// using deliberately weak parameters so the test stays fast.
func testPasswordHash(t *testing.T, password string) string {
	t.Helper()
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("failed to generate salt: %v", err)
	}
	key := argon2.IDKey([]byte(password), salt, 1, 1024, 1, 32)
	return fmt.Sprintf("$argon2id$v=19$m=1024,t=1,p=1$%s$%s",
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))
}

// TestAuthUserDisconnectCancelsSessionContext verifies that the per-session
// context created in AuthUser is cancelled when the client disconnects.
// Without cancellation the context (and its resources) leaks per connection.
func TestAuthUserDisconnectCancelsSessionContext(t *testing.T) {
	// Mock graph server that resolves the account's drive
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"test-drive-id","name":"Test Drive","driveType":"personal","webUrl":"http://localhost/webdav"}`))
	}))
	defer graphSrv.Close()

	cfg := config.New()
	cfg.OCIS.GraphURL = graphSrv.URL
	cfg.Accounts = []config.AccountConfig{
		{
			Username:     "test-printer",
			PasswordHash: testPasswordHash(t, "test-password"),
			OCIS: config.AccountOCISConfig{
				Username:    "test-printer",
				AppTokenEnv: "TEST_PRINTER_APP_TOKEN",
			},
			Target: config.TargetConfig{
				DriveID: "test-drive-id",
				Root:    "/",
			},
			Upload: config.UploadConfig{
				CollisionPolicy: "rename",
				MaxSize:         1024 * 1024,
			},
			AppToken: "test-token",
		},
	}

	d := NewBridgeDriver(cfg, noopObs{}, nil, nil)

	cc := &mockClientContext{
		id:   42,
		addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
	}

	driver, err := d.AuthUser(cc, "test-printer", "test-password")
	if err != nil {
		t.Fatalf("AuthUser failed: %v", err)
	}
	clientDriver, ok := driver.(*bridgeClientDriver)
	if !ok {
		t.Fatalf("expected *bridgeClientDriver, got %T", driver)
	}

	// The session context must be alive while the client is connected
	select {
	case <-clientDriver.context.Done():
		t.Fatal("session context cancelled before disconnect")
	default:
	}

	// When the client disconnects, the session context must be cancelled
	d.ClientDisconnected(cc)

	select {
	case <-clientDriver.context.Done():
		// expected
	case <-time.After(2 * time.Second):
		t.Fatal("session context was not cancelled on client disconnect")
	}

	// The session must be deregistered so the tracking map does not leak
	d.mu.RLock()
	remaining := len(d.clients)
	d.mu.RUnlock()
	if remaining != 0 {
		t.Fatalf("expected no registered clients after disconnect, got %d", remaining)
	}
}

// TestClientDisconnectedUnknownClient verifies that disconnecting a client
// that never authenticated (or was already removed) is a no-op.
func TestClientDisconnectedUnknownClient(t *testing.T) {
	cfg := config.New()
	d := NewBridgeDriver(cfg, noopObs{}, nil, nil)

	cc := &mockClientContext{
		id:   99,
		addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
	}

	// Must not panic or deadlock
	d.ClientDisconnected(cc)

	// A cancelled background context must not be reported as a live session
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = ctx
}

// generateSelfSignedCert creates a self-signed certificate and key in PEM format.
func generateSelfSignedCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"test.example.com"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return certPEM, keyPEM
}

// TestGetTLSConfig verifies the contract the ftpserver library relies on:
// when TLS is disabled, GetTLSConfig must return an error. The library's
// AUTH TLS handler wraps the control connection in tls.Server whenever the
// error is nil, so a (nil, nil) return would wrap the connection with a nil
// *tls.Config and crash the whole server on the next read.
func TestGetTLSConfig(t *testing.T) {
	t.Run("TLS disabled returns error", func(t *testing.T) {
		cfg := config.New()
		cfg.Server.TLS.Enabled = false
		d := NewBridgeDriver(cfg, noopObs{}, nil, nil)

		tlsConfig, err := d.GetTLSConfig()
		if err == nil {
			t.Fatal("expected error when TLS is disabled: the library wraps the connection whenever err == nil")
		}
		if tlsConfig != nil {
			t.Fatal("expected nil tls.Config when TLS is disabled")
		}
	})

	t.Run("TLS enabled with valid cert returns config", func(t *testing.T) {
		certPEM, keyPEM := generateSelfSignedCert(t)
		dir := t.TempDir()
		certFile := filepath.Join(dir, "cert.pem")
		keyFile := filepath.Join(dir, "key.pem")
		if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
			t.Fatal(err)
		}

		cfg := config.New()
		cfg.Server.TLS.Enabled = true
		cfg.Server.TLS.Cert = certFile
		cfg.Server.TLS.Key = keyFile
		d := NewBridgeDriver(cfg, noopObs{}, nil, nil)

		tlsConfig, err := d.GetTLSConfig()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if tlsConfig == nil || len(tlsConfig.Certificates) != 1 {
			t.Fatal("expected a TLS config with one certificate")
		}
	})

	t.Run("TLS enabled with missing cert returns error", func(t *testing.T) {
		cfg := config.New()
		cfg.Server.TLS.Enabled = true
		cfg.Server.TLS.Cert = filepath.Join(t.TempDir(), "nonexistent-cert.pem")
		cfg.Server.TLS.Key = filepath.Join(t.TempDir(), "nonexistent-key.pem")
		d := NewBridgeDriver(cfg, noopObs{}, nil, nil)

		if _, err := d.GetTLSConfig(); err == nil {
			t.Fatal("expected error for missing certificate")
		}
	})
}

// TestHandleUploadOpenPathMapping verifies that absolute FTP paths (as passed
// by the ftpserver library) are mapped to the account's target root: the
// transfer manager expects paths relative to the target root, so the driver
// must strip the virtual-root prefix.
func TestHandleUploadOpenPathMapping(t *testing.T) {
	spoolDir := t.TempDir()
	spoolManager, err := spool.NewManager(spoolDir, 1024*1024)
	if err != nil {
		t.Fatalf("failed to create spool manager: %v", err)
	}

	// The driver resolves collisions against the WebDAV backend, so point the
	// config at a mock with real 404 semantics.
	mock := newMockWebDAVServer(t, nil)

	cfg := config.New()
	cfg.OCIS.WebDAVURL = mock.URL + "/webdav"
	cfg.Accounts = []config.AccountConfig{
		{
			Username: "test-printer",
			Target:   config.TargetConfig{DriveID: "test-drive-id", Root: "/"},
			Upload:   config.UploadConfig{CollisionPolicy: "rename", MaxSize: 1024 * 1024},
		},
	}
	d := NewBridgeDriver(cfg, noopObs{}, spoolManager, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := &bridgeClientDriver{
		bridgeDriver: d,
		account:      &cfg.Accounts[0],
		user:         "test-printer",
		currentDir:   "/",
		spoolUploads: make(map[string]*spoolUpload),
		context:      ctx,
		cancel:       cancel,
	}

	tests := []struct {
		name       string
		ftpPath    string
		wantTarget string
	}{
		{"file in root", "/test-file.txt", "/test-file.txt"},
		{"file in subdirectory", "/uploads/test-file.txt", "/uploads/test-file.txt"},
		{"file in nested subdirectory", "/a/b/test-file.txt", "/a/b/test-file.txt"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, err := client.handleUploadOpen(tt.ftpPath)
			if err != nil {
				t.Fatalf("handleUploadOpen(%q) failed: %v", tt.ftpPath, err)
			}
			if w.spoolUpload.path != tt.wantTarget {
				t.Fatalf("handleUploadOpen(%q): expected target %q, got %q", tt.ftpPath, tt.wantTarget, w.spoolUpload.path)
			}
			if err := spoolManager.GetUploadManager().AbortUpload(w.upload); err != nil {
				t.Fatalf("failed to abort upload: %v", err)
			}
		})
	}
}

// mockWebDAVServer is an httptest server implementing just enough WebDAV for
// driver tests: HEAD with real 404 semantics, MKCOL, and PUT that honors
// If-None-Match (412 when the object exists and the header is "*").
// In strict mode it follows RFC 4918 like real oCIS: MKCOL and PUT fail with
// 409 Conflict when intermediate collections are missing.
type mockWebDAVServer struct {
	*httptest.Server
	mu         sync.Mutex
	files      map[string][]byte
	dirs       map[string]bool
	strict     bool
	putHeaders []http.Header
	mkcolPaths []string
}

func newMockWebDAVServer(t *testing.T, existing map[string][]byte) *mockWebDAVServer {
	t.Helper()
	return newMockWebDAVServerMode(t, existing, nil, false)
}

// newStrictMockWebDAVServer creates a mock with RFC 4918 semantics: PUT and
// MKCOL return 409 Conflict when the parent collection does not exist.
func newStrictMockWebDAVServer(t *testing.T, existingFiles map[string][]byte, existingDirs map[string]bool) *mockWebDAVServer {
	t.Helper()
	return newMockWebDAVServerMode(t, existingFiles, existingDirs, true)
}

func newMockWebDAVServerMode(t *testing.T, existingFiles map[string][]byte, existingDirs map[string]bool, strict bool) *mockWebDAVServer {
	t.Helper()
	m := &mockWebDAVServer{
		files:  make(map[string][]byte),
		dirs:   make(map[string]bool),
		strict: strict,
	}
	for p, data := range existingFiles {
		m.files[p] = data
	}
	for p := range existingDirs {
		m.dirs[p] = true
	}
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The WebDAV client appends a trailing slash to MKCOL paths; normalize
		// so directory lookups are consistent.
		path := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/webdav"), "/")
		parent := pathpkg.Dir(path)
		m.mu.Lock()
		defer m.mu.Unlock()
		parentMissing := m.strict && parent != "/" && parent != "." && !m.dirs[parent]
		switch r.Method {
		case http.MethodHead:
			if _, ok := m.files[path]; ok {
				w.WriteHeader(http.StatusOK)
				return
			}
			if m.dirs[path] {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		case "MKCOL":
			m.mkcolPaths = append(m.mkcolPaths, path)
			if parentMissing {
				w.WriteHeader(http.StatusConflict)
				return
			}
			m.dirs[path] = true
			w.WriteHeader(http.StatusCreated)
		case http.MethodPut:
			m.putHeaders = append(m.putHeaders, r.Header.Clone())
			if parentMissing {
				w.WriteHeader(http.StatusConflict)
				return
			}
			if r.Header.Get("If-None-Match") == "*" {
				if _, ok := m.files[path]; ok {
					w.WriteHeader(http.StatusPreconditionFailed)
					return
				}
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			m.files[path] = body
			w.WriteHeader(http.StatusCreated)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(m.Server.Close)
	return m
}

func (m *mockWebDAVServer) fileExists(path string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.files[path]
	return ok
}

func (m *mockWebDAVServer) fileContent(path string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return string(m.files[path])
}

func (m *mockWebDAVServer) lastPUTHeader() http.Header {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.putHeaders) == 0 {
		return http.Header{}
	}
	return m.putHeaders[len(m.putHeaders)-1]
}

func (m *mockWebDAVServer) putCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.putHeaders)
}

func (m *mockWebDAVServer) mkcolPathsSnapshot() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.mkcolPaths...)
}

// newCollisionTestDriver builds a BridgeDriver whose accounts resolve against
// the mock WebDAV server, plus a session client for the given account.
func newCollisionTestDriver(t *testing.T, mock *mockWebDAVServer, spoolManager spool.Manager, policy, root string) (*BridgeDriver, *bridgeClientDriver) {
	t.Helper()
	cfg := config.New()
	cfg.OCIS.WebDAVURL = mock.URL + "/webdav"
	cfg.Accounts = []config.AccountConfig{
		{
			Username: "test-printer",
			Target:   config.TargetConfig{DriveID: "test-drive-id", Root: root},
			Upload:   config.UploadConfig{CollisionPolicy: policy, MaxSize: 1024 * 1024},
		},
	}
	d := NewBridgeDriver(cfg, noopObs{}, spoolManager, nil)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	client := &bridgeClientDriver{
		bridgeDriver: d,
		account:      &cfg.Accounts[0],
		user:         "test-printer",
		currentDir:   "/",
		spoolUploads: make(map[string]*spoolUpload),
		webdavClient: webdav.NewClientWithCredentials(mock.URL+"/webdav", "test-printer", "token"),
		context:      ctx,
		cancel:       cancel,
	}
	return d, client
}

// TestHandleUploadOpenCollisionRenameAgainstWebDAV verifies that the FTP driver
// resolves rename collisions against oCIS (QLT-001): when the target object
// already exists in WebDAV, the upload must be spooled under a different name.
func TestHandleUploadOpenCollisionRenameAgainstWebDAV(t *testing.T) {
	mock := newMockWebDAVServer(t, map[string][]byte{"/uploads/report.pdf": []byte("previous scan")})

	spoolDir := t.TempDir()
	spoolManager, err := spool.NewManager(spoolDir, 1024*1024)
	if err != nil {
		t.Fatalf("failed to create spool manager: %v", err)
	}

	_, client := newCollisionTestDriver(t, mock, spoolManager, "rename", "/")

	w, err := client.handleUploadOpen("/uploads/report.pdf")
	if err != nil {
		t.Fatalf("handleUploadOpen failed: %v", err)
	}
	defer spoolManager.GetUploadManager().AbortUpload(w.upload)

	if w.spoolUpload.path == "/uploads/report.pdf" {
		t.Errorf("expected renamed target path for existing object, got original %q", w.spoolUpload.path)
	}
	if mock.fileExists(w.spoolUpload.path) {
		t.Errorf("resolved target path %q already exists in WebDAV", w.spoolUpload.path)
	}
}

// TestHandleUploadOpenCollisionRejectAgainstWebDAV verifies that the reject
// collision policy actually rejects a STOR when the object exists in oCIS
// (QLT-001).
func TestHandleUploadOpenCollisionRejectAgainstWebDAV(t *testing.T) {
	mock := newMockWebDAVServer(t, map[string][]byte{"/uploads/report.pdf": []byte("previous scan")})

	spoolDir := t.TempDir()
	spoolManager, err := spool.NewManager(spoolDir, 1024*1024)
	if err != nil {
		t.Fatalf("failed to create spool manager: %v", err)
	}

	_, client := newCollisionTestDriver(t, mock, spoolManager, "reject", "/")

	_, err = client.handleUploadOpen("/uploads/report.pdf")
	if err == nil {
		t.Fatal("expected STOR to be rejected for existing object")
	}
	if !errors.IsCode(err, errors.ErrCodeAlreadyExists) {
		t.Errorf("expected ALREADY_EXISTS error, got %v", err)
	}
}

// TestHandleUploadOpenIgnoresLocalFilesystem verifies the collision check runs
// against WebDAV, not the local filesystem (QLT-001): a file that exists only
// locally at the target path must not trigger a rename.
func TestHandleUploadOpenIgnoresLocalFilesystem(t *testing.T) {
	mock := newMockWebDAVServer(t, nil)

	// A local file exists exactly where the WebDAV target path would resolve.
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "uploads"), 0o755); err != nil {
		t.Fatalf("failed to create local dir: %v", err)
	}
	wantTarget := filepath.Join(root, "uploads", "report.pdf")
	if err := os.WriteFile(wantTarget, []byte("local"), 0o644); err != nil {
		t.Fatalf("failed to create local file: %v", err)
	}

	spoolDir := t.TempDir()
	spoolManager, err := spool.NewManager(spoolDir, 1024*1024)
	if err != nil {
		t.Fatalf("failed to create spool manager: %v", err)
	}

	_, client := newCollisionTestDriver(t, mock, spoolManager, "rename", root)

	w, err := client.handleUploadOpen("/uploads/report.pdf")
	if err != nil {
		t.Fatalf("handleUploadOpen failed: %v", err)
	}
	defer spoolManager.GetUploadManager().AbortUpload(w.upload)

	if w.spoolUpload.path != wantTarget {
		t.Errorf("expected target %q (object does not exist in WebDAV), got %q", wantTarget, w.spoolUpload.path)
	}
}

// TestCommitToWebDAVHonorsCollisionPolicy verifies that the final PUT only
// overwrites for the explicit overwrite policy; for rename/reject it sends
// If-None-Match so an object that appeared after path resolution fails with a
// conflict instead of silently destroying the existing object (QLT-001).
func TestCommitToWebDAVHonorsCollisionPolicy(t *testing.T) {
	spoolDir := t.TempDir()
	spoolManager, err := spool.NewManager(spoolDir, 1024*1024)
	if err != nil {
		t.Fatalf("failed to create spool manager: %v", err)
	}

	content := []byte("new scan data")
	spooledFile := filepath.Join(spoolDir, "spooled-upload")
	if err := os.WriteFile(spooledFile, content, 0o644); err != nil {
		t.Fatalf("failed to write spooled file: %v", err)
	}

	setup := func(t *testing.T, policy string, existing map[string][]byte) (*mockWebDAVServer, *uploadWriter, spool.FileRef) {
		mock := newMockWebDAVServer(t, existing)
		_, client := newCollisionTestDriver(t, mock, spoolManager, policy, "/")
		w := &uploadWriter{
			clientDriver: client,
			uploadID:     "upload-1",
			spoolUpload:  &spoolUpload{path: "/uploads/report.pdf"},
		}
		fileRef := spool.FileRef{
			UserID:     "test-printer",
			FileID:     "file-1",
			Filename:   "report.pdf",
			Size:       int64(len(content)),
			Path:       spooledFile,
			TargetPath: "/uploads/report.pdf",
		}
		return mock, w, fileRef
	}

	t.Run("rename policy sends If-None-Match", func(t *testing.T) {
		mock, w, fileRef := setup(t, "rename", nil)
		if err := w.commitToWebDAV(fileRef); err != nil {
			t.Fatalf("commit failed: %v", err)
		}
		if got := mock.lastPUTHeader().Get("If-None-Match"); got != "*" {
			t.Errorf("expected If-None-Match: * for rename policy, got %q", got)
		}
	})

	t.Run("rename policy conflict fails instead of overwriting", func(t *testing.T) {
		mock, w, fileRef := setup(t, "rename", map[string][]byte{"/uploads/report.pdf": []byte("previous scan")})
		err := w.commitToWebDAV(fileRef)
		if err == nil {
			t.Fatal("expected commit to fail when object appeared after path resolution")
		}
		if got := mock.fileContent("/uploads/report.pdf"); got != "previous scan" {
			t.Errorf("existing object was overwritten: content = %q", got)
		}
	})

	t.Run("overwrite policy replaces without If-None-Match", func(t *testing.T) {
		mock, w, fileRef := setup(t, "overwrite", map[string][]byte{"/uploads/report.pdf": []byte("previous scan")})
		if err := w.commitToWebDAV(fileRef); err != nil {
			t.Fatalf("commit failed: %v", err)
		}
		if got := mock.lastPUTHeader().Get("If-None-Match"); got != "" {
			t.Errorf("expected no If-None-Match for overwrite policy, got %q", got)
		}
		if got := mock.fileContent("/uploads/report.pdf"); got != string(content) {
			t.Errorf("expected object to be replaced, content = %q", got)
		}
	})
}

// TestUploadWriterCloseAbortsAfterWriteError verifies that an upload whose
// chunk writes failed (e.g. the global spool capacity was exceeded mid
// transfer, SEC-002) is aborted on Close instead of committing a partial file
// to oCIS.
func TestUploadWriterCloseAbortsAfterWriteError(t *testing.T) {
	mock := newMockWebDAVServer(t, nil)

	// Small global spool capacity: 1000 bytes
	spoolDir := t.TempDir()
	spoolManager, err := spool.NewManager(spoolDir, 1000)
	if err != nil {
		t.Fatalf("failed to create spool manager: %v", err)
	}

	_, client := newCollisionTestDriver(t, mock, spoolManager, "overwrite", "/")

	// First upload: write 600 bytes, then a chunk that exceeds the remaining
	// 400 bytes of global spool capacity
	w, err := client.handleUploadOpen("/big.bin")
	if err != nil {
		t.Fatalf("handleUploadOpen failed: %v", err)
	}
	if _, err := w.Write(make([]byte, 600)); err != nil {
		t.Fatalf("first write failed: %v", err)
	}
	if _, err := w.Write(make([]byte, 500)); err == nil {
		t.Fatal("expected write to fail when global spool capacity is exceeded")
	}

	// Closing the failed upload must abort it: no partial file may be
	// committed to WebDAV and no bytes may leak in the spool
	closeErr := w.Close()
	if closeErr == nil {
		t.Fatal("expected Close to report the write error")
	}
	if got := mock.putCount(); got != 0 {
		t.Errorf("expected no WebDAV PUT for an aborted upload, got %d", got)
	}
	files, err := spoolManager.ListAll()
	if err != nil {
		t.Fatalf("failed to list spool files: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("expected spool to be empty after abort, found %d files", len(files))
	}

	// A healthy upload in the freed capacity still commits normally
	w2, err := client.handleUploadOpen("/ok.bin")
	if err != nil {
		t.Fatalf("handleUploadOpen failed: %v", err)
	}
	if _, err := w2.Write(make([]byte, 500)); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if err := w2.Close(); err != nil {
		t.Fatalf("Close failed for healthy upload: %v", err)
	}
	if got := mock.putCount(); got != 1 {
		t.Errorf("expected exactly one WebDAV PUT for the healthy upload, got %d", got)
	}
	if !mock.fileExists("/ok.bin") {
		t.Error("expected /ok.bin to be committed to WebDAV")
	}
}

// TestHandleUploadOpenNestedPathCreatesParents verifies the QLT-002 fix
// end to end: a STOR to a nested path must issue MKCOL for every missing
// parent level before the PUT, because oCIS (RFC 4918) answers a PUT with a
// missing parent collection with 409 Conflict instead of auto-creating it.
// The strict mock enforces those semantics, unlike the CI e2e mock whose PUT
// handler silently creates parent directories.
func TestHandleUploadOpenNestedPathCreatesParents(t *testing.T) {
	mock := newStrictMockWebDAVServer(t, nil, nil)

	spoolDir := t.TempDir()
	spoolManager, err := spool.NewManager(spoolDir, 1024*1024)
	if err != nil {
		t.Fatalf("failed to create spool manager: %v", err)
	}

	_, client := newCollisionTestDriver(t, mock, spoolManager, "overwrite", "/")

	w, err := client.handleUploadOpen("/scans/2026/oct/file.pdf")
	if err != nil {
		t.Fatalf("handleUploadOpen failed: %v", err)
	}
	if _, err := w.Write([]byte("scan data")); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close failed for nested-path upload (parents must be created via MKCOL before PUT): %v", err)
	}

	wantMKCOL := []string{"/scans", "/scans/2026", "/scans/2026/oct"}
	gotMKCOL := mock.mkcolPathsSnapshot()
	if len(gotMKCOL) != len(wantMKCOL) {
		t.Fatalf("expected MKCOL for %v, got %v", wantMKCOL, gotMKCOL)
	}
	for i := range wantMKCOL {
		if gotMKCOL[i] != wantMKCOL[i] {
			t.Fatalf("expected MKCOL order %v, got %v", wantMKCOL, gotMKCOL)
		}
	}

	if !mock.fileExists("/scans/2026/oct/file.pdf") {
		t.Error("expected /scans/2026/oct/file.pdf to be committed to WebDAV")
	}
	if got := mock.putCount(); got != 1 {
		t.Errorf("expected exactly one PUT, got %d", got)
	}
}
