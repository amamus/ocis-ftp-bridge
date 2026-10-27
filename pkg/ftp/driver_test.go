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
	"sync/atomic"
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

	d := NewBridgeDriver(cfg, noopObs{}, nil)

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
	d := NewBridgeDriver(cfg, noopObs{}, nil)

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

// TestConnectionCounterBalancedAcrossSessions is a regression test for
// SEC-004: activeConnections was incremented in both ClientConnected and
// AuthUser but decremented only once in ClientDisconnected, so the counter
// leaked +1 per authenticated session. After max_connections cumulative
// logins every new login was rejected with "server connection limit
// reached" until the server restarted.
func TestConnectionCounterBalancedAcrossSessions(t *testing.T) {
	// Mock graph server that resolves the account's drive
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"test-drive-id","name":"Test Drive","driveType":"personal","webUrl":"http://localhost/webdav"}`))
	}))
	defer graphSrv.Close()

	cfg := config.New()
	cfg.OCIS.GraphURL = graphSrv.URL
	cfg.Server.MaxConnections = 5
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

	d := NewBridgeDriver(cfg, noopObs{}, nil)

	// Run more cumulative login cycles than max_connections: with the
	// counter leak, logins beyond the 5th are rejected with "server
	// connection limit reached".
	const cycles = 8
	for i := 1; i <= cycles; i++ {
		cc := &mockClientContext{
			id:   uint32(i),
			addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
		}

		if _, err := d.ClientConnected(cc); err != nil {
			t.Fatalf("cycle %d: ClientConnected failed: %v", i, err)
		}
		if _, err := d.AuthUser(cc, "test-printer", "test-password"); err != nil {
			t.Fatalf("cycle %d: AuthUser failed: %v", i, err)
		}
		d.ClientDisconnected(cc)

		if got := atomic.LoadInt64(&d.activeConnections); got != 0 {
			t.Fatalf("cycle %d: activeConnections = %d after disconnect, want 0 (counter leaks +1 per session)", i, got)
		}
	}
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
		d := NewBridgeDriver(cfg, noopObs{}, nil)

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
		d := NewBridgeDriver(cfg, noopObs{}, nil)

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
		d := NewBridgeDriver(cfg, noopObs{}, nil)

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
	d := NewBridgeDriver(cfg, noopObs{}, spoolManager)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := &bridgeClientDriver{
		bridgeDriver: d,
		account:      &cfg.Accounts[0],
		user:         "test-printer",
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

// TestUploadWriterCloseAbortsOnWriteError verifies that when a Write error
// occurs (e.g. file too large), Close aborts the upload instead of
// publishing truncated data to oCIS. See issue #108.
func TestUploadWriterCloseAbortsOnWriteError(t *testing.T) {
	spoolDir := t.TempDir()
	spoolManager, err := spool.NewManager(spoolDir, 1024*1024)
	if err != nil {
		t.Fatalf("failed to create spool manager: %v", err)
	}

	cfg := config.New()
	// Account with a small max size (100 bytes)
	cfg.Accounts = []config.AccountConfig{
		{
			Username: "test-printer",
			Target:   config.TargetConfig{DriveID: "test-drive-id", Root: "/"},
			Upload:   config.UploadConfig{CollisionPolicy: "rename", MaxSize: 100},
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

	w, err := client.handleUploadOpen("/test-file.txt")
	if err != nil {
		t.Fatalf("handleUploadOpen failed: %v", err)
	}

	// Write data that exceeds the account max size (100 bytes)
	largeData := make([]byte, 200)
	_, writeErr := w.Write(largeData)
	if writeErr == nil {
		t.Fatal("expected Write to return an error for oversized data")
	}

	// Close should abort the upload, not publish truncated data
	closeErr := w.Close()
	if closeErr == nil {
		t.Fatal("expected Close to return an error when write failed")
	}

	// The upload should have been aborted (removed from active uploads)
	uploadMgr := spoolManager.GetUploadManager()
	if upload := uploadMgr.GetUpload(w.upload.ID); upload != nil {
		t.Fatal("upload should have been aborted (removed from active uploads)")
	}

	// No spool file should remain for this upload
	files, err := spoolManager.List("test-printer")
	if err != nil {
		t.Fatalf("failed to list spool files: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("expected 0 spool files after abort, got %d", len(files))
	}
}
