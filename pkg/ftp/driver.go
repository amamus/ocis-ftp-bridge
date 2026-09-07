// Package ftp provides the FTP server implementation for ocis-ftp-bridge.
//
// This file implements the ftpserverlib MainDriver and ClientDriver interfaces
// to provide a complete FTP server that bridges FTP uploads to oCIS via WebDAV.
package ftp

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/afero"
	ftpserver "github.com/fclairamb/ftpserverlib"

	"github.com/amamus/ocis-ftp-bridge/pkg/config"
	"github.com/amamus/ocis-ftp-bridge/pkg/graph"
	"github.com/amamus/ocis-ftp-bridge/pkg/observability"
	"github.com/amamus/ocis-ftp-bridge/pkg/spool"
	"github.com/amamus/ocis-ftp-bridge/pkg/transfer"
	"github.com/amamus/ocis-ftp-bridge/pkg/webdav"
)

// ConnectionTracker tracks connections per IP for rate limiting
type ConnectionTracker struct {
	mu            sync.Mutex
	ipConnections map[string]int64 // IP -> connection count
	maxPerIP     int
	maxGlobal    int64
	globalCount  int64
}

// AuthAttemptTracker tracks authentication attempts per IP for rate limiting
type AuthAttemptTracker struct {
	mu               sync.Mutex
	ipAttempts      map[string]*authAttemptInfo // IP -> attempt tracking
	maxAttempts     int
	window          time.Duration
	lockoutDuration time.Duration
}

// authAttemptInfo stores tracking information for rate limiting authentication attempts
type authAttemptInfo struct {
	count       int
	firstFail   time.Time
	lastAttempt time.Time
	lockedOut   bool
	lockoutEnd  time.Time
}

// newConnectionTracker creates a new connection tracker
func newConnectionTracker(maxPerIP, maxGlobal int) *ConnectionTracker {
	return &ConnectionTracker{
		ipConnections: make(map[string]int64),
		maxPerIP:     maxPerIP,
		maxGlobal:    int64(maxGlobal),
	}
}

// newAuthAttemptTracker creates a new auth attempt tracker
func newAuthAttemptTracker(maxAttempts int, window, lockoutDuration time.Duration) *AuthAttemptTracker {
	return &AuthAttemptTracker{
		ipAttempts:      make(map[string]*authAttemptInfo),
		maxAttempts:     maxAttempts,
		window:          window,
		lockoutDuration: lockoutDuration,
	}
}

// AllowConnection checks if a connection from the given IP is allowed
func (ct *ConnectionTracker) AllowConnection(ip string) bool {
	if ct == nil {
		return true // No rate limiting configured
	}
	
	ct.mu.Lock()
	defer ct.mu.Unlock()
	
	// Check global limit
	if ct.globalCount >= ct.maxGlobal {
		return false
	}
	
	// Check per-IP limit
	count, exists := ct.ipConnections[ip]
	if exists && count >= int64(ct.maxPerIP) {
		return false
	}
	
	// Allow the connection
	ct.ipConnections[ip] = count + 1
	ct.globalCount++
	return true
}

// ReleaseConnection decrements counters when a connection is closed
func (ct *ConnectionTracker) ReleaseConnection(ip string) {
	if ct == nil {
		return
	}
	
	ct.mu.Lock()
	defer ct.mu.Unlock()
	
	if count, exists := ct.ipConnections[ip]; exists && count > 0 {
		ct.ipConnections[ip] = count - 1
	}
	if ct.globalCount > 0 {
		ct.globalCount--
	}
}

// IsIPLockedOut checks if the given IP is currently locked out due to too many failed auth attempts
func (at *AuthAttemptTracker) IsIPLockedOut(ip string) bool {
	if at == nil {
		return false // No rate limiting configured
	}
	
	at.mu.Lock()
	defer at.mu.Unlock()
	
	if info, exists := at.ipAttempts[ip]; exists {
		if info.lockedOut {
			// Check if lockout has expired
			if time.Now().Before(info.lockoutEnd) {
				return true
			}
			// Lockout expired, reset the tracking
			delete(at.ipAttempts, ip)
			return false
		}
		
		// Also check if the attempt window has expired (even without lockout)
		if !info.firstFail.IsZero() && time.Since(info.firstFail) > at.window {
			// Window expired, clean up
			delete(at.ipAttempts, ip)
			return false
		}
		
		// If not locked out and window hasn't expired, check if we're still in lockout state
		// This handles the case where the window expired but we haven't cleaned up yet
		if !info.firstFail.IsZero() && info.count >= at.maxAttempts {
			// This should have triggered lockout, but check if window expired
			if time.Since(info.firstFail) > at.window {
				delete(at.ipAttempts, ip)
				return false
			}
			// If we're within the window and have max attempts, we should be locked out
			// This shouldn't happen normally, but handle it
			info.lockedOut = true
			info.lockoutEnd = time.Now().Add(at.lockoutDuration)
			return true
		}
	}
	return false
}

// RecordAuthAttempt records an authentication attempt and checks rate limits
func (at *AuthAttemptTracker) RecordAuthAttempt(ip string, success bool) bool {
	if at == nil {
		return true // No rate limiting configured
	}
	
	at.mu.Lock()
	defer at.mu.Unlock()
	
	info, exists := at.ipAttempts[ip]
	if !exists {
		info = &authAttemptInfo{
			count:       0,
			lastAttempt: time.Now(),
		}
		at.ipAttempts[ip] = info
	}
	
	// If this is a successful attempt, reset the failure tracking
	if success {
		info.count = 0 // Reset counter on success
		info.firstFail = time.Time{} // Reset failure tracking
		info.lastAttempt = time.Now()
		return true
	}
	
	// For failed attempts
	info.count++
	info.lastAttempt = time.Now()
	
	// Check if we need to start lockout tracking
	if info.firstFail.IsZero() {
		info.firstFail = time.Now()
	}
	
	// Check if we've reached or exceeded the limit within the window
	// Lock out when count >= maxAttempts (i.e., allow maxAttempts-1 failed attempts)
	if info.count >= at.maxAttempts {
		// Check if we're still within the window from first failure
		if time.Since(info.firstFail) <= at.window {
			// Lock out this IP
			info.lockedOut = true
			info.lockoutEnd = time.Now().Add(at.lockoutDuration)
			return false
		}
		// Window has expired, reset tracking
		info.count = 1
		info.firstFail = time.Now()
	}
	
	return true
}

// BridgeDriver implements MainDriver interface
// to handle FTP connections and provide authentication for oCIS bridge.
type BridgeDriver struct {
	// Configuration
	cfg          *config.Config
	obs          observability.Client
	spoolManager spool.Manager
	graphClient  graph.Client
	transferManager *transfer.TransferManager

	// Client management
	activeConnections int64
	maxConnections    int

	// Metrics
	uploadsTotal     uint64
	uploadsSuccess   uint64
	uploadsFailed    uint64
	totalBytesUploaded uint64

	// Account management
	accounts map[string]*config.AccountConfig
	
	// Rate limiting
	connectionTracker *ConnectionTracker
	authAttemptTracker *AuthAttemptTracker

	// Sync primitives
	mu sync.RWMutex

	// Shutdown
	shutdownChan chan struct{}
	shutdown     bool
}

// NewBridgeDriver creates a new bridge FTP server driver.


func NewBridgeDriver(
	cfg *config.Config,
	obs observability.Client,
	spoolManager spool.Manager,
	graphClient graph.Client,
) *BridgeDriver {
	// Extract accounts for faster lookup
	accounts := make(map[string]*config.AccountConfig)
	for i := range cfg.Accounts {
		accounts[cfg.Accounts[i].Username] = &cfg.Accounts[i]
	}

	// Create transfer manager for path mapping and collision handling
	transferMgr := transfer.NewTransferManager()
	
	// Add target configurations for each account
	for i := range cfg.Accounts {
		account := &cfg.Accounts[i]
		transferMgr.AddTarget(account.Username, transfer.TargetConfig{
			DriveID:          account.Target.DriveID,
			Drive:           account.Target.Drive,
			Root:            account.Target.Root,
			CollisionPolicy: transfer.CollisionPolicy(account.Upload.CollisionPolicy),
			MaxSize:         uint64(account.Upload.MaxSize),
		})
	}

	// Initialize rate limiting trackers
	var connTracker *ConnectionTracker
	var authTracker *AuthAttemptTracker
	
	if cfg.Server.RateLimiting.TrackFailedAttempts {
		connTracker = newConnectionTracker(
			cfg.Server.RateLimiting.MaxConnectionsPerIP,
			cfg.Server.RateLimiting.MaxGlobalConnections,
		)
		authTracker = newAuthAttemptTracker(
			cfg.Server.RateLimiting.MaxAuthAttemptsPerIP,
			cfg.Server.RateLimiting.AuthAttemptWindow,
			cfg.Server.RateLimiting.AuthLockoutDuration,
		)
	}

	return &BridgeDriver{
		cfg:           cfg,
		obs:          obs,
		spoolManager:  spoolManager,
		graphClient:   graphClient,
		transferManager: transferMgr,
		accounts:      accounts,
		maxConnections: cfg.Server.MaxConnections,
		connectionTracker: connTracker,
		authAttemptTracker: authTracker,
		shutdownChan:  make(chan struct{}),
	}
}

// =========================================================================
// MainDriver Interface Implementation
// =========================================================================

// AuthUser is called when USER command is received. Returns a ClientDriver
// if authentication succeeds.
func (d *BridgeDriver) AuthUser(cc ftpserver.ClientContext, user, password string) (ftpserver.ClientDriver, error) {
	// Get client IP for rate limiting
	clientIP := cc.RemoteAddr().String()
	
	// Check shutdown
	select {
	case <-d.shutdownChan:
		return nil, ErrServerShuttingDown
	default:
	}

	// Rate limiting: Check if IP is locked out due to too many failed attempts
	if d.authAttemptTracker != nil && d.authAttemptTracker.IsIPLockedOut(clientIP) {
		return nil, fmt.Errorf("too many failed authentication attempts from %s. Try again later", clientIP)
	}

	// Rate limiting: Check connection limits per IP
	if d.connectionTracker != nil && !d.connectionTracker.AllowConnection(clientIP) {
		return nil, fmt.Errorf("connection limit reached for this IP")
	}

	// Check global connection limit
	if d.maxConnections > 0 {
		current := atomic.LoadInt64(&d.activeConnections)
		if current >= int64(d.maxConnections) {
			return nil, fmt.Errorf("server connection limit reached")
		}
	}

	// Authenticate user
	account, err := d.authenticateUser(user, password)
	if err != nil {
		d.obs.Log("info", fmt.Sprintf("FTP authentication failed for user %s: %v", user, err))
		// Record failed authentication attempt for rate limiting
		if d.authAttemptTracker != nil {
			d.authAttemptTracker.RecordAuthAttempt(clientIP, false)
		}
		return nil, ErrInvalidCredentials
	}

	// Check if account has required oCIS configuration
	if account.OCIS.Username == "" || account.AppToken == "" {
		d.obs.Log("warn", fmt.Sprintf("FTP account missing oCIS configuration for user %s", user))
		// Record failed authentication attempt for rate limiting
		if d.authAttemptTracker != nil {
			d.authAttemptTracker.RecordAuthAttempt(clientIP, false)
		}
		return nil, ErrInvalidCredentials
	}

	// Resolve the drive for this account
	resolvedDrive, err := d.resolveDriveForAccount(account)
	if err != nil {
		d.obs.Log("warn", fmt.Sprintf("Failed to resolve drive for account %s: %v", user, err))
		return nil, fmt.Errorf("drive resolution failed: %w", err)
	}

	// Create WebDAV client for this account
	webdavClient := webdav.NewClientWithCredentials(
		d.cfg.OCIS.WebDAVURL,
		account.OCIS.Username,
		account.AppToken,
	)

	// Create client-specific driver
	clientDriver := &bridgeClientDriver{
		bridgeDriver:   d,
		account:        account,
		resolvedDrive:  &resolvedDrive,
		user:           user,
		currentDir:     "/",
		webdavClient:   webdavClient,
		spoolUploads:   make(map[string]*spoolUpload),
		uploadCounter:  0,
		lastAccess:     time.Now(),
		context:        context.Background(),
		cancel:         func() {},
	}

	// Create a real context for this session
	clientDriver.context, clientDriver.cancel = context.WithCancel(context.Background())

	// Record successful authentication attempt for rate limiting
	if d.authAttemptTracker != nil {
		d.authAttemptTracker.RecordAuthAttempt(clientIP, true)
	}

	// Increment connection counter
	atomic.AddInt64(&d.activeConnections, 1)

	d.obs.Log("info", fmt.Sprintf("FTP authentication successful for user %s (oCIS: %s)", user, account.OCIS.Username))

	return clientDriver, nil
}

// OnLogin is called after successful authentication.
func (d *BridgeDriver) OnLogin(client ftpserver.ClientContext) error {
	// Update the remote address in logs
	d.obs.Log("info", fmt.Sprintf("FTP client logged in from %s (ID: %d)", client.RemoteAddr().String(), client.ID()))
	return nil
}

// OnLogout is called when a client disconnects.
func (d *BridgeDriver) OnLogout(client ftpserver.ClientContext) error {
	// Decrement connection counter
	atomic.AddInt64(&d.activeConnections, -1)
	
	// Release rate limiting connection tracking
	if d.connectionTracker != nil {
		d.connectionTracker.ReleaseConnection(client.RemoteAddr().String())
	}

	d.obs.Log("info", fmt.Sprintf("FTP client logged out (ID: %d, addr: %s)", client.ID(), client.RemoteAddr().String()))
	return nil
}

// GetSettings returns the server settings.
func (d *BridgeDriver) GetSettings() (*ftpserver.Settings, error) {
	settings := &ftpserver.Settings{
		ListenAddr:       d.cfg.Server.Listen,
		PublicHost:      d.cfg.Server.Passive.PublicIP,
		IdleTimeout:     300, // 5 minutes
		ConnectionTimeout: 60,
		PassiveTransferPortRange: ftpserver.PortRange{
			Start: d.cfg.Server.Passive.MinPort,
			End:   d.cfg.Server.Passive.MaxPort,
		},
		DisableMLSD:           false,
		DisableMLST:           false,
		DisableMFMT:           true, // Disable features not needed for printers
		DisableSTAT:           true,
		DisableSYST:           false,
		ActiveTransferPortNon20: true,
		DefaultTransferType:   ftpserver.TransferTypeBinary,
		TLSRequired:           func() ftpserver.TLSRequirement {
			if d.cfg.Server.TLS.Enabled {
				return ftpserver.TLSRequirement(1) // Required = 1
			}
			return ftpserver.TLSRequirement(0) // ClearOrEncrypted = 0
		}(),
		DisableActiveMode:     false,
		DisableSite:           true,
		DisableLISTArgs:       true,
	}
	return settings, nil
}

// GetTLSConfig returns TLS configuration for the FTP server.
func (d *BridgeDriver) GetTLSConfig() (*tls.Config, error) {
	if !d.cfg.Server.TLS.Enabled {
		return nil, nil
	}

	// Load certificate and key
	cert, err := tls.LoadX509KeyPair(d.cfg.Server.TLS.Cert, d.cfg.Server.TLS.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12, // Require at least TLS 1.2
	}, nil
}

// ClientConnected is called when a new client connects.
func (d *BridgeDriver) ClientConnected(cc ftpserver.ClientContext) (string, error) {
	return "220 ocis-ftp-bridge ready", nil
}

// ClientDisconnected is called when a client disconnects.
func (d *BridgeDriver) ClientDisconnected(cc ftpserver.ClientContext) {
	// Decrement connection counter
	atomic.AddInt64(&d.activeConnections, -1)

	d.obs.Log("info", fmt.Sprintf("FTP client disconnected (ID: %d, addr: %s)", cc.ID(), cc.RemoteAddr().String()))
}

// Shutdown initiates server shutdown.
func (d *BridgeDriver) Shutdown() {
	select {
	case <-d.shutdownChan:
		// Already shutting down
		return
	default:
		close(d.shutdownChan)
		d.shutdown = true
	}

	d.obs.Log("info", "FTP server shutting down")
}

// IsShuttingDown returns true if the server is shutting down.
func (d *BridgeDriver) IsShuttingDown() bool {
	select {
	case <-d.shutdownChan:
		return true
	default:
		return d.shutdown
	}
}

// =========================================================================
// BridgeClientDriver implements ClientDriver for account-scoped operations
// =========================================================================

// bridgeClientDriver handles FTP client sessions and implements ClientDriverExtensionFileTransfer
// to provide custom file upload handling without implementing the full afero.Fs interface.
type bridgeClientDriver struct {
	bridgeDriver *BridgeDriver
	account      *config.AccountConfig
	resolvedDrive *graph.Drive
	user         string
	currentDir   string
	webdavClient webdav.Client

	// Upload tracking
	spoolUploads   map[string]*spoolUpload
	uploadCounter  uint64
	mu             sync.Mutex

	// Session management
	lastAccess time.Time
	context    context.Context
	cancel     context.CancelFunc
}

// spoolUpload tracks an active upload operation
type spoolUpload struct {
	upload    *spool.Upload
	fileRef   spool.FileRef
	startTime time.Time
	lastChunk time.Time
	bytesWritten int64
	path       string
}

// Ensure bridgeClientDriver implements required interfaces
var _ ftpserver.ClientDriver = &bridgeClientDriver{}

// uploadFile implements afero.File for upload operations
type uploadFile struct {
	writer *uploadWriter
	name   string
	flag   int
	pos    int64
}

// Read reads data from the file (not supported for upload files)
func (f *uploadFile) Read(p []byte) (n int, err error) {
	return 0, ErrOperationNotSupported
}

// ReadAt reads data from the file at offset (not supported for upload files)
func (f *uploadFile) ReadAt(p []byte, off int64) (n int, err error) {
	return 0, ErrOperationNotSupported
}

// Write writes data to the file
func (f *uploadFile) Write(p []byte) (n int, err error) {
	return f.writer.Write(p)
}

// WriteAt writes data to the file at offset (not supported for upload files)
func (f *uploadFile) WriteAt(p []byte, off int64) (n int, err error) {
	return 0, ErrOperationNotSupported
}

// Seek is not supported for upload files
func (f *uploadFile) Seek(offset int64, whence int) (int64, error) {
	return 0, ErrOperationNotSupported
}

// Readdir is not supported for upload files
func (f *uploadFile) Readdir(count int) ([]os.FileInfo, error) {
	return nil, ErrOperationNotSupported
}

// Readdirnames is not supported for upload files
func (f *uploadFile) Readdirnames(n int) ([]string, error) {
	return nil, ErrOperationNotSupported
}

// Stat returns file info
func (f *uploadFile) Stat() (os.FileInfo, error) {
	return &uploadFileInfo{name: f.name, size: f.pos}, nil
}

// Sync syncs the file (not supported for upload files)
func (f *uploadFile) Sync() error {
	return ErrOperationNotSupported
}

// Truncate truncates the file (not supported for upload files)
func (f *uploadFile) Truncate(size int64) error {
	return ErrOperationNotSupported
}

// WriteString writes a string to the file
func (f *uploadFile) WriteString(s string) (ret int, err error) {
	return f.Write([]byte(s))
}

// Close closes the file
func (f *uploadFile) Close() error {
	return f.writer.Close()
}

// Name returns the file name
func (f *uploadFile) Name() string {
	return f.name
}

// uploadFileInfo implements os.FileInfo for upload files
type uploadFileInfo struct {
	name string
	size int64
}

func (fi *uploadFileInfo) Name() string       { return fi.name }
func (fi *uploadFileInfo) Size() int64        { return fi.size }
func (fi *uploadFileInfo) Mode() os.FileMode   { return 0644 }
func (fi *uploadFileInfo) ModTime() time.Time { return time.Now() }
func (fi *uploadFileInfo) IsDir() bool        { return false }
func (fi *uploadFileInfo) Sys() interface{}   { return nil }

// Name returns the name of this filesystem.
func (c *bridgeClientDriver) Name() string {
	return "ocis-ftp-bridge-vfs"
}

// Create creates a file in the virtual filesystem.
func (c *bridgeClientDriver) Create(name string) (afero.File, error) {
	// For uploads, use the file transfer extension
	return nil, ErrOperationNotSupported
}

// Mkdir creates a directory in the virtual filesystem.
func (c *bridgeClientDriver) Mkdir(name string, perm os.FileMode) error {
	// Directories are created on-demand during upload
	return nil
}

// MkdirAll creates a directory path and all parents.
func (c *bridgeClientDriver) MkdirAll(path string, perm os.FileMode) error {
	return nil
}

// Open opens a file for reading.
func (c *bridgeClientDriver) Open(name string) (afero.File, error) {
	// Reading files is not supported for the bridge
	return nil, ErrOperationNotSupported
}

// OpenFile opens a file using the given flags and mode.
func (c *bridgeClientDriver) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	// Check if this is a write operation (STOR command)
	if flag&os.O_WRONLY != 0 || flag&os.O_CREATE != 0 {
		// Handle upload
		uploadWriter, err := c.handleUploadOpen(name)
		if err != nil {
			return nil, err
		}
		// Wrap the writer in an afero.File
		return &uploadFile{
			writer: uploadWriter,
			name:   name,
			flag:   flag,
			pos:    0,
		}, nil
	}
	// Reading not supported
	return nil, ErrOperationNotSupported
}

// Remove removes a file.
func (c *bridgeClientDriver) Remove(name string) error {
	return ErrNotImplemented
}

// RemoveAll removes a directory path and any children.
func (c *bridgeClientDriver) RemoveAll(path string) error {
	return ErrNotImplemented
}

// Rename renames a file.
func (c *bridgeClientDriver) Rename(oldname, newname string) error {
	return ErrNotImplemented
}

// Stat returns a FileInfo describing the named file.
func (c *bridgeClientDriver) Stat(name string) (os.FileInfo, error) {
	// For directories, return virtual directory info
	if name == "/" || name == "" || name == "." {
		return &virtualDir{name: "/"}, nil
	}
	// For files, return not found
	return nil, os.ErrNotExist
}

// Chmod changes the mode of the named file.
func (c *bridgeClientDriver) Chmod(name string, mode os.FileMode) error {
	return ErrNotImplemented
}

// Chown changes the uid and gid of the named file.
func (c *bridgeClientDriver) Chown(name string, uid, gid int) error {
	return ErrNotImplemented
}

// Chtimes changes the access and modification times of the named file.
func (c *bridgeClientDriver) Chtimes(name string, atime time.Time, mtime time.Time) error {
	return ErrNotImplemented
}

// =========================================================================
// Path Handling
// =========================================================================

// normalizeUploadPath normalizes and validates the upload path
func (c *bridgeClientDriver) normalizeUploadPath(path string) (string, error) {
	// Convert to absolute path
	absPath := path
	if !filepath.IsAbs(absPath) {
		absPath = filepath.Join("/", absPath)
	}

	// Clean the path
	cleanPath := filepath.Clean(absPath)

	// Remove leading slash and ensure it's relative to target root
	cleanPath = strings.TrimLeft(cleanPath, "/")

	// Combine with account's target root
	targetPath := filepath.Join(c.account.Target.Root, cleanPath)

	// Validate no path traversal
	if strings.Contains(targetPath, "..") {
		return "", ErrPathTraversal
	}

	// Ensure it's within the target root
	if !strings.HasPrefix(targetPath, c.account.Target.Root) {
		return "", ErrPathTraversal
	}

	return targetPath, nil
}

// generateUploadID generates a unique upload ID for the client
func (c *bridgeClientDriver) generateUploadID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.uploadCounter++
	return fmt.Sprintf("%s-%d-%d", c.user, c.uploadCounter, time.Now().UnixNano())
}

// =========================================================================
// Upload Handling
// =========================================================================

// handleUploadOpen is called when a client sends STOR command
func (c *bridgeClientDriver) handleUploadOpen(path string) (*uploadWriter, error) {
	// Use transfer manager for proper path mapping and collision handling
	filename := filepath.Base(path)
	
	// Create transfer request
	request := transfer.TransferRequest{
		UserID:   c.user,
		Filename: filename,
		Path:     filepath.Dir(path),
		Size:     -1, // unknown size initially
	}

	// Process the upload request to get the final target path
	transferResult := c.bridgeDriver.transferManager.ProcessUpload(request)
	if !transferResult.Success {
		c.bridgeDriver.obs.Log("warn", fmt.Sprintf("Transfer processing failed for user %s, path %s: %v", 
			c.user, path, transferResult.Error))
		return nil, transferResult.Error
	}

	// Generate a unique upload ID
	uploadID := c.generateUploadID()

	// Start the upload in spool using the resolved target path
	uploadManager := c.bridgeDriver.spoolManager.GetUploadManager()
	
	upload, err := uploadManager.StartUpload(
		c.context,
		c.user,
		transferResult.Filename, // final filename (may be modified for collision handling)
		transferResult.TargetPath, // final target path
		-1, // unknown size initially, will be updated as we receive data
		uint64(c.account.Upload.MaxSize), // account max size
	)
	if err != nil {
		c.bridgeDriver.obs.Log("error", fmt.Sprintf("Failed to start upload for user %s, path %s: %v", c.user, path, err))
		return nil, err
	}

	// Create spool upload tracker
	spoolUpload := &spoolUpload{
		upload:    upload,
		startTime: time.Now(),
		lastChunk: time.Now(),
		path:      transferResult.TargetPath,
	}

	// Store the upload for later reference
	c.mu.Lock()
	c.spoolUploads[uploadID] = spoolUpload
	c.mu.Unlock()

	// Create an upload writer that streams to spool
	writer := &uploadWriter{
		clientDriver: c,
		uploadID:    uploadID,
		upload:      upload,
		spoolUpload: spoolUpload,
		bytesWritten: 0,
	}

	c.bridgeDriver.obs.Log("info", fmt.Sprintf("Upload started for user %s, upload %s, target %s, filename %s",
		c.user, uploadID, transferResult.TargetPath, transferResult.Filename))

	// Increment upload counter
	atomic.AddUint64(&c.bridgeDriver.uploadsTotal, 1)

	return writer, nil
}

// uploadWriter implements io.Writer for streaming uploads to spool
type uploadWriter struct {
	clientDriver *bridgeClientDriver
	uploadID     string
	upload       *spool.Upload
	spoolUpload  *spoolUpload
	bytesWritten int64
}

// Write implements io.Writer interface
func (w *uploadWriter) Write(p []byte) (n int, err error) {
	// Check if upload was cancelled
	select {
	case <-w.upload.Context.Done():
		return 0, ErrUploadCancelled
	default:
	}

	// Update last chunk time
	w.spoolUpload.lastChunk = time.Now()

	// Check size limits
	remaining := w.upload.Size - w.upload.BytesReceived
	if int64(len(p)) > remaining && w.upload.Size > 0 {
		return 0, spool.ErrFileTooLarge
	}

	// Check account max size
	if w.upload.BytesReceived+int64(len(p)) > int64(w.upload.AccountMaxSize) {
		return 0, spool.ErrFileTooLarge
	}

	// Write to spool
	n, err = w.clientDriver.bridgeDriver.spoolManager.GetUploadManager().WriteChunk(w.upload, p)
	if err != nil {
		w.clientDriver.bridgeDriver.obs.Log("error", fmt.Sprintf("Upload write failed for user %s, upload %s: %v", w.clientDriver.user, w.uploadID, err))
		return n, err
	}

	w.bytesWritten += int64(n)
	w.spoolUpload.bytesWritten += int64(n)

	return n, nil
}

// Close is called when the upload is complete or aborted
func (w *uploadWriter) Close() error {
	// Try to finish the upload
	if w.upload.BytesReceived == w.upload.Size || w.upload.Size <= 0 {
		// If we don't know the size or we've received all data, finish the upload
		fileRef, err := w.clientDriver.bridgeDriver.spoolManager.GetUploadManager().FinishUpload(w.upload)
		if err != nil {
			w.clientDriver.bridgeDriver.obs.Log("error", fmt.Sprintf("Upload finish failed for user %s, upload %s: %v", w.clientDriver.user, w.uploadID, err))
			
			// Clean up the spool upload tracking
			w.clientDriver.mu.Lock()
			delete(w.clientDriver.spoolUploads, w.uploadID)
			w.clientDriver.mu.Unlock()
			
			atomic.AddUint64(&w.clientDriver.bridgeDriver.uploadsFailed, 1)
			return err
		}

		// Store the file reference
		w.spoolUpload.fileRef = fileRef

		// Commit to WebDAV - this is the critical integration point
		// The FTP transfer only succeeds if the WebDAV upload succeeds
		err = w.commitToWebDAV(fileRef)
		if err != nil {
			// WebDAV commit failed - clean up spool file and return error
			w.clientDriver.bridgeDriver.spoolManager.DeleteByPath(fileRef.Path)
			w.clientDriver.bridgeDriver.obs.Log("error", fmt.Sprintf("WebDAV commit failed for user %s, upload %s: %v", w.clientDriver.user, w.uploadID, err))
			
			// Clean up tracking
			w.clientDriver.mu.Lock()
			delete(w.clientDriver.spoolUploads, w.uploadID)
			w.clientDriver.mu.Unlock()
			
			atomic.AddUint64(&w.clientDriver.bridgeDriver.uploadsFailed, 1)
			return err
		}

		// WebDAV commit succeeded - FTP transfer can now be considered successful
		w.clientDriver.bridgeDriver.obs.Log("info", fmt.Sprintf("Upload and WebDAV commit succeeded for user %s, upload %s, file %s, size %d",
			w.clientDriver.user, w.uploadID, fileRef.FileID, fileRef.Size))

		// Clean up spool file since it's now safely in oCIS
		w.clientDriver.bridgeDriver.spoolManager.DeleteByPath(fileRef.Path)

		// Update metrics
		atomic.AddUint64(&w.clientDriver.bridgeDriver.uploadsSuccess, 1)
		atomic.AddUint64(&w.clientDriver.bridgeDriver.totalBytesUploaded, uint64(fileRef.Size))

		// Clean up tracking
		w.clientDriver.mu.Lock()
		delete(w.clientDriver.spoolUploads, w.uploadID)
		w.clientDriver.mu.Unlock()

		return nil
	} else {
		// Upload was incomplete, abort it
		err := w.clientDriver.bridgeDriver.spoolManager.GetUploadManager().AbortUpload(w.upload)
		if err != nil {
			w.clientDriver.bridgeDriver.obs.Log("warn", fmt.Sprintf("Upload abort failed for user %s, upload %s: %v", w.clientDriver.user, w.uploadID, err))
		}

		// Clean up tracking
		w.clientDriver.mu.Lock()
		delete(w.clientDriver.spoolUploads, w.uploadID)
		w.clientDriver.mu.Unlock()

		atomic.AddUint64(&w.clientDriver.bridgeDriver.uploadsFailed, 1)
		return err
	}
}

// commitToWebDAV commits a spooled file to WebDAV and handles the required path mapping.
// This uses the transfer manager for proper path mapping, collision handling, and directory creation.
func (w *uploadWriter) commitToWebDAV(fileRef spool.FileRef) error {
	// Get the resolved target path from the spool upload (set during handleUploadOpen)
	// This path already includes proper path mapping and collision resolution
	finalPath := w.spoolUpload.path
	if finalPath == "" {
		// Fallback to the fileRef target path
		finalPath = fileRef.TargetPath
		if finalPath == "" {
			// Last fallback: use the filename relative to account root
			finalPath = filepath.Join(w.clientDriver.account.Target.Root, filepath.Base(fileRef.Filename))
		}
	}

	// Ensure parent directories exist
	err := w.clientDriver.bridgeDriver.transferManager.EnsureParentDirectories(finalPath)
	if err != nil {
		return fmt.Errorf("failed to ensure parent directories: %w", err)
	}

	// Open the spooled file for reading
	fileData, err := os.ReadFile(fileRef.Path)
	if err != nil {
		return fmt.Errorf("failed to read spooled file for WebDAV upload: %w", err)
	}

	// Upload to WebDAV
	// The collision policy is already handled by the transfer manager during path resolution
	// We use overwrite=true here since the transfer manager has already resolved any collisions
	err = w.clientDriver.webdavClient.Upload(w.clientDriver.context, finalPath, fileData, true)
	if err != nil {
		return fmt.Errorf("WebDAV upload failed: %w", err)
	}

	// Success - the file is now in oCIS
	return nil
}

// =========================================================================
// Authentication and Account Resolution
// =========================================================================

// authenticateUser authenticates an FTP user against configured accounts
func (d *BridgeDriver) authenticateUser(user, password string) (*config.AccountConfig, error) {
	account, exists := d.accounts[user]
	if !exists {
		return nil, ErrUserNotFound
	}

	// Verify password hash
	if account.PasswordHash != "" {
		if ok, err := config.VerifyPassword(account.PasswordHash, password); err != nil {
			return nil, fmt.Errorf("password verification error: %w", err)
		} else if !ok {
			return nil, ErrInvalidCredentials
		}
	} else {
		// If no password hash is set, reject authentication
		return nil, ErrInvalidCredentials
	}

	return account, nil
}

// resolveDriveForAccount resolves the oCIS drive for an account
func (d *BridgeDriver) resolveDriveForAccount(account *config.AccountConfig) (graph.Drive, error) {
	// Check if we already have a cached resolution
	// In a real implementation, we would cache this or resolve on-demand
	
	// Use the account's oCIS credentials
	client := graph.NewClientWithCredentials(d.cfg.OCIS.GraphURL, account.OCIS.Username, account.AppToken)
	
	// Try to resolve by drive_id first
	if account.Target.DriveID != "" {
		drive, err := client.ResolveDrive(account.Target.DriveID)
		if err != nil {
			return graph.Drive{}, fmt.Errorf("failed to resolve drive by ID %s: %w", account.Target.DriveID, err)
		}
		return drive, nil
	}

	// Try to resolve by drive name
	if account.Target.Drive != "" {
		drives, err := client.ListDrives(account.OCIS.Username)
		if err != nil {
			return graph.Drive{}, fmt.Errorf("failed to list drives: %w", err)
		}

		// Find the drive with matching name
		for _, drive := range drives {
			if drive.Name == account.Target.Drive {
				// Check for ambiguity
				matches := 0
				for _, d2 := range drives {
					if d2.Name == account.Target.Drive {
						matches++
					}
				}
				if matches > 1 {
					return graph.Drive{}, fmt.Errorf("ambiguous drive name %s, use drive_id instead", account.Target.Drive)
				}
				return drive, nil
			}
		}

		return graph.Drive{}, fmt.Errorf("drive not found: %s", account.Target.Drive)
	}

	return graph.Drive{}, fmt.Errorf("no drive configured for account")
}

// =========================================================================
// Helper Methods
// =========================================================================
// Virtual Filesystem Types
// =========================================================================

// virtualDir implements os.FileInfo for virtual directories
type virtualDir struct {
	name string
}

func (d *virtualDir) Name() string       { return d.name }
func (d *virtualDir) Size() int64        { return 0 }
func (d *virtualDir) Mode() os.FileMode   { return os.ModeDir | 0755 }
func (d *virtualDir) ModTime() time.Time { return time.Now() }
func (d *virtualDir) IsDir() bool        { return true }
func (d *virtualDir) Sys() interface{}   { return nil }

// =========================================================================
// FileTransfer Interface (for streaming uploads)
// =========================================================================

// This would be implemented if we need more control over file transfers
// For now, the basic OpenFileWrite implementation should suffice

// =========================================================================
// ClientDriver Extensions for Advanced Features
// =========================================================================

// The ftpserverlib library also supports ClientDriverExtension for
// additional features like custom file transfer handling

// For Issue #6, the basic implementation should be sufficient

// =========================================================================
// Error Definitions
// =========================================================================

var (
	ErrServerShuttingDown = fmt.Errorf("server is shutting down")
	ErrUploadCancelled     = fmt.Errorf("upload cancelled")
)