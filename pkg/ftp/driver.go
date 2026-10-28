// Package ftp provides the FTP server implementation for ocis-ftp-bridge.
//
// This file implements the ftpserverlib MainDriver and ClientDriver interfaces
// to provide a complete FTP server that bridges FTP uploads to oCIS via WebDAV.
package ftp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	ftpserver "github.com/fclairamb/ftpserverlib"
	"github.com/spf13/afero"

	"github.com/amamus/ocis-ftp-bridge/pkg/config"
	"github.com/amamus/ocis-ftp-bridge/pkg/graph"
	"github.com/amamus/ocis-ftp-bridge/pkg/observability"
	"github.com/amamus/ocis-ftp-bridge/pkg/spool"
	"github.com/amamus/ocis-ftp-bridge/pkg/transfer"
	"github.com/amamus/ocis-ftp-bridge/pkg/webdav"
)

// extractClientIP extracts the client IP from a RemoteAddr string.
// RemoteAddr typically includes a port (e.g. "192.168.1.1:12345"); rate
// limiting must key on the IP alone so clients cannot bypass limits by
// reconnecting with a new ephemeral port.
func extractClientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// No port present; return as-is
		return remoteAddr
	}
	return host
}

// ConnectionTracker tracks connections per IP for rate limiting
type ConnectionTracker struct {
	mu            sync.Mutex
	ipConnections map[string]int64 // IP -> connection count
	maxPerIP      int
	maxGlobal     int64
	globalCount   int64
}

// AuthAttemptTracker tracks authentication attempts per IP for rate limiting
type AuthAttemptTracker struct {
	mu              sync.Mutex
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
		maxPerIP:      maxPerIP,
		maxGlobal:     int64(maxGlobal),
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

	// Check global limit (0 means unlimited)
	if ct.maxGlobal > 0 && ct.globalCount >= ct.maxGlobal {
		return false
	}

	// Check per-IP limit (0 means unlimited)
	count, exists := ct.ipConnections[ip]
	if ct.maxPerIP > 0 && exists && count >= int64(ct.maxPerIP) {
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
		count--
		if count == 0 {
			// Evict the entry so every distinct source IP does not leave a
			// permanent zero-count entry (SEC-012, CWE-401).
			delete(ct.ipConnections, ip)
		} else {
			ct.ipConnections[ip] = count
		}
	}
	if ct.globalCount > 0 {
		ct.globalCount--
	}
}

// sweep evicts zero-count connection entries (defensive; ReleaseConnection
// already deletes them) so the tracking map stays bounded (SEC-012).
func (ct *ConnectionTracker) sweep() {
	if ct == nil {
		return
	}

	ct.mu.Lock()
	defer ct.mu.Unlock()

	for ip, count := range ct.ipConnections {
		if count <= 0 {
			delete(ct.ipConnections, ip)
		}
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
	if success {
		// Drop the tracking entry entirely so every source IP that ever
		// authenticated does not leave a permanent entry (SEC-012, CWE-401).
		if exists {
			delete(at.ipAttempts, ip)
		}
		return true
	}
	if !exists {
		info = &authAttemptInfo{
			count:       0,
			lastAttempt: time.Now(),
		}
		at.ipAttempts[ip] = info
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

// sweep evicts auth-attempt entries whose tracking window or lockout has
// expired, so source IPs that never return do not leave permanent entries
// (SEC-012, CWE-401).
func (at *AuthAttemptTracker) sweep() {
	if at == nil {
		return
	}

	at.mu.Lock()
	defer at.mu.Unlock()

	now := time.Now()
	for ip, info := range at.ipAttempts {
		if info.lockedOut {
			if now.After(info.lockoutEnd) {
				delete(at.ipAttempts, ip)
			}
			continue
		}
		if !info.firstFail.IsZero() && now.Sub(info.firstFail) > at.window {
			delete(at.ipAttempts, ip)
		}
	}
}

// MetricsRecorder is an optional interface for recording Prometheus metrics.
// Implemented by the HTTP operations server. See issue #115.
type MetricsRecorder interface {
	IncrementUploadsTotal(status string)
	IncrementUploadFailuresTotal(reason string)
	AddUploadBytes(bytes uint64)
	ObserveUploadDuration(duration time.Duration, status string)
	IncrementFTPSessionTotal(status string)
	SetFTPActiveSessions(count float64)
}

// BridgeDriver implements MainDriver interface
// to handle FTP connections and provide authentication for oCIS bridge.
type BridgeDriver struct {
	// Configuration
	cfg          *config.Config
	obs          observability.Client
	spoolManager spool.Manager
	// transferManagers holds one transfer manager per account, each with a
	// WebDAV client built from that account's oCIS credentials.
	transferManagers map[string]*transfer.TransferManager

	// metrics, if set, records Prometheus metrics. See issue #115.
	metrics MetricsRecorder

	// Client management
	activeConnections int64
	maxConnections    int

	// Metrics
	uploadsTotal       uint64
	uploadsSuccess     uint64
	uploadsFailed      uint64
	totalBytesUploaded uint64

	// Account management
	accounts map[string]*config.AccountConfig

	// Drive resolution cache (PERF-002): repeated logins for the same
	// account reuse the resolved drive instead of calling the Graph API.
	driveCacheMu sync.Mutex
	driveCache   map[string]driveCacheEntry

	// Active client sessions, keyed by connection ID. Used to cancel the
	// per-session context when the client disconnects.
	clients map[uint32]*bridgeClientDriver

	// allowedConnections tracks connection IDs that were granted a slot
	// by the connection tracker, so ClientDisconnected only releases
	// slots that were actually acquired. See issue #116.
	allowedConnections map[uint32]bool

	// Rate limiting
	connectionTracker  *ConnectionTracker
	authAttemptTracker *AuthAttemptTracker

	// authSemaphore bounds concurrent Argon2id password verifications.
	// Each verification allocates ~64 MiB; without a bound, concurrent
	// logins can exhaust memory (e.g. 8 logins = ~512 MiB). See issue #111.
	authSemaphore chan struct{}

	// Per-account upload concurrency caps (PERF-004): one semaphore channel
	// per account username, created lazily with the account's configured
	// capacity.
	uploadSlotsMu sync.Mutex
	uploadSlots   map[string]chan struct{}

	// Sync primitives
	mu sync.RWMutex

	// Lifecycle: ctx is the driver lifecycle context. Session contexts and
	// the per-account transfer managers derive from it, and Shutdown cancels
	// it so in-flight uploads abort on SIGTERM instead of surviving until
	// the client disconnects (QLT-011). The tracker janitor stops with it.
	ctx    context.Context
	cancel context.CancelFunc

	// Shutdown: shutdownChan is closed exactly once (shutdownOnce) and is
	// the single synchronization point for shutdown state (QLT-008).
	shutdownChan chan struct{}
	shutdownOnce sync.Once
}

// NewBridgeDriver creates a new bridge FTP server driver.

func NewBridgeDriver(
	cfg *config.Config,
	obs observability.Client,
	spoolManager spool.Manager,
) *BridgeDriver {
	// The driver lifecycle context: session contexts and transfer managers
	// derive from it, and Shutdown cancels it so in-flight uploads abort on
	// SIGTERM instead of surviving until the client disconnects (QLT-011).
	ctx, cancel := context.WithCancel(context.Background())

	// Extract accounts for faster lookup
	accounts := make(map[string]*config.AccountConfig)
	for i := range cfg.Accounts {
		accounts[cfg.Accounts[i].Username] = &cfg.Accounts[i]
	}

	// Create one transfer manager per account for path mapping and collision
	// handling. Each manager gets a WebDAV client built from that account's
	// oCIS credentials so collision checks and directory creation run against
	// the same oCIS endpoint the uploads target.
	transferMgrs := make(map[string]*transfer.TransferManager, len(cfg.Accounts))
	for i := range cfg.Accounts {
		account := &cfg.Accounts[i]
		webdavClient := webdav.NewClientWithCredentials(
			cfg.OCIS.WebDAVURL,
			account.OCIS.Username,
			account.AppToken,
		)
		transferMgr := transfer.NewTransferManagerWithWebDAV(ctx, webdavClient)
		transferMgr.AddTarget(account.Username, transfer.TargetConfig{
			DriveID:         account.Target.DriveID,
			Drive:           account.Target.Drive,
			Root:            account.Target.Root,
			CollisionPolicy: transfer.CollisionPolicy(account.Upload.CollisionPolicy),
			MaxSize:         uint64(account.Upload.MaxSize),
		})
		transferMgrs[account.Username] = transferMgr
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

	d := &BridgeDriver{
		cfg:                cfg,
		obs:                obs,
		spoolManager:       spoolManager,
		transferManagers:   transferMgrs,
		accounts:           accounts,
		driveCache:         make(map[string]driveCacheEntry),
		clients:            make(map[uint32]*bridgeClientDriver),
		allowedConnections: make(map[uint32]bool),
		maxConnections:     cfg.Server.MaxConnections,
		connectionTracker:  connTracker,
		authAttemptTracker: authTracker,
		authSemaphore:  make(chan struct{}, 4), // Max 4 concurrent Argon2id verifications
		ctx:           ctx,
		cancel:        cancel,
		shutdownChan:  make(chan struct{}),
	}
	d.startTrackerJanitor()
	return d
}

// recordUploadFailure records an upload failure in both the internal counter
// and Prometheus metrics (if configured). See issue #115.
func (d *BridgeDriver) recordUploadFailure(reason string, duration time.Duration) {
	atomic.AddUint64(&d.uploadsFailed, 1)
	if d.metrics != nil {
		d.metrics.IncrementUploadsTotal("failure")
		d.metrics.IncrementUploadFailuresTotal(reason)
		d.metrics.ObserveUploadDuration(duration, "failure")
	}
}

// SetMetricsRecorder sets the metrics recorder for Prometheus metrics.
// Called during server initialization to wire up observability. See issue #115.
func (d *BridgeDriver) SetMetricsRecorder(m MetricsRecorder) {
	d.metrics = m
}

// trackerSweepInterval is how often the rate-limiting trackers are swept
// for expired entries (SEC-012).
const trackerSweepInterval = time.Minute

// startTrackerJanitor periodically sweeps the rate-limiting trackers so
// entries for source IPs that never return are evicted (SEC-012). It stops
// when the driver lifecycle context is cancelled.
func (d *BridgeDriver) startTrackerJanitor() {
	if d.connectionTracker == nil && d.authAttemptTracker == nil {
		return
	}

	go func() {
		ticker := time.NewTicker(trackerSweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-d.ctx.Done():
				return
			case <-ticker.C:
				d.connectionTracker.sweep()
				d.authAttemptTracker.sweep()
			}
		}
	}()
}

// transferManagerFor returns the transfer manager for the given account, or
// nil if the account has no target configuration.
func (d *BridgeDriver) transferManagerFor(user string) *transfer.TransferManager {
	return d.transferManagers[user]
}

// =========================================================================
// MainDriver Interface Implementation
// =========================================================================

// AuthUser is called when USER command is received. Returns a ClientDriver
// if authentication succeeds.
func (d *BridgeDriver) AuthUser(cc ftpserver.ClientContext, user, password string) (ftpserver.ClientDriver, error) {
	// Get client IP for rate limiting (strip ephemeral port)
	clientIP := extractClientIP(cc.RemoteAddr().String())

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

	// Check global connection limit
	if d.maxConnections > 0 {
		current := atomic.LoadInt64(&d.activeConnections)
		if current >= int64(d.maxConnections) {
			return nil, fmt.Errorf("server connection limit reached")
		}
	}

	// Bound concurrent Argon2id verifications to prevent memory exhaustion.
	// Each verification allocates ~64 MiB; the semaphore limits this to 4
	// concurrent verifications (~256 MiB max). See issue #111.
	select {
	case d.authSemaphore <- struct{}{}:
		defer func() { <-d.authSemaphore }()
	default:
		return nil, fmt.Errorf("too many concurrent authentication attempts, try again later")
	}

	// Authenticate user
	account, err := d.authenticateUser(user, password)
	if err != nil {
		d.obs.Log("info", fmt.Sprintf("FTP authentication failed for user %s: %v", user, err))
		// Record failed authentication attempt for rate limiting
		if d.authAttemptTracker != nil {
			d.authAttemptTracker.RecordAuthAttempt(clientIP, false)
		}
		if d.metrics != nil {
			d.metrics.IncrementFTPSessionTotal("failure")
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

	// Create WebDAV client for this account using the resolved drive's URL.
	// Using the drive-specific URL ensures uploads land in the correct
	// project space, not the service user's personal space. See issue #107.
	webdavBaseURL := resolvedDrive.WebDAVURL
	if webdavBaseURL == "" {
		// Fallback to the global config if the drive didn't provide a URL
		webdavBaseURL = d.cfg.OCIS.WebDAVURL
	}
	webdavClient := webdav.NewClientWithCredentials(
		webdavBaseURL,
		account.OCIS.Username,
		account.AppToken,
	)

	// Create client-specific driver
	clientDriver := &bridgeClientDriver{
		bridgeDriver:  d,
		account:       account,
		resolvedDrive: &resolvedDrive,
		user:          user,
		webdavClient:  webdavClient,
		spoolUploads:  make(map[string]*spoolUpload),
		uploadCounter: 0,
		context:       context.Background(),
		cancel:        func() {},
	}

	// Create the session context derived from the driver lifecycle so the
	// session is cancelled when the client disconnects or the driver shuts
	// down (QLT-011)
	clientDriver.context, clientDriver.cancel = context.WithCancel(d.ctx)

	// Track the session so its context is cancelled when the client disconnects
	d.mu.Lock()
	d.clients[cc.ID()] = clientDriver
	d.mu.Unlock()

	// Record successful authentication attempt for rate limiting
	if d.authAttemptTracker != nil {
		d.authAttemptTracker.RecordAuthAttempt(clientIP, true)
	}

	// The connection is already counted by ClientConnected, which follows
	// the socket lifecycle. Counting it again here would leak +1 per
	// authenticated session and eventually lock out all logins once the
	// counter reaches max_connections (SEC-004).

	d.obs.Log("info", fmt.Sprintf("FTP authentication successful for user %s (oCIS: %s)", user, account.OCIS.Username))

	// Record session metric
	if d.metrics != nil {
		d.metrics.IncrementFTPSessionTotal("success")
		d.metrics.SetFTPActiveSessions(float64(atomic.LoadInt64(&d.activeConnections)))
	}

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
	// Connection tracking is handled in ClientConnected/ClientDisconnected
	// to follow the actual socket lifecycle, not the authentication lifecycle.
	d.obs.Log("info", fmt.Sprintf("FTP client logged out (ID: %d, addr: %s)", client.ID(), client.RemoteAddr().String()))
	return nil
}

// GetSettings returns the server settings.
func (d *BridgeDriver) GetSettings() (*ftpserver.Settings, error) {
	// Log warning if plain FTP is enabled (insecure)
	if !d.cfg.Server.TLS.Enabled {
		d.obs.Log("warn", "Plain FTP is enabled! Credentials and data will be transmitted in cleartext. This is a security risk. Enable TLS for production use.")
	}

	// Make the active-mode residual risk visible at startup: the server
	// dials the client's own IP on a client-chosen port (SEC-005).
	if d.cfg.Server.AllowActiveMode {
		d.obs.Log("info", "FTP active mode (PORT/EPRT) is enabled: the server dials the client's own IP on a client-chosen port; restrict egress with a firewall (SEC-005)")
	}

	settings := &ftpserver.Settings{
		ListenAddr:        d.cfg.Server.Listen,
		PublicHost:        d.cfg.Server.Passive.PublicIP,
		IdleTimeout:       300, // 5 minutes
		ConnectionTimeout: 60,
		PassiveTransferPortRange: ftpserver.PortRange{
			Start: d.cfg.Server.Passive.MinPort,
			End:   d.cfg.Server.Passive.MaxPort,
		},
		DisableMLSD:             false,
		DisableMLST:             false,
		DisableMFMT:             true, // Disable features not needed for printers
		DisableSTAT:             true,
		DisableSYST:             false,
		ActiveTransferPortNon20: true,
		DefaultTransferType:     ftpserver.TransferTypeBinary,
		TLSRequired: func() ftpserver.TLSRequirement {
			if d.cfg.Server.TLS.Enabled {
				return ftpserver.TLSRequirement(1) // Required = 1
			}
			return ftpserver.TLSRequirement(0) // ClearOrEncrypted = 0
		}(),
		DisableActiveMode: !d.cfg.Server.AllowActiveMode,
		// SEC-005: require the data-connection peer IP to match the control
		// connection peer IP for both active and passive transfers. Set
		// explicitly instead of relying on the library's zero value.
		ActiveConnectionsCheck: ftpserver.IPMatchRequired,
		PasvConnectionsCheck:   ftpserver.IPMatchRequired,
		DisableSite:            true,
		DisableLISTArgs:        true,
	}
	return settings, nil
}

// GetTLSConfig returns TLS configuration for the FTP server.
func (d *BridgeDriver) GetTLSConfig() (*tls.Config, error) {
	if !d.cfg.Server.TLS.Enabled {
		// An error (not nil, nil) is required here: ftpserverlib's AUTH TLS
		// handler wraps the control connection in tls.Server whenever the error
		// is nil, and a nil *tls.Config crashes the server on the next read.
		return nil, fmt.Errorf("TLS is not enabled")
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
// Connection slots are acquired here (per TCP socket) so that clients
// cannot bypass limits by reconnecting, and unauthenticated connections
// are still counted.
func (d *BridgeDriver) ClientConnected(cc ftpserver.ClientContext) (string, error) {
	clientIP := extractClientIP(cc.RemoteAddr().String())

	// Acquire connection slot for rate limiting
	if d.connectionTracker != nil && !d.connectionTracker.AllowConnection(clientIP) {
		return "", fmt.Errorf("connection limit reached for this IP")
	}

	// Track that this connection was granted a slot, so ClientDisconnected
	// only releases slots that were actually acquired. See issue #116.
	d.mu.Lock()
	d.allowedConnections[cc.ID()] = true
	d.mu.Unlock()

	// Increment active connection counter
	atomic.AddInt64(&d.activeConnections, 1)

	// Update active sessions gauge
	if d.metrics != nil {
		d.metrics.SetFTPActiveSessions(float64(atomic.LoadInt64(&d.activeConnections)))
	}

	return "220 ocis-ftp-bridge ready", nil
}

// ClientDisconnected is called when a client disconnects.
// Connection slots are released here so they follow the actual socket lifecycle.
func (d *BridgeDriver) ClientDisconnected(cc ftpserver.ClientContext) {
	clientIP := extractClientIP(cc.RemoteAddr().String())

	// Cancel the session context so per-connection resources are released
	d.mu.Lock()
	clientDriver, registered := d.clients[cc.ID()]
	if registered {
		delete(d.clients, cc.ID())
	}
	// Only release the connection slot if it was actually acquired.
	// Rejected connections (limit reached) never held a slot. See issue #116.
	_, wasAllowed := d.allowedConnections[cc.ID()]
	if wasAllowed {
		delete(d.allowedConnections, cc.ID())
	}
	d.mu.Unlock()
	if registered {
		clientDriver.cancel()
	}

	// Release connection slot only if it was granted
	if wasAllowed && d.connectionTracker != nil {
		d.connectionTracker.ReleaseConnection(clientIP)
	}

	// Decrement connection counter
	atomic.AddInt64(&d.activeConnections, -1)

	// Update active sessions gauge
	if d.metrics != nil {
		d.metrics.SetFTPActiveSessions(float64(atomic.LoadInt64(&d.activeConnections)))
	}

	d.obs.Log("info", fmt.Sprintf("FTP client disconnected (ID: %d, addr: %s)", cc.ID(), cc.RemoteAddr().String()))
}

// Shutdown initiates server shutdown: it cancels the driver lifecycle
// context (aborting in-flight uploads, QLT-011) and signals shutdown. It is
// safe to call multiple times.
func (d *BridgeDriver) Shutdown() {
	d.shutdownOnce.Do(func() {
		close(d.shutdownChan)
		d.cancel()
	})

	d.obs.Log("info", "FTP server shutting down")
}

// IsShuttingDown returns true if the server is shutting down.
func (d *BridgeDriver) IsShuttingDown() bool {
	select {
	case <-d.shutdownChan:
		return true
	default:
		return false
	}
}

// =========================================================================
// BridgeClientDriver implements ClientDriver for account-scoped operations
// =========================================================================

// bridgeClientDriver handles FTP client sessions and implements ClientDriverExtensionFileTransfer
// to provide custom file upload handling without implementing the full afero.Fs interface.
type bridgeClientDriver struct {
	bridgeDriver  *BridgeDriver
	account       *config.AccountConfig
	resolvedDrive *graph.Drive
	user          string
	webdavClient  webdav.Client

	// Upload tracking
	spoolUploads  map[string]*spoolUpload
	uploadCounter uint64
	mu            sync.Mutex

	// Session management
	context context.Context
	cancel  context.CancelFunc
}

// spoolUpload tracks an active upload operation
type spoolUpload struct {
	upload    *spool.Upload
	fileRef   spool.FileRef
	startTime time.Time
	lastChunk time.Time
	path      string
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
	n, err = f.writer.Write(p)
	f.pos += int64(n)
	return n, err
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
func (fi *uploadFileInfo) Mode() os.FileMode  { return 0644 }
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
	// Virtual directory model: any path under the account root is a valid
	// directory. This makes CWD succeed for any path, and MKD is a no-op
	// (directories are created on-demand during upload). See issue #114.
	cleanPath := filepath.Clean(name)
	if cleanPath == "." || cleanPath == "/" {
		cleanPath = "/"
	}
	// Return virtual directory info for any path
	return &virtualDir{name: cleanPath}, nil
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

// acquireUploadSlot takes one of the account's concurrent-upload slots
// (PERF-004). Accounts without a configured cap are unlimited. It fails fast
// with ErrTooManyConcurrentUploads when the cap is reached, so the FTP client
// gets an immediate error instead of an ever-growing upload backlog.
func (d *BridgeDriver) acquireUploadSlot(account *config.AccountConfig) error {
	max := account.Upload.MaxConcurrentUploads
	if max <= 0 {
		return nil
	}
	d.uploadSlotsMu.Lock()
	if d.uploadSlots == nil {
		d.uploadSlots = make(map[string]chan struct{})
	}
	ch, ok := d.uploadSlots[account.Username]
	if !ok {
		ch = make(chan struct{}, max)
		d.uploadSlots[account.Username] = ch
	}
	d.uploadSlotsMu.Unlock()

	select {
	case ch <- struct{}{}:
		return nil
	default:
		return ErrTooManyConcurrentUploads
	}
}

// releaseUploadSlot returns one of the account's concurrent-upload slots. It
// is a no-op for uncapped accounts and for slots that were never taken.
func (d *BridgeDriver) releaseUploadSlot(account *config.AccountConfig) {
	if account.Upload.MaxConcurrentUploads <= 0 {
		return
	}
	d.uploadSlotsMu.Lock()
	ch := d.uploadSlots[account.Username]
	d.uploadSlotsMu.Unlock()
	if ch == nil {
		return
	}
	select {
	case <-ch:
	default:
	}
}

// handleUploadOpen is called when a client sends STOR command
func (c *bridgeClientDriver) handleUploadOpen(path string) (*uploadWriter, error) {
	// Use transfer manager for proper path mapping and collision handling
	filename := filepath.Base(path)

	// The ftpserver library always passes absolute paths; the transfer manager
	// expects paths relative to the account's target root (the FTP namespace
	// root "/" maps to the target root), so strip the leading slash.
	relDir := strings.TrimPrefix(filepath.Dir(path), "/")

	// Create transfer request
	request := transfer.TransferRequest{
		UserID:   c.user,
		Filename: filename,
		Path:     relDir,
		Size:     -1, // unknown size initially
	}

	// Process the upload request to get the final target path
	transferMgr := c.bridgeDriver.transferManagerFor(c.user)
	if transferMgr == nil {
		return nil, fmt.Errorf("no transfer configuration for user %s", c.user)
	}
	transferResult := transferMgr.ProcessUpload(request)
	if !transferResult.Success {
		c.bridgeDriver.obs.Log("warn", fmt.Sprintf("Transfer processing failed for user %s, path %s: %v",
			c.user, path, transferResult.Error))
		return nil, transferResult.Error
	}

	// Enforce the per-account concurrent upload cap (PERF-004)
	if err := c.bridgeDriver.acquireUploadSlot(c.account); err != nil {
		c.bridgeDriver.obs.Log("warn", fmt.Sprintf("Upload rejected for user %s, path %s: %v", c.user, path, err))
		return nil, err
	}

	// Generate a unique upload ID
	uploadID := c.generateUploadID()

	// Start the upload in spool using the resolved target path
	uploadManager := c.bridgeDriver.spoolManager.GetUploadManager()

	upload, err := uploadManager.StartUpload(
		c.context,
		c.user,
		transferResult.Filename,          // final filename (may be modified for collision handling)
		transferResult.TargetPath,        // final target path
		-1,                               // unknown size initially, will be updated as we receive data
		uint64(c.account.Upload.MaxSize), // account max size
	)
	if err != nil {
		c.bridgeDriver.releaseUploadSlot(c.account)
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
		uploadID:     uploadID,
		upload:       upload,
		spoolUpload:  spoolUpload,
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
	// writeErr is the first chunk write error, if any. Close aborts the
	// upload instead of committing a partial file when it is set.
	writeErr error
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
	// #nosec G115 -- AccountMaxSize is validated <= math.MaxInt64 in spool StartUpload and config validation
	if w.upload.BytesReceived+int64(len(p)) > int64(w.upload.AccountMaxSize) {
		return 0, spool.ErrFileTooLarge
	}

	// Write to spool
	n, err = w.clientDriver.bridgeDriver.spoolManager.GetUploadManager().WriteChunk(w.upload, p)
	if err != nil {
		// Remember the first write error so Close aborts the upload instead
		// of committing a partial file
		if w.writeErr == nil {
			w.writeErr = err
		}
		w.clientDriver.bridgeDriver.obs.Log("error", fmt.Sprintf("Upload write failed for user %s, upload %s: %v", w.clientDriver.user, w.uploadID, err))
		return n, err
	}

	return n, nil
}

// Close is called when the upload is complete or aborted
func (w *uploadWriter) Close() error {
	// Release the per-account upload slot on every Close path: ftpserverlib
	// closes the file exactly once when the transfer ends (success, write
	// error, or disconnect) (PERF-004).
	defer w.clientDriver.bridgeDriver.releaseUploadSlot(w.clientDriver.account)

	// If any chunk write failed the upload is incomplete: abort it instead
	// of committing a partial file to oCIS
	if w.writeErr != nil {
		w.clientDriver.bridgeDriver.obs.Log("warn", fmt.Sprintf("Aborting upload %s for user %s after write error: %v",
			w.uploadID, w.clientDriver.user, w.writeErr))
		if err := w.clientDriver.bridgeDriver.spoolManager.GetUploadManager().AbortUpload(w.upload); err != nil {
			w.clientDriver.bridgeDriver.obs.Log("warn", fmt.Sprintf("Upload abort failed for user %s, upload %s: %v", w.clientDriver.user, w.uploadID, err))
		}

		// Clean up tracking
		w.clientDriver.mu.Lock()
		delete(w.clientDriver.spoolUploads, w.uploadID)
		w.clientDriver.mu.Unlock()

		w.clientDriver.bridgeDriver.recordUploadFailure("aborted", time.Since(w.spoolUpload.startTime))
		return w.writeErr
	}

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
			w.clientDriver.bridgeDriver.recordUploadFailure("finish_error", time.Since(w.spoolUpload.startTime))
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
			w.clientDriver.bridgeDriver.recordUploadFailure("webdav_error", time.Since(w.spoolUpload.startTime))
			return err
		}

		// WebDAV commit succeeded - FTP transfer can now be considered successful
		w.clientDriver.bridgeDriver.obs.Log("info", fmt.Sprintf("Upload and WebDAV commit succeeded for user %s, upload %s, file %s, size %d",
			w.clientDriver.user, w.uploadID, fileRef.FileID, fileRef.Size))

		// Clean up spool file since it's now safely in oCIS
		w.clientDriver.bridgeDriver.spoolManager.DeleteByPath(fileRef.Path)

		// Update metrics
		atomic.AddUint64(&w.clientDriver.bridgeDriver.uploadsSuccess, 1)
		if fileRef.Size > 0 {
			atomic.AddUint64(&w.clientDriver.bridgeDriver.totalBytesUploaded, uint64(fileRef.Size))
		}

		// Record Prometheus metrics. See issue #115.
		if w.clientDriver.bridgeDriver.metrics != nil {
			w.clientDriver.bridgeDriver.metrics.IncrementUploadsTotal("success")
			// #nosec G115 -- fileRef.Size is validated non-negative by spool manager
			w.clientDriver.bridgeDriver.metrics.AddUploadBytes(uint64(fileRef.Size))
			w.clientDriver.bridgeDriver.metrics.ObserveUploadDuration(time.Since(w.spoolUpload.startTime), "success")
		}

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

		w.clientDriver.bridgeDriver.recordUploadFailure("incomplete", time.Since(w.spoolUpload.startTime))
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
	transferMgr := w.clientDriver.bridgeDriver.transferManagerFor(w.clientDriver.user)
	if transferMgr == nil {
		return fmt.Errorf("no transfer configuration for user %s", w.clientDriver.user)
	}
	if err := transferMgr.EnsureParentDirectories(finalPath); err != nil {
		return fmt.Errorf("failed to ensure parent directories: %w", err)
	}

	// Upload to WebDAV with retry on 412 conflict for rename policy.
	// Concurrent uploads of the same filename can race: both pick the same
	// unique name before either writes to WebDAV. The loser gets a 412
	// (If-None-Match) and should retry with the next unique name. See issue #110.
	const maxRetries = 3
	uploadPath := finalPath
	isRenamePolicy := transfer.CollisionPolicy(w.clientDriver.account.Upload.CollisionPolicy) == transfer.CollisionPolicyRename

	for attempt := 0; attempt < maxRetries; attempt++ {
		// Open the spooled file and stream it to WebDAV. The file must never be
		// read fully into memory: a 50 MiB upload with up to max_connections
		// concurrent sessions would otherwise buffer several GiB transiently and
		// get the container OOM-killed (SEC-003).
		spooledFile, err := os.Open(fileRef.Path)
		if err != nil {
			return fmt.Errorf("failed to open spooled file for WebDAV upload: %w", err)
		}

		// The collision policy was already applied during path resolution. Only the
		// explicit "overwrite" policy may replace an existing object; for rename and
		// reject the PUT carries If-None-Match so an object that appeared after
		// resolution fails with a conflict instead of silently overwriting it.
		overwrite := transfer.CollisionPolicy(w.clientDriver.account.Upload.CollisionPolicy) == transfer.CollisionPolicyOverwrite
		err = w.clientDriver.webdavClient.UploadStream(w.clientDriver.context, uploadPath, spooledFile, fileRef.Size, overwrite)
		spooledFile.Close()
		if err == nil {
			// Success - update the spool upload path if we retried
			if attempt > 0 {
				w.spoolUpload.path = uploadPath
			}
			return nil
		}

		// On conflict (412) with rename policy, retry with a new unique name
		if isRenamePolicy && attempt < maxRetries-1 {
			// Generate a new unique path by appending a counter
			dir := filepath.Dir(uploadPath)
			base := filepath.Base(uploadPath)
			ext := filepath.Ext(base)
			name := strings.TrimSuffix(base, ext)
			uploadPath = filepath.Join(dir, fmt.Sprintf("%s-%d%s", name, attempt+2, ext))
			continue
		}

		return fmt.Errorf("WebDAV upload failed: %w", err)
	}

	return fmt.Errorf("WebDAV upload failed after %d retries", maxRetries)
}

// =========================================================================
// Authentication and Account Resolution
// =========================================================================

// dummyPasswordHash is a valid Argon2id PHC string (the hash of a random
// throwaway secret). It is verified when the username does not exist so an
// unknown user pays the same Argon2id cost as a known one and response
// timing does not reveal whether the username is valid (SEC-011, CWE-204).
// #nosec G101 -- not a credential: hash of a random throwaway secret, used only to equalize auth timing
var dummyPasswordHash = "$argon2id$v=19$m=65536,t=3,p=4$V2HEceVvtTsIpU6Wij92vw$n/WMbvGMAALmNM9yA18u19MLN7rn16akha2yqhAWQOo"

// authenticateUser authenticates an FTP user against configured accounts
func (d *BridgeDriver) authenticateUser(user, password string) (*config.AccountConfig, error) {
	account, exists := d.accounts[user]
	if !exists {
		// Burn the same Argon2id work as for a known user so response timing
		// does not reveal whether the username exists (SEC-011, CWE-204).
		if _, err := config.VerifyPassword(dummyPasswordHash, password); err != nil {
			return nil, ErrInvalidCredentials
		}
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

// driveResolutionCacheTTL bounds how long a resolved drive is reused before
// it is re-resolved against the Graph API. Drive targets change rarely, but
// the TTL keeps deletions and renames from going unnoticed (PERF-002).
var driveResolutionCacheTTL = 5 * time.Minute

// driveCacheEntry is a cached per-account drive resolution.
type driveCacheEntry struct {
	drive     graph.Drive
	expiresAt time.Time
}

// resolveDriveForAccount resolves the oCIS drive for an account. Successful
// resolutions are cached per account for driveResolutionCacheTTL so repeated
// logins do not each hit the Graph API. Failures are never cached — a 401
// (revoked app token) or 404 (deleted drive) re-resolves on the next login
// (PERF-002).
func (d *BridgeDriver) resolveDriveForAccount(account *config.AccountConfig) (graph.Drive, error) {
	if drive, ok := d.cachedDriveResolution(account.Username); ok {
		return drive, nil
	}

	drive, err := d.resolveDriveFresh(account)
	if err != nil {
		return graph.Drive{}, err
	}

	d.storeDriveResolution(account.Username, drive)
	return drive, nil
}

// cachedDriveResolution returns the cached resolution for the account if one
// exists and has not expired.
func (d *BridgeDriver) cachedDriveResolution(username string) (graph.Drive, bool) {
	d.driveCacheMu.Lock()
	defer d.driveCacheMu.Unlock()
	entry, ok := d.driveCache[username]
	if !ok || time.Now().After(entry.expiresAt) {
		return graph.Drive{}, false
	}
	return entry.drive, true
}

// storeDriveResolution caches a successful resolution for the account.
func (d *BridgeDriver) storeDriveResolution(username string, drive graph.Drive) {
	d.driveCacheMu.Lock()
	defer d.driveCacheMu.Unlock()
	if d.driveCache == nil {
		d.driveCache = make(map[string]driveCacheEntry)
	}
	d.driveCache[username] = driveCacheEntry{
		drive:     drive,
		expiresAt: time.Now().Add(driveResolutionCacheTTL),
	}
}

// resolveDriveFresh resolves the account's drive against the Graph API
// without consulting the cache.
func (d *BridgeDriver) resolveDriveFresh(account *config.AccountConfig) (graph.Drive, error) {
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
func (d *virtualDir) Mode() os.FileMode  { return os.ModeDir | 0755 }
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
	ErrUploadCancelled    = fmt.Errorf("upload cancelled")
)
