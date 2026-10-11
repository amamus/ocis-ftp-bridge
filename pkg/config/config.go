// Package config loads and validates ocis-ftp-bridge configuration.
package config

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"gopkg.in/yaml.v3"
)

const redacted = "<redacted>"

type ByteSize uint64

func ParseByteSize(value string) (ByteSize, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, errors.New("byte size is empty")
	}
	units := []struct {
		suffix string
		factor uint64
	}{
		{"GiB", 1024 * 1024 * 1024},
		{"MiB", 1024 * 1024},
		{"KiB", 1024},
		{"B", 1},
	}
	for _, unit := range units {
		if strings.HasSuffix(value, unit.suffix) {
			n, err := strconv.ParseUint(strings.TrimSpace(strings.TrimSuffix(value, unit.suffix)), 10, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid byte size %q: %w", value, err)
			}
			if n > ^uint64(0)/unit.factor {
				return 0, fmt.Errorf("byte size %q overflows uint64", value)
			}
			return ByteSize(n * unit.factor), nil
		}
	}
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid byte size %q: expected B, KiB, MiB or GiB", value)
	}
	return ByteSize(n), nil
}

func (b *ByteSize) UnmarshalYAML(node *yaml.Node) error {
	size, err := ParseByteSize(node.Value)
	if err != nil {
		return err
	}
	*b = size
	return nil
}

type Config struct {
	Server        ServerConfig        `yaml:"server" json:"server"`
	OCIS          OCISConfig          `yaml:"ocis" json:"ocis"`
	Spool         SpoolConfig         `yaml:"spool" json:"spool"`
	Accounts      []AccountConfig     `yaml:"accounts" json:"accounts"`
	Observability ObservabilityConfig `yaml:"observability,omitempty" json:"observability,omitempty"`
	HTTP          HTTPConfig          `yaml:"http,omitempty" json:"http,omitempty"`
}

type ServerConfig struct {
	Listen        string        `yaml:"listen" json:"listen"`
	Passive       PassiveConfig `yaml:"passive" json:"passive"`
	TLS           TLSConfig     `yaml:"tls" json:"tls"`
	MaxConnections int         `yaml:"max_connections,omitempty" json:"max_connections,omitempty"`
	// Rate limiting configuration
	RateLimiting RateLimitConfig `yaml:"rate_limiting,omitempty" json:"rate_limiting,omitempty"`
}

type PassiveConfig struct {
	MinPort  int    `yaml:"min_port" json:"min_port"`
	MaxPort  int    `yaml:"max_port" json:"max_port"`
	PublicIP string `yaml:"public_ip,omitempty" json:"public_ip,omitempty"`
}

type TLSConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Cert    string `yaml:"cert,omitempty" json:"cert,omitempty"`
	Key     string `yaml:"key,omitempty" json:"key,omitempty"`
}

// RateLimitConfig defines rate limiting settings for FTP server
type RateLimitConfig struct {
	// Per-IP connection rate limiting
	MaxConnectionsPerIP int `yaml:"max_connections_per_ip,omitempty" json:"max_connections_per_ip,omitempty"`
	
	// Global connection limiting (overrides per-IP if lower)
	MaxGlobalConnections int `yaml:"max_global_connections,omitempty" json:"max_global_connections,omitempty"`
	
	// Authentication attempt rate limiting
	MaxAuthAttemptsPerIP int `yaml:"max_auth_attempts_per_ip,omitempty" json:"max_auth_attempts_per_ip,omitempty"`
	AuthAttemptWindow time.Duration `yaml:"auth_attempt_window,omitempty" json:"auth_attempt_window,omitempty"`
	AuthLockoutDuration time.Duration `yaml:"auth_lockout_duration,omitempty" json:"auth_lockout_duration,omitempty"`
	
	// IP lockout tracking
	TrackFailedAttempts bool `yaml:"track_failed_attempts,omitempty" json:"track_failed_attempts,omitempty"`
}

type OCISConfig struct {
	URL       string `yaml:"url" json:"url"`
	GraphURL  string `yaml:"graph_url,omitempty" json:"graph_url,omitempty"`
	WebDAVURL string `yaml:"webdav_url,omitempty" json:"webdav_url,omitempty"`
}

type SpoolConfig struct {
	Directory    string   `yaml:"directory" json:"directory"`
	MaxTotalSize ByteSize `yaml:"max_total_size" json:"max_total_size"`
	MaxSize      uint64   `yaml:"-" json:"-"`
	// Monitoring configuration
	Monitoring MonitoringConfig `yaml:"monitoring" json:"monitoring"`
}

// MonitoringConfig contains spool monitoring settings
type MonitoringConfig struct {
	// Enabled enables spool monitoring (default: true)
	Enabled bool `yaml:"enabled" json:"enabled"`
	// WarningThreshold is the percentage usage at which to log warnings (default: 80%)
	WarningThreshold float64 `yaml:"warning_threshold" json:"warning_threshold"`
	// CriticalThreshold is the percentage usage at which to log critical alerts (default: 95%)
	CriticalThreshold float64 `yaml:"critical_threshold" json:"critical_threshold"`
	// CheckInterval is how often to check spool usage (default: 30s)
	CheckInterval time.Duration `yaml:"check_interval" json:"check_interval"`
}

type AccountConfig struct {
	Username     string            `yaml:"username" json:"username"`
	PasswordHash string            `yaml:"password_hash" json:"-"`
	OCIS         AccountOCISConfig `yaml:"ocis" json:"ocis"`
	Target       TargetConfig      `yaml:"target" json:"target"`
	Upload       UploadConfig      `yaml:"upload" json:"upload"`
	AppToken     string            `yaml:"-" json:"-"`
}

type AccountOCISConfig struct {
	Username    string `yaml:"username" json:"username"`
	AppTokenEnv string `yaml:"app_token_env" json:"app_token_env"`
}

type TargetConfig struct {
	DriveID string `yaml:"drive_id,omitempty" json:"drive_id,omitempty"`
	Drive   string `yaml:"drive,omitempty" json:"drive,omitempty"`
	Root    string `yaml:"root" json:"root"`
}

type UploadConfig struct {
	CollisionPolicy string   `yaml:"collision_policy" json:"collision_policy"`
	MaxSize         ByteSize `yaml:"max_size" json:"max_size"`
}

// LoggerConfig contains configuration for the logger
type LoggerConfig struct {
	// Level is the minimum log level to output
	Level string `yaml:"level,omitempty" json:"level,omitempty"`
	// Format is the output format: "text" or "json"
	Format string `yaml:"format,omitempty" json:"format,omitempty"`
	// Output is the output destination: "stdout", "stderr", or a file path
	Output string `yaml:"output,omitempty" json:"output,omitempty"`
	// AddSource adds source file and line to log records
	AddSource bool `yaml:"add_source,omitempty" json:"add_source,omitempty"`
}

// ObservabilityConfig contains configuration for observability
type ObservabilityConfig struct {
	Debug  bool        `yaml:"debug,omitempty" json:"debug,omitempty"`
	Logger LoggerConfig `yaml:"logger,omitempty" json:"logger,omitempty"`
}

type HTTPConfig struct {
	Address string `yaml:"address,omitempty" json:"address,omitempty"`
	// Authentication settings for HTTP endpoints
	Auth HTTPAuthConfig `yaml:"auth,omitempty" json:"auth,omitempty"`
}

type HTTPAuthConfig struct {
	// Enable authentication for HTTP endpoints
	Enabled bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	// Authentication method: "basic", "bearer", "none"
	Method string `yaml:"method,omitempty" json:"method,omitempty"`
	// Basic authentication credentials
	Username string `yaml:"username,omitempty" json:"username,omitempty"`
	Password string `yaml:"password,omitempty" json:"-"`
	// Bearer token authentication
	BearerToken string `yaml:"bearer_token,omitempty" json:"-"`
	// Token can also be sourced from environment variable
	BearerTokenEnv string `yaml:"bearer_token_env,omitempty" json:"bearer_token_env,omitempty"`
}

func New() *Config {
	return &Config{
		Server: ServerConfig{
			Listen:          ":2121",
			Passive:         PassiveConfig{MinPort: 40000, MaxPort: 50000},
			MaxConnections:  100,
			// TLS is enabled by default for security
			// Plain FTP (unencrypted) is insecure and should be avoided
			TLS: TLSConfig{
				Enabled: true,  // TLS is enabled by default for security
				Cert:    "", // Will be validated at startup if enabled
				Key:     "", // Will be validated at startup if enabled
			},
			RateLimiting: RateLimitConfig{
				MaxConnectionsPerIP:   10,    // Max 10 connections per IP
				MaxGlobalConnections:  100,   // Max 100 total connections
				MaxAuthAttemptsPerIP:  5,     // Max 5 auth attempts per IP per window
				AuthAttemptWindow:     time.Minute, // 1 minute window for auth attempts
				AuthLockoutDuration:   5 * time.Minute, // 5 minute lockout after max attempts
				TrackFailedAttempts:   true,   // Track failed auth attempts for rate limiting
			},
		},
		OCIS: OCISConfig{
			URL:       "http://localhost:9200",
			GraphURL:  "http://localhost:9200/api/libregraph",
			WebDAVURL: "http://localhost:9200/webdav",
		},
		Spool: SpoolConfig{
			Directory:    "/var/tmp/ocis-ftp-bridge-spool",
			MaxTotalSize: ByteSize(1024 * 1024 * 1024),
			MaxSize:      1024 * 1024 * 1024,
			Monitoring: MonitoringConfig{
				Enabled:           true,
				WarningThreshold:  80.0,  // Warn at 80% usage
				CriticalThreshold: 95.0,  // Alert at 95% usage
				CheckInterval:     30 * time.Second, // Check every 30 seconds
			},
		},
		HTTP: HTTPConfig{
			Address: ":9090",
			Auth: HTTPAuthConfig{
				Enabled: true,  // Authentication enabled by default for security
				Method:  "basic",
				Username: "admin",
				// Password will be randomly generated on first run if not specified
			},
		},
	}
}

// checkForPlaintextCredentials scans the config file for potential plaintext credentials
// This is a best-effort check to warn users about potential security issues
func checkForPlaintextCredentials(filename string) error {
	// Read the raw file content
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil // Can't read, skip check
	}
	
	content := string(data)
	
	// Check for common patterns that might indicate plaintext passwords
	// These are heuristic checks and may have false positives
	passwordPatterns := []string{
		"password:",
		"password: ",
		"passwd:",
		"passwd: ",
		"secret:",
		"secret: ",
		"token:",
		"token: ",
	}
	
	// Check for plaintext passwords that look like common passwords
	// These are weak checks but can catch obvious issues
	commonPasswords := []string{
		"password",
		"123456",
		"qwerty",
		"admin",
		"letmein",
		"welcome",
		"secret",
		"changeme",
	}
	
	for _, pattern := range passwordPatterns {
		if strings.Contains(content, pattern) {
			// Check if it's followed by what looks like a plaintext password
			lines := strings.Split(content, "\n")
			for _, line := range lines {
				if strings.Contains(line, pattern) {
					// Extract the value after the pattern
					parts := strings.SplitN(line, ":", 2)
					if len(parts) > 1 {
						value := strings.TrimSpace(parts[1])
						// Skip if it looks like a hash (starts with $)
						if strings.HasPrefix(value, "$") {
							continue
						}
						// Skip if it's empty or in quotes (might be a reference)
						if value == "" || strings.HasPrefix(value, "\"") || strings.HasPrefix(value, "'") {
							continue
						}
						// Check if it matches a common password
						for _, commonPW := range commonPasswords {
							if strings.EqualFold(value, commonPW) {
								return fmt.Errorf("potential plaintext password detected: %s", pattern)
							}
						}
						// Check if it looks like a base64 token (common for oCIS tokens)
						if len(value) > 20 && !strings.ContainsAny(value, " \t\n") {
							// This might be a token - warn about it
							return fmt.Errorf("potential plaintext credential detected: %s", pattern)
						}
					}
				}
			}
		}
	}
	
	return nil
}

func LoadFile(filename string) (*Config, error) {
	return LoadFileWithEnv(filename, os.LookupEnv)
}

func LoadFileWithEnv(filename string, lookupEnv func(string) (string, bool)) (*Config, error) {
	if strings.TrimSpace(filename) == "" {
		return nil, errors.New("configuration file path is required")
	}

	// Security check: warn if config file contains potential plaintext passwords.
	// This must run before KnownFields(true) decoding so that unknown credential
	// keys (e.g. "password:") are caught by the scanner rather than silently
	// rejected by strict field validation before the check can run.
	if err := checkForPlaintextCredentials(filename); err != nil {
		slog.Warn("Potential security issue in configuration", "file", filename, "error", err)
	}

	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("open configuration %q: %w", filename, err)
	}
	defer f.Close()

	cfg := New()
	dec := yaml.NewDecoder(f)

	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("decode configuration %q: %w", filename, err)
	}

	accountsMap := make(map[string]bool, len(cfg.Accounts))
	for i := range cfg.Accounts {
		account := &cfg.Accounts[i]
		if strings.TrimSpace(account.Username) == "" {
			return nil, fmt.Errorf("accounts[%d].username is required", i)
		}
		if _, exists := accountsMap[account.Username]; exists {
			return nil, fmt.Errorf("duplicate FTP username %q", account.Username)
		}
		accountsMap[account.Username] = true
	}

	if err := cfg.validateWithEnv(lookupEnv); err != nil {
		return nil, fmt.Errorf("validate configuration %q: %w", filename, err)
	}
	return cfg, nil
}

func (c *Config) Validate() error {
	return c.validateWithEnv(os.LookupEnv)
}

func (c *Config) validateWithEnv(lookupEnv func(string) (string, bool)) error {
	if c == nil {
		return errors.New("configuration is nil")
	}
	if strings.TrimSpace(c.Server.Listen) == "" {
		return errors.New("server.listen is required")
	}
	if err := validateServerListenAddress(c.Server.Listen); err != nil {
		return fmt.Errorf("server.listen: %w", err)
	}
	if err := validatePassive(c.Server.Passive); err != nil {
		return err
	}
	if c.Server.TLS.Enabled && (strings.TrimSpace(c.Server.TLS.Cert) == "" || strings.TrimSpace(c.Server.TLS.Key) == "") {
		return errors.New("server.tls.cert and server.tls.key are required when TLS is enabled")
	}
	if err := c.validateOCIS(); err != nil {
		return err
	}
	
	// Validate HTTP configuration
	if err := c.validateHTTP(lookupEnv); err != nil {
		return err
	}
	if !filepath.IsAbs(c.Spool.Directory) {
		return fmt.Errorf("spool.directory must be an absolute path: %q", c.Spool.Directory)
	}
	if c.Spool.MaxTotalSize == 0 && c.Spool.MaxSize > 0 {
		c.Spool.MaxTotalSize = ByteSize(c.Spool.MaxSize)
	}
	if c.Spool.MaxTotalSize == 0 {
		return errors.New("spool.max_total_size must be greater than zero")
	}
	c.Spool.MaxSize = uint64(c.Spool.MaxTotalSize)

	seen := make(map[string]struct{}, len(c.Accounts))
	for i := range c.Accounts {
		account := &c.Accounts[i]
		prefix := fmt.Sprintf("accounts[%d]", i)
		if strings.TrimSpace(account.Username) == "" {
			return fmt.Errorf("%s.username is required", prefix)
		}
		if _, ok := seen[account.Username]; ok {
			return fmt.Errorf("duplicate FTP username %q", account.Username)
		}
		seen[account.Username] = struct{}{}

		// Validate password hash
		if _, err := parseArgon2ID(account.PasswordHash); err != nil {
			return fmt.Errorf("%s.password_hash: %w", prefix, err)
		}
		
		// Check for known example/test password hashes
		// These are commonly used in examples and should not be used in production
	exampleHashes := []string{
			"$argon2id$v=19$m=65536,t=3,p=1$MDEyMzQ1Njc4OWFiY2RlZg$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			"$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJC1OeqncgJ2almHUfLnhtRTVrjD8zGQ",
		}
		for _, exampleHash := range exampleHashes {
			if strings.Contains(account.PasswordHash, exampleHash) {
				return fmt.Errorf("%s.password_hash: example/default hash detected. Generate a unique hash for production use", prefix)
			}
		}
		if strings.TrimSpace(account.OCIS.Username) == "" {
			return fmt.Errorf("%s.ocis.username is required", prefix)
		}
		if strings.TrimSpace(account.OCIS.AppTokenEnv) == "" {
			return fmt.Errorf("%s.ocis.app_token_env is required", prefix)
		}
		token, ok := lookupEnv(account.OCIS.AppTokenEnv)
		if !ok || strings.TrimSpace(token) == "" {
			return fmt.Errorf("%s.ocis.app_token_env %q is not set or empty", prefix, account.OCIS.AppTokenEnv)
		}
		account.AppToken = token

		if strings.TrimSpace(account.Target.DriveID) == "" && strings.TrimSpace(account.Target.Drive) == "" {
			return fmt.Errorf("%s.target requires drive_id or drive", prefix)
		}
		root, err := normalizeTargetRoot(account.Target.Root)
		if err != nil {
			return fmt.Errorf("%s.target.root: %w", prefix, err)
		}
		account.Target.Root = root

		switch account.Upload.CollisionPolicy {
		case "rename", "reject", "overwrite":
		default:
			return fmt.Errorf("%s.upload.collision_policy %q is invalid; expected rename, reject or overwrite", prefix, account.Upload.CollisionPolicy)
		}
		if account.Upload.MaxSize == 0 {
			return fmt.Errorf("%s.upload.max_size must be greater than zero", prefix)
		}
	}
	return nil
}

func (c *Config) validateHTTP(lookupEnv func(string) (string, bool)) error {
	// Validate HTTP auth configuration if enabled
	if c.HTTP.Auth.Enabled {
		switch c.HTTP.Auth.Method {
		case "basic":
			// Basic auth requires username and password
			if strings.TrimSpace(c.HTTP.Auth.Username) == "" {
				return fmt.Errorf("http.auth.username is required when http.auth.enabled=true and method=basic")
			}
			if strings.TrimSpace(c.HTTP.Auth.Password) == "" {
				// Check if we can generate a password later, but warn for now
				// We'll generate a random password if not provided
				c.HTTP.Auth.Password = "" // Will be generated at runtime
			}
		case "bearer":
			// Bearer auth requires token
			if strings.TrimSpace(c.HTTP.Auth.BearerToken) == "" && strings.TrimSpace(c.HTTP.Auth.BearerTokenEnv) == "" {
				return fmt.Errorf("http.auth.bearer_token or http.auth.bearer_token_env is required when http.auth.enabled=true and method=bearer")
			}
			if strings.TrimSpace(c.HTTP.Auth.BearerTokenEnv) != "" {
				token, ok := lookupEnv(c.HTTP.Auth.BearerTokenEnv)
				if !ok || strings.TrimSpace(token) == "" {
					return fmt.Errorf("http.auth.bearer_token_env %q is not set or empty", c.HTTP.Auth.BearerTokenEnv)
				}
				c.HTTP.Auth.BearerToken = token
			}
		case "none", "":
			// No authentication, but warn if enabled
			if c.HTTP.Auth.Enabled {
				return fmt.Errorf("http.auth.method is required when http.auth.enabled=true")
			}
		default:
			return fmt.Errorf("http.auth.method %q is invalid; expected basic, bearer, or none", c.HTTP.Auth.Method)
		}
	}
	
	return nil
}

func (c *Config) validateOCIS() error {
	if strings.TrimSpace(c.OCIS.URL) != "" {
		u, err := url.Parse(c.OCIS.URL)
		if err != nil || u.Scheme == "" || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("ocis.url %q must be an absolute http(s) URL", c.OCIS.URL)
		}
		base := strings.TrimRight(c.OCIS.URL, "/")
		if c.OCIS.GraphURL == "" {
			c.OCIS.GraphURL = base + "/api/libregraph"
		}
		if c.OCIS.WebDAVURL == "" {
			c.OCIS.WebDAVURL = base + "/webdav"
		}
	}
	for name, raw := range map[string]string{"ocis.graph_url": c.OCIS.GraphURL, "ocis.webdav_url": c.OCIS.WebDAVURL} {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("%s %q must be an absolute http(s) URL", name, raw)
		}
	}
	return nil
}

// ValidateTLSConfig validates TLS configuration at startup
// This ensures that TLS certificates are valid before the server starts
func (c *Config) ValidateTLSConfig() error {
	if !c.Server.TLS.Enabled {
		// TLS is not enabled, nothing to validate
		return nil
	}

	// Check if certificate and key files are specified
	if strings.TrimSpace(c.Server.TLS.Cert) == "" {
		return fmt.Errorf("server.tls.cert is required when TLS is enabled")
	}
	if strings.TrimSpace(c.Server.TLS.Key) == "" {
		return fmt.Errorf("server.tls.key is required when TLS is enabled")
	}

	// Check if certificate file exists and is readable
	if _, err := os.Stat(c.Server.TLS.Cert); os.IsNotExist(err) {
		return fmt.Errorf("TLS certificate file not found: %s", c.Server.TLS.Cert)
	}
	if _, err := os.Stat(c.Server.TLS.Key); os.IsNotExist(err) {
		return fmt.Errorf("TLS key file not found: %s", c.Server.TLS.Key)
	}

	// Load and validate the certificate
	cert, err := tls.LoadX509KeyPair(c.Server.TLS.Cert, c.Server.TLS.Key)
	if err != nil {
		return fmt.Errorf("failed to load TLS certificate/key pair: %w", err)
	}

	// Parse the certificate to check for issues
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse TLS certificate: %w", err)
	}

	// Validate certificate expiration
	now := time.Now()
	if now.After(x509Cert.NotAfter) {
		return fmt.Errorf("TLS certificate expired on %s", x509Cert.NotAfter.Format(time.RFC3339))
	}
	if now.Before(x509Cert.NotBefore) {
		return fmt.Errorf("TLS certificate not yet valid (valid from %s)", x509Cert.NotBefore.Format(time.RFC3339))
	}

	// Validate certificate key strength
	switch pubKey := x509Cert.PublicKey.(type) {
	case *rsa.PublicKey:
		// rsa.PublicKey.Size() returns bytes, not bits; use N.BitLen() for bits.
		keyBits := pubKey.N.BitLen()
		if keyBits < 2048 {
			return fmt.Errorf("TLS certificate RSA key too weak: %d bits (minimum 2048)", keyBits)
		}
	case *ecdsa.PublicKey:
		// Check ECDSA curve strength
		// P-256, P-384, and P-521 are acceptable
		curveName := pubKey.Curve.Params().Name
		if curveName != "P-256" && curveName != "P-384" && curveName != "P-521" {
			return fmt.Errorf("TLS certificate uses unsupported ECDSA curve: %s", curveName)
		}
	case ed25519.PublicKey:
		// Ed25519 is acceptable
	default:
		return fmt.Errorf("TLS certificate uses unsupported public key type: %T", pubKey)
	}

	return nil
}

// validateServerListenAddress validates the server listen address format.
// Supports hostname:port, :port, IPv4:port, and [IPv6]:port including
// scoped IPv6 addresses with zone identifiers (e.g. [fe80::1%eth0]:2121).
func validateServerListenAddress(addr string) error {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return errors.New("address is required")
	}

	// Support both hostname:port and :port formats
	if !strings.Contains(addr, ":") {
		return fmt.Errorf("invalid address format %q: expected host:port or :port", addr)
	}

	// Split into host and port parts
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// If it starts with :, it might be just a port
		if strings.HasPrefix(addr, ":") {
			port = strings.TrimPrefix(addr, ":")
			host = ""
		} else {
			return fmt.Errorf("invalid address format %q: %w", addr, err)
		}
	}

	// Validate port
	if port == "" {
		return errors.New("port is required")
	}
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("invalid port %q: %w", port, err)
	}
	if portNum < 1 || portNum > 65535 {
		return fmt.Errorf("port %d must be between 1 and 65535", portNum)
	}

	// Validate host if provided
	if host != "" && host != "0.0.0.0" && host != "::" && host != "*" {
		// Strip IPv6 zone identifier (e.g. fe80::1%eth0 -> fe80::1) before parsing
		hostForParse := host
		if idx := strings.Index(hostForParse, "%"); idx >= 0 {
			hostForParse = hostForParse[:idx]
		}
		if ip := net.ParseIP(hostForParse); ip == nil {
			// Check if it's a valid hostname
			if !isValidHostname(host) {
				return fmt.Errorf("invalid hostname %q", host)
			}
		}
	}

	return nil
}

// isValidHostname checks if a string is a valid hostname
func isValidHostname(hostname string) bool {
	if len(hostname) > 253 {
		return false
	}

	labels := strings.Split(hostname, ".")
	if len(labels) == 0 {
		return false
	}

	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-') {
				return false
			}
		}
	}

	return true
}

func validatePassive(p PassiveConfig) error {
	if p.MinPort < 1 || p.MinPort > 65535 || p.MaxPort < 1 || p.MaxPort > 65535 || p.MinPort > p.MaxPort {
		return fmt.Errorf("server.passive port range %d-%d is invalid", p.MinPort, p.MaxPort)
	}
	if p.PublicIP != "" && net.ParseIP(p.PublicIP) == nil {
		return fmt.Errorf("server.passive.public_ip %q is invalid", p.PublicIP)
	}
	return nil
}

func normalizeTargetRoot(root string) (string, error) {
	if strings.TrimSpace(root) == "" || !strings.HasPrefix(root, "/") {
		return "", fmt.Errorf("must be an absolute path")
	}
	for _, part := range strings.Split(strings.ReplaceAll(root, "\\", "/"), "/") {
		if part == ".." {
			return "", errors.New("path traversal is not allowed")
		}
	}
	return path.Clean(root), nil
}

type argon2Params struct {
	memory  uint32
	time    uint32
	threads uint8
	salt    []byte
	hash    []byte
}

func parseArgon2ID(encoded string) (argon2Params, error) {
	var p argon2Params
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return p, errors.New("must be a valid Argon2id PHC string using version 19")
	}
	var threads uint64
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memory, &p.time, &threads); err != nil || p.memory == 0 || p.time == 0 || threads == 0 || threads > 255 {
		return p, errors.New("invalid Argon2id parameters")
	}
	p.threads = uint8(threads)
	var err error
	p.salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(p.salt) < 8 {
		if err == nil {
			return p, errors.New("invalid Argon2id salt")
		}
		return p, fmt.Errorf("invalid Argon2id salt: %w", err)
	}
	p.hash, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(p.hash) < 16 {
		if err == nil {
			return p, errors.New("invalid Argon2id digest")
		}
		return p, fmt.Errorf("invalid Argon2id digest: %w", err)
	}
	return p, nil
}

func VerifyPassword(encodedHash, password string) (bool, error) {
	p, err := parseArgon2ID(encodedHash)
	if err != nil {
		return false, err
	}
	actual := argon2.IDKey([]byte(password), p.salt, p.time, p.memory, p.threads, uint32(len(p.hash)))
	return subtle.ConstantTimeCompare(actual, p.hash) == 1, nil
}

func (a AccountConfig) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("username", a.Username),
		slog.String("password_hash", redacted),
		slog.Group("ocis",
			slog.String("username", a.OCIS.Username),
			slog.String("app_token_env", a.OCIS.AppTokenEnv),
			slog.String("app_token", redacted),
		),
		slog.String("target_root", a.Target.Root),
	)
}

func (a AccountConfig) String() string {
	return fmt.Sprintf("AccountConfig{Username:%q PasswordHash:%s OCISUsername:%q AppToken:%s TargetRoot:%q}",
		a.Username, redacted, a.OCIS.Username, redacted, a.Target.Root)
}

func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("listen", c.Server.Listen),
		slog.String("ocis_url", c.OCIS.URL),
		slog.String("spool_directory", c.Spool.Directory),
		slog.Int("account_count", len(c.Accounts)),
	)
}

func (c Config) String() string {
	return fmt.Sprintf("Config{Listen:%q OCISURL:%q SpoolDirectory:%q Accounts:%d secrets:%s}",
		c.Server.Listen, c.OCIS.URL, c.Spool.Directory, len(c.Accounts), redacted)
}
