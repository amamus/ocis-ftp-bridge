// Package config provides configuration management for ocis-ftp-bridge.
//
// It defines the configuration structure and validation logic
// for the FTP bridge service.
package config

// Config represents the configuration for ocis-ftp-bridge.
// It contains all necessary settings for the service to operate.
type Config struct {
	// Observability configuration
	Observability ObservabilityConfig `json:"observability"`
	
	// FTP configuration
	FTP FTPConfig `json:"ftp"`
	
	// HTTP server configuration
	HTTP HTTPConfig `json:"http"`
	
	// oCIS client configuration
	OCIS toCISConfig `json:"ocis"`
	
	// Spool configuration
	Spool SpoolConfig `json:"spool"`
}

// ObservabilityConfig contains observability settings.
type ObservabilityConfig struct {
	// Debug enables verbose logging
	Debug bool `json:"debug"`
}

// FTPConfig contains FTP server settings.
type FTPConfig struct {
	// Address is the listen address for the FTP server.
	Address string `json:"address"`
	
	// PassivePortsRange defines the range of ports for passive connections.
	PassivePortsRange string `json:"passive_ports_range"`
	
	// TLS enables FTPS.
	TLS TLSConfig `json:"tls"`
}

// TLSConfig contains TLS settings for FTPS.
type TLSConfig struct {
	// CertFile is the path to the TLS certificate.
	CertFile string `json:"cert_file"`
	
	// KeyFile is the path to the TLS private key.
	KeyFile string `json:"key_file"`
	
	// CAFile is the path to the CA certificate for client authentication.
	CAFile string `json:"ca_file"`
}

// HTTPConfig contains HTTP API server settings.
type HTTPConfig struct {
	// Address is the listen address for the HTTP server.
	Address string `json:"address"`
}

// toCISConfig contains oCIS client settings.
type toCISConfig struct {
	// GraphURL is the base URL for LibreGraph API.
	GraphURL string `json:"graph_url"`
	
	// WebDAVURL is the base URL for WebDAV API.
	WebDAVURL string `json:"webdav_url"`
	
	// OAuth2 configuration
	OAuth2 OAuth2Config `json:"oauth2"`
}

// OAuth2Config contains OAuth2 settings for authenticating with oCIS.
type OAuth2Config struct {
	// ClientID is the OAuth2 client ID.
	ClientID string `json:"client_id"`
	
	// ClientSecret is the OAuth2 client secret.
	ClientSecret string `json:"client_secret"`
	
	// TokenURL is the OAuth2 token endpoint URL.
	TokenURL string `json:"token_url"`
}

// SpoolConfig contains settings for local file spool.
type SpoolConfig struct {
	// Directory is the path to the spool directory.
	Directory string `json:"directory"`
	
	// MaxSize is the maximum size of a file that can be spooled.
	MaxSize uint64 `json:"max_size"`
}

// New creates a new default configuration.
func New() *Config {
	return &Config{
		Observability: ObservabilityConfig{
			Debug: false,
		},
		FTP: FTPConfig{
			Address: ":2121",
			PassivePortsRange: "40000-50000",
			TLS: TLSConfig{},
		},
		HTTP: HTTPConfig{
			Address: ":9200",
		},
		OCIS: toCISConfig{
			GraphURL: "http://localhost:9200/api/libregraph",
			WebDAVURL: "http://localhost:9200/webdav",
			OAuth2: OAuth2Config{},
		},
		Spool: SpoolConfig{
			Directory: "/var/tmp/ocis-ftp-bridge-spool",
			MaxSize: 1024 * 1024 * 1024, // 1 GB
		},
	}
}

// Validate checks if the configuration is valid.
// Returns an error if any required field is missing or invalid.
func (c *Config) Validate() error {
	// Validate FTP configuration
	if c.FTP.Address == "" {
		return ErrMissingFTPAddress
	}
	
	// Validate HTTP configuration
	if c.HTTP.Address == "" {
		return ErrMissingHTTPAddress
	}
	
	// Validate oCIS configuration
	if c.OCIS.GraphURL == "" {
		return ErrMissingGraphURL
	}

	if c.OCIS.WebDAVURL == "" {
		return ErrMissingWebDAVURL
	}
	
	// Validate spool configuration
	if c.Spool.Directory == "" {
		return ErrMissingSpoolDirectory
	}
	
	if c.Spool.MaxSize == 0 {
		return ErrInvalidSpoolMaxSize
	}
	
	return nil
}

// Errors
type ConfigError struct {
	msg string
}

func (e *ConfigError) Error() string {
	return e.msg
}

var (
	ErrMissingFTPAddress      = &ConfigError{msg: "FTP address is required"}
	ErrMissingHTTPAddress     = &ConfigError{msg: "HTTP address is required"}
	ErrMissingGraphURL        = &ConfigError{msg: "Graph URL is required"}
	ErrMissingWebDAVURL       = &ConfigError{msg: "WebDAV URL is required"}
	ErrMissingSpoolDirectory  = &ConfigError{msg: "Spool directory is required"}
	ErrInvalidSpoolMaxSize    = &ConfigError{msg: "Spool max size must be greater than 0"}
)