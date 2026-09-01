// Package config loads and validates ocis-ftp-bridge configuration.
package config

import (
	"crypto/subtle"
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
	Listen  string        `yaml:"listen" json:"listen"`
	Passive PassiveConfig `yaml:"passive" json:"passive"`
	TLS     TLSConfig     `yaml:"tls" json:"tls"`
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

type OCISConfig struct {
	URL       string `yaml:"url" json:"url"`
	GraphURL  string `yaml:"graph_url,omitempty" json:"graph_url,omitempty"`
	WebDAVURL string `yaml:"webdav_url,omitempty" json:"webdav_url,omitempty"`
}

type SpoolConfig struct {
	Directory    string   `yaml:"directory" json:"directory"`
	MaxTotalSize ByteSize `yaml:"max_total_size" json:"max_total_size"`
	MaxSize      uint64   `yaml:"-" json:"-"`
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

type ObservabilityConfig struct {
	Debug bool `yaml:"debug,omitempty" json:"debug,omitempty"`
}

type HTTPConfig struct {
	Address string `yaml:"address,omitempty" json:"address,omitempty"`
}

func New() *Config {
	return &Config{
		Server: ServerConfig{
			Listen:  ":2121",
			Passive: PassiveConfig{MinPort: 40000, MaxPort: 50000},
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
		},
		HTTP: HTTPConfig{Address: ":9200"},
	}
}

func LoadFile(filename string) (*Config, error) {
	return LoadFileWithEnv(filename, os.LookupEnv)
}

func LoadFileWithEnv(filename string, lookupEnv func(string) (string, bool)) (*Config, error) {
	if strings.TrimSpace(filename) == "" {
		return nil, errors.New("configuration file path is required")
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
	if err := validatePassive(c.Server.Passive); err != nil {
		return err
	}
	if c.Server.TLS.Enabled && (strings.TrimSpace(c.Server.TLS.Cert) == "" || strings.TrimSpace(c.Server.TLS.Key) == "") {
		return errors.New("server.tls.cert and server.tls.key are required when TLS is enabled")
	}
	if err := c.validateOCIS(); err != nil {
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

		if _, err := parseArgon2ID(account.PasswordHash); err != nil {
			return fmt.Errorf("%s.password_hash: %w", prefix, err)
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
		return p, errors.New("invalid Argon2id salt")
	}
	p.hash, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(p.hash) < 16 {
		return p, errors.New("invalid Argon2id digest")
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
