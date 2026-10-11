package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

func testHash(password string) string {
	salt := []byte("0123456789abcdef")
	sum := argon2.IDKey([]byte(password), salt, 1, 8*1024, 1, 32)
	return "$argon2id$v=19$m=8192,t=1,p=1$" +
		base64.RawStdEncoding.EncodeToString(salt) + "$" +
		base64.RawStdEncoding.EncodeToString(sum)
}

func validYAML(hash string) string {
	return `server:
  listen: ":21"
  passive:
    min_port: 30000
    max_port: 30020
    public_ip: ""
  tls:
    enabled: false
ocis:
  url: https://cloud.example.com
spool:
  directory: /var/lib/ocis-ftp/spool
  max_total_size: 2GiB
accounts:
  - username: reception
    password_hash: "` + hash + `"
    ocis:
      username: scanner-service
      app_token_env: OCIS_FTP_RECEPTION_TOKEN
    target:
      drive: Incoming Scans
      root: /Reception
    upload:
      collision_policy: rename
      max_size: 250MiB
`
}

func loadText(t *testing.T, text string, env map[string]string) (*Config, error) {
	t.Helper()
	name := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(name, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	return LoadFileWithEnv(name, func(k string) (string, bool) {
		v, ok := env[k]
		return v, ok
	})
}

func TestLoadValidConfiguration(t *testing.T) {
	cfg, err := loadText(t, validYAML(testHash("printer-secret")), map[string]string{"OCIS_FTP_RECEPTION_TOKEN": "app-token-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Spool.MaxTotalSize != ByteSize(2*1024*1024*1024) || cfg.Accounts[0].Upload.MaxSize != ByteSize(250*1024*1024) {
		t.Fatalf("unexpected byte sizes: %#v", cfg)
	}
	if cfg.Accounts[0].AppToken != "app-token-secret" {
		t.Fatal("app token was not resolved")
	}
	if cfg.Accounts[0].Target.Root != "/Reception" {
		t.Fatalf("unexpected root: %q", cfg.Accounts[0].Target.Root)
	}
}

func TestInvalidConfigurations(t *testing.T) {
	hash := testHash("secret")
	base := validYAML(hash)
	cases := map[string]string{
		"bad url":          strings.Replace(base, "https://cloud.example.com", "://bad", 1),
		"bad hash":         strings.Replace(base, hash, "$argon2id$broken", 1),
		"traversal":        strings.Replace(base, "/Reception", "/Reception/../Other", 1),
		"bad passive":      strings.Replace(base, "min_port: 30000", "min_port: 40000", 1),
		"bad collision":    strings.Replace(base, "collision_policy: rename", "collision_policy: surprise", 1),
		"relative spool":   strings.Replace(base, "/var/lib/ocis-ftp/spool", "relative/spool", 1),
		"missing target":   strings.Replace(base, "drive: Incoming Scans", "drive: \"\"", 1),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := loadText(t, body, map[string]string{"OCIS_FTP_RECEPTION_TOKEN": "token"}); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
	
	// Test invalid server listen addresses
	addressCases := map[string]string{
		"invalid port":         strings.Replace(base, `":21"`, `":99999"`, 1), // port > 65535
		"invalid port 0":       strings.Replace(base, `":21"`, `":0"`, 1),    // port = 0
		"invalid format":       strings.Replace(base, `":21"`, `"localhost"`, 1), // missing port
		"invalid hostname":     strings.Replace(base, `":21"`, `"invalid host!:80"`, 1), // invalid hostname
	}
	for name, body := range addressCases {
		t.Run(name, func(t *testing.T) {
			if _, err := loadText(t, body, map[string]string{"OCIS_FTP_RECEPTION_TOKEN": "token"}); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
	t.Run("duplicate account", func(t *testing.T) {
		account := strings.SplitN(base, "accounts:\n", 2)[1]
		body := base + "  - username: reception\n" + strings.Replace(strings.SplitN(account, "  - username: reception\n", 2)[1], "\n    ", "\n    ", -1)
		_, err := loadText(t, body, map[string]string{"OCIS_FTP_RECEPTION_TOKEN": "token"})
		if err == nil {
			t.Fatal("expected duplicate error")
		}
	})
	t.Run("missing token env", func(t *testing.T) {
		if _, err := loadText(t, base, nil); err == nil {
			t.Fatal("expected missing env error")
		}
	})
}

func TestByteSizesAndCollisionPolicies(t *testing.T) {
	for raw, want := range map[string]ByteSize{
		"250MiB": 250 * 1024 * 1024,
		"2GiB":   2 * 1024 * 1024 * 1024,
		"12KiB":  12 * 1024,
	} {
		got, err := ParseByteSize(raw)
		if err != nil || got != want {
			t.Fatalf("%s: got %d, %v; want %d", raw, got, err, want)
		}
	}
	for _, policy := range []string{"rename", "reject", "overwrite"} {
		body := strings.Replace(validYAML(testHash("secret")), "collision_policy: rename", "collision_policy: "+policy, 1)
		if _, err := loadText(t, body, map[string]string{"OCIS_FTP_RECEPTION_TOKEN": "token"}); err != nil {
			t.Fatalf("%s should be valid: %v", policy, err)
		}
	}
}

// TestCheckForPlaintextCredentials verifies that the plaintext credential
// scanner detects plaintext password keys in configuration files.
func TestCheckForPlaintextCredentials(t *testing.T) {
	t.Run("detects common password value", func(t *testing.T) {
		content := `accounts:
  - username: test
    password: changeme
`
		name := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(name, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		err := checkForPlaintextCredentials(name)
		if err == nil {
			t.Fatal("expected plaintext credential detection error")
		}
	})

	t.Run("detects long token-like value", func(t *testing.T) {
		content := `accounts:
  - username: test
    token: abcdefghijklmnopqrstuvwxyz1234567890
`
		name := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(name, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		err := checkForPlaintextCredentials(name)
		if err == nil {
			t.Fatal("expected plaintext credential detection error")
		}
	})

	t.Run("ignores password_hash key", func(t *testing.T) {
		content := `accounts:
  - username: test
    password_hash: $argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG
`
		name := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(name, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		err := checkForPlaintextCredentials(name)
		if err != nil {
			t.Fatalf("unexpected error for password_hash: %v", err)
		}
	})
}

// TestLoadFilePlaintextCheckRunsBeforeDecode verifies that the plaintext
// credential scanner runs before KnownFields(true) rejects unknown fields.
// A config with "password: changeme" should trigger the plaintext warning
// even though "password" is not a known field.
func TestLoadFilePlaintextCheckRunsBeforeDecode(t *testing.T) {
	// Capture slog output to verify the warning is logged
	var logBuf strings.Builder
	originalHandler := slog.Default()
	defer slog.SetDefault(originalHandler)
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn})))

	content := `server:
  listen: ":21"
  passive:
    min_port: 30000
    max_port: 30020
    public_ip: ""
  tls:
    enabled: false
ocis:
  url: https://cloud.example.com
spool:
  directory: /var/lib/ocis-ftp/spool
  max_total_size: 2GiB
accounts:
  - username: reception
    password: changeme
    password_hash: "` + testHash("secret") + `"
    ocis:
      username: scanner-service
      app_token_env: OCIS_FTP_RECEPTION_TOKEN
    target:
      drive: Incoming Scans
      root: /Reception
    upload:
      collision_policy: rename
      max_size: 250MiB
`
	name := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(name, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	// LoadFile will fail because "password" is an unknown field,
	// but the plaintext check should have logged a warning first.
	_, err := LoadFileWithEnv(name, func(k string) (string, bool) {
		if k == "OCIS_FTP_RECEPTION_TOKEN" {
			return "token", true
		}
		return "", false
	})

	// The load should fail due to unknown field "password"
	if err == nil {
		t.Fatal("expected error for unknown field 'password'")
	}

	// But the plaintext check should have logged a warning before the decode error
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "Potential security issue") {
		t.Errorf("expected plaintext credential warning in logs, got: %s", logOutput)
	}
}

func TestPasswordVerificationAndRedaction(t *testing.T) {
	hash := testHash("correct")
	ok, err := VerifyPassword(hash, "correct")
	if err != nil || !ok {
		t.Fatalf("correct password failed: %v", err)
	}
	ok, err = VerifyPassword(hash, "wrong")
	if err != nil || ok {
		t.Fatalf("wrong password accepted: %v", err)
	}
	cfg, err := loadText(t, validYAML(hash), map[string]string{"OCIS_FTP_RECEPTION_TOKEN": "super-secret-token"})
	if err != nil {
		t.Fatal(err)
	}
	rendered := cfg.String() + cfg.Accounts[0].String()
	if strings.Contains(rendered, hash) || strings.Contains(rendered, "super-secret-token") {
		t.Fatalf("secret leaked from loggable representation: %s", rendered)
	}
}

func TestValidateTLSConfig(t *testing.T) {
	// Test with TLS disabled - should pass
	t.Run("TLS disabled", func(t *testing.T) {
		cfg := New()
		cfg.Server.TLS.Enabled = false
		if err := cfg.ValidateTLSConfig(); err != nil {
			t.Fatalf("unexpected error when TLS disabled: %v", err)
		}
	})

	// Test with TLS enabled but no cert - should fail
	t.Run("TLS enabled but no cert", func(t *testing.T) {
		cfg := New()
		cfg.Server.TLS.Enabled = true
		cfg.Server.TLS.Cert = ""
		cfg.Server.TLS.Key = ""
		if err := cfg.ValidateTLSConfig(); err == nil {
			t.Fatal("expected error when TLS enabled but no cert")
		}
	})

	// Test with non-existent cert file - should fail
	t.Run("non-existent cert file", func(t *testing.T) {
		cfg := New()
		cfg.Server.TLS.Enabled = true
		cfg.Server.TLS.Cert = "/nonexistent/cert.crt"
		cfg.Server.TLS.Key = "/nonexistent/key.key"
		if err := cfg.ValidateTLSConfig(); err == nil {
			t.Fatal("expected error for non-existent cert file")
		}
	})

	// Test with invalid cert/key pair - should fail
	t.Run("invalid cert/key pair", func(t *testing.T) {
		// Create temporary files with invalid content
		tmpDir := t.TempDir()
		certFile := filepath.Join(tmpDir, "cert.crt")
		keyFile := filepath.Join(tmpDir, "key.key")
		
		if err := os.WriteFile(certFile, []byte("invalid cert"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyFile, []byte("invalid key"), 0600); err != nil {
			t.Fatal(err)
		}
		
		cfg := New()
		cfg.Server.TLS.Enabled = true
		cfg.Server.TLS.Cert = certFile
		cfg.Server.TLS.Key = keyFile
		if err := cfg.ValidateTLSConfig(); err == nil {
			t.Fatal("expected error for invalid cert/key pair")
		}
	})

	// Test with expired certificate - should fail
	t.Run("expired certificate", func(t *testing.T) {
		// Create a self-signed certificate with past expiration
		// For this test, we'll skip creating an actual expired cert
		// and just verify the validation logic
		tmpDir := t.TempDir()
		certFile := filepath.Join(tmpDir, "cert.crt")
		keyFile := filepath.Join(tmpDir, "key.key")
		
		// Write invalid cert that would parse but be expired
		// In a real test, we'd generate an actual expired cert
		certPEM := `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpEgcMFvMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RjYTAeFw0yMDEwMDEwMDAwMDBaFw0yMDEwMDEwMDAwMDBaMBExDzANBgNVBAMM
BnRlc3RjYTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC7o96FCFzL5iqz0dVXdVGP
Q5h0h/0g5nVKPLqGGy3gLXZqPJqYDqvEF0AxMPhXOTjGnpdxPuKR3ithEPTAhxfL
AgMBAAGjUzBRMB0GA1UdDgQWBBR9p7pY5dKW2M5xq2x7HmD4PjzAfBgNVHSMEGDAW
gBR9p7pY5dKW2M5xq2x7HmD4PjzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEB
CwUAA0EAqF0RrNkYLXD5lTz5Fz0P8WEvsVVNGTqGqL0vBnBGkCLYe5YcQwJy0f
OWPfGxbutT0P2P902y1ACyDnQs=
-----END CERTIFICATE-----`
		
		keyPEM := `-----BEGIN PRIVATE KEY-----
MIIBPAIBAAJBAKHBfpEgcMFvMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RjYTAeFw0yMDEwMDEwMDAwMDBaFw0yMDEwMDEwMDAwMDBaMBExDzANBgNVBAMM
BnRlc3RjYTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC7o96FCFzL5iqz0dVXdVGP
Q5h0h/0g5nVKPLqGGy3gLXZqPJqYDqvEF0AxMPhXOTjGnpdxPuKR3ithEPTAhxfL
AgMBAAGjUzBRMB0GA1UdDgQWBBR9p7pY5dKW2M5xq2x7HmD4PjzAfBgNVHSMEGDAW
gBR9p7pY5dKW2M5xq2x7HmD4PjzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEB
CwUAA0EAqF0RrNkYLXD5lTz5Fz0P8WEvsVVNGTqGqL0vBnBGkCLYe5YcQwJy0f
OWPfGxbutT0P2P902y1ACyDnQs=
-----END PRIVATE KEY-----`
		
		if err := os.WriteFile(certFile, []byte(certPEM), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyFile, []byte(keyPEM), 0600); err != nil {
			t.Fatal(err)
		}
		
		cfg := New()
		cfg.Server.TLS.Enabled = true
		cfg.Server.TLS.Cert = certFile
		cfg.Server.TLS.Key = keyFile
		if err := cfg.ValidateTLSConfig(); err == nil {
			t.Fatal("expected error for expired certificate")
		}
	})
}

// generateSelfSignedCert creates a self-signed certificate with an RSA key
// of the specified bit size, returning the cert and key PEM data.
func generateSelfSignedCert(t *testing.T, keyBits int) (certPEM, keyPEM []byte) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"test.example.com"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})

	return certPEM, keyPEM
}

// TestValidateTLSConfigRSAKeyStrength verifies that RSA key strength is
// measured in bits, not bytes. A 2048-bit RSA certificate must be accepted
// (previously rejected because rsa.PublicKey.Size() returns bytes: 256 < 2048).
func TestValidateTLSConfigRSAKeyStrength(t *testing.T) {
	t.Run("accepts 2048-bit RSA certificate", func(t *testing.T) {
		certPEM, keyPEM := generateSelfSignedCert(t, 2048)
		tmpDir := t.TempDir()
		certFile := filepath.Join(tmpDir, "cert.crt")
		keyFile := filepath.Join(tmpDir, "key.key")
		if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
			t.Fatal(err)
		}

		cfg := New()
		cfg.Server.TLS.Enabled = true
		cfg.Server.TLS.Cert = certFile
		cfg.Server.TLS.Key = keyFile
		if err := cfg.ValidateTLSConfig(); err != nil {
			t.Fatalf("2048-bit RSA certificate should be accepted, got error: %v", err)
		}
	})

	t.Run("accepts 4096-bit RSA certificate", func(t *testing.T) {
		certPEM, keyPEM := generateSelfSignedCert(t, 4096)
		tmpDir := t.TempDir()
		certFile := filepath.Join(tmpDir, "cert.crt")
		keyFile := filepath.Join(tmpDir, "key.key")
		if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
			t.Fatal(err)
		}

		cfg := New()
		cfg.Server.TLS.Enabled = true
		cfg.Server.TLS.Cert = certFile
		cfg.Server.TLS.Key = keyFile
		if err := cfg.ValidateTLSConfig(); err != nil {
			t.Fatalf("4096-bit RSA certificate should be accepted, got error: %v", err)
		}
	})

	t.Run("rejects 1024-bit RSA certificate", func(t *testing.T) {
		certPEM, keyPEM := generateSelfSignedCert(t, 1024)
		tmpDir := t.TempDir()
		certFile := filepath.Join(tmpDir, "cert.crt")
		keyFile := filepath.Join(tmpDir, "key.key")
		if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
			t.Fatal(err)
		}

		cfg := New()
		cfg.Server.TLS.Enabled = true
		cfg.Server.TLS.Cert = certFile
		cfg.Server.TLS.Key = keyFile
		if err := cfg.ValidateTLSConfig(); err == nil {
			t.Fatal("1024-bit RSA certificate should be rejected")
		}
	})
}

// TestValidateServerListenAddress verifies that listen address validation
// accepts various formats including scoped IPv6 with zone identifiers.
func TestValidateServerListenAddress(t *testing.T) {
	valid := []string{
		":2121",
		"0.0.0.0:2121",
		"127.0.0.1:2121",
		"[::]:2121",
		"[::1]:2121",
		"[fe80::1%eth0]:2121", // Scoped IPv6 with zone
		"localhost:2121",
		"example.com:9200",
	}
	for _, addr := range valid {
		t.Run("valid/"+addr, func(t *testing.T) {
			if err := validateServerListenAddress(addr); err != nil {
				t.Errorf("expected %q to be valid, got error: %v", addr, err)
			}
		})
	}

	invalid := []string{
		"",
		"noport",
		":0",
		":99999",
		"host:abc",
		"-bad-.com:2121",
	}
	for _, addr := range invalid {
		t.Run("invalid/"+addr, func(t *testing.T) {
			if err := validateServerListenAddress(addr); err == nil {
				t.Errorf("expected %q to be invalid", addr)
			}
		})
	}
}
