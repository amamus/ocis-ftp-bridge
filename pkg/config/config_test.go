package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
