package auth

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/amamus/ocis-ftp-bridge/pkg/config"
	"golang.org/x/crypto/argon2"
)

func hash(password string) string {
	salt := []byte("0123456789abcdef")
	sum := argon2.IDKey([]byte(password), salt, 1, 8*1024, 1, 32)
	return "$argon2id$v=19$m=8192,t=1,p=1$" +
		base64.RawStdEncoding.EncodeToString(salt) + "$" +
		base64.RawStdEncoding.EncodeToString(sum)
}

func TestConfiguredAccountMapping(t *testing.T) {
	mapper := NewAccountMapper([]config.AccountConfig{{
		Username:     "reception",
		PasswordHash: hash("secret"),
		OCIS:         config.AccountOCISConfig{Username: "scanner-service", AppTokenEnv: "TOKEN"},
		AppToken:     "app-token",
		Target:       config.TargetConfig{Drive: "Incoming Scans", Root: "/Reception"},
		Upload:       config.UploadConfig{CollisionPolicy: "rename", MaxSize: 250},
	}})

	mapping, err := mapper.Authenticate("reception", "secret")
	if err != nil {
		t.Fatal(err)
	}
	if mapping.OCISUsername != "scanner-service" || mapping.AppToken != "app-token" || mapping.Root != "/Reception" {
		t.Fatalf("unexpected mapping: %#v", mapping)
	}
	if strings.Contains(mapping.String(), "app-token") {
		t.Fatalf("token leaked: %s", mapping.String())
	}
	if _, err := mapper.Authenticate("reception", "wrong"); !errorsIs(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password: %v", err)
	}
	if _, err := mapper.Authenticate("unknown", "secret"); !errorsIs(err, ErrInvalidCredentials) {
		t.Fatalf("unknown user: %v", err)
	}
}

func errorsIs(err, target error) bool { return err == target }
