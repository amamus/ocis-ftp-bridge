package main

import (
	"encoding/base64"
	"os/exec"
	"strings"
	"testing"

	"github.com/amamus/ocis-ftp-bridge/pkg/config"
)

// TestHashPasswordGeneratesValidPHC verifies that the hash-password tool
// produces a valid Argon2id PHC string that VerifyPassword can verify.
func TestHashPasswordGeneratesValidPHC(t *testing.T) {
	// Build and run the tool
	bin := t.TempDir() + "/hash-password"
	buildCmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build hash-password: %v\n%s", err, out)
	}

	runCmd := exec.Command(bin, "test-password-123")
	out, err := runCmd.Output()
	if err != nil {
		t.Fatalf("hash-password failed: %v", err)
	}

	hash := strings.TrimSpace(string(out))

	// Verify PHC format: $argon2id$v=19$m=...,t=...,p=...$salt$hash
	if !strings.HasPrefix(hash, "$argon2id$v=19$") {
		t.Fatalf("expected Argon2id PHC string, got: %s", hash)
	}

	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		t.Fatalf("expected 6 parts in PHC string, got %d: %s", len(parts), hash)
	}

	// Verify the hash with the config package's VerifyPassword
	ok, err := config.VerifyPassword(hash, "test-password-123")
	if err != nil {
		t.Fatalf("VerifyPassword returned error: %v", err)
	}
	if !ok {
		t.Fatal("VerifyPassword rejected the generated hash")
	}

	// Verify wrong password is rejected
	ok, err = config.VerifyPassword(hash, "wrong-password")
	if err != nil {
		t.Fatalf("VerifyPassword returned error for wrong password: %v", err)
	}
	if ok {
		t.Fatal("VerifyPassword accepted wrong password")
	}
}

// TestHashPasswordCustomParams verifies that custom Argon2id parameters
// are reflected in the generated PHC string.
func TestHashPasswordCustomParams(t *testing.T) {
	bin := t.TempDir() + "/hash-password"
	buildCmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build hash-password: %v\n%s", err, out)
	}

	runCmd := exec.Command(bin, "-m", "32768", "-t", "2", "-p", "2", "secret")
	out, err := runCmd.Output()
	if err != nil {
		t.Fatalf("hash-password failed: %v", err)
	}

	hash := strings.TrimSpace(string(out))

	// Verify custom parameters are in the PHC string
	if !strings.Contains(hash, "m=32768,t=2,p=2") {
		t.Fatalf("expected custom params in PHC string, got: %s", hash)
	}

	// Verify the hash is valid
	ok, err := config.VerifyPassword(hash, "secret")
	if err != nil || !ok {
		t.Fatalf("VerifyPassword failed for custom params hash: %v", err)
	}
}

// TestHashPasswordEmptyPassword verifies that empty passwords are rejected.
func TestHashPasswordEmptyPassword(t *testing.T) {
	bin := t.TempDir() + "/hash-password"
	buildCmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build hash-password: %v\n%s", err, out)
	}

	runCmd := exec.Command(bin, "")
	if err := runCmd.Run(); err == nil {
		t.Fatal("expected non-zero exit code for empty password")
	}
}

// TestHashPasswordSaltUniqueness verifies that each invocation generates
// a unique salt (and thus a unique hash).
func TestHashPasswordSaltUniqueness(t *testing.T) {
	bin := t.TempDir() + "/hash-password"
	buildCmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build hash-password: %v\n%s", err, out)
	}

	out1, err := exec.Command(bin, "same-password").Output()
	if err != nil {
		t.Fatalf("first run failed: %v", err)
	}
	out2, err := exec.Command(bin, "same-password").Output()
	if err != nil {
		t.Fatalf("second run failed: %v", err)
	}

	hash1 := strings.TrimSpace(string(out1))
	hash2 := strings.TrimSpace(string(out2))

	if hash1 == hash2 {
		t.Fatal("expected different hashes for same password (unique salt)")
	}

	// Extract and compare salts
	parts1 := strings.Split(hash1, "$")
	parts2 := strings.Split(hash2, "$")
	salt1, _ := base64.RawStdEncoding.DecodeString(parts1[4])
	salt2, _ := base64.RawStdEncoding.DecodeString(parts2[4])
	if string(salt1) == string(salt2) {
		t.Fatal("expected different salts")
	}
}

// TestHashPasswordInvalidParams verifies that out-of-range Argon2id parameters
// are rejected with a clean error (exit code 1, no panic) instead of an
// argon2 panic or a silently truncated conversion.
func TestHashPasswordInvalidParams(t *testing.T) {
	bin := t.TempDir() + "/hash-password"
	buildCmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build hash-password: %v\n%s", err, out)
	}

	cases := map[string][]string{
		"zero time":                   {"-t", "0", "secret"},
		"zero memory":                 {"-m", "0", "secret"},
		"zero threads":                {"-p", "0", "secret"},
		"threads above uint8":         {"-p", "256", "secret"},
		"zero key length":             {"-k", "0", "secret"},
		"time overflows uint32":       {"-t", "4294967296", "secret"},
		"memory overflows uint32":     {"-m", "4294967296", "secret"},
		"key length overflows uint32": {"-k", "4294967296", "secret"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			out, err := exec.Command(bin, args...).CombinedOutput()
			if err == nil {
				t.Fatalf("expected non-zero exit for args %v, got output: %s", args, out)
			}
			exitErr, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatalf("expected ExitError, got %T: %v", err, err)
			}
			if exitErr.ExitCode() != 1 {
				t.Fatalf("expected exit code 1 for args %v, got %d (output: %s)", args, exitErr.ExitCode(), out)
			}
			if strings.Contains(string(out), "panic") {
				t.Fatalf("expected clean error, got panic for args %v: %s", args, out)
			}
			if !strings.Contains(string(out), "invalid") {
				t.Fatalf("expected error message to mention invalid parameter for args %v, got: %s", args, out)
			}
		})
	}
}

// TestHashPasswordReadsPasswordFromStdin verifies that hash-password reads
// the password from stdin when no argument is given, so the plaintext never
// appears in the process list or shell history (SEC-013).
func TestHashPasswordReadsPasswordFromStdin(t *testing.T) {
	bin := t.TempDir() + "/hash-password"
	buildCmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build hash-password: %v\n%s", err, out)
	}

	runCmd := exec.Command(bin)
	runCmd.Stdin = strings.NewReader("stdin-secret-456\n")
	out, err := runCmd.Output()
	if err != nil {
		t.Fatalf("hash-password without arguments must read the password from stdin (SEC-013): %v", err)
	}

	hash := strings.TrimSpace(string(out))
	if !strings.HasPrefix(hash, "$argon2id$v=19$") {
		t.Fatalf("expected Argon2id PHC string on stdout, got: %s", hash)
	}

	ok, err := config.VerifyPassword(hash, "stdin-secret-456")
	if err != nil {
		t.Fatalf("VerifyPassword returned error: %v", err)
	}
	if !ok {
		t.Fatal("hash read from stdin does not verify against the stdin password")
	}
}
