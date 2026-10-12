package main

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"testing"
)

// minimumGoVersion is the minimum Go toolchain the module must declare.
// Go 1.27.0/1.27.1 ship 9 standard-library vulnerabilities fixed in
// 1.27.2 (GO-2026-6603 … GO-2026-6617, finding SEC-007), so both the go
// directive and the toolchain pin must require at least this version.
var minimumGoVersion = [3]int{1, 27, 2}

var (
	goDirectiveRE        = regexp.MustCompile(`(?m)^go\s+(\d+)\.(\d+)(?:\.(\d+))?`)
	toolchainDirectiveRE = regexp.MustCompile(`(?m)^toolchain\s+go(\d+)\.(\d+)(?:\.(\d+))?`)
)

// parseGoModVersion extracts a version from go.mod using the given directive
// regexp and fails the test if the directive is missing or unparsable.
func parseGoModVersion(t *testing.T, re *regexp.Regexp, directive string) [3]int {
	t.Helper()
	data, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("failed to read go.mod: %v", err)
	}
	m := re.FindSubmatch(data)
	if m == nil {
		t.Fatalf("go.mod has no %q directive; the module must pin its Go toolchain (SEC-007)", directive)
	}
	var v [3]int
	for i := 0; i < 3; i++ {
		if len(m[i+1]) == 0 {
			break
		}
		n, err := strconv.Atoi(string(m[i+1]))
		if err != nil {
			t.Fatalf("go.mod %q directive has unparsable version %q", directive, m[0])
		}
		v[i] = n
	}
	return v
}

func atLeast(v, min [3]int) bool {
	for i := 0; i < 3; i++ {
		if v[i] != min[i] {
			return v[i] > min[i]
		}
	}
	return true
}

func versionString(v [3]int) string {
	return fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2])
}

// TestGoModRequiresPatchedToolchain guards finding SEC-007: the module must
// not build with Go 1.27.0/1.27.1, which ship 9 stdlib CVEs fixed in
// 1.27.2. Both the go directive and the toolchain pin are checked.
func TestGoModRequiresPatchedToolchain(t *testing.T) {
	min := versionString(minimumGoVersion)

	goVer := parseGoModVersion(t, goDirectiveRE, "go")
	if !atLeast(goVer, minimumGoVersion) {
		t.Errorf("go.mod go directive = %s, want >= %s (Go 1.27.0/1.27.1 ship 9 stdlib CVEs fixed in 1.27.2, SEC-007)", versionString(goVer), min)
	}

	toolchainVer := parseGoModVersion(t, toolchainDirectiveRE, "toolchain")
	if !atLeast(toolchainVer, minimumGoVersion) {
		t.Errorf("go.mod toolchain directive = %s, want >= %s (pin the exact toolchain so builds cannot silently use a vulnerable Go, SEC-007)", versionString(toolchainVer), min)
	}
}
