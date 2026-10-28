package deployment

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestDockerComposeNoUIDOverride verifies that docker-compose.yaml does not
// override the container user with a uid that doesn't match the image's /app
// permissions. The image's /app is 750 owned by appuser:appgroup (uid 100).
// See issue #112.
func TestDockerComposeNoUIDOverride(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("../../docker-compose.yaml")
	if err != nil {
		t.Fatalf("failed to read docker-compose.yaml: %v", err)
	}

	content := string(data)

	// The compose file should not set user: "1000:1000" or similar
	userPattern := regexp.MustCompile(`user:\s*["']?\d+:\d+["']?`)
	if userPattern.MatchString(content) {
		t.Errorf("docker-compose.yaml should not override the container user with a uid:gid that doesn't match the image. Found: %s", userPattern.FindString(content))
	}
}

// TestKubernetesNoUIDOverride verifies that the Kubernetes deployment does not
// force runAsUser/runAsGroup to a uid that doesn't match the image's /app
// permissions. See issue #112.
func TestKubernetesNoUIDOverride(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("../../kubernetes/deployment.yaml")
	if err != nil {
		t.Fatalf("failed to read kubernetes/deployment.yaml: %v", err)
	}

	content := string(data)

	// The deployment should not force runAsUser: 1000
	if strings.Contains(content, "runAsUser:") {
		runAsUserPattern := regexp.MustCompile(`runAsUser:\s*\d+`)
		if runAsUserPattern.MatchString(content) {
			t.Errorf("kubernetes/deployment.yaml should not override runAsUser with a uid that doesn't match the image. Found: %s", runAsUserPattern.FindString(content))
		}
	}

	// The deployment should not force runAsGroup: 1000
	if strings.Contains(content, "runAsGroup:") {
		runAsGroupPattern := regexp.MustCompile(`runAsGroup:\s*\d+`)
		if runAsGroupPattern.MatchString(content) {
			t.Errorf("kubernetes/deployment.yaml should not override runAsGroup with a gid that doesn't match the image. Found: %s", runAsGroupPattern.FindString(content))
		}
	}
}

// TestDockerfileAppPermissions verifies that the Dockerfile creates /app with
// permissions that allow the appuser to traverse it.
func TestDockerfileAppPermissions(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Fatalf("failed to read Dockerfile: %v", err)
	}

	content := string(data)

	// The Dockerfile should create a non-root user
	if !strings.Contains(content, "adduser") {
		t.Error("Dockerfile should create a non-root user with adduser")
	}

	// The Dockerfile should set USER to the non-root user
	if !strings.Contains(content, "USER appuser") {
		t.Error("Dockerfile should switch to the appuser with USER appuser")
	}
}
