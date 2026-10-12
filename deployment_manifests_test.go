package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// These tests guard the deployment manifests against the drift found in the
// audit (SEC-008, SEC-014, SEC-015, QLT-007): the operations HTTP port must
// be 9090 everywhere, the Kubernetes example must not ship plaintext FTP or
// Helm template syntax, docker-compose must not publish the same host port
// twice, and the docker build context must not include local artifacts.

// readRepoFile reads a file from the repository root.
func readRepoFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	return data
}

// splitYAMLDocuments splits a multi-document YAML stream into individual
// document byte slices.
func splitYAMLDocuments(data []byte) [][]byte {
	var docs [][]byte
	var current []string
	flush := func() {
		if len(current) > 0 {
			docs = append(docs, []byte(strings.Join(current, "\n")))
			current = nil
		}
	}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "---" || strings.HasPrefix(line, "--- ") {
			flush()
			continue
		}
		current = append(current, line)
	}
	flush()
	return docs
}

// decodeYAMLDocuments decodes a (possibly multi-document) YAML stream into
// generic maps. Documents that fail to decode are returned via decodeErrs so
// callers can surface them as test failures and keep checking the rest.
func decodeYAMLDocuments(data []byte) ([]map[string]any, []error) {
	var docs []map[string]any
	var decodeErrs []error
	for _, raw := range splitYAMLDocuments(data) {
		var doc map[string]any
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			decodeErrs = append(decodeErrs, err)
			continue
		}
		docs = append(docs, doc)
	}
	return docs, decodeErrs
}

// findDocument returns the first decoded document of the given kind and name,
// or nil.
func findDocument(docs []map[string]any, kind, name string) map[string]any {
	for _, doc := range docs {
		if doc["kind"] != kind {
			continue
		}
		meta, ok := doc["metadata"].(map[string]any)
		if !ok {
			continue
		}
		if meta["name"] == name {
			return doc
		}
	}
	return nil
}

// embeddedBridgeConfig extracts and parses the bridge config.yaml embedded in
// the ocis-ftp-bridge-config ConfigMap.
func embeddedBridgeConfig(t *testing.T, docs []map[string]any) map[string]any {
	t.Helper()
	cm := findDocument(docs, "ConfigMap", "ocis-ftp-bridge-config")
	if cm == nil {
		t.Fatal("ConfigMap ocis-ftp-bridge-config not found in kubernetes/deployment.yaml")
	}
	dataField, ok := cm["data"].(map[string]any)
	if !ok {
		t.Fatal("ConfigMap ocis-ftp-bridge-config has no data")
	}
	raw, ok := dataField["config.yaml"].(string)
	if !ok {
		t.Fatal("ConfigMap ocis-ftp-bridge-config has no config.yaml entry")
	}
	var cfg map[string]any
	if err := yaml.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("embedded config.yaml is not valid YAML: %v", err)
	}
	return cfg
}

// podSpec extracts the pod spec of a Deployment document.
func podSpec(t *testing.T, deploy map[string]any) map[string]any {
	t.Helper()
	spec, ok := deploy["spec"].(map[string]any)
	if !ok {
		t.Fatal("Deployment has no spec")
	}
	template, ok := spec["template"].(map[string]any)
	if !ok {
		t.Fatal("Deployment has no template")
	}
	pod, ok := template["spec"].(map[string]any)
	if !ok {
		t.Fatal("Deployment template has no pod spec")
	}
	return pod
}

// TestKubernetesManifestOpsPort9090 guards SEC-015: the operations HTTP port
// must be 9090 in the Kubernetes example (ConfigMap, container port, Service),
// matching the code default, Dockerfile and example config.
func TestKubernetesManifestOpsPort9090(t *testing.T) {
	docs, decodeErrs := decodeYAMLDocuments(readRepoFile(t, "kubernetes/deployment.yaml"))
	for _, err := range decodeErrs {
		t.Errorf("kubernetes/deployment.yaml: document failed to parse: %v", err)
	}

	cfg := embeddedBridgeConfig(t, docs)
	httpCfg, ok := cfg["http"].(map[string]any)
	if !ok {
		t.Fatal("embedded config has no http section")
	}
	if got := httpCfg["address"]; got != ":9090" {
		t.Errorf("k8s ConfigMap http.address = %v, want \":9090\" (SEC-015)", got)
	}

	deploy := findDocument(docs, "Deployment", "ocis-ftp-bridge")
	if deploy == nil {
		t.Error("Deployment ocis-ftp-bridge not found or not parseable")
		return
	}
	containers, ok := podSpec(t, deploy)["containers"].([]any)
	if !ok || len(containers) == 0 {
		t.Fatal("Deployment has no containers")
	}
	ports, _ := containers[0].(map[string]any)["ports"].([]any)
	found := false
	for _, p := range ports {
		port, ok := p.(map[string]any)
		if !ok || port["name"] != "http" {
			continue
		}
		found = true
		if port["containerPort"] != 9090 {
			t.Errorf("containerPort http = %v, want 9090 (SEC-015)", port["containerPort"])
		}
	}
	if !found {
		t.Error("Deployment container has no port named \"http\"")
	}

	svc := findDocument(docs, "Service", "ocis-ftp-bridge-http")
	if svc == nil {
		t.Error("Service ocis-ftp-bridge-http not found or not parseable")
		return
	}
	svcPorts, _ := svc["spec"].(map[string]any)["ports"].([]any)
	if len(svcPorts) == 0 {
		t.Fatal("Service ocis-ftp-bridge-http has no ports")
	}
	svcPort := svcPorts[0].(map[string]any)
	if svcPort["port"] != 9090 || svcPort["targetPort"] != 9090 {
		t.Errorf("Service ocis-ftp-bridge-http port/targetPort = %v/%v, want 9090/9090 (SEC-015)",
			svcPort["port"], svcPort["targetPort"])
	}
}

// TestKubernetesManifestFTPSEnabledWithSecret guards SEC-008: the Kubernetes
// example must enable explicit FTPS (no plaintext FTP by default) and mount a
// TLS Secret providing the configured certificate and key.
func TestKubernetesManifestFTPSEnabledWithSecret(t *testing.T) {
	docs, decodeErrs := decodeYAMLDocuments(readRepoFile(t, "kubernetes/deployment.yaml"))
	for _, err := range decodeErrs {
		t.Errorf("kubernetes/deployment.yaml: document failed to parse: %v", err)
	}
	cfg := embeddedBridgeConfig(t, docs)

	server, ok := cfg["server"].(map[string]any)
	if !ok {
		t.Fatal("embedded config has no server section")
	}
	tlsCfg, ok := server["tls"].(map[string]any)
	if !ok {
		t.Fatal("embedded config has no server.tls section")
	}
	if enabled, _ := tlsCfg["enabled"].(bool); !enabled {
		t.Error("k8s ConfigMap server.tls.enabled = false, want true: the example must not ship plaintext FTP (SEC-008)")
	}
	cert, _ := tlsCfg["cert"].(string)
	key, _ := tlsCfg["key"].(string)
	if cert == "" || key == "" {
		t.Errorf("k8s ConfigMap server.tls cert/key = %q/%q, want paths into the mounted TLS Secret (SEC-008)", cert, key)
	}
	if cert == "" || key == "" {
		return
	}

	// The manifest must mount a Secret at the directory holding the
	// configured certificate and key, read-only.
	deploy := findDocument(docs, "Deployment", "ocis-ftp-bridge")
	if deploy == nil {
		t.Error("Deployment ocis-ftp-bridge not found or not parseable")
		return
	}
	pod := podSpec(t, deploy)
	mountDir := filepath.Dir(cert)

	containers, _ := pod["containers"].([]any)
	mounts, _ := containers[0].(map[string]any)["volumeMounts"].([]any)
	var mountName string
	foundMount := false
	for _, m := range mounts {
		mount, ok := m.(map[string]any)
		if !ok || mount["mountPath"] != mountDir {
			continue
		}
		foundMount = true
		mountName, _ = mount["name"].(string)
		if ro, _ := mount["readOnly"].(bool); !ro {
			t.Errorf("volumeMount for %s is not readOnly; TLS keys must not be writable (SEC-008)", mountDir)
		}
	}
	if !foundMount {
		t.Errorf("no volumeMount mounts the TLS certificate directory %s (SEC-008)", mountDir)
		return
	}

	volumes, _ := pod["volumes"].([]any)
	foundVolume := false
	for _, v := range volumes {
		vol, ok := v.(map[string]any)
		if !ok || vol["name"] != mountName {
			continue
		}
		foundVolume = true
		secret, ok := vol["secret"].(map[string]any)
		if !ok || secret["secretName"] == "" {
			t.Errorf("volume %s is not backed by a Secret with secretName (SEC-008)", mountName)
		}
	}
	if !foundVolume {
		t.Errorf("no volume named %s backing the TLS mount (SEC-008)", mountName)
	}
}

// TestKubernetesManifestPlainKubectlApplicable guards SEC-008: the manifest
// must apply with plain kubectl and must not contain Helm template syntax.
func TestKubernetesManifestPlainKubectlApplicable(t *testing.T) {
	raw := string(readRepoFile(t, "kubernetes/deployment.yaml"))
	if strings.Contains(raw, "{{") {
		t.Error("kubernetes/deployment.yaml contains Helm template syntax ({{ ... }}); it must apply with plain kubectl (SEC-008)")
	}
}

// TestKubernetesManifestMultiReplicaSafe guards the multi-replica design from
// issue #71 (QLT-010): the example must be safe to scale horizontally. The
// spool is a per-replica emptyDir (files are pushed to oCIS within the
// session, so the spool never needs sharing), the FTP Service pins sessions
// to a pod with sessionAffinity: ClientIP (FTP sessions are long-lived and
// cannot be rebalanced), and the HPA may scale past one replica.
func TestKubernetesManifestMultiReplicaSafe(t *testing.T) {
	docs, decodeErrs := decodeYAMLDocuments(readRepoFile(t, "kubernetes/deployment.yaml"))
	for _, err := range decodeErrs {
		t.Errorf("kubernetes/deployment.yaml: document failed to parse: %v", err)
	}

	// The spool must be a per-replica emptyDir, not a shared PVC: a
	// ReadWriteOnce PVC would block multi-replica operation.
	deploy := findDocument(docs, "Deployment", "ocis-ftp-bridge")
	if deploy == nil {
		t.Error("Deployment ocis-ftp-bridge not found or not parseable")
		return
	}
	volumes, _ := podSpec(t, deploy)["volumes"].([]any)
	var spoolVolume map[string]any
	for _, v := range volumes {
		vol, ok := v.(map[string]any)
		if !ok || vol["name"] != "spool" {
			continue
		}
		spoolVolume = vol
	}
	if spoolVolume == nil {
		t.Fatal("pod spec has no volume named \"spool\"")
	}
	if _, isPVC := spoolVolume["persistentVolumeClaim"]; isPVC {
		t.Error("spool volume is a persistentVolumeClaim; multi-replica operation requires a per-replica emptyDir (issue #71, QLT-010)")
	}
	if _, isEmptyDir := spoolVolume["emptyDir"]; !isEmptyDir {
		t.Error("spool volume is not an emptyDir; multi-replica operation requires a per-replica emptyDir (issue #71, QLT-010)")
	}
	if pvc := findDocument(docs, "PersistentVolumeClaim", "ocis-ftp-bridge-spool"); pvc != nil {
		t.Error("a PersistentVolumeClaim ocis-ftp-bridge-spool still exists; the spool must be a per-replica emptyDir (issue #71, QLT-010)")
	}

	// The FTP Service must pin sessions to a pod: FTP sessions are
	// long-lived, so the load balancer must not rebalance them.
	svc := findDocument(docs, "Service", "ocis-ftp-bridge-ftp")
	if svc == nil {
		t.Error("Service ocis-ftp-bridge-ftp not found or not parseable")
		return
	}
	svcSpec, _ := svc["spec"].(map[string]any)
	if got := svcSpec["sessionAffinity"]; got != "ClientIP" {
		t.Errorf("Service ocis-ftp-bridge-ftp sessionAffinity = %v, want ClientIP (issue #71, QLT-010)", got)
	}

	// The passive-port Service must pin the same way: a printer's passive
	// data connections must land on the same pod as its control connection
	// (ClientIP affinity hashes the same client IP to the same pod).
	pasvSvc := findDocument(docs, "Service", "ocis-ftp-bridge-passive")
	if pasvSvc == nil {
		t.Error("Service ocis-ftp-bridge-passive not found or not parseable")
		return
	}
	pasvSpec, _ := pasvSvc["spec"].(map[string]any)
	if got := pasvSpec["sessionAffinity"]; got != "ClientIP" {
		t.Errorf("Service ocis-ftp-bridge-passive sessionAffinity = %v, want ClientIP (issue #71, QLT-010)", got)
	}

	// The HPA may scale past one replica now that the spool is per-replica
	// and sessions are pinned.
	hpa := findDocument(docs, "HorizontalPodAutoscaler", "ocis-ftp-bridge-hpa")
	if hpa == nil {
		t.Error("HorizontalPodAutoscaler ocis-ftp-bridge-hpa not found or not parseable")
		return
	}
	spec, ok := hpa["spec"].(map[string]any)
	if !ok {
		t.Fatal("HPA has no spec")
	}
	maxReplicas, ok := spec["maxReplicas"].(int)
	if !ok {
		t.Fatalf("HPA maxReplicas is not an integer: %v", spec["maxReplicas"])
	}
	if maxReplicas <= 1 {
		t.Errorf("HPA maxReplicas = %d, want > 1: the spool is a per-replica emptyDir and sessions are pinned by sessionAffinity, so the bridge is multi-replica safe (issue #71, QLT-010)", maxReplicas)
	}
}

// TestDockerComposeNoPublishedPortClash guards SEC-014: no host port may be
// published by two services (ocis-ftp-bridge and ocis both published 9200),
// and the bridge healthcheck must probe the aligned ops port 9090.
func TestDockerComposeNoPublishedPortClash(t *testing.T) {
	docs, decodeErrs := decodeYAMLDocuments(readRepoFile(t, "docker-compose.yaml"))
	for _, err := range decodeErrs {
		t.Errorf("docker-compose.yaml: document failed to parse: %v", err)
	}
	if len(docs) == 0 {
		t.Error("docker-compose.yaml has no parseable documents")
		return
	}
	services, ok := docs[0]["services"].(map[string]any)
	if !ok {
		t.Fatal("docker-compose.yaml has no services")
	}

	hostPortOwner := map[string]string{}
	for name, svcRaw := range services {
		svc, ok := svcRaw.(map[string]any)
		if !ok {
			continue
		}
		ports, _ := svc["ports"].([]any)
		for _, p := range ports {
			mapping, ok := p.(string)
			if !ok {
				continue
			}
			host := strings.SplitN(mapping, ":", 2)[0]
			// Skip ranges (e.g. "40000-50000:..."): they cannot clash with a
			// single host port in this example.
			if strings.Contains(host, "-") {
				continue
			}
			if owner, dup := hostPortOwner[host]; dup {
				t.Errorf("host port %s is published by both %q and %q (SEC-014)", host, owner, name)
			} else {
				hostPortOwner[host] = name
			}
		}
	}

	// Port 9200 belongs to oCIS itself; only the ocis service may publish it.
	if owner := hostPortOwner["9200"]; owner != "ocis" {
		t.Errorf("host port 9200 is published by %q, want only \"ocis\" (SEC-014)", owner)
	}

	bridge, ok := services["ocis-ftp-bridge"].(map[string]any)
	if !ok {
		t.Fatal("docker-compose.yaml has no ocis-ftp-bridge service")
	}
	hc, ok := bridge["healthcheck"].(map[string]any)
	if !ok {
		t.Fatal("ocis-ftp-bridge service has no healthcheck")
	}
	testCmd, ok := hc["test"].([]any)
	if !ok || len(testCmd) == 0 {
		t.Fatal("ocis-ftp-bridge healthcheck has no test command")
	}
	probe, _ := testCmd[len(testCmd)-1].(string)
	if !strings.Contains(probe, "localhost:9090/healthz") {
		t.Errorf("ocis-ftp-bridge healthcheck probes %q, want localhost:9090/healthz (SEC-015)", probe)
	}
}

// TestDockerfileOpsPort9090 guards SEC-015: the Dockerfile must EXPOSE the
// aligned ops port 9090 and probe it in the HEALTHCHECK.
func TestDockerfileOpsPort9090(t *testing.T) {
	raw := string(readRepoFile(t, "Dockerfile"))
	if !strings.Contains(raw, "EXPOSE 9090/tcp") {
		t.Error("Dockerfile does not EXPOSE 9090/tcp for the HTTP operations port (SEC-015)")
	}
	if strings.Contains(raw, "EXPOSE 9200") {
		t.Error("Dockerfile EXPOSEs 9200 for the HTTP operations port; 9200 belongs to oCIS (SEC-014/SEC-015)")
	}
	if !strings.Contains(raw, "http://localhost:9090/healthz") {
		t.Error("Dockerfile HEALTHCHECK does not probe http://localhost:9090/healthz (SEC-015)")
	}
}

// TestExampleConfigOpsPort9090 guards SEC-015: the example configuration must
// use the aligned ops port 9090.
func TestExampleConfigOpsPort9090(t *testing.T) {
	var cfg map[string]any
	if err := yaml.Unmarshal(readRepoFile(t, "config.yaml.example"), &cfg); err != nil {
		t.Fatalf("config.yaml.example is not valid YAML: %v", err)
	}
	httpCfg, ok := cfg["http"].(map[string]any)
	if !ok {
		t.Fatal("config.yaml.example has no http section")
	}
	if got := httpCfg["address"]; got != ":9090" {
		t.Errorf("config.yaml.example http.address = %v, want \":9090\" (SEC-015)", got)
	}
}

// TestDockerignoreExcludesLocalArtifacts guards QLT-007: the docker build
// context must not include the gitignored repo-root binary or the generated
// SBOM documents.
func TestDockerignoreExcludesLocalArtifacts(t *testing.T) {
	hasBinary, hasSBOM := false, false
	for _, line := range strings.Split(string(readRepoFile(t, ".dockerignore")), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == "/ocis-ftp-bridge" || line == "ocis-ftp-bridge" {
			hasBinary = true
		}
		if strings.Contains(line, "sbom") && strings.Contains(line, ".json") {
			hasSBOM = true
		}
	}
	if !hasBinary {
		t.Error(".dockerignore does not exclude the repo-root ocis-ftp-bridge binary (QLT-007)")
	}
	if !hasSBOM {
		t.Error(".dockerignore does not exclude the generated sbom.*.json files (QLT-007)")
	}
}
