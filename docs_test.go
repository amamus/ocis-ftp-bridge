package main

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/amamus/ocis-ftp-bridge/pkg/config"
	"gopkg.in/yaml.v3"
)

// These tests guard docs/security.md against the documentation drift found in
// the audit (QLT-004): bridge-configuration snippets must decode against the
// real config schema with strict field validation (the same KnownFields(true)
// the production loader uses), the operations port must be 9090 (9200 belongs
// to oCIS), and the metric names referenced in the examples must exist.

// configRootKeys are the top-level keys of the bridge configuration schema
// (the yaml tags of config.Config).
var configRootKeys = map[string]bool{
	"server":        true,
	"ocis":          true,
	"spool":         true,
	"accounts":      true,
	"observability": true,
	"http":          true,
}

// retiredConfigRootKeys are top-level keys that older documentation used for
// the bridge configuration but that the schema never accepted. A yaml block
// using one of these is a bridge-config snippet with the wrong root and must
// fail the known-key check below (QLT-004).
var retiredConfigRootKeys = map[string]bool{
	"ftp": true,
}

// knownMetricNames are the Prometheus metric names exposed on /metrics
// (pkg/http/server.go).
var knownMetricNames = map[string]bool{
	"ocis_ftp_sessions_total":                true,
	"ocis_ftp_sessions_active":               true,
	"ocis_ftp_uploads_total":                 true,
	"ocis_ftp_uploads_failures_total":        true,
	"ocis_ftp_uploads_bytes_total":           true,
	"ocis_ftp_uploads_duration_seconds":      true,
	"ocis_ftp_ocis_requests_total":           true,
	"ocis_ftp_health_check_total":            true,
	"ocis_ftp_health_check_duration_seconds": true,
	"ocis_ftp_spool_size_bytes":              true,
	"ocis_ftp_spool_file_count":              true,
	"ocis_ftp_spool_capacity_bytes":          true,
	"ocis_ftp_spool_usage_percent":           true,
	"ocis_ftp_spool_capacity_exceeded_total": true,
}

// yamlFences extracts the contents of all yaml fenced code blocks from a
// Markdown document, split into individual YAML documents.
func yamlFences(t *testing.T, doc string) [][]byte {
	t.Helper()
	var docs [][]byte
	var current []string
	inYAML := false
	flushBlock := func() {
		if len(current) > 0 {
			docs = append(docs, splitYAMLDocuments([]byte(strings.Join(current, "\n")))...)
			current = nil
		}
	}
	for _, line := range strings.Split(doc, "\n") {
		if strings.HasPrefix(line, "```") {
			if inYAML {
				flushBlock()
				inYAML = false
			} else if strings.TrimSpace(line) == "```yaml" {
				inYAML = true
			}
			continue
		}
		if inYAML {
			current = append(current, line)
		}
	}
	if inYAML {
		flushBlock()
	}
	return docs
}

// TestSecurityDocConfigSnippets decodes every bridge-configuration YAML
// snippet in docs/security.md against the real configuration schema with
// strict field validation, so the documentation cannot drift from the keys
// the loader actually accepts (QLT-004).
func TestSecurityDocConfigSnippets(t *testing.T) {
	doc := string(readRepoFile(t, "docs/security.md"))

	checked := 0
	for i, raw := range yamlFences(t, doc) {
		var top map[string]any
		if err := yaml.Unmarshal(raw, &top); err != nil {
			t.Errorf("yaml block %d does not parse: %v", i, err)
			continue
		}
		if len(top) == 0 {
			continue
		}
		isBridgeConfig := false
		for key := range top {
			if configRootKeys[key] || retiredConfigRootKeys[key] {
				isBridgeConfig = true
				break
			}
		}
		if !isBridgeConfig {
			// docker-compose, Kubernetes, dependabot, ... snippets
			continue
		}
		checked++
		for key := range top {
			if !configRootKeys[key] {
				t.Errorf("yaml block %d uses unknown top-level key %q (known keys: server, ocis, spool, accounts, observability, http)", i, key)
			}
		}
		cfg := config.New()
		dec := yaml.NewDecoder(bytes.NewReader(raw))
		dec.KnownFields(true)
		if err := dec.Decode(cfg); err != nil {
			t.Errorf("yaml block %d does not decode against the config schema: %v", i, err)
		}
	}
	if checked == 0 {
		t.Error("no bridge-configuration YAML snippets found in docs/security.md; the doc-test is not covering anything")
	}
}

// TestSecurityDocOpsPort guards the stale port references from the audit:
// 9200 is the oCIS port; the bridge operations server listens on 9090
// (QLT-004).
func TestSecurityDocOpsPort(t *testing.T) {
	doc := string(readRepoFile(t, "docs/security.md"))
	if strings.Contains(doc, "9200") {
		t.Error("docs/security.md still references port 9200; the bridge operations port is 9090 (9200 belongs to oCIS)")
	}
}

// TestSecurityDocMetricNames ensures every ocis_ftp_* metric referenced in
// docs/security.md actually exists on /metrics (QLT-004).
func TestSecurityDocMetricNames(t *testing.T) {
	doc := string(readRepoFile(t, "docs/security.md"))
	re := regexp.MustCompile(`ocis_ftp_[a-z_]+\*?`)
	seen := map[string]bool{}
	for _, name := range re.FindAllString(doc, -1) {
		seen[name] = true
		if strings.HasSuffix(name, "*") {
			// Glob family reference (e.g. ocis_ftp_spool_*): valid when at
			// least one known metric carries the prefix.
			prefix := strings.TrimSuffix(name, "*")
			found := false
			for known := range knownMetricNames {
				if strings.HasPrefix(known, prefix) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("docs/security.md references unknown metric family %q", name)
			}
			continue
		}
		if !knownMetricNames[name] {
			t.Errorf("docs/security.md references unknown metric %q", name)
		}
	}
	if len(seen) == 0 {
		t.Error("docs/security.md references no ocis_ftp_* metrics; expected the metrics examples to be present")
	}
}
