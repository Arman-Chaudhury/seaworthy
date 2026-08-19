package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const demoFixture = "../../testdata/fixtures/demo-app.yaml"

func runCLI(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestAuditFailsOnFixture(t *testing.T) {
	code, out, _ := runCLI(t, "", "audit", demoFixture)
	if code != 1 {
		t.Errorf("exit = %d, want 1 (fixture has high findings)", code)
	}
	if !strings.Contains(out, "latest-image") || !strings.Contains(out, "shop/Deployment/shop-web") {
		t.Errorf("table output missing expected content:\n%s", out)
	}
}

func TestAuditJSON(t *testing.T) {
	code, out, _ := runCLI(t, "", "audit", "--format", "json", demoFixture)
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
	var doc struct {
		SchemaVersion int `json:"schema_version"`
		Summary       struct{ Total, High int }
		Findings      []struct {
			Rule, Severity, Fingerprint string
		}
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
	if doc.SchemaVersion != 1 || doc.Summary.Total == 0 || len(doc.Findings) != doc.Summary.Total {
		t.Errorf("bad run document: %+v", doc)
	}
	if doc.Findings[0].Severity == "" || doc.Findings[0].Fingerprint == "" {
		t.Errorf("finding missing severity/fingerprint: %+v", doc.Findings[0])
	}
}

func TestAuditCleanManifestPasses(t *testing.T) {
	clean := `
apiVersion: v1
kind: ConfigMap
metadata: {name: settings, namespace: shop}
data: {key: value}
`
	dir := t.TempDir()
	path := filepath.Join(dir, "clean.yaml")
	if err := os.WriteFile(path, []byte(clean), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := runCLI(t, "", "audit", path); code != 0 {
		t.Errorf("exit = %d, want 0; stderr: %s", code, errOut)
	}
}

func TestAuditStdin(t *testing.T) {
	code, _, _ := runCLI(t, "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n  containers:\n    - name: c\n      image: busybox\n", "audit", "-")
	if code != 1 {
		t.Errorf("exit = %d, want 1 (busybox untagged)", code)
	}
}

func TestFailOnThreshold(t *testing.T) {
	// Only low findings requested via a low-only rule filter would still
	// exit 1 at --fail-on low; at --fail-on high a medium/low-only run
	// passes. The fixture always has highs, so filter to a single rule
	// that yields none at high severity is not available yet — instead
	// verify threshold parsing failure paths.
	if code, _, _ := runCLI(t, "", "audit", "--fail-on", "critical", demoFixture); code != 2 {
		t.Error("unknown --fail-on should exit 2")
	}
}

func TestUsageErrors(t *testing.T) {
	if code, _, _ := runCLI(t, "", "audit"); code != 2 {
		t.Error("no paths should exit 2")
	}
	if code, _, _ := runCLI(t, "", "audit", "/no/such/path.yaml"); code != 2 {
		t.Error("missing path should exit 2")
	}
	if code, _, _ := runCLI(t, "", "audit", "--rule", "nope", demoFixture); code != 2 {
		t.Error("unknown rule should exit 2")
	}
	if code, _, _ := runCLI(t, "", "bogus"); code != 2 {
		t.Error("unknown command should exit 2")
	}
	if code, _, _ := runCLI(t, ""); code != 2 {
		t.Error("no args should exit 2")
	}
}

func TestRulesCommand(t *testing.T) {
	code, out, _ := runCLI(t, "", "rules")
	if code != 0 || !strings.Contains(out, "latest-image") {
		t.Errorf("rules output: code=%d\n%s", code, out)
	}
}
