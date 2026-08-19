package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBaselineWorkflow drives the brownfield-adoption loop end to end:
// freeze current debt, pass the gate, then catch only new debt.
func TestBaselineWorkflow(t *testing.T) {
	dir := t.TempDir()
	blPath := filepath.Join(dir, "baseline.yaml")

	// 1. Accept all current findings.
	code, _, errOut := runCLI(t, "", "audit", "--baseline", blPath, "--update-baseline", demoFixture)
	if code != 0 {
		t.Fatalf("update-baseline exit = %d (%s)", code, errOut)
	}
	if !strings.Contains(errOut, "accepted into") {
		t.Errorf("no confirmation message: %s", errOut)
	}

	// 2. Same input now passes, with everything suppressed.
	code, out, _ := runCLI(t, "", "audit", "--baseline", blPath, "--format", "json", demoFixture)
	if code != 0 {
		t.Fatalf("baselined audit exit = %d, want 0", code)
	}
	var run struct {
		Summary struct{ Total, Suppressed int }
	}
	if err := json.Unmarshal([]byte(out), &run); err != nil {
		t.Fatal(err)
	}
	if run.Summary.Total != 0 || run.Summary.Suppressed != 18 {
		t.Errorf("summary = %+v, want 0 total / 18 suppressed", run.Summary)
	}

	// 3. New debt still fails the gate.
	data, err := os.ReadFile(demoFixture)
	if err != nil {
		t.Fatal(err)
	}
	extra := string(data) + `
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: brand-new, namespace: shop}
spec:
  selector: {matchLabels: {app: brand-new}}
  template:
    metadata: {labels: {app: brand-new}}
    spec:
      containers: [{name: c, image: fresh:latest}]
`
	code, out, _ = runCLI(t, extra, "audit", "--baseline", blPath, "--format", "json", "-")
	if code != 1 {
		t.Errorf("new debt exit = %d, want 1", code)
	}
	if !strings.Contains(out, "brand-new") || strings.Contains(out, `"name": "shop-web"`) {
		t.Errorf("only the new object should surface:\n%s", out)
	}
}

func TestPreviousDelta(t *testing.T) {
	dir := t.TempDir()
	prevPath := filepath.Join(dir, "prev.json")

	// Record a run, then audit a subset (one rule) against it: every
	// other finding shows as fixed, nothing as new.
	_, out, _ := runCLI(t, "", "audit", "--format", "json", demoFixture)
	if err := os.WriteFile(prevPath, []byte(out), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ := runCLI(t, "", "audit", "--rule", "latest-image", "--previous", prevPath, "--format", "json", demoFixture)
	if code != 1 {
		t.Fatalf("exit = %d", code)
	}
	var run struct {
		Delta struct{ New, Fixed []string }
	}
	if err := json.Unmarshal([]byte(out), &run); err != nil {
		t.Fatal(err)
	}
	if len(run.Delta.New) != 0 || len(run.Delta.Fixed) != 16 {
		t.Errorf("delta = %d new / %d fixed, want 0 / 16", len(run.Delta.New), len(run.Delta.Fixed))
	}
	if len(run.Delta.Fixed) > 0 && !strings.Contains(run.Delta.Fixed[0], " ") {
		t.Errorf("delta entries should read 'fingerprint rule object': %q", run.Delta.Fixed[0])
	}
}

func TestConfigFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "seaworthy.yaml")
	cfg := `
rules:
  missing-labels: {enabled: false}
  single-replica: {severity: high}
ignore-namespaces: [shop]
`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	// Everything in the fixture is namespace shop → all ignored.
	code, out, _ := runCLI(t, "", "audit", "--config", cfgPath, "--format", "json", demoFixture)
	if code != 0 {
		t.Errorf("exit = %d, want 0 (namespace ignored); out:\n%s", code, out)
	}

	badCfg := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(badCfg, []byte("rules:\n  nope: {enabled: false}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runCLI(t, "", "audit", "--config", badCfg, demoFixture); code != 2 {
		t.Error("invalid config should exit 2")
	}
}
