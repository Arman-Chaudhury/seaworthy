package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Arman-Chaudhury/seaworthy/internal/audit"
)

func write(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "seaworthy.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

const sample = `
rules:
  missing-labels:
    enabled: false
  single-replica:
    severity: high
required-labels: [team]
ignore-namespaces: [kube-system]
`

func TestLoadAndAccessors(t *testing.T) {
	c, err := Load(write(t, sample))
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{"missing-labels": true, "single-replica": true}
	if err := c.Validate(known); err != nil {
		t.Fatal(err)
	}
	if !c.Disabled()["missing-labels"] || c.Disabled()["single-replica"] {
		t.Errorf("Disabled = %v", c.Disabled())
	}
	if c.SeverityOverrides()["single-replica"] != audit.SeverityHigh {
		t.Errorf("SeverityOverrides = %v", c.SeverityOverrides())
	}
	if !c.IgnoredNamespaces()["kube-system"] {
		t.Errorf("IgnoredNamespaces = %v", c.IgnoredNamespaces())
	}
	if len(c.RequiredLabels) != 1 || c.RequiredLabels[0] != "team" {
		t.Errorf("RequiredLabels = %v", c.RequiredLabels)
	}
}

func TestValidateRejectsUnknowns(t *testing.T) {
	c, err := Load(write(t, "rules:\n  no-such-rule: {enabled: false}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(map[string]bool{}); err == nil {
		t.Error("unknown rule id should fail validation")
	}
	c, err = Load(write(t, "rules:\n  ok: {severity: critical}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(map[string]bool{"ok": true}); err == nil {
		t.Error("unknown severity should fail validation")
	}
}

func TestStrictParsing(t *testing.T) {
	if _, err := Load(write(t, "rulez: {}\n")); err == nil {
		t.Error("unknown top-level key should fail (typo protection)")
	}
	if _, err := Load("/no/such/config.yaml"); err == nil {
		t.Error("explicit missing config should error")
	}
}
