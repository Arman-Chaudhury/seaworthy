package report

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Arman-Chaudhury/seaworthy/internal/audit"
)

var update = flag.Bool("update", false, "rewrite golden files")

// fixtureFindings is a small, fixed set covering all severities, a
// cross-resource finding without detail, and a location-less (live)
// finding — enough to exercise every renderer path.
func fixtureFindings() []audit.Finding {
	fs := []audit.Finding{
		{
			Rule: "latest-image", Severity: audit.SeverityHigh,
			Kind: "Deployment", Namespace: "shop", Name: "web", Detail: "web",
			Message: `container "web": image "nginx:latest" is not pinned`,
			Hint:    "pin a version tag or digest so rollouts and rollbacks are reproducible",
			File:    "deploy/web.yaml", Line: 4,
		},
		{
			Rule: "no-pdb", Severity: audit.SeverityMedium,
			Kind: "Deployment", Namespace: "shop", Name: "web",
			Message: "3 replicas but no PodDisruptionBudget matches its pods",
			Hint:    "add a PDB so voluntary disruptions cannot take every replica down at once",
			File:    "deploy/web.yaml", Line: 4,
		},
		{
			Rule: "missing-labels", Severity: audit.SeverityLow,
			Kind: "Deployment", Namespace: "shop", Name: "api",
			Message: "missing label(s) app.kubernetes.io/name",
			Hint:    "add the recommended labels",
			// No file/line: a live-cluster finding.
		},
	}
	audit.Sort(fs)
	return fs
}

func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing golden (run `go test ./internal/report -update`): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s output differs from golden file %s;\ngot:\n%s", name, path, got)
	}
}

func TestTableGolden(t *testing.T) {
	fs := fixtureFindings()
	var buf bytes.Buffer
	WriteTable(&buf, fs, Summarize(fs, 1), &Delta{New: []string{"abc"}, Fixed: nil}, false)
	checkGolden(t, "table", buf.Bytes())
}

func TestTableColor(t *testing.T) {
	fs := fixtureFindings()
	var buf bytes.Buffer
	WriteTable(&buf, fs, Summarize(fs, 0), nil, true)
	if !strings.Contains(buf.String(), "\x1b[31m") {
		t.Error("color mode should emit ANSI escapes for high severity")
	}
}

func TestJSONGolden(t *testing.T) {
	fs := fixtureFindings()
	var buf bytes.Buffer
	if err := NewRun(fs, 1).WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "run", buf.Bytes())
}

func TestSARIFGolden(t *testing.T) {
	fs := fixtureFindings()
	rules := []RuleInfo{
		{ID: "latest-image", Desc: "image not pinned", Hint: "pin it"},
		{ID: "no-pdb", Desc: "no PDB", Hint: "add one"},
		{ID: "missing-labels", Desc: "labels missing", Hint: "add them"},
	}
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, "test", rules, fs); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, `"version": "2.1.0"`) || !strings.Contains(out, `"level": "error"`) {
		t.Errorf("SARIF missing required fields:\n%s", out)
	}
	// The live finding has no location; the file finding does.
	if strings.Count(out, `"physicalLocation"`) != 2 {
		t.Errorf("want 2 physical locations, got:\n%s", out)
	}
	checkGolden(t, "sarif", buf.Bytes())
}

func TestHTMLGolden(t *testing.T) {
	fs := fixtureFindings()
	var buf bytes.Buffer
	if err := WriteHTML(&buf, fs, Summarize(fs, 1), &Delta{New: []string{"abc"}}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"<!doctype html>", "latest-image", "shop/Deployment/web", "baseline-suppressed"} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
	if strings.Contains(out, "http://") || strings.Contains(out, "https://") {
		t.Error("HTML must be self-contained (no external references)")
	}
	checkGolden(t, "html", buf.Bytes())
}

func TestSummarize(t *testing.T) {
	sum := Summarize(fixtureFindings(), 2)
	if sum.Total != 3 || sum.High != 1 || sum.Medium != 1 || sum.Low != 1 || sum.Suppressed != 2 {
		t.Errorf("Summarize = %+v", sum)
	}
}
