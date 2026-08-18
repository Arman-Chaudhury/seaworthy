package rules

import (
	"testing"

	"github.com/Arman-Chaudhury/seaworthy/internal/audit"
	"github.com/Arman-Chaudhury/seaworthy/internal/manifest"
)

const demoFixture = "../../testdata/fixtures/demo-app.yaml"

func demoContext(t *testing.T) *Context {
	t.Helper()
	snap, findings, err := manifest.Load([]string{demoFixture}, nil)
	if err != nil || len(findings) != 0 {
		t.Fatalf("Load: err=%v findings=%v", err, findings)
	}
	return &Context{Snap: snap}
}

// keys renders findings as rule|object|detail for compact set assertions.
func keys(fs []audit.Finding) map[string]bool {
	out := map[string]bool{}
	for _, f := range fs {
		out[f.Rule+"|"+f.Name+"|"+f.Detail] = true
	}
	return out
}

func runRules(t *testing.T, ctx *Context, only ...string) []audit.Finding {
	t.Helper()
	fs, err := Run(ctx, Options{Only: only})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return fs
}

func expectFindings(t *testing.T, got []audit.Finding, want []string) {
	t.Helper()
	gotKeys := keys(got)
	for _, w := range want {
		if !gotKeys[w] {
			t.Errorf("missing finding %s", w)
		}
	}
	if len(gotKeys) != len(want) {
		t.Errorf("finding count = %d, want %d: %v", len(gotKeys), len(want), gotKeys)
	}
}

func TestLatestImage(t *testing.T) {
	expectFindings(t, runRules(t, demoContext(t), "latest-image"), []string{
		"latest-image|shop-web|web",
		"latest-image|shop-worker|worker",
	})
}

func TestNoResourceRequests(t *testing.T) {
	expectFindings(t, runRules(t, demoContext(t), "no-resource-requests"), []string{
		"no-resource-requests|shop-web|web",
	})
}

func TestRunStampsIdentityAndSorts(t *testing.T) {
	fs := runRules(t, demoContext(t), "latest-image")
	for _, f := range fs {
		if f.Rule != "latest-image" || f.Severity != audit.SeverityHigh || f.Hint == "" {
			t.Errorf("identity not stamped: %+v", f)
		}
	}
	for i := 1; i < len(fs); i++ {
		if fs[i].Line < fs[i-1].Line {
			t.Errorf("findings not sorted by line: %d before %d", fs[i-1].Line, fs[i].Line)
		}
	}
}

func TestUnknownRuleIsError(t *testing.T) {
	if _, err := Run(demoContext(t), Options{Only: []string{"no-such-rule"}}); err == nil {
		t.Error("want error for unknown rule id")
	}
}

func TestDisabledAndOverride(t *testing.T) {
	ctx := demoContext(t)
	fs, err := Run(ctx, Options{Disabled: map[string]bool{"latest-image": true}})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if f.Rule == "latest-image" {
			t.Error("disabled rule still ran")
		}
	}
	fs, err = Run(ctx, Options{
		Only:             []string{"latest-image"},
		SeverityOverride: map[string]audit.Severity{"latest-image": audit.SeverityLow},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if f.Severity != audit.SeverityLow {
			t.Errorf("override not applied: %v", f.Severity)
		}
	}
}

func TestIgnoreNamespaces(t *testing.T) {
	fs, err := Run(demoContext(t), Options{IgnoreNamespaces: map[string]bool{"shop": true}})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("ignored namespace still produced %d findings", len(fs))
	}
}

func TestImageTag(t *testing.T) {
	cases := map[string]string{
		"nginx":                           "",
		"nginx:latest":                    "latest",
		"nginx:1.27":                      "1.27",
		"registry:5000/team/app":          "",
		"registry:5000/team/app:2.1":      "2.1",
		"ghcr.io/a/b@sha256:abcd":         "digest",
		"registry:5000/team/app@sha256:x": "digest",
	}
	for img, want := range cases {
		if got := imageTag(img); got != want {
			t.Errorf("imageTag(%q) = %q, want %q", img, got, want)
		}
	}
}
