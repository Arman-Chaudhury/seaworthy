package baseline

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Arman-Chaudhury/seaworthy/internal/audit"
)

func sampleFindings() []audit.Finding {
	return []audit.Finding{
		{Rule: "latest-image", Severity: audit.SeverityHigh, Kind: "Deployment", Namespace: "shop", Name: "web", Detail: "web", Message: "not pinned"},
		{Rule: "no-pdb", Severity: audit.SeverityMedium, Kind: "Deployment", Namespace: "shop", Name: "web", Message: "no pdb"},
	}
}

func TestRoundTripAndApply(t *testing.T) {
	fs := sampleFindings()
	path := filepath.Join(t.TempDir(), "baseline.yaml")
	if err := Build(fs, nil).Write(path); err != nil {
		t.Fatal(err)
	}
	bl, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(bl.Findings) != 2 || bl.Findings[0].Object != "shop/Deployment/web" {
		t.Fatalf("round trip lost data: %+v", bl.Findings)
	}
	kept, suppressed := bl.Apply(fs, time.Now())
	if len(kept) != 0 || suppressed != 2 {
		t.Errorf("Apply = %d kept, %d suppressed; want 0, 2", len(kept), suppressed)
	}
	// A finding not in the baseline passes through.
	extra := audit.Finding{Rule: "runs-as-root", Kind: "Deployment", Namespace: "shop", Name: "api"}
	kept, suppressed = bl.Apply(append(fs, extra), time.Now())
	if len(kept) != 1 || kept[0].Rule != "runs-as-root" || suppressed != 2 {
		t.Errorf("Apply with extra = %v, %d", kept, suppressed)
	}
}

func TestMissingFileIsEmpty(t *testing.T) {
	bl, err := Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err != nil || len(bl.Findings) != 0 {
		t.Fatalf("missing baseline: bl=%+v err=%v", bl, err)
	}
}

func TestExpiry(t *testing.T) {
	f := sampleFindings()[0]
	bl := Build([]audit.Finding{f}, nil)
	bl.Findings[0].Expires = "2026-06-30"
	before, _ := time.Parse("2006-01-02", "2026-06-30")
	after, _ := time.Parse("2006-01-02", "2026-07-01")
	if !bl.Suppresses(f.Fingerprint(), before) {
		t.Error("should suppress on the expiry day itself")
	}
	if bl.Suppresses(f.Fingerprint(), after) {
		t.Error("must stop suppressing after expiry")
	}
	bl.Findings[0].Expires = "not-a-date"
	if bl.Suppresses(f.Fingerprint(), before) {
		t.Error("unparsable expiry must not suppress")
	}
}

func TestBuildCarriesExpiries(t *testing.T) {
	fs := sampleFindings()
	old := Build(fs, nil)
	old.Findings[0].Expires = "2027-01-01"
	expiringFP := old.Findings[0].Fingerprint
	rebuilt := Build(fs, old)
	for _, e := range rebuilt.Findings {
		if e.Fingerprint == expiringFP && e.Expires != "2027-01-01" {
			t.Errorf("expiry lost on rebuild: %+v", e)
		}
	}
}

func TestWriteIsReviewable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.yaml")
	if err := Build(sampleFindings(), nil).Write(path); err != nil {
		t.Fatal(err)
	}
	bl, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range bl.Findings {
		if e.Rule == "" || e.Object == "" || !strings.Contains(e.Object, "/") {
			t.Errorf("entry not human-reviewable: %+v", e)
		}
	}
}
