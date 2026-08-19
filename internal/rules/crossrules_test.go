package rules

import (
	"testing"

	"github.com/Arman-Chaudhury/seaworthy/internal/audit"
)

func TestDanglingService(t *testing.T) {
	expectFindings(t, runRules(t, demoContext(t), "dangling-service"), []string{
		"dangling-service|shop-api|",
	})
	// Selector-less Services are exempt.
	ctx := inlineContext(t, `
apiVersion: v1
kind: Service
metadata: {name: external, namespace: shop}
spec:
  type: ExternalName
  externalName: db.example.com
`)
	expectFindings(t, runRules(t, ctx, "dangling-service"), nil)
}

func TestHPATargetMissing(t *testing.T) {
	expectFindings(t, runRules(t, demoContext(t), "hpa-target-missing"), []string{
		"hpa-target-missing|shop-search-hpa|",
	})
}

func TestHPAReplicasConflict(t *testing.T) {
	expectFindings(t, runRules(t, demoContext(t), "hpa-replicas-conflict"), []string{
		"hpa-replicas-conflict|shop-web|",
	})
}

func TestNoPDB(t *testing.T) {
	// shop-web: 3 replicas, uncovered. shop-catalog: covered by its PDB.
	expectFindings(t, runRules(t, demoContext(t), "no-pdb"), []string{
		"no-pdb|shop-web|",
	})
	// matchExpressions selectors are honored.
	ctx := inlineContext(t, `
apiVersion: apps/v1
kind: Deployment
metadata: {name: exp, namespace: shop}
spec:
  replicas: 2
  selector: {matchLabels: {app: exp}}
  template:
    metadata: {labels: {app: exp}}
    spec:
      containers: [{name: c, image: img:1}]
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata: {name: exp-pdb, namespace: shop}
spec:
  minAvailable: 1
  selector:
    matchExpressions:
      - {key: app, operator: In, values: [exp]}
`)
	expectFindings(t, runRules(t, ctx, "no-pdb"), nil)
}

func TestSingleReplica(t *testing.T) {
	expectFindings(t, runRules(t, demoContext(t), "single-replica"), []string{
		"single-replica|shop-worker|",
	})
	// Unset replicas defaults to 1; an HPA suppresses the finding.
	ctx := inlineContext(t, `
apiVersion: apps/v1
kind: Deployment
metadata: {name: implicit, namespace: shop}
spec:
  selector: {matchLabels: {app: implicit}}
  template:
    metadata: {labels: {app: implicit}}
    spec:
      containers: [{name: c, image: img:1}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: scaled, namespace: shop}
spec:
  replicas: 1
  selector: {matchLabels: {app: scaled}}
  template:
    metadata: {labels: {app: scaled}}
    spec:
      containers: [{name: c, image: img:1}]
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata: {name: scaled-hpa, namespace: shop}
spec:
  scaleTargetRef: {apiVersion: apps/v1, kind: Deployment, name: scaled}
  minReplicas: 1
  maxReplicas: 5
  metrics: []
`)
	expectFindings(t, runRules(t, ctx, "single-replica"), []string{
		"single-replica|implicit|",
	})
}

// TestDemoFixtureFullAudit pins the complete expected finding set for
// the seeded fixture — the same contract the kind e2e asserts (M7).
func TestDemoFixtureFullAudit(t *testing.T) {
	fs := runRules(t, demoContext(t))
	var high, medium, low int
	for _, f := range fs {
		switch f.Severity {
		case audit.SeverityHigh:
			high++
		case audit.SeverityMedium:
			medium++
		case audit.SeverityLow:
			low++
		}
	}
	if len(fs) != 18 || high != 13 || medium != 3 || low != 2 {
		t.Errorf("full audit = %d findings (%d/%d/%d high/med/low), want 18 (13/3/2)",
			len(fs), high, medium, low)
		for _, f := range fs {
			t.Logf("  %s %s|%s|%s", f.Severity, f.Rule, f.Name, f.Detail)
		}
	}
}
