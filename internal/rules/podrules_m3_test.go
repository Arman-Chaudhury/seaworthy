package rules

import (
	"strings"
	"testing"

	"github.com/Arman-Chaudhury/seaworthy/internal/manifest"
)

// inlineContext builds a Context from an inline manifest string.
func inlineContext(t *testing.T, yaml string) *Context {
	t.Helper()
	snap, findings, err := manifest.Load([]string{"-"}, strings.NewReader(yaml))
	if err != nil || len(findings) != 0 {
		t.Fatalf("load inline: err=%v findings=%v", err, findings)
	}
	return &Context{Snap: snap}
}

func TestMissingProbes(t *testing.T) {
	expectFindings(t, runRules(t, demoContext(t), "missing-probes"), []string{
		"missing-probes|shop-web|web",
		"missing-probes|shop-worker|worker",
	})
}

func TestMissingProbesJobExemptFromReadiness(t *testing.T) {
	ctx := inlineContext(t, `
apiVersion: batch/v1
kind: Job
metadata: {name: migrate, namespace: shop}
spec:
  template:
    spec:
      containers:
        - name: migrate
          image: shop/migrate:1.0
          livenessProbe:
            exec: {command: ["/bin/true"]}
`)
	expectFindings(t, runRules(t, ctx, "missing-probes"), nil)
}

func TestRunsAsRoot(t *testing.T) {
	expectFindings(t, runRules(t, demoContext(t), "runs-as-root"), []string{
		"runs-as-root|shop-web|web",
		"runs-as-root|shop-worker|worker",
	})
}

func TestRunsAsRootContainerOverridesPod(t *testing.T) {
	// Pod says uid 0, container overrides to non-root: no finding.
	ctx := inlineContext(t, `
apiVersion: v1
kind: Pod
metadata: {name: p, namespace: shop}
spec:
  securityContext: {runAsUser: 0}
  containers:
    - name: c
      image: img:1
      securityContext: {runAsNonRoot: true}
`)
	expectFindings(t, runRules(t, ctx, "runs-as-root"), nil)
	// Non-zero runAsUser alone is proof enough of non-root.
	ctx = inlineContext(t, `
apiVersion: v1
kind: Pod
metadata: {name: p2, namespace: shop}
spec:
  containers:
    - name: c
      image: img:1
      securityContext: {runAsUser: 1000}
`)
	expectFindings(t, runRules(t, ctx, "runs-as-root"), nil)
}

func TestPrivilegeEscalation(t *testing.T) {
	expectFindings(t, runRules(t, demoContext(t), "privilege-escalation"), []string{
		"privilege-escalation|shop-web|web",
		"privilege-escalation|shop-worker|worker",
	})
	ctx := inlineContext(t, `
apiVersion: v1
kind: Pod
metadata: {name: priv, namespace: shop}
spec:
  containers:
    - name: c
      image: img:1
      securityContext: {privileged: true, allowPrivilegeEscalation: false}
`)
	fs := runRules(t, ctx, "privilege-escalation")
	if len(fs) != 1 || fs[0].Message != `container "c" sets privileged: true` {
		t.Errorf("privileged should dominate: %+v", fs)
	}
}

func TestHostAccess(t *testing.T) {
	expectFindings(t, runRules(t, demoContext(t), "host-access"), []string{
		"host-access|shop-worker|volume/spool",
	})
	ctx := inlineContext(t, `
apiVersion: v1
kind: Pod
metadata: {name: hosty, namespace: shop}
spec:
  hostNetwork: true
  hostPID: true
  containers:
    - name: c
      image: img:1
`)
	expectFindings(t, runRules(t, ctx, "host-access"), []string{
		"host-access|hosty|hostNetwork",
		"host-access|hosty|hostPID",
	})
}

func TestSecretsInEnv(t *testing.T) {
	expectFindings(t, runRules(t, demoContext(t), "secrets-in-env"), []string{
		"secrets-in-env|shop-web|web/DB_PASSWORD",
	})
	// valueFrom references are the fix, not a finding.
	ctx := inlineContext(t, `
apiVersion: v1
kind: Pod
metadata: {name: p, namespace: shop}
spec:
  containers:
    - name: c
      image: img:1
      env:
        - name: API_TOKEN
          valueFrom:
            secretKeyRef: {name: creds, key: token}
`)
	expectFindings(t, runRules(t, ctx, "secrets-in-env"), nil)
}

func TestSecretsInEnvNeverLeaksValue(t *testing.T) {
	ctx := inlineContext(t, `
apiVersion: v1
kind: Pod
metadata: {name: p, namespace: shop}
spec:
  containers:
    - name: c
      image: img:1
      env:
        - name: SECRET_KEY
          value: super-secret-value
`)
	fs := runRules(t, ctx, "secrets-in-env")
	if len(fs) != 1 {
		t.Fatalf("findings = %d, want 1", len(fs))
	}
	if got := fs[0].Message + fs[0].Detail; strings.Contains(got, "super-secret-value") {
		t.Errorf("finding leaks the secret value: %q", got)
	}
}

func TestMissingLabels(t *testing.T) {
	expectFindings(t, runRules(t, demoContext(t), "missing-labels"), []string{
		"missing-labels|shop-web|",
		"missing-labels|shop-worker|",
	})
}

func TestMissingLabelsConfigurable(t *testing.T) {
	ctx := demoContext(t)
	ctx.RequiredLabels = []string{"app"}
	// Both defective deployments carry app:; only the catalog (which
	// uses the recommended labels instead) fires under this config.
	expectFindings(t, runRules(t, ctx, "missing-labels"), []string{
		"missing-labels|shop-catalog|",
	})
}

func TestDeprecatedAPI(t *testing.T) {
	expectFindings(t, runRules(t, demoContext(t), "deprecated-api"), nil)
	ctx := inlineContext(t, `
apiVersion: policy/v1beta1
kind: PodDisruptionBudget
metadata: {name: legacy, namespace: shop}
spec: {minAvailable: 1}
---
apiVersion: batch/v1beta1
kind: CronJob
metadata: {name: old-cron, namespace: shop}
spec: {}
`)
	expectFindings(t, runRules(t, ctx, "deprecated-api"), []string{
		"deprecated-api|legacy|",
		"deprecated-api|old-cron|",
	})
}
