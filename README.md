# seaworthy

Workload-hygiene auditor for Kubernetes: point it at rendered manifests (or a
live cluster) and it flags the deploy-breakers reviewers miss — missing
probes, unbounded resources, `:latest` images, root containers, multi-replica
Deployments with no PodDisruptionBudget, Services whose selectors match
nothing — then gates your CI/CD pipeline on the result.

Single-doc linters (kube-score, kube-linter, Polaris) check each resource in
isolation. Most real outages live *between* resources: the Service pointing at
a label that was renamed, the HPA scaling a Deployment that pins `replicas`,
the PDB nobody wrote. seaworthy loads the whole manifest set into one model so
its rules can see across documents — and the same rules run identically
against files in CI and against a live cluster via the Kubernetes API.

```
 manifests/*.yaml ─┐
 helm template ────┼─▶ loader ─▶ workload model ─▶ rules engine ─▶ findings
 kustomize build ──┤             (cross-resource     (12+ stock        │
 live cluster ─────┘              graph)              rules)           ├─▶ terminal / JSON
   (client-go)                                                        ├─▶ SARIF (code scanning)
                                                                      ├─▶ HTML dashboard
                                                                      └─▶ exit code (--fail-on)
```

## Status

Scaffolded — being built milestone-by-milestone per [BUILD_PLAN.md](BUILD_PLAN.md);
full design in [SPEC.md](SPEC.md).

## Quickstart (target CLI)

```bash
go build ./cmd/seaworthy

# Audit rendered manifests — no cluster needed
./seaworthy audit ./deploy/                      # terminal table
helm template ./chart | ./seaworthy audit -      # anything that emits YAML

# Gate a pipeline: exit 1 if any high-severity finding survives the baseline
./seaworthy audit --fail-on high --format sarif ./deploy/ > results.sarif

# Audit a live cluster (read-only, uses your kubeconfig)
./seaworthy audit --live --context prod --namespace payments

# Self-contained HTML report
./seaworthy audit --format html ./deploy/ > report.html
```

## Stock rules

| Rule | Signal | Severity |
| --- | --- | --- |
| `latest-image` | image untagged or `:latest` | high |
| `missing-probes` | container without liveness/readiness probes | high |
| `no-resource-requests` | container without CPU/memory requests or limits | high |
| `runs-as-root` | no `runAsNonRoot`, or explicit root user | high |
| `privilege-escalation` | `privileged` or `allowPrivilegeEscalation` | high |
| `host-access` | `hostPath` / `hostNetwork` / `hostPID` | high |
| `secrets-in-env` | credential-shaped env var with a literal value | high |
| `deprecated-api` | apiVersion removed or deprecated upstream | high |
| `dangling-service` | Service selector matches no workload | high |
| `hpa-target-missing` | HPA `scaleTargetRef` resolves to nothing | high |
| `hpa-replicas-conflict` | Deployment pins `replicas` under an HPA | medium |
| `no-pdb` | multi-replica workload without a matching PDB | medium |
| `single-replica` | Deployment with one replica (no HA) | medium |
| `missing-labels` | missing `app.kubernetes.io/*` recommended labels | low |

Cross-resource rules (`dangling-service`, `no-pdb`, both `hpa-*`) are the
point: they need the whole manifest set, not one document at a time.

## Ops surface

- **Baselines**: accept current findings into a suppression file (with
  expiry dates) so brownfield repos can adopt the gate without a big-bang fix.
- **Deltas**: `--previous run.json` reports new/fixed findings run-over-run.
- **Exit codes**: `0` clean or below threshold, `1` findings at/above
  `--fail-on`, `2` load/usage error — designed for CI.
- **In-cluster**: Helm chart deploys seaworthy as a read-only CronJob with a
  least-privilege ClusterRole; kind-based e2e tests run in GitHub Actions.

## License

MIT
