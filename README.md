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
 kustomize build ──┤             (cross-resource     (14 stock         │
 live cluster ─────┘              graph)              rules)           ├─▶ terminal / JSON
   (client-go)                                                        ├─▶ SARIF (code scanning)
                                                                      ├─▶ HTML dashboard
                                                                      └─▶ exit code (--fail-on)
```

## Quickstart

```bash
go build ./cmd/seaworthy

# Audit rendered manifests — no cluster needed
./seaworthy audit ./deploy/                      # terminal table
helm template ./chart | ./seaworthy audit -      # anything that emits YAML

# Try it on the seeded demo fixture (18 findings)
./seaworthy audit testdata/fixtures/demo-app.yaml
```

```
shop/Deployment/shop-web  (testdata/fixtures/demo-app.yaml:10)
  high     latest-image           container "web": image "nginx:latest" is not pinned
  high     missing-probes         container "web" has no liveness or readiness probe
  high     no-resource-requests   container "web" is missing requests.cpu, requests.memory, …
  high     secrets-in-env         container "web" sets env DB_PASSWORD from a literal value…
  medium   hpa-replicas-conflict  spec.replicas is pinned to 3 while HPA "shop-web-hpa"…
  medium   no-pdb                 3 replicas but no PodDisruptionBudget matches its pods
  …

18 findings: 13 high, 3 medium, 2 low (0 suppressed by baseline)
```

Audit a live cluster (read-only, uses your kubeconfig):

```bash
./seaworthy audit --live --context prod --namespace payments
```

## Stock rules

`seaworthy rules` lists these; per-rule hints explain the fix.

| Rule | Signal | Severity |
| --- | --- | --- |
| `latest-image` | image untagged or `:latest` | high |
| `missing-probes` | container without liveness/readiness probes (batch exempt) | high |
| `no-resource-requests` | container without CPU/memory requests or limits | high |
| `runs-as-root` | no `runAsNonRoot`, or explicit uid 0 | high |
| `privilege-escalation` | `privileged`, or escalation not disabled | high |
| `host-access` | `hostPath` / `hostNetwork` / `hostPID` / `hostIPC` | high |
| `secrets-in-env` | credential-shaped env var with a literal value | high |
| `deprecated-api` | apiVersion removed or deprecated upstream | high |
| `dangling-service` | Service selector matches no workload | high |
| `hpa-target-missing` | HPA `scaleTargetRef` resolves to nothing | high |
| `parse-error` | document the loader could not parse | high |
| `hpa-replicas-conflict` | workload pins `replicas` under an HPA | medium |
| `no-pdb` | multi-replica workload without a matching PDB | medium |
| `single-replica` | Deployment with one replica (no HA) | medium |
| `missing-labels` | missing `app.kubernetes.io/*` recommended labels | low |

The cross-resource rules (`dangling-service`, `no-pdb`, both `hpa-*`) are the
point: they need the whole manifest set, not one document at a time.

## Gating CI

Exit codes: `0` clean or below threshold, `1` findings at/above `--fail-on`
(default `high`), `2` load/usage error.

```yaml
# .github/workflows/hygiene.yml
- run: helm template ./chart | seaworthy audit --fail-on high -
```

SARIF output turns findings into PR annotations via GitHub code scanning:

```yaml
- run: seaworthy audit --format sarif ./deploy/ > results.sarif || true
- uses: github/codeql-action/upload-sarif@v3
  with: {sarif_file: results.sarif}
```

### Adopting on a brownfield repo

Freeze today's debt, block new debt:

```bash
seaworthy audit --update-baseline ./deploy/     # writes seaworthy-baseline.yaml
git add seaworthy-baseline.yaml                 # review it like any other file
seaworthy audit ./deploy/                       # exit 0 — old debt suppressed
```

Baseline entries carry optional `expires: YYYY-MM-DD` dates so accepted debt
resurfaces instead of living forever. `--previous run.json` adds a new/fixed
delta against an earlier run (`--format json` output is the run document).

## Configuration

Optional `seaworthy.yaml` at the repo root (or `--config`); see
[`examples/seaworthy.yaml`](examples/seaworthy.yaml):

```yaml
rules:
  missing-labels: {enabled: false}
  single-replica: {severity: high}
required-labels: [app.kubernetes.io/name, team]
ignore-namespaces: [kube-system]
```

## Running inside the cluster

The Helm chart deploys a CronJob with a least-privilege read-only
ClusterRole — seaworthy never mutates the cluster, and the chart passes
seaworthy's own rules (dogfooded in CI):

```bash
helm install audit deploy/chart/seaworthy --set schedule="0 6 * * *"
```

There is also a multi-stage distroless [Dockerfile](Dockerfile):

```bash
docker build -t seaworthy .
docker run --rm -v "$PWD/deploy:/deploy:ro" seaworthy audit /deploy
```

## Design

Full design in [SPEC.md](SPEC.md); milestone history in
[BUILD_PLAN.md](BUILD_PLAN.md). The short version: everything is
offline-first (every rule is fixture-testable with zero infrastructure), the
live collector normalizes cluster objects into the exact same model the YAML
loader produces (a fake-clientset parity test and a kind e2e in CI hold the
two paths equal), and output is fully deterministic — no timestamps, stable
ordering — so runs diff cleanly.

## License

MIT
