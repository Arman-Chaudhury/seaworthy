# seaworthy — Build Specification

## 1. What it is

A single-binary Go CLI that audits Kubernetes workloads for hygiene defects
and gates CI/CD pipelines on the result. Two input paths, one audit path:

- **Offline (primary)**: rendered YAML manifests — files, directories, or
  stdin (`helm template … | seaworthy audit -`). No cluster, no network.
- **Live**: a read-only snapshot of a cluster taken via client-go, normalized
  into the exact same in-memory model, so offline and live audits agree.

Findings surface as a terminal table, JSON, SARIF 2.1.0 (GitHub code
scanning), or a self-contained single-file HTML dashboard, with baseline
suppressions, run-over-run deltas, and a `--fail-on` exit-code contract.

## 2. Why this design

- **Offline-first** is the same trick siemlet and entrasweep use: every rule
  is testable from fixtures in CI with zero infrastructure. The live
  collector is a thin adapter added late (M7), never a dependency of the
  engine.
- **Whole-set model, not per-document linting.** Cross-resource defects
  (dangling Service selectors, HPA/replicas conflicts, missing PDBs) are the
  differentiator over kube-score/kube-linter/Polaris and require loading all
  documents into one graph before any rule runs.
- **CI-native outputs.** SARIF makes findings appear as PR annotations via
  GitHub code scanning; `--fail-on` + baselines make the tool adoptable on
  brownfield repos (freeze current debt, block new debt).

## 3. Manifest model & loader (M1)

- Parse multi-document YAML (`---`-separated) from files, directories
  (recursive, `*.yaml`/`*.yml`), or stdin. `sigs.k8s.io/yaml` for
  JSON-compatible decoding into typed structs; unknown kinds are retained
  as `Unstructured` and skipped by rules, never a hard error.
- Typed kinds v0.1: Deployment, StatefulSet, DaemonSet, CronJob, Job, Pod,
  Service, PodDisruptionBudget, HorizontalPodAutoscaler, Ingress,
  ConfigMap, Secret (metadata only — values never loaded into findings).
- `Snapshot` = all parsed objects + index by (kind, namespace, name) +
  label-selector matching helpers. Workload kinds expose a common
  `PodSpec()` accessor so pod-level rules are written once.
- Malformed YAML in one document → finding of rule `parse-error` (high) with
  file/line, remaining documents still audited. Empty input → exit 2.

## 4. Rule pack (stock rules)

Severities: `high`, `medium`, `low`. Each rule: kebab-case ID, one-line
message with the offending path (container name, env var, selector), and a
remediation hint. Every rule ships with fixture-backed positive, negative,
and edge tests.

Pod-level (M2–M3) — applied to every workload's pod template:
1. `latest-image` (high) — image has no tag or tag `latest`.
2. `missing-probes` (high) — container lacks liveness or readiness probe
   (Jobs/CronJobs exempt from readiness).
3. `no-resource-requests` (high) — missing CPU/memory requests or limits.
4. `runs-as-root` (high) — neither pod nor container sets
   `runAsNonRoot: true` (or sets `runAsUser: 0` explicitly).
5. `privilege-escalation` (high) — `privileged: true` or
   `allowPrivilegeEscalation` not `false`.
6. `host-access` (high) — `hostNetwork`, `hostPID`, `hostIPC`, or a
   `hostPath` volume.
7. `secrets-in-env` (high) — env var whose name matches
   `(?i)(password|passwd|secret|token|api_?key|credential)` with a literal
   `value` (refs via `valueFrom` are fine). Finding reports the name only,
   never the value.
8. `missing-labels` (low) — missing `app.kubernetes.io/name` or
   `app.kubernetes.io/part-of`.
9. `deprecated-api` (high) — apiVersion in a static removed/deprecated
   table (e.g. `policy/v1beta1` PDB, `autoscaling/v2beta2` HPA), with the
   replacement named in the hint.

Cross-resource (M4) — need the full Snapshot:
10. `dangling-service` (high) — Service selector matches no workload pod
    template in the set (namespace-scoped; selector-less Services exempt).
11. `hpa-target-missing` (high) — HPA `scaleTargetRef` resolves to no object.
12. `hpa-replicas-conflict` (medium) — Deployment sets `spec.replicas`
    while an HPA targets it.
13. `no-pdb` (medium) — workload with ≥2 replicas and no PDB whose selector
    matches its pods.
14. `single-replica` (medium) — Deployment with `replicas: 1` (or unset →
    defaults to 1); suppressed when an HPA targets it.

## 5. CLI & exit codes

```
seaworthy audit [flags] <path...|->   audit manifests (or --live)
seaworthy rules                       list rules, severities, hints
seaworthy version
```

Flags on `audit`: `--format table|json|sarif|html` (default table),
`--fail-on high|medium|low` (default high), `--rule <id>` (repeatable
filter), `--baseline <file>`, `--update-baseline`, `--previous <run.json>`,
`--live`, `--context`, `--namespace`, `--kubeconfig`.

Exit codes: `0` no findings at/above `--fail-on` after baseline filtering;
`1` at least one; `2` usage/load error. Deterministic output ordering
(file, then object, then rule) so diffs are stable.

## 6. Configuration & baselines (M6)

- `seaworthy.yaml` (optional, auto-discovered at repo root): per-rule
  enable/disable, severity overrides, `missing-labels` required-label list,
  ignored namespaces.
- Baseline file (`seaworthy-baseline.yaml`): fingerprints of accepted
  findings (`rule + kind/ns/name + detail-path` hashed), each with optional
  `expires: YYYY-MM-DD`; expired entries stop suppressing. Written by
  `--update-baseline`, reviewed like any other file in the repo.
- `--previous run.json` adds a delta section: new / fixed / unchanged.

## 7. Reports (M5)

- **table**: grouped by object, severity-colored (TTY-aware, `NO_COLOR`).
- **json**: schema-versioned run document (also the `--previous` input).
- **sarif**: SARIF 2.1.0 with rule metadata + physical location (file/line
  from the YAML decoder) so GitHub annotates PRs.
- **html**: self-contained single file (inline CSS/JS, no external assets):
  severity tiles, per-rule tables, client-side filtering — same pattern as
  entrasweep's dashboard.

## 8. Live collector & in-cluster mode (M7–M8)

- `--live` builds the Snapshot via client-go list calls (kubeconfig,
  `--context`, in-cluster config auto-detected), read-only verbs only.
  The collector is behind an interface; unit tests use fake clientsets.
- e2e: GitHub Actions job spins up a kind cluster, applies the seeded
  fixture, runs `seaworthy audit --live`, asserts on findings JSON. (Local
  dev has no Docker daemon — kind runs in CI only.)
- Helm chart (`deploy/chart/`): CronJob + ServiceAccount + least-privilege
  read-only ClusterRole/Binding; findings JSON to stdout for log scraping.
- Multi-stage Dockerfile, distroless runtime image, binary release via
  GoReleaser config (release job manual until v0.1.0).

## 9. Quality gates

- `go vet`, `gofmt -l` clean; `go test ./... -race` green on every PR.
- Table-driven unit tests per rule (positive/negative/edge); golden-file
  tests for table/JSON/SARIF/HTML outputs; kind e2e in CI from M7.
- No panics on adversarial YAML (fuzz seed corpus for the loader).
- Dependencies: stdlib + `sigs.k8s.io/yaml` until M7; client-go only in the
  live collector package.

## 10. Non-goals (v0.1)

- Admission control / webhook mode (audit-only; no cluster mutation ever).
- Policy-as-code DSLs (OPA/Rego, CEL) — stock rules + YAML config only.
- Scanning image contents/CVEs (that's trivy's job), cost analysis, or
  multi-cluster fleet aggregation.
- Windows containers, CRD-defined workloads (Argo Rollouts etc.).
