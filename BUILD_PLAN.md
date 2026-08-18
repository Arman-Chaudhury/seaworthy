# seaworthy — Build Plan

Milestones are ordered so the project is demoable (fixture manifests →
findings → CI gate) from M2 onward. Each milestone lands with its tests and
green CI. See SPEC.md for the full design.

- [ ] **M1 — Manifest loader & workload model.** Multi-doc YAML decode
      (files/dirs/stdin), typed kinds + `Unstructured` passthrough,
      `Snapshot` with (kind, ns, name) index and selector matching, common
      `PodSpec()` accessor, `parse-error` findings with file/line, seeded
      fixture set under `testdata/fixtures/`.
- [ ] **M2 — Rules engine core.** `Finding`/`Severity` model, rule registry,
      `audit` command with `--rule` filtering and deterministic ordering;
      first rules: `latest-image`, `no-resource-requests`; JSON run document
      (schema v1); exit-code contract (0/1/2) with `--fail-on`.
- [ ] **M3 — Full pod-level rule pack.** `missing-probes`, `runs-as-root`,
      `privilege-escalation`, `host-access`, `secrets-in-env`,
      `missing-labels`, `deprecated-api` — fixture-backed
      positive/negative/edge tests per rule (SPEC §4).
- [ ] **M4 — Cross-resource rules.** `dangling-service`,
      `hpa-target-missing`, `hpa-replicas-conflict`, `no-pdb`,
      `single-replica` over the whole-Snapshot graph.
- [ ] **M5 — Reports.** TTY-aware severity-colored table, SARIF 2.1.0 with
      physical locations (PR annotations via code scanning), self-contained
      single-file HTML dashboard; golden-file tests for all formats.
- [ ] **M6 — Ops surface.** `seaworthy.yaml` config (rule toggles, severity
      overrides, required labels), baseline suppressions with expiries +
      `--update-baseline`, `--previous` delta section.
- [ ] **M7 — Live collector + kind e2e.** client-go read-only Snapshot
      builder (kubeconfig/context/in-cluster), fake-clientset unit tests,
      GitHub Actions kind e2e: apply seeded fixture, `audit --live`, assert
      findings. (No local Docker daemon — kind runs in CI only.)
- [ ] **M8 — Packaging & docs.** Multi-stage Dockerfile (distroless), Helm
      chart with least-privilege read-only RBAC CronJob, GoReleaser config,
      README walkthrough (CI gate, baselines, code-scanning setup), tag
      v0.1.0 on merge.
