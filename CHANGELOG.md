# Changelog

## v0.1.0 — 2026-08-19

Initial release.

- Offline-first audits of rendered manifests (files, directories, stdin);
  malformed documents become `parse-error` findings, never a crash.
- 14 stock rules: 9 pod-level (`latest-image`, `missing-probes`,
  `no-resource-requests`, `runs-as-root`, `privilege-escalation`,
  `host-access`, `secrets-in-env`, `missing-labels`, `deprecated-api`)
  and 5 cross-resource (`dangling-service`, `hpa-target-missing`,
  `hpa-replicas-conflict`, `no-pdb`, `single-replica`).
- Output formats: severity-colored table, JSON run document, SARIF 2.1.0
  (GitHub code scanning), self-contained HTML dashboard.
- Ops surface: `seaworthy.yaml` config (rule toggles, severity
  overrides, required labels, ignored namespaces), baseline suppressions
  with per-entry expiry and `--update-baseline`, `--previous` deltas,
  `--fail-on` exit-code gate (0/1/2).
- Live cluster mode via client-go (`--live`, `--namespace`, `--context`,
  `--kubeconfig`), read-only; fake-clientset parity tests and a kind
  e2e in CI prove live == offline on the seeded fixture.
- Packaging: multi-stage distroless Dockerfile, Helm chart (CronJob +
  least-privilege read-only RBAC, dogfooded by seaworthy itself in CI),
  GoReleaser config.
