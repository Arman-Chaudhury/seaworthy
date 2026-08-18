package rules

import (
	"fmt"
	"regexp"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/Arman-Chaudhury/seaworthy/internal/audit"
	"github.com/Arman-Chaudhury/seaworthy/internal/manifest"
)

var missingProbes = Rule{
	ID:       "missing-probes",
	Severity: audit.SeverityHigh,
	Desc:     "container lacks liveness or readiness probes",
	Hint:     "add probes so Kubernetes can restart wedged containers and route traffic only when ready",
	Check: forWorkloads(func(_ *Context, w *manifest.Workload) []audit.Finding {
		// Batch workloads never receive traffic, so readiness is not
		// expected there (SPEC §4).
		needsReadiness := w.Kind != "Job" && w.Kind != "CronJob"
		var out []audit.Finding
		for _, c := range w.Template.Spec.Containers {
			var missing []string
			if c.LivenessProbe == nil {
				missing = append(missing, "liveness")
			}
			if needsReadiness && c.ReadinessProbe == nil {
				missing = append(missing, "readiness")
			}
			if len(missing) > 0 {
				out = append(out, found(w.Object, c.Name,
					fmt.Sprintf("container %q has no %s probe", c.Name, strings.Join(missing, " or "))))
			}
		}
		return out
	}),
}

// effectiveRootRisk merges pod- and container-level security contexts
// (container overrides pod) and reports whether the container may run
// as root.
func effectiveRootRisk(pod *corev1.PodSecurityContext, c *corev1.SecurityContext) (bool, string) {
	var runAsNonRoot *bool
	var runAsUser *int64
	if pod != nil {
		runAsNonRoot = pod.RunAsNonRoot
		runAsUser = pod.RunAsUser
	}
	if c != nil {
		if c.RunAsNonRoot != nil {
			runAsNonRoot = c.RunAsNonRoot
		}
		if c.RunAsUser != nil {
			runAsUser = c.RunAsUser
		}
	}
	switch {
	case runAsNonRoot != nil && *runAsNonRoot:
		// An explicit runAsNonRoot: true is enforced by the kubelet at
		// container start, so it dominates even a conflicting uid.
		return false, ""
	case runAsUser != nil && *runAsUser == 0:
		return true, "explicitly runs as uid 0"
	case runAsUser != nil && *runAsUser > 0:
		return false, ""
	default:
		return true, "does not set runAsNonRoot"
	}
}

var runsAsRoot = Rule{
	ID:       "runs-as-root",
	Severity: audit.SeverityHigh,
	Desc:     "container may run as root (no runAsNonRoot, or explicit uid 0)",
	Hint:     "set securityContext.runAsNonRoot: true (and a non-zero runAsUser) at the pod or container level",
	Check: forWorkloads(func(_ *Context, w *manifest.Workload) []audit.Finding {
		var out []audit.Finding
		for _, c := range w.Template.Spec.Containers {
			if risky, why := effectiveRootRisk(w.Template.Spec.SecurityContext, c.SecurityContext); risky {
				out = append(out, found(w.Object, c.Name,
					fmt.Sprintf("container %q %s", c.Name, why)))
			}
		}
		return out
	}),
}

var privilegeEscalation = Rule{
	ID:       "privilege-escalation",
	Severity: audit.SeverityHigh,
	Desc:     "container is privileged or does not disable privilege escalation",
	Hint:     "set securityContext.allowPrivilegeEscalation: false (and avoid privileged: true)",
	Check: forWorkloads(func(_ *Context, w *manifest.Workload) []audit.Finding {
		var out []audit.Finding
		for _, c := range w.Template.Spec.Containers {
			sc := c.SecurityContext
			switch {
			case sc != nil && sc.Privileged != nil && *sc.Privileged:
				out = append(out, found(w.Object, c.Name,
					fmt.Sprintf("container %q sets privileged: true", c.Name)))
			case sc == nil || sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation:
				out = append(out, found(w.Object, c.Name,
					fmt.Sprintf("container %q does not set allowPrivilegeEscalation: false", c.Name)))
			}
		}
		return out
	}),
}

var hostAccess = Rule{
	ID:       "host-access",
	Severity: audit.SeverityHigh,
	Desc:     "pod uses host namespaces or hostPath volumes",
	Hint:     "drop hostNetwork/hostPID/hostIPC and replace hostPath with a proper volume type",
	Check: forWorkloads(func(_ *Context, w *manifest.Workload) []audit.Finding {
		var out []audit.Finding
		spec := w.Template.Spec
		for _, ns := range []struct {
			on   bool
			name string
		}{
			{spec.HostNetwork, "hostNetwork"},
			{spec.HostPID, "hostPID"},
			{spec.HostIPC, "hostIPC"},
		} {
			if ns.on {
				out = append(out, found(w.Object, ns.name,
					fmt.Sprintf("pod sets %s: true", ns.name)))
			}
		}
		for _, v := range spec.Volumes {
			if v.HostPath != nil {
				out = append(out, found(w.Object, "volume/"+v.Name,
					fmt.Sprintf("volume %q mounts hostPath %q", v.Name, v.HostPath.Path)))
			}
		}
		return out
	}),
}

var credentialEnvName = regexp.MustCompile(`(?i)(password|passwd|secret|token|api_?key|credential)`)

var secretsInEnv = Rule{
	ID:       "secrets-in-env",
	Severity: audit.SeverityHigh,
	Desc:     "credential-shaped env var carries a literal value",
	Hint:     "move the value into a Secret and reference it with valueFrom.secretKeyRef",
	Check: forWorkloads(func(_ *Context, w *manifest.Workload) []audit.Finding {
		var out []audit.Finding
		for _, c := range w.Template.Spec.Containers {
			for _, e := range c.Env {
				// The finding names the variable, never its value.
				if e.Value != "" && e.ValueFrom == nil && credentialEnvName.MatchString(e.Name) {
					out = append(out, found(w.Object, c.Name+"/"+e.Name,
						fmt.Sprintf("container %q sets env %s from a literal value in the manifest", c.Name, e.Name)))
				}
			}
		}
		return out
	}),
}

var missingLabels = Rule{
	ID:       "missing-labels",
	Severity: audit.SeverityLow,
	Desc:     "workload is missing recommended app.kubernetes.io labels",
	Hint:     "add the recommended labels so tooling can group and select workloads consistently",
	Check: forWorkloads(func(ctx *Context, w *manifest.Workload) []audit.Finding {
		var missing []string
		for _, l := range ctx.RequiredLabels {
			if _, ok := w.Labels[l]; !ok {
				missing = append(missing, l)
			}
		}
		if len(missing) == 0 {
			return nil
		}
		return []audit.Finding{found(w.Object, "",
			fmt.Sprintf("missing label(s) %s", strings.Join(missing, ", ")))}
	}),
}

// deprecatedAPIs maps "Kind apiVersion" to the replacement to name in
// the finding. Static table per SPEC §4.
var deprecatedAPIs = map[string]string{
	"PodDisruptionBudget policy/v1beta1":          "policy/v1",
	"PodSecurityPolicy policy/v1beta1":            "removed in v1.25 — use Pod Security admission",
	"HorizontalPodAutoscaler autoscaling/v2beta1": "autoscaling/v2",
	"HorizontalPodAutoscaler autoscaling/v2beta2": "autoscaling/v2",
	"CronJob batch/v1beta1":                       "batch/v1",
	"Ingress networking.k8s.io/v1beta1":           "networking.k8s.io/v1",
	"Ingress extensions/v1beta1":                  "networking.k8s.io/v1",
	"Deployment apps/v1beta1":                     "apps/v1",
	"Deployment apps/v1beta2":                     "apps/v1",
	"Deployment extensions/v1beta1":               "apps/v1",
	"StatefulSet apps/v1beta1":                    "apps/v1",
	"StatefulSet apps/v1beta2":                    "apps/v1",
	"DaemonSet apps/v1beta2":                      "apps/v1",
	"DaemonSet extensions/v1beta1":                "apps/v1",
	"ReplicaSet extensions/v1beta1":               "apps/v1",
}

var deprecatedAPI = Rule{
	ID:       "deprecated-api",
	Severity: audit.SeverityHigh,
	Desc:     "object uses a removed or deprecated apiVersion",
	Hint:     "migrate to the replacement apiVersion before upgrading the cluster",
	Check: func(ctx *Context) []audit.Finding {
		var out []audit.Finding
		for _, o := range ctx.Snap.Objects {
			if repl, ok := deprecatedAPIs[o.Kind+" "+o.APIVersion]; ok {
				out = append(out, found(o, "",
					fmt.Sprintf("%s uses %s (replacement: %s)", o.Kind, o.APIVersion, repl)))
			}
		}
		return out
	},
}
