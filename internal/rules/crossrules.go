package rules

import (
	"fmt"
	"sort"
	"strings"

	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/Arman-Chaudhury/seaworthy/internal/audit"
)

// The rules in this file need the whole Snapshot, not one document at a
// time — seaworthy's differentiator over per-document linters (SPEC §2).

func fmtSelector(sel map[string]string) string {
	parts := make([]string, 0, len(sel))
	for k, v := range sel {
		parts = append(parts, k+"="+v)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

var danglingService = Rule{
	ID:       "dangling-service",
	Severity: audit.SeverityHigh,
	Desc:     "Service selector matches no workload pod template",
	Hint:     "fix the selector or the pod template labels — as written, the Service has no endpoints",
	Check: func(ctx *Context) []audit.Finding {
		var out []audit.Finding
		for _, o := range ctx.Snap.Services {
			svc := o.Typed.(*corev1.Service)
			// Selector-less Services (ExternalName, manual Endpoints)
			// are legitimate and exempt.
			if len(svc.Spec.Selector) == 0 {
				continue
			}
			sel := labels.SelectorFromSet(svc.Spec.Selector)
			if len(ctx.Snap.WorkloadsMatching(o.Namespace, sel)) == 0 {
				out = append(out, found(o, "",
					fmt.Sprintf("selector %q matches no workload pod template in the set", fmtSelector(svc.Spec.Selector))))
			}
		}
		return out
	},
}

var hpaTargetMissing = Rule{
	ID:       "hpa-target-missing",
	Severity: audit.SeverityHigh,
	Desc:     "HPA scaleTargetRef resolves to no object",
	Hint:     "point scaleTargetRef at an existing workload (or delete the orphaned HPA)",
	Check: func(ctx *Context) []audit.Finding {
		var out []audit.Finding
		for _, o := range ctx.Snap.HPAs {
			h := o.Typed.(*autoscalingv2.HorizontalPodAutoscaler)
			ref := h.Spec.ScaleTargetRef
			if ctx.Snap.Lookup(ref.Kind, o.Namespace, ref.Name) == nil {
				out = append(out, found(o, "",
					fmt.Sprintf("scaleTargetRef %s/%s does not exist in the manifest set", ref.Kind, ref.Name)))
			}
		}
		return out
	},
}

var hpaReplicasConflict = Rule{
	ID:       "hpa-replicas-conflict",
	Severity: audit.SeverityMedium,
	Desc:     "workload pins spec.replicas while an HPA manages it",
	Hint:     "remove spec.replicas — every re-apply resets the HPA's scaling decision to the pinned count",
	Check: func(ctx *Context) []audit.Finding {
		var out []audit.Finding
		for _, w := range ctx.Snap.Workloads {
			if !w.HPAScalable || w.Replicas == nil {
				continue
			}
			if h := ctx.Snap.HPAFor(w); h != nil {
				out = append(out, found(w.Object, "",
					fmt.Sprintf("spec.replicas is pinned to %d while HPA %q manages scaling", *w.Replicas, h.Name)))
			}
		}
		return out
	},
}

var noPDB = Rule{
	ID:       "no-pdb",
	Severity: audit.SeverityMedium,
	Desc:     "multi-replica workload has no matching PodDisruptionBudget",
	Hint:     "add a PDB so voluntary disruptions (drains, upgrades) cannot take every replica down at once",
	Check: func(ctx *Context) []audit.Finding {
		var out []audit.Finding
		for _, w := range ctx.Snap.Workloads {
			if w.Replicas == nil || *w.Replicas < 2 {
				continue
			}
			covered := false
			for _, o := range ctx.Snap.PDBs {
				pdb := o.Typed.(*policyv1.PodDisruptionBudget)
				if o.Namespace != w.Namespace || pdb.Spec.Selector == nil {
					continue
				}
				sel, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
				if err != nil {
					continue
				}
				if sel.Matches(labels.Set(w.Template.Labels)) {
					covered = true
					break
				}
			}
			if !covered {
				out = append(out, found(w.Object, "",
					fmt.Sprintf("%d replicas but no PodDisruptionBudget matches its pods", *w.Replicas)))
			}
		}
		return out
	},
}

var singleReplica = Rule{
	ID:       "single-replica",
	Severity: audit.SeverityMedium,
	Desc:     "Deployment runs a single replica (no HA)",
	Hint:     "run at least two replicas (or let an HPA manage scale) so one pod failure is not an outage",
	Check: func(ctx *Context) []audit.Finding {
		var out []audit.Finding
		for _, w := range ctx.Snap.Workloads {
			if w.Kind != "Deployment" {
				continue
			}
			replicas := int32(1) // API default when spec.replicas is unset
			if w.Replicas != nil {
				replicas = *w.Replicas
			}
			if replicas != 1 {
				continue
			}
			if ctx.Snap.HPAFor(w) != nil {
				continue
			}
			out = append(out, found(w.Object, "",
				"deployment runs a single replica"))
		}
		return out
	},
}
