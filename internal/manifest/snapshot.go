package manifest

import (
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// Workload is any object owning a pod template, normalized so pod-level
// rules are written once (SPEC §3).
type Workload struct {
	*Object
	Template corev1.PodTemplateSpec
	// Replicas is the declared count for kinds that have one
	// (Deployment, StatefulSet); nil otherwise.
	Replicas *int32
	// HPAScalable marks kinds an HPA can target.
	HPAScalable bool
}

// Snapshot is the whole manifest set as one graph — what lets rules see
// across documents (SPEC §2).
type Snapshot struct {
	Objects   []*Object
	Workloads []*Workload
	Services  []*Object
	PDBs      []*Object
	HPAs      []*Object
	index     map[string]*Object
}

func indexKey(kind, ns, name string) string { return kind + "|" + ns + "|" + name }

// NewSnapshot builds the graph from decoded objects.
func NewSnapshot(objs []*Object) *Snapshot {
	s := &Snapshot{index: map[string]*Object{}}
	for _, o := range objs {
		s.add(o)
	}
	return s
}

func (s *Snapshot) add(o *Object) {
	s.Objects = append(s.Objects, o)
	s.index[indexKey(o.Kind, o.Namespace, o.Name)] = o
	switch t := o.Typed.(type) {
	case *appsv1.Deployment:
		s.Workloads = append(s.Workloads, &Workload{Object: o, Template: t.Spec.Template, Replicas: t.Spec.Replicas, HPAScalable: true})
	case *appsv1.StatefulSet:
		s.Workloads = append(s.Workloads, &Workload{Object: o, Template: t.Spec.Template, Replicas: t.Spec.Replicas, HPAScalable: true})
	case *appsv1.DaemonSet:
		s.Workloads = append(s.Workloads, &Workload{Object: o, Template: t.Spec.Template})
	case *batchv1.Job:
		s.Workloads = append(s.Workloads, &Workload{Object: o, Template: t.Spec.Template})
	case *batchv1.CronJob:
		s.Workloads = append(s.Workloads, &Workload{Object: o, Template: t.Spec.JobTemplate.Spec.Template})
	case *corev1.Pod:
		s.Workloads = append(s.Workloads, &Workload{
			Object:   o,
			Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: t.Labels}, Spec: t.Spec},
		})
	case *corev1.Service:
		s.Services = append(s.Services, o)
	case *policyv1.PodDisruptionBudget:
		s.PDBs = append(s.PDBs, o)
	case *autoscalingv2.HorizontalPodAutoscaler:
		s.HPAs = append(s.HPAs, o)
	}
}

// Lookup finds an object by kind, namespace, and name.
func (s *Snapshot) Lookup(kind, ns, name string) *Object {
	return s.index[indexKey(kind, ns, name)]
}

// WorkloadsMatching returns the workloads in ns whose pod template
// labels match sel.
func (s *Snapshot) WorkloadsMatching(ns string, sel labels.Selector) []*Workload {
	var out []*Workload
	for _, w := range s.Workloads {
		if w.Namespace == ns && sel.Matches(labels.Set(w.Template.Labels)) {
			out = append(out, w)
		}
	}
	return out
}

// HPAFor returns the HPA whose scaleTargetRef points at w, if any.
func (s *Snapshot) HPAFor(w *Workload) *autoscalingv2.HorizontalPodAutoscaler {
	for _, o := range s.HPAs {
		h := o.Typed.(*autoscalingv2.HorizontalPodAutoscaler)
		ref := h.Spec.ScaleTargetRef
		if o.Namespace == w.Namespace && ref.Kind == w.Kind && ref.Name == w.Name {
			return h
		}
	}
	return nil
}
