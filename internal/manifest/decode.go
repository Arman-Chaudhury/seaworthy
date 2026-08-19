package manifest

import (
	"fmt"

	"gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	sigsyaml "sigs.k8s.io/yaml"

	"github.com/Arman-Chaudhury/seaworthy/internal/audit"
)

// Object is one Kubernetes manifest document (or one live object).
type Object struct {
	APIVersion string
	Kind       string
	Namespace  string
	Name       string
	Labels     map[string]string
	// Typed points at the decoded API struct for kinds seaworthy
	// understands; nil for unknown kinds, which are still retained for
	// object-level rules like deprecated-api.
	Typed any
	// File/Line locate the source document for reports; zero for live
	// snapshots.
	File string
	Line int
}

// Ref renders the object as ns/Kind/name for messages and ordering.
func (o *Object) Ref() string {
	if o.Namespace == "" {
		return o.Kind + "/" + o.Name
	}
	return o.Namespace + "/" + o.Kind + "/" + o.Name
}

func newTyped(apiVersion, kind string) any {
	switch apiVersion + " " + kind {
	case "apps/v1 Deployment":
		return &appsv1.Deployment{}
	case "apps/v1 StatefulSet":
		return &appsv1.StatefulSet{}
	case "apps/v1 DaemonSet":
		return &appsv1.DaemonSet{}
	case "batch/v1 Job":
		return &batchv1.Job{}
	case "batch/v1 CronJob":
		return &batchv1.CronJob{}
	case "v1 Pod":
		return &corev1.Pod{}
	case "v1 Service":
		return &corev1.Service{}
	case "v1 ConfigMap":
		return &corev1.ConfigMap{}
	case "v1 Secret":
		return &corev1.Secret{}
	case "policy/v1 PodDisruptionBudget":
		return &policyv1.PodDisruptionBudget{}
	case "autoscaling/v2 HorizontalPodAutoscaler":
		return &autoscalingv2.HorizontalPodAutoscaler{}
	case "networking.k8s.io/v1 Ingress":
		return &networkingv1.Ingress{}
	}
	return nil
}

// decodeDoc parses one document; malformed input becomes a parse-error
// finding, never an error, so the rest of the file is still audited.
func decodeDoc(doc rawDoc, file string) (*Object, *audit.Finding) {
	var node yaml.Node
	if err := yaml.Unmarshal([]byte(doc.text), &node); err != nil {
		return nil, parseErr(file, doc.startLine, fmt.Sprintf("invalid YAML: %v", err))
	}
	line := doc.startLine
	if len(node.Content) > 0 {
		line = doc.startLine + node.Content[0].Line - 1
	}
	var probe struct {
		APIVersion string `yaml:"apiVersion"`
		Kind       string `yaml:"kind"`
		Metadata   struct {
			Name      string            `yaml:"name"`
			Namespace string            `yaml:"namespace"`
			Labels    map[string]string `yaml:"labels"`
		} `yaml:"metadata"`
	}
	if err := node.Decode(&probe); err != nil {
		return nil, parseErr(file, line, fmt.Sprintf("invalid document: %v", err))
	}
	if probe.APIVersion == "" || probe.Kind == "" {
		return nil, parseErr(file, line, "document has no apiVersion/kind")
	}
	obj := &Object{
		APIVersion: probe.APIVersion,
		Kind:       probe.Kind,
		Namespace:  probe.Metadata.Namespace,
		Name:       probe.Metadata.Name,
		Labels:     probe.Metadata.Labels,
		File:       file,
		Line:       line,
	}
	if t := newTyped(probe.APIVersion, probe.Kind); t != nil {
		if err := sigsyaml.Unmarshal([]byte(doc.text), t); err != nil {
			return nil, parseErr(file, line, fmt.Sprintf("invalid %s: %v", probe.Kind, err))
		}
		obj.Typed = t
	}
	return obj, nil
}

func parseErr(file string, line int, msg string) *audit.Finding {
	return &audit.Finding{
		Rule:     "parse-error",
		Severity: audit.SeverityHigh,
		Kind:     "Document",
		Name:     fmt.Sprintf("%s:%d", file, line),
		Message:  msg,
		Hint:     "fix the YAML so the document can be audited",
		File:     file,
		Line:     line,
	}
}
