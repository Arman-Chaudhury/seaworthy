// Package live builds a manifest.Snapshot from a running cluster with
// read-only list calls, so live audits share the exact same rule path
// as offline ones (SPEC §8). client-go stays confined to this package.
package live

import (
	"context"
	"fmt"
	"os"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/Arman-Chaudhury/seaworthy/internal/manifest"
)

// BuildClient resolves cluster access: explicit kubeconfig/context if
// given, in-cluster config when running as a pod, else the default
// kubeconfig chain.
func BuildClient(kubeconfig, kubeContext string) (kubernetes.Interface, error) {
	if kubeconfig == "" && kubeContext == "" && os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		cfg, err := rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("in-cluster config: %w", err)
		}
		return kubernetes.NewForConfig(cfg)
	}
	loading := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		loading.ExplicitPath = kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{CurrentContext: kubeContext}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loading, overrides).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("kubeconfig: %w", err)
	}
	return kubernetes.NewForConfig(cfg)
}

// Collect lists the audited kinds (namespace "" = all namespaces) and
// normalizes them into a Snapshot. Bare Pods and controller-owned Jobs
// are skipped so one defect is not reported once per replica.
func Collect(cs kubernetes.Interface, namespace string) (*manifest.Snapshot, error) {
	ctx := context.Background()
	opts := metav1.ListOptions{}
	var objs []*manifest.Object

	add := func(apiVersion, kind string, meta metav1.ObjectMeta, typed any) {
		objs = append(objs, &manifest.Object{
			APIVersion: apiVersion,
			Kind:       kind,
			Namespace:  meta.Namespace,
			Name:       meta.Name,
			Labels:     meta.Labels,
			Typed:      typed,
		})
	}

	deps, err := cs.AppsV1().Deployments(namespace).List(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("listing deployments: %w", err)
	}
	for i := range deps.Items {
		add("apps/v1", "Deployment", deps.Items[i].ObjectMeta, &deps.Items[i])
	}
	stss, err := cs.AppsV1().StatefulSets(namespace).List(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("listing statefulsets: %w", err)
	}
	for i := range stss.Items {
		add("apps/v1", "StatefulSet", stss.Items[i].ObjectMeta, &stss.Items[i])
	}
	dss, err := cs.AppsV1().DaemonSets(namespace).List(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("listing daemonsets: %w", err)
	}
	for i := range dss.Items {
		add("apps/v1", "DaemonSet", dss.Items[i].ObjectMeta, &dss.Items[i])
	}
	jobs, err := cs.BatchV1().Jobs(namespace).List(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("listing jobs: %w", err)
	}
	for i := range jobs.Items {
		if len(jobs.Items[i].OwnerReferences) > 0 {
			continue // CronJob-owned: the CronJob itself is audited
		}
		add("batch/v1", "Job", jobs.Items[i].ObjectMeta, &jobs.Items[i])
	}
	cjs, err := cs.BatchV1().CronJobs(namespace).List(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("listing cronjobs: %w", err)
	}
	for i := range cjs.Items {
		add("batch/v1", "CronJob", cjs.Items[i].ObjectMeta, &cjs.Items[i])
	}
	svcs, err := cs.CoreV1().Services(namespace).List(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("listing services: %w", err)
	}
	for i := range svcs.Items {
		add("v1", "Service", svcs.Items[i].ObjectMeta, &svcs.Items[i])
	}
	pdbs, err := cs.PolicyV1().PodDisruptionBudgets(namespace).List(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("listing poddisruptionbudgets: %w", err)
	}
	for i := range pdbs.Items {
		add("policy/v1", "PodDisruptionBudget", pdbs.Items[i].ObjectMeta, &pdbs.Items[i])
	}
	hpas, err := cs.AutoscalingV2().HorizontalPodAutoscalers(namespace).List(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("listing horizontalpodautoscalers: %w", err)
	}
	for i := range hpas.Items {
		add("autoscaling/v2", "HorizontalPodAutoscaler", hpas.Items[i].ObjectMeta, &hpas.Items[i])
	}

	return manifest.NewSnapshot(objs), nil
}
