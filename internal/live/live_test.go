package live

import (
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/Arman-Chaudhury/seaworthy/internal/manifest"
	"github.com/Arman-Chaudhury/seaworthy/internal/rules"
)

const demoFixture = "../../testdata/fixtures/demo-app.yaml"

// TestCollectParity is the SPEC §1 contract: a live audit of the seeded
// fixture yields the same finding set as the offline audit of the same
// documents (modulo file/line locations).
func TestCollectParity(t *testing.T) {
	offline, findings, err := manifest.Load([]string{demoFixture}, nil)
	if err != nil || len(findings) != 0 {
		t.Fatalf("load: err=%v findings=%v", err, findings)
	}
	var seed []runtime.Object
	for _, o := range offline.Objects {
		seed = append(seed, o.Typed.(runtime.Object))
	}
	liveSnap, err := Collect(fake.NewSimpleClientset(seed...), "shop")
	if err != nil {
		t.Fatal(err)
	}

	offlineFindings, err := rules.Run(&rules.Context{Snap: offline}, rules.Options{})
	if err != nil {
		t.Fatal(err)
	}
	liveFindings, err := rules.Run(&rules.Context{Snap: liveSnap}, rules.Options{})
	if err != nil {
		t.Fatal(err)
	}

	offlineSet := map[string]bool{}
	for _, f := range offlineFindings {
		offlineSet[f.Rule+"|"+f.Ref()+"|"+f.Detail] = true
	}
	liveSet := map[string]bool{}
	for _, f := range liveFindings {
		liveSet[f.Rule+"|"+f.Ref()+"|"+f.Detail] = true
		if f.File != "" {
			t.Errorf("live finding should have no file location: %+v", f)
		}
	}
	if len(liveSet) != len(offlineSet) {
		t.Errorf("live = %d findings, offline = %d", len(liveSet), len(offlineSet))
	}
	for k := range offlineSet {
		if !liveSet[k] {
			t.Errorf("live audit missing %s", k)
		}
	}
}

func TestCollectNamespaceScope(t *testing.T) {
	snap, _, err := manifest.Load([]string{demoFixture}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var seed []runtime.Object
	for _, o := range snap.Objects {
		seed = append(seed, o.Typed.(runtime.Object))
	}
	got, err := Collect(fake.NewSimpleClientset(seed...), "elsewhere")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Objects) != 0 {
		t.Errorf("namespace scope leaked: %d objects", len(got.Objects))
	}
}

func TestCollectSkipsOwnedJobs(t *testing.T) {
	owned := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name: "owned", Namespace: "shop",
			OwnerReferences: []metav1.OwnerReference{{Kind: "CronJob", Name: "parent"}},
		},
		Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "img:1"}}},
		}},
	}
	standalone := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: "standalone", Namespace: "shop"},
		Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "img:1"}}},
		}},
	}
	snap, err := Collect(fake.NewSimpleClientset(owned, standalone), "shop")
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Workloads) != 1 || snap.Workloads[0].Name != "standalone" {
		t.Errorf("workloads = %+v, want only standalone", snap.Workloads)
	}
}
