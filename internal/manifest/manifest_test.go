package manifest

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/labels"
)

const demoFixture = "../../testdata/fixtures/demo-app.yaml"
const brokenFixture = "../../testdata/fixtures/broken.yaml"

func TestLoadDemoFixture(t *testing.T) {
	snap, findings, err := Load([]string{demoFixture}, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("want no parse findings, got %v", findings)
	}
	if got := len(snap.Objects); got != 7 {
		t.Errorf("objects = %d, want 7", got)
	}
	if got := len(snap.Workloads); got != 3 {
		t.Errorf("workloads = %d, want 3", got)
	}
	if len(snap.Services) != 1 || len(snap.PDBs) != 1 || len(snap.HPAs) != 2 {
		t.Errorf("services/pdbs/hpas = %d/%d/%d, want 1/1/2",
			len(snap.Services), len(snap.PDBs), len(snap.HPAs))
	}
	web := snap.Lookup("Deployment", "shop", "shop-web")
	if web == nil {
		t.Fatal("Lookup(shop-web) = nil")
	}
	if web.Line == 0 || web.File != demoFixture {
		t.Errorf("shop-web location = %s:%d, want %s:>0", web.File, web.Line, demoFixture)
	}
	for _, w := range snap.Workloads {
		if w.Name == "shop-web" {
			if w.Replicas == nil || *w.Replicas != 3 {
				t.Errorf("shop-web replicas = %v, want 3", w.Replicas)
			}
			if h := snap.HPAFor(w); h == nil || h.Name != "shop-web-hpa" {
				t.Errorf("HPAFor(shop-web) = %v, want shop-web-hpa", h)
			}
		}
	}
}

func TestLoadBrokenFixture(t *testing.T) {
	snap, findings, err := Load([]string{brokenFixture}, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := len(snap.Objects); got != 1 {
		t.Errorf("objects = %d, want 1 (the valid ConfigMap)", got)
	}
	if got := len(findings); got != 2 {
		t.Fatalf("parse findings = %d, want 2: %v", got, findings)
	}
	for _, f := range findings {
		if f.Rule != "parse-error" || f.File != brokenFixture || f.Line == 0 {
			t.Errorf("bad parse finding: %+v", f)
		}
	}
}

func TestLoadStdin(t *testing.T) {
	in := strings.NewReader("apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n    - name: c\n      image: busybox:1.36\n")
	snap, findings, err := Load([]string{"-"}, in)
	if err != nil || len(findings) != 0 {
		t.Fatalf("Load stdin: err=%v findings=%v", err, findings)
	}
	if len(snap.Workloads) != 1 || snap.Workloads[0].Template.Spec.Containers[0].Image != "busybox:1.36" {
		t.Errorf("stdin pod not normalized into a workload: %+v", snap.Workloads)
	}
}

func TestCronJobTemplate(t *testing.T) {
	objs, findings := parseFile("t.yaml", `
apiVersion: batch/v1
kind: CronJob
metadata: {name: backup, namespace: shop}
spec:
  schedule: "0 3 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: backup
              image: shop/backup:2.0
`)
	if len(findings) != 0 || len(objs) != 1 {
		t.Fatalf("parseFile: objs=%d findings=%v", len(objs), findings)
	}
	snap := NewSnapshot(objs)
	if len(snap.Workloads) != 1 || snap.Workloads[0].Template.Spec.Containers[0].Image != "shop/backup:2.0" {
		t.Errorf("cronjob pod template not extracted: %+v", snap.Workloads)
	}
}

func TestUnknownKindRetained(t *testing.T) {
	objs, findings := parseFile("t.yaml", `
apiVersion: policy/v1beta1
kind: PodDisruptionBudget
metadata: {name: legacy, namespace: shop}
spec: {minAvailable: 1}
`)
	if len(findings) != 0 || len(objs) != 1 {
		t.Fatalf("objs=%d findings=%v", len(objs), findings)
	}
	if objs[0].Typed != nil {
		t.Error("deprecated PDB should be retained untyped")
	}
	if objs[0].Ref() != "shop/PodDisruptionBudget/legacy" {
		t.Errorf("Ref() = %q", objs[0].Ref())
	}
}

func TestWorkloadsMatching(t *testing.T) {
	snap, _, err := Load([]string{demoFixture}, nil)
	if err != nil {
		t.Fatal(err)
	}
	sel := labels.SelectorFromSet(labels.Set{"app": "shop-web"})
	if got := snap.WorkloadsMatching("shop", sel); len(got) != 1 || got[0].Name != "shop-web" {
		t.Errorf("WorkloadsMatching(app=shop-web) = %v", got)
	}
	none := labels.SelectorFromSet(labels.Set{"app": "shop-api"})
	if got := snap.WorkloadsMatching("shop", none); len(got) != 0 {
		t.Errorf("WorkloadsMatching(app=shop-api) = %v, want none", got)
	}
}

func TestSplitDocs(t *testing.T) {
	docs := splitDocs("# header comment\n---\na: 1\n---\n# only a comment\n---\nb: 2\n")
	if len(docs) != 2 {
		t.Fatalf("docs = %d, want 2 (comment-only skipped)", len(docs))
	}
	if docs[0].startLine != 3 || docs[1].startLine != 7 {
		t.Errorf("start lines = %d, %d; want 3, 7", docs[0].startLine, docs[1].startLine)
	}
}
