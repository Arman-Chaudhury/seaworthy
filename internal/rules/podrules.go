package rules

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/Arman-Chaudhury/seaworthy/internal/audit"
	"github.com/Arman-Chaudhury/seaworthy/internal/manifest"
)

// forWorkloads lifts a per-workload check into a snapshot check.
func forWorkloads(fn func(*Context, *manifest.Workload) []audit.Finding) func(*Context) []audit.Finding {
	return func(ctx *Context) []audit.Finding {
		var out []audit.Finding
		for _, w := range ctx.Snap.Workloads {
			out = append(out, fn(ctx, w)...)
		}
		return out
	}
}

var latestImage = Rule{
	ID:       "latest-image",
	Severity: audit.SeverityHigh,
	Desc:     "container image has no tag or the mutable tag `latest`",
	Hint:     "pin a version tag or digest so rollouts and rollbacks are reproducible",
	Check: forWorkloads(func(_ *Context, w *manifest.Workload) []audit.Finding {
		var out []audit.Finding
		for _, c := range w.Template.Spec.Containers {
			if tag := imageTag(c.Image); tag == "" || tag == "latest" {
				out = append(out, found(w.Object, c.Name,
					fmt.Sprintf("container %q: image %q is not pinned", c.Name, c.Image)))
			}
		}
		return out
	}),
}

// imageTag extracts the tag from an image reference; "@" digests count
// as pinned, and a colon in the registry host (host:port/img) is not a
// tag separator.
func imageTag(img string) string {
	if strings.Contains(img, "@") {
		return "digest"
	}
	i := strings.LastIndex(img, ":")
	if i == -1 || i < strings.LastIndex(img, "/") {
		return ""
	}
	return img[i+1:]
}

var noResourceRequests = Rule{
	ID:       "no-resource-requests",
	Severity: audit.SeverityHigh,
	Desc:     "container is missing CPU/memory requests or limits",
	Hint:     "set resources.requests and resources.limits so scheduling and evictions behave predictably",
	Check: forWorkloads(func(_ *Context, w *manifest.Workload) []audit.Finding {
		var out []audit.Finding
		for _, c := range w.Template.Spec.Containers {
			var missing []string
			for _, group := range []struct {
				list corev1.ResourceList
				name string
			}{
				{c.Resources.Requests, "requests"},
				{c.Resources.Limits, "limits"},
			} {
				for _, res := range []corev1.ResourceName{corev1.ResourceCPU, corev1.ResourceMemory} {
					if _, ok := group.list[res]; !ok {
						missing = append(missing, group.name+"."+string(res))
					}
				}
			}
			if len(missing) > 0 {
				out = append(out, found(w.Object, c.Name,
					fmt.Sprintf("container %q is missing %s", c.Name, strings.Join(missing, ", "))))
			}
		}
		return out
	}),
}
