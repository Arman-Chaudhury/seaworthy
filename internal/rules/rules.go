// Package rules is the audit engine: a fixed, ordered registry of stock
// rules run against one manifest.Snapshot (SPEC §4).
package rules

import (
	"fmt"

	"github.com/Arman-Chaudhury/seaworthy/internal/audit"
	"github.com/Arman-Chaudhury/seaworthy/internal/manifest"
)

// Context carries the snapshot plus the configuration rules may consult.
type Context struct {
	Snap *manifest.Snapshot
	// RequiredLabels is the label set missing-labels enforces.
	RequiredLabels []string
}

// DefaultRequiredLabels per SPEC §4.
var DefaultRequiredLabels = []string{"app.kubernetes.io/name", "app.kubernetes.io/part-of"}

// Rule is one check over the whole snapshot. Pod-level rules iterate
// Snap.Workloads; cross-resource rules walk the graph directly. Check
// returns findings carrying only location, detail, and message — Run
// stamps the rule's identity (ID, severity, hint) afterwards, so rule
// bodies stay declaration-order independent.
type Rule struct {
	ID       string
	Severity audit.Severity
	Desc     string
	Hint     string
	Check    func(*Context) []audit.Finding
}

// found builds the location part of a finding; Run fills in the rest.
func found(o *manifest.Object, detail, msg string) audit.Finding {
	return audit.Finding{
		Kind:      o.Kind,
		Namespace: o.Namespace,
		Name:      o.Name,
		Detail:    detail,
		Message:   msg,
		File:      o.File,
		Line:      o.Line,
	}
}

// Options filters and reshapes a run (CLI flags + config file).
type Options struct {
	Only             []string // --rule; empty = all
	Disabled         map[string]bool
	SeverityOverride map[string]audit.Severity
	IgnoreNamespaces map[string]bool
}

// Run executes the registry against ctx and returns sorted findings.
// Unknown rule IDs in opts.Only are a usage error (exit 2).
func Run(ctx *Context, opts Options) ([]audit.Finding, error) {
	byID := map[string]Rule{}
	for _, r := range All() {
		byID[r.ID] = r
	}
	selected := All()
	if len(opts.Only) > 0 {
		selected = nil
		for _, id := range opts.Only {
			r, ok := byID[id]
			if !ok {
				return nil, fmt.Errorf("unknown rule %q (see `seaworthy rules`)", id)
			}
			selected = append(selected, r)
		}
	}
	if ctx.RequiredLabels == nil {
		ctx.RequiredLabels = DefaultRequiredLabels
	}
	var out []audit.Finding
	for _, r := range selected {
		if opts.Disabled[r.ID] {
			continue
		}
		for _, f := range r.Check(ctx) {
			if opts.IgnoreNamespaces[f.Namespace] {
				continue
			}
			f.Rule = r.ID
			f.Severity = r.Severity
			f.Hint = r.Hint
			if sev, ok := opts.SeverityOverride[r.ID]; ok {
				f.Severity = sev
			}
			out = append(out, f)
		}
	}
	audit.Sort(out)
	return out, nil
}

// All returns the stock registry in stable order.
func All() []Rule {
	return []Rule{
		latestImage,
		noResourceRequests,
	}
}
