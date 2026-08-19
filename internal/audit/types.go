// Package audit defines the core finding model shared by the rules engine,
// reporters, and baseline machinery (SPEC §4–§6).
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Severity orders findings for --fail-on threshold checks.
type Severity int

const (
	SeverityLow Severity = iota + 1
	SeverityMedium
	SeverityHigh
)

func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	default:
		return fmt.Sprintf("Severity(%d)", int(s))
	}
}

// ParseSeverity parses the --fail-on / config severity names.
func ParseSeverity(s string) (Severity, error) {
	switch s {
	case "low":
		return SeverityLow, nil
	case "medium":
		return SeverityMedium, nil
	case "high":
		return SeverityHigh, nil
	default:
		return 0, fmt.Errorf("unknown severity %q (want low, medium, or high)", s)
	}
}

// Finding is one rule violation on one object.
type Finding struct {
	Rule      string   `json:"rule"`
	Severity  Severity `json:"severity"`
	Kind      string   `json:"kind"`
	Namespace string   `json:"namespace,omitempty"`
	Name      string   `json:"name"`
	// Detail names the offending element (container, env var, selector)
	// so two findings from one rule on one object stay distinguishable.
	Detail  string `json:"detail,omitempty"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
	// File/Line locate the source document for SARIF output; zero for
	// live-cluster snapshots.
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`
}

// AtOrAbove reports whether the finding meets a --fail-on threshold.
func (f Finding) AtOrAbove(t Severity) bool { return f.Severity >= t }

// Ref renders the finding's object as ns/Kind/name.
func (f Finding) Ref() string {
	ref := f.Name
	if f.Kind != "" {
		ref = f.Kind + "/" + f.Name
	}
	if f.Namespace != "" {
		ref = f.Namespace + "/" + ref
	}
	return ref
}

// MarshalJSON renders severities as their names so run documents and
// baselines stay readable and stable across releases.
func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

func (s *Severity) UnmarshalJSON(b []byte) error {
	var name string
	if err := json.Unmarshal(b, &name); err != nil {
		return err
	}
	sev, err := ParseSeverity(name)
	if err != nil {
		return err
	}
	*s = sev
	return nil
}

// Fingerprint identifies a finding across runs for baselines and deltas:
// stable under file moves and message rewording, distinct per offending
// element (SPEC §6).
func (f Finding) Fingerprint() string {
	h := sha256.Sum256([]byte(strings.Join(
		[]string{f.Rule, f.Kind, f.Namespace, f.Name, f.Detail}, "|")))
	return hex.EncodeToString(h[:])[:12]
}

// Sort orders findings deterministically: file, line, object, rule,
// detail — so output diffs are stable (SPEC §5).
func Sort(fs []Finding) {
	sort.Slice(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Rule != b.Rule {
			return a.Rule < b.Rule
		}
		return a.Detail < b.Detail
	})
}
