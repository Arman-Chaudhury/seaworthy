// Package audit defines the core finding model shared by the rules engine,
// reporters, and baseline machinery (SPEC §4–§6).
package audit

import "fmt"

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
