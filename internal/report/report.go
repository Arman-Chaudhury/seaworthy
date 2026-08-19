// Package report renders audit runs: table, JSON run document, and — in
// later milestones — SARIF and a self-contained HTML dashboard (SPEC §7).
package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/Arman-Chaudhury/seaworthy/internal/audit"
)

// Summary counts findings by severity.
type Summary struct {
	Total  int `json:"total"`
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`
	// Suppressed counts findings hidden by the baseline (SPEC §6).
	Suppressed int `json:"suppressed"`
}

// Delta is the run-over-run comparison against --previous (SPEC §6).
type Delta struct {
	New   []string `json:"new"`
	Fixed []string `json:"fixed"`
}

// Run is the schema-versioned JSON run document; it is also the
// --previous input, so it contains no timestamps — output is fully
// deterministic (SPEC §5).
type Run struct {
	SchemaVersion int          `json:"schema_version"`
	Summary       Summary      `json:"summary"`
	Findings      []runFinding `json:"findings"`
	Delta         *Delta       `json:"delta,omitempty"`
}

type runFinding struct {
	audit.Finding
	Fingerprint string `json:"fingerprint"`
}

// NewRun assembles the run document from already-sorted findings.
func NewRun(findings []audit.Finding, suppressed int) Run {
	r := Run{SchemaVersion: 1, Summary: Summarize(findings, suppressed)}
	for _, f := range findings {
		r.Findings = append(r.Findings, runFinding{Finding: f, Fingerprint: f.Fingerprint()})
	}
	return r
}

// Summarize tallies findings by severity.
func Summarize(findings []audit.Finding, suppressed int) Summary {
	s := Summary{Total: len(findings), Suppressed: suppressed}
	for _, f := range findings {
		switch f.Severity {
		case audit.SeverityHigh:
			s.High++
		case audit.SeverityMedium:
			s.Medium++
		case audit.SeverityLow:
			s.Low++
		}
	}
	return s
}

// WriteJSON writes the run document, indented for humans and diffs.
func (r Run) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

const (
	ansiReset  = "\x1b[0m"
	ansiRed    = "\x1b[31m"
	ansiYellow = "\x1b[33m"
	ansiCyan   = "\x1b[36m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
)

func sevColor(s audit.Severity) string {
	switch s {
	case audit.SeverityHigh:
		return ansiRed
	case audit.SeverityMedium:
		return ansiYellow
	default:
		return ansiCyan
	}
}

// WriteTable renders findings grouped by object (they arrive sorted, so
// groups are contiguous), followed by the summary line.
func WriteTable(w io.Writer, findings []audit.Finding, sum Summary, delta *Delta, color bool) {
	paint := func(code, s string) string {
		if !color {
			return s
		}
		return code + s + ansiReset
	}
	lastGroup := ""
	for _, f := range findings {
		ref := f.Ref()
		loc := ""
		if f.File != "" {
			loc = fmt.Sprintf("  (%s:%d)", f.File, f.Line)
		}
		group := ref + loc
		if group != lastGroup {
			if lastGroup != "" {
				fmt.Fprintln(w)
			}
			fmt.Fprintf(w, "%s%s\n", paint(ansiBold, ref), paint(ansiDim, loc))
			lastGroup = group
		}
		fmt.Fprintf(w, "  %-8s %-22s %s\n",
			paint(sevColor(f.Severity), f.Severity.String()), f.Rule, f.Message)
	}
	if len(findings) > 0 {
		fmt.Fprintln(w)
	}
	if delta != nil {
		fmt.Fprintf(w, "delta vs previous run: %d new, %d fixed\n", len(delta.New), len(delta.Fixed))
	}
	fmt.Fprintf(w, "%d findings: %d high, %d medium, %d low (%d suppressed by baseline)\n",
		sum.Total, sum.High, sum.Medium, sum.Low, sum.Suppressed)
}
