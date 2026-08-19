// seaworthy audits Kubernetes workloads for hygiene defects and gates
// CI/CD pipelines on the result. See SPEC.md; built per BUILD_PLAN.md.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Arman-Chaudhury/seaworthy/internal/audit"
	"github.com/Arman-Chaudhury/seaworthy/internal/manifest"
	"github.com/Arman-Chaudhury/seaworthy/internal/report"
	"github.com/Arman-Chaudhury/seaworthy/internal/rules"
)

var version = "0.0.1-dev"

const usage = `seaworthy — Kubernetes workload-hygiene auditor

Usage:
  seaworthy audit [flags] <path...|->   audit rendered manifests
  seaworthy rules                       list rules, severities, and hints
  seaworthy version                     print version

Audit flags:
  --format table|json     output format (default table)
  --fail-on high|medium|low
                          exit 1 at/above this severity (default high)
  --rule <id>             run only this rule (repeatable)

Exit codes: 0 clean (below --fail-on), 1 findings at/above threshold,
2 usage or load error.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "audit":
		return cmdAudit(args[1:], stdin, stdout, stderr)
	case "rules":
		return cmdRules(stdout)
	case "version", "--version":
		fmt.Fprintln(stdout, "seaworthy "+version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "seaworthy: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func cmdAudit(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "table", "output format: table|json|sarif|html")
	failOn := fs.String("fail-on", "high", "exit 1 at/above this severity")
	var only stringList
	fs.Var(&only, "rule", "run only this rule (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	threshold, err := audit.ParseSeverity(*failOn)
	if err != nil {
		fmt.Fprintf(stderr, "seaworthy: --fail-on: %v\n", err)
		return 2
	}
	paths := fs.Args()
	if len(paths) == 0 {
		fmt.Fprintln(stderr, "seaworthy audit: no manifest paths given (use \"-\" for stdin)")
		return 2
	}

	snap, findings, err := manifest.Load(paths, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "seaworthy: %v\n", err)
		return 2
	}
	if len(snap.Objects) == 0 && len(findings) == 0 {
		fmt.Fprintln(stderr, "seaworthy: no Kubernetes objects found in input")
		return 2
	}
	ruleFindings, err := rules.Run(&rules.Context{Snap: snap}, rules.Options{Only: only})
	if err != nil {
		fmt.Fprintf(stderr, "seaworthy: %v\n", err)
		return 2
	}
	findings = append(findings, ruleFindings...)
	audit.Sort(findings)

	sum := report.Summarize(findings, 0)
	var renderErr error
	switch *format {
	case "json":
		renderErr = report.NewRun(findings, 0).WriteJSON(stdout)
	case "table":
		report.WriteTable(stdout, findings, sum, nil, wantColor(stdout))
	case "sarif":
		renderErr = report.WriteSARIF(stdout, version, ruleInfos(), findings)
	case "html":
		renderErr = report.WriteHTML(stdout, findings, sum, nil)
	default:
		fmt.Fprintf(stderr, "seaworthy: unknown --format %q\n", *format)
		return 2
	}
	if renderErr != nil {
		fmt.Fprintf(stderr, "seaworthy: %v\n", renderErr)
		return 2
	}

	for _, f := range findings {
		if f.AtOrAbove(threshold) {
			return 1
		}
	}
	return 0
}

// ruleInfos converts the registry (plus the loader's synthetic
// parse-error rule) into SARIF rule metadata.
func ruleInfos() []report.RuleInfo {
	out := []report.RuleInfo{{
		ID:   "parse-error",
		Desc: "document could not be parsed",
		Hint: "fix the YAML so the document can be audited",
	}}
	for _, r := range rules.All() {
		out = append(out, report.RuleInfo{ID: r.ID, Desc: r.Desc, Hint: r.Hint})
	}
	return out
}

// wantColor enables ANSI colors only for real terminals that have not
// opted out via NO_COLOR.
func wantColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}

func cmdRules(w io.Writer) int {
	fmt.Fprintf(w, "%-24s %-8s %s\n", "RULE", "SEVERITY", "DESCRIPTION")
	for _, r := range rules.All() {
		fmt.Fprintf(w, "%-24s %-8s %s\n", r.ID, r.Severity, r.Desc)
	}
	return 0
}
