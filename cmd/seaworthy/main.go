// seaworthy audits Kubernetes workloads for hygiene defects and gates
// CI/CD pipelines on the result. See SPEC.md; built per BUILD_PLAN.md.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Arman-Chaudhury/seaworthy/internal/audit"
	"github.com/Arman-Chaudhury/seaworthy/internal/baseline"
	"github.com/Arman-Chaudhury/seaworthy/internal/config"
	"github.com/Arman-Chaudhury/seaworthy/internal/live"
	"github.com/Arman-Chaudhury/seaworthy/internal/manifest"
	"github.com/Arman-Chaudhury/seaworthy/internal/report"
	"github.com/Arman-Chaudhury/seaworthy/internal/rules"
)

var version = "0.0.1-dev"

const usage = `seaworthy — Kubernetes workload-hygiene auditor

Usage:
  seaworthy audit [flags] <path...|->   audit rendered manifests
  seaworthy audit --live [flags]        audit a running cluster (read-only)
  seaworthy rules                       list rules, severities, and hints
  seaworthy version                     print version

Audit flags:
  --format table|json|sarif|html
                          output format (default table)
  --fail-on high|medium|low
                          exit 1 at/above this severity (default high)
  --rule <id>             run only this rule (repeatable)
  --config <file>         config file (default: seaworthy.yaml if present)
  --baseline <file>       suppression file (default seaworthy-baseline.yaml)
  --update-baseline       accept current findings into the baseline
  --previous <run.json>   previous run for new/fixed delta reporting
  --live                  audit a running cluster instead of files
  --namespace <ns>        live mode: audit one namespace (default: all)
  --context <name>        live mode: kubeconfig context
  --kubeconfig <file>     live mode: explicit kubeconfig path

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
	configPath := fs.String("config", "", "config file")
	baselinePath := fs.String("baseline", "seaworthy-baseline.yaml", "baseline suppression file")
	updateBaseline := fs.Bool("update-baseline", false, "accept current findings into the baseline")
	previousPath := fs.String("previous", "", "previous run JSON for delta reporting")
	liveMode := fs.Bool("live", false, "audit a running cluster instead of files")
	namespace := fs.String("namespace", "", "live mode: namespace to audit (default: all)")
	kubeContext := fs.String("context", "", "live mode: kubeconfig context")
	kubeconfig := fs.String("kubeconfig", "", "live mode: explicit kubeconfig path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	threshold, err := audit.ParseSeverity(*failOn)
	if err != nil {
		fmt.Fprintf(stderr, "seaworthy: --fail-on: %v\n", err)
		return 2
	}
	paths := fs.Args()
	var snap *manifest.Snapshot
	var findings []audit.Finding
	if *liveMode {
		if len(paths) > 0 {
			fmt.Fprintln(stderr, "seaworthy audit: --live takes no manifest paths")
			return 2
		}
		cs, err := live.BuildClient(*kubeconfig, *kubeContext)
		if err != nil {
			fmt.Fprintf(stderr, "seaworthy: %v\n", err)
			return 2
		}
		snap, err = live.Collect(cs, *namespace)
		if err != nil {
			fmt.Fprintf(stderr, "seaworthy: %v\n", err)
			return 2
		}
		if len(snap.Objects) == 0 {
			// A typo'd namespace must not slip through a CI gate green.
			fmt.Fprintln(stderr, "seaworthy: no audited objects found in cluster scope")
			return 2
		}
	} else {
		if len(paths) == 0 {
			fmt.Fprintln(stderr, "seaworthy audit: no manifest paths given (use \"-\" for stdin)")
			return 2
		}
		var err error
		snap, findings, err = manifest.Load(paths, stdin)
		if err != nil {
			fmt.Fprintf(stderr, "seaworthy: %v\n", err)
			return 2
		}
		if len(snap.Objects) == 0 && len(findings) == 0 {
			fmt.Fprintln(stderr, "seaworthy: no Kubernetes objects found in input")
			return 2
		}
	}
	var cfg *config.Config
	if *configPath != "" {
		cfg, err = config.Load(*configPath)
	} else {
		cfg, err = config.Discover()
	}
	if err != nil {
		fmt.Fprintf(stderr, "seaworthy: %v\n", err)
		return 2
	}
	ctx := &rules.Context{Snap: snap}
	opts := rules.Options{Only: only}
	if cfg != nil {
		known := map[string]bool{}
		for _, r := range rules.All() {
			known[r.ID] = true
		}
		if err := cfg.Validate(known); err != nil {
			fmt.Fprintf(stderr, "seaworthy: %v\n", err)
			return 2
		}
		opts.Disabled = cfg.Disabled()
		opts.SeverityOverride = cfg.SeverityOverrides()
		opts.IgnoreNamespaces = cfg.IgnoredNamespaces()
		if len(cfg.RequiredLabels) > 0 {
			ctx.RequiredLabels = cfg.RequiredLabels
		}
	}
	ruleFindings, err := rules.Run(ctx, opts)
	if err != nil {
		fmt.Fprintf(stderr, "seaworthy: %v\n", err)
		return 2
	}
	findings = append(findings, ruleFindings...)
	audit.Sort(findings)

	bl, err := baseline.Load(*baselinePath)
	if err != nil {
		fmt.Fprintf(stderr, "seaworthy: %v\n", err)
		return 2
	}
	suppressed := 0
	if *updateBaseline {
		if err := baseline.Build(findings, bl).Write(*baselinePath); err != nil {
			fmt.Fprintf(stderr, "seaworthy: %v\n", err)
			return 2
		}
		fmt.Fprintf(stderr, "seaworthy: %d finding(s) accepted into %s\n", len(findings), *baselinePath)
		suppressed = len(findings)
		findings = nil
	} else {
		findings, suppressed = bl.Apply(findings, time.Now())
	}

	var delta *report.Delta
	if *previousPath != "" {
		prev, err := report.LoadRun(*previousPath)
		if err != nil {
			fmt.Fprintf(stderr, "seaworthy: %v\n", err)
			return 2
		}
		delta = report.ComputeDelta(prev, findings)
	}

	sum := report.Summarize(findings, suppressed)
	var renderErr error
	switch *format {
	case "json":
		run := report.NewRun(findings, suppressed)
		run.Delta = delta
		renderErr = run.WriteJSON(stdout)
	case "table":
		report.WriteTable(stdout, findings, sum, delta, wantColor(stdout))
	case "sarif":
		renderErr = report.WriteSARIF(stdout, version, ruleInfos(), findings)
	case "html":
		renderErr = report.WriteHTML(stdout, findings, sum, delta)
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
