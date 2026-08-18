// seaworthy audits Kubernetes workloads for hygiene defects and gates
// CI/CD pipelines on the result. See SPEC.md; built per BUILD_PLAN.md.
package main

import (
	"fmt"
	"os"
)

var version = "0.0.1-dev"

const usage = `seaworthy — Kubernetes workload-hygiene auditor

Usage:
  seaworthy audit [flags] <path...|->   audit rendered manifests (or --live)
  seaworthy rules                       list rules, severities, and hints
  seaworthy version                     print version

Exit codes: 0 clean (below --fail-on), 1 findings at/above threshold,
2 usage or load error.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version", "--version":
		fmt.Println("seaworthy " + version)
	case "audit", "rules":
		// Implemented milestone-by-milestone; see BUILD_PLAN.md.
		fmt.Fprintf(os.Stderr, "seaworthy %s: not implemented yet (BUILD_PLAN M2)\n", os.Args[1])
		os.Exit(2)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "seaworthy: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
}
