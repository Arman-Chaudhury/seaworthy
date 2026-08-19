// Package baseline implements suppression files: accepted findings,
// fingerprinted, each with an optional expiry — how brownfield repos
// adopt the CI gate without a big-bang fix (SPEC §6).
package baseline

import (
	"fmt"
	"os"
	"sort"
	"time"

	sigsyaml "sigs.k8s.io/yaml"

	"github.com/Arman-Chaudhury/seaworthy/internal/audit"
)

// Entry is one accepted finding. Rule/Object/Detail are informational
// (so reviews of the baseline file are meaningful); Fingerprint is what
// matches.
type Entry struct {
	Fingerprint string `json:"fingerprint"`
	Rule        string `json:"rule"`
	Object      string `json:"object"`
	Detail      string `json:"detail,omitempty"`
	// Expires ("YYYY-MM-DD") stops the suppression at that date, so
	// accepted debt cannot live forever unnoticed.
	Expires string `json:"expires,omitempty"`
}

type File struct {
	Version  int     `json:"version"`
	Findings []Entry `json:"findings"`
}

// Load reads a baseline; a missing file is an empty baseline, so the
// first --update-baseline run needs no setup.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &File{Version: 1}, nil
	}
	if err != nil {
		return nil, err
	}
	var f File
	if err := sigsyaml.UnmarshalStrict(data, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &f, nil
}

// Suppresses reports whether fp is baselined and not expired at now.
func (f *File) Suppresses(fp string, now time.Time) bool {
	for _, e := range f.Findings {
		if e.Fingerprint != fp {
			continue
		}
		if e.Expires == "" {
			return true
		}
		exp, err := time.Parse("2006-01-02", e.Expires)
		if err != nil {
			// An unparsable expiry must not suppress silently forever.
			return false
		}
		return !now.After(exp.AddDate(0, 0, 1).Add(-time.Nanosecond))
	}
	return false
}

// Apply partitions findings into (kept, suppressedCount).
func (f *File) Apply(findings []audit.Finding, now time.Time) ([]audit.Finding, int) {
	kept := make([]audit.Finding, 0, len(findings))
	suppressed := 0
	for _, fd := range findings {
		if f.Suppresses(fd.Fingerprint(), now) {
			suppressed++
			continue
		}
		kept = append(kept, fd)
	}
	return kept, suppressed
}

// Build creates a baseline accepting all of findings, carrying forward
// expiry dates from old for fingerprints that persist.
func Build(findings []audit.Finding, old *File) *File {
	expiries := map[string]string{}
	if old != nil {
		for _, e := range old.Findings {
			expiries[e.Fingerprint] = e.Expires
		}
	}
	out := &File{Version: 1}
	seen := map[string]bool{}
	for _, fd := range findings {
		fp := fd.Fingerprint()
		if seen[fp] {
			continue
		}
		seen[fp] = true
		out.Findings = append(out.Findings, Entry{
			Fingerprint: fp,
			Rule:        fd.Rule,
			Object:      fd.Ref(),
			Detail:      fd.Detail,
			Expires:     expiries[fp],
		})
	}
	sort.Slice(out.Findings, func(i, j int) bool {
		a, b := out.Findings[i], out.Findings[j]
		if a.Object != b.Object {
			return a.Object < b.Object
		}
		if a.Rule != b.Rule {
			return a.Rule < b.Rule
		}
		return a.Detail < b.Detail
	})
	return out
}

// Write persists the baseline as YAML, reviewable like any other file.
func (f *File) Write(path string) error {
	data, err := sigsyaml.Marshal(f)
	if err != nil {
		return err
	}
	header := []byte("# seaworthy baseline — accepted findings by fingerprint.\n# Entries with `expires: YYYY-MM-DD` stop suppressing after that date.\n")
	return os.WriteFile(path, append(header, data...), 0o644)
}
