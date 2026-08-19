package report

import (
	"encoding/json"
	"io"

	"github.com/Arman-Chaudhury/seaworthy/internal/audit"
)

// RuleInfo is the rule metadata SARIF embeds; the cmd layer converts
// the registry (plus the synthetic parse-error rule) into these.
type RuleInfo struct {
	ID   string
	Desc string
	Hint string
}

// SARIF 2.1.0 — the minimum GitHub code scanning needs to annotate PRs
// (SPEC §7).
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string          `json:"name"`
	Version        string          `json:"version"`
	InformationURI string          `json:"informationUri"`
	Rules          []sarifRuleMeta `json:"rules"`
}

type sarifRuleMeta struct {
	ID               string    `json:"id"`
	ShortDescription sarifText `json:"shortDescription"`
	Help             sarifText `json:"help"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func sarifLevel(s audit.Severity) string {
	switch s {
	case audit.SeverityHigh:
		return "error"
	case audit.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// WriteSARIF renders findings as one SARIF run.
func WriteSARIF(w io.Writer, version string, rules []RuleInfo, findings []audit.Finding) error {
	driver := sarifDriver{
		Name:           "seaworthy",
		Version:        version,
		InformationURI: "https://github.com/Arman-Chaudhury/seaworthy",
	}
	for _, r := range rules {
		driver.Rules = append(driver.Rules, sarifRuleMeta{
			ID:               r.ID,
			ShortDescription: sarifText{Text: r.Desc},
			Help:             sarifText{Text: r.Hint},
		})
	}
	results := []sarifResult{}
	for _, f := range findings {
		res := sarifResult{
			RuleID:  f.Rule,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: f.Ref() + ": " + f.Message},
			PartialFingerprints: map[string]string{
				"seaworthy/v1": f.Fingerprint(),
			},
		}
		if f.File != "" && f.File != "<stdin>" {
			line := f.Line
			if line < 1 {
				line = 1
			}
			res.Locations = []sarifLocation{{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: f.File},
					Region:           sarifRegion{StartLine: line},
				},
			}}
		}
		results = append(results, res)
	}
	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{{Tool: sarifTool{Driver: driver}, Results: results}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
