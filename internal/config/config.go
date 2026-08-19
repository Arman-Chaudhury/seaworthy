// Package config loads seaworthy.yaml: per-rule toggles and severity
// overrides, the required-label set, and ignored namespaces (SPEC §6).
package config

import (
	"fmt"
	"os"
	"sort"

	sigsyaml "sigs.k8s.io/yaml"

	"github.com/Arman-Chaudhury/seaworthy/internal/audit"
)

// DiscoverName is the file auto-discovered in the working directory
// when --config is not given.
const DiscoverName = "seaworthy.yaml"

type RuleConfig struct {
	Enabled *bool `json:"enabled,omitempty"`
	// Severity overrides the rule's default (low|medium|high).
	Severity string `json:"severity,omitempty"`
}

type Config struct {
	Rules            map[string]RuleConfig `json:"rules,omitempty"`
	RequiredLabels   []string              `json:"required-labels,omitempty"`
	IgnoreNamespaces []string              `json:"ignore-namespaces,omitempty"`
}

// Load reads an explicit config path; a missing file is an error.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := sigsyaml.UnmarshalStrict(data, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

// Discover loads DiscoverName from the working directory if present;
// (nil, nil) when there is no config.
func Discover() (*Config, error) {
	if _, err := os.Stat(DiscoverName); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return Load(DiscoverName)
}

// Validate checks rule ids and severities against the known registry.
func (c *Config) Validate(knownRules map[string]bool) error {
	ids := make([]string, 0, len(c.Rules))
	for id := range c.Rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if !knownRules[id] {
			return fmt.Errorf("config: unknown rule %q (see `seaworthy rules`)", id)
		}
		if s := c.Rules[id].Severity; s != "" {
			if _, err := audit.ParseSeverity(s); err != nil {
				return fmt.Errorf("config: rule %q: %w", id, err)
			}
		}
	}
	return nil
}

// Disabled returns the rules the config turns off.
func (c *Config) Disabled() map[string]bool {
	out := map[string]bool{}
	for id, rc := range c.Rules {
		if rc.Enabled != nil && !*rc.Enabled {
			out[id] = true
		}
	}
	return out
}

// SeverityOverrides returns the per-rule severity replacements.
func (c *Config) SeverityOverrides() map[string]audit.Severity {
	out := map[string]audit.Severity{}
	for id, rc := range c.Rules {
		if rc.Severity != "" {
			if sev, err := audit.ParseSeverity(rc.Severity); err == nil {
				out[id] = sev
			}
		}
	}
	return out
}

// IgnoredNamespaces returns the namespace skip-set.
func (c *Config) IgnoredNamespaces() map[string]bool {
	out := map[string]bool{}
	for _, ns := range c.IgnoreNamespaces {
		out[ns] = true
	}
	return out
}
