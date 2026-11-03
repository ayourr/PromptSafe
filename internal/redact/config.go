package redact

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Term is a user-supplied sensitive word or phrase.
type Term struct {
	Value string `json:"value"`
	Label string `json:"label,omitempty"`
}

// Pattern is a user-supplied regular expression.
type Pattern struct {
	Regex string `json:"regex"`
	Label string `json:"label,omitempty"`
}

// Config controls what gets redacted and how placeholders look.
type Config struct {
	// PlaceholderFormat uses {LABEL} (or {label} for lower case) and {N}.
	PlaceholderFormat string          `json:"placeholder_format,omitempty"`
	Detectors         map[string]bool `json:"detectors,omitempty"`
	Terms             []Term          `json:"terms,omitempty"`
	TermsFiles        []string        `json:"terms_files,omitempty"`
	Patterns          []Pattern       `json:"patterns,omitempty"`
	InternalDomains   []string        `json:"internal_domains,omitempty"`
	// Keywords are extra words whose following value is redacted, as in
	// "sec: value" or "codeword=value". Entries may be "word => LABEL".
	Keywords []string `json:"keywords,omitempty"`
	// Allow lists values that must never be redacted (e.g. 127.0.0.1).
	Allow []string `json:"allow,omitempty"`

	baseDir string
}

// DefaultConfig returns a config with built-in defaults.
func DefaultConfig() *Config {
	return &Config{PlaceholderFormat: "{LABEL}_{N}"}
}

// LoadConfig reads a JSON config file. Relative terms_files paths are
// resolved against the config file's directory.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := DefaultConfig()
	if err := json.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if c.PlaceholderFormat == "" {
		c.PlaceholderFormat = "{LABEL}_{N}"
	}
	c.baseDir = filepath.Dir(path)
	for _, f := range c.TermsFiles {
		if !filepath.IsAbs(f) {
			f = filepath.Join(c.baseDir, f)
		}
		terms, err := LoadTermsFile(f)
		if err != nil {
			return nil, err
		}
		c.Terms = append(c.Terms, terms...)
	}
	return c, nil
}

// LoadTermsFile reads one term per line. Lines may be "word" or
// "word => LABEL". Blank lines and lines starting with # are ignored.
func LoadTermsFile(path string) ([]Term, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseTerms(bufio.NewScanner(f))
}

// ParseTermsText parses the same format as LoadTermsFile from a string.
func ParseTermsText(s string) []Term {
	t, _ := ParseTerms(bufio.NewScanner(strings.NewReader(s)))
	return t
}

func ParseTerms(sc *bufio.Scanner) ([]Term, error) {
	var out []Term
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		t := Term{Value: line}
		if i := strings.LastIndex(line, "=>"); i > 0 {
			t.Value = strings.TrimSpace(line[:i])
			t.Label = strings.TrimSpace(line[i+2:])
		}
		if t.Value != "" {
			out = append(out, t)
		}
	}
	return out, sc.Err()
}

// SampleConfig is written by `promptsafe init`.
const SampleConfig = `{
  "placeholder_format": "{LABEL}_{N}",
  "detectors": {
    "uuid": false,
    "person_name": true
  },
  "terms": [
    { "value": "Acme Corp", "label": "COMPANY" },
    { "value": "Project Falcon", "label": "PROJECT" }
  ],
  "terms_files": ["words.txt"],
  "patterns": [
    { "regex": "EMP-\\d{6}", "label": "EMPLOYEE_ID" }
  ],
  "internal_domains": ["acme.com", "acme.lan"],
  "keywords": ["codeword", "vault_pin => PIN"],
  "allow": ["127.0.0.1", "0.0.0.0", "localhost"]
}
`

// SampleWords is written by `promptsafe init`.
const SampleWords = `# One sensitive word or phrase per line.
# Optionally give it a label:  word => LABEL
# Matching is case-insensitive and also catches the word inside longer words.
johndoe => USER
s3cr3t-db-name => DATABASE
`
