package redact

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Entry links one placeholder to the original value it replaced.
type Entry struct {
	Placeholder string `json:"placeholder"`
	Label       string `json:"label"`
	Value       string `json:"value"`
	Key         string `json:"key"`
}

// Mapping keeps placeholders consistent: the same value always gets the
// same placeholder, across one input and across runs that share a file.
type Mapping struct {
	Format  string   `json:"format"`
	Entries []*Entry `json:"entries"`

	byKey         map[string]*Entry
	byPlaceholder map[string]*Entry
	counters      map[string]int
}

func NewMapping(format string) *Mapping {
	if format == "" {
		format = "{LABEL}_{N}"
	}
	m := &Mapping{Format: format}
	m.reindex()
	return m
}

func (m *Mapping) reindex() {
	m.byKey = map[string]*Entry{}
	m.byPlaceholder = map[string]*Entry{}
	m.counters = map[string]int{}
	for _, e := range m.Entries {
		m.byKey[e.Key] = e
		m.byPlaceholder[e.Placeholder] = e
		m.counters[strings.ToUpper(e.Label)]++
	}
}

// LoadMapping reads a mapping file. A missing file gives an empty mapping.
func LoadMapping(path, format string) (*Mapping, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return NewMapping(format), nil
	}
	if err != nil {
		return nil, err
	}
	m := &Mapping{}
	if err := json.Unmarshal(data, m); err != nil {
		return nil, fmt.Errorf("parse mapping %s: %w", path, err)
	}
	if m.Format == "" {
		m.Format = format
	}
	m.reindex()
	return m, nil
}

// Save writes the mapping with owner-only permissions, since it holds the
// original sensitive values.
func (m *Mapping) Save(path string) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

func (m *Mapping) Len() int { return len(m.Entries) }

// IsPlaceholder reports whether s is a placeholder issued by this mapping.
func (m *Mapping) IsPlaceholder(s string) bool { _, ok := m.byPlaceholder[s]; return ok }

// placeholderFor returns the placeholder for key, creating one if needed.
func (m *Mapping) placeholderFor(key, label, value string) string {
	if e, ok := m.byKey[key]; ok {
		return e.Placeholder
	}
	label = sanitizeLabel(label)
	for {
		m.counters[label]++
		p := formatPlaceholder(m.Format, label, m.counters[label])
		if _, taken := m.byPlaceholder[p]; taken {
			continue
		}
		e := &Entry{Placeholder: p, Label: label, Value: value, Key: key}
		m.Entries = append(m.Entries, e)
		m.byKey[key] = e
		m.byPlaceholder[p] = e
		return p
	}
}

func formatPlaceholder(format, label string, n int) string {
	r := strings.NewReplacer("{LABEL}", label, "{label}", strings.ToLower(label), "{N}", strconv.Itoa(n))
	return r.Replace(format)
}

var labelClean = regexp.MustCompile(`[^A-Z0-9_]+`)

func sanitizeLabel(l string) string {
	l = labelClean.ReplaceAllString(strings.ToUpper(strings.TrimSpace(l)), "_")
	l = strings.Trim(l, "_")
	if l == "" {
		return "REDACTED"
	}
	return l
}

func (m *Mapping) placeholderRegexp() *regexp.Regexp {
	if len(m.Entries) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m.Entries))
	for _, e := range m.Entries {
		keys = append(keys, e.Placeholder)
	}
	// Longest first so IP_12 wins over IP_1.
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	for i, k := range keys {
		keys[i] = regexp.QuoteMeta(k)
	}
	return regexp.MustCompile(strings.Join(keys, "|"))
}

// placeholderMask marks the bytes of text that belong to a placeholder.
func (m *Mapping) placeholderMask(text string) []bool {
	mask := make([]bool, len(text)+1)
	if re := m.placeholderRegexp(); re != nil {
		for _, loc := range re.FindAllStringIndex(text, -1) {
			for i := loc[0]; i < loc[1]; i++ {
				mask[i] = true
			}
		}
	}
	return mask
}

// Restore puts the original values back in place of placeholders, for
// example in an AI's answer to a redacted prompt.
func (m *Mapping) Restore(text string) string {
	re := m.placeholderRegexp()
	if re == nil {
		return text
	}
	var b strings.Builder
	last := 0
	for _, loc := range re.FindAllStringIndex(text, -1) {
		if !atBoundary(text, loc[0], loc[1]) {
			continue
		}
		b.WriteString(text[last:loc[0]])
		b.WriteString(m.byPlaceholder[text[loc[0]:loc[1]]].Value)
		last = loc[1]
	}
	b.WriteString(text[last:])
	return b.String()
}

func isWordByte(c byte) bool {
	return c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// atBoundary reports whether text[start:end] is not glued to a longer word.
func atBoundary(text string, start, end int) bool {
	if start > 0 && isWordByte(text[start-1]) && isWordByte(text[start]) {
		return false
	}
	if end < len(text) && isWordByte(text[end]) && isWordByte(text[end-1]) {
		return false
	}
	return true
}
