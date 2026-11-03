package redact

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// minPropagateLen is the shortest detected value that is also replaced
// everywhere else it appears in the text, and checked for leaks.
const minPropagateLen = 4

// Redactor replaces sensitive values with placeholders.
type Redactor struct {
	cfg       *Config
	detectors []*Detector
	terms     []Term
	allow     map[string]bool
	Mapping   *Mapping
}

// Finding is one redacted value.
type Finding struct {
	Detector    string `json:"detector"`
	Label       string `json:"label"`
	Placeholder string `json:"placeholder"`
	Line        int    `json:"line"`
}

// Leak is something the final check found in the output.
type Leak struct {
	Reason string `json:"reason"`
	Line   int    `json:"line"`
	Hint   string `json:"hint"` // masked, never the full value
}

// Result is the outcome of one redaction.
type Result struct {
	Output   string         `json:"output"`
	Findings []Finding      `json:"findings"`
	Counts   map[string]int `json:"counts"`
	Leaks    []Leak         `json:"leaks"`
}

// Safe reports whether the output passed the final leak check.
func (r *Result) Safe() bool { return len(r.Leaks) == 0 }

type span struct {
	start, end int
	label      string
	key        string
	detector   string
	prio       int
}

// New builds a Redactor from cfg. mapping may be nil.
func New(cfg *Config, mapping *Mapping) (*Redactor, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if mapping == nil {
		mapping = NewMapping(cfg.PlaceholderFormat)
	}
	r := &Redactor{cfg: cfg, Mapping: mapping, allow: map[string]bool{}}
	for _, a := range cfg.Allow {
		r.allow[strings.ToLower(a)] = true
	}

	known := map[string]bool{}
	for _, d := range BuiltinDetectors() {
		known[d.ID] = true
		on := d.Default
		if v, ok := cfg.Detectors[d.ID]; ok {
			on = v
		}
		if on {
			r.detectors = append(r.detectors, d)
		}
	}
	for id := range cfg.Detectors {
		if !known[id] {
			return nil, fmt.Errorf("unknown detector %q (run `promptsafe detectors` to list them)", id)
		}
	}

	for i, p := range cfg.Patterns {
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			return nil, fmt.Errorf("pattern %q: %w", p.Regex, err)
		}
		d := &Detector{ID: fmt.Sprintf("pattern_%d", i+1), Label: orDefault(p.Label, "CUSTOM"), Re: re, Priority: 105}
		if re.NumSubexp() > 0 {
			d.Group = 1
		}
		r.detectors = append(r.detectors, d)
	}

	if len(cfg.InternalDomains) > 0 {
		var parts []string
		for _, dom := range cfg.InternalDomains {
			dom = strings.Trim(strings.TrimSpace(dom), ".")
			if dom != "" {
				parts = append(parts, regexp.QuoteMeta(dom))
			}
		}
		if len(parts) > 0 {
			r.detectors = append(r.detectors, &Detector{
				ID: "internal_domain", Label: "HOST", Normalize: lower, Priority: 61,
				Re: regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*(?:` + strings.Join(parts, "|") + `)\b`),
			})
		}
	}

	// User terms: one detector per label, longest terms first.
	byLabel := map[string][]string{}
	var labels []string
	for _, t := range cfg.Terms {
		v := strings.TrimSpace(t.Value)
		if v == "" {
			continue
		}
		r.terms = append(r.terms, Term{Value: v, Label: t.Label})
		l := sanitizeLabel(orDefault(t.Label, "TERM"))
		if _, ok := byLabel[l]; !ok {
			labels = append(labels, l)
		}
		byLabel[l] = append(byLabel[l], v)
	}
	for _, l := range labels {
		vals := byLabel[l]
		sort.Slice(vals, func(i, j int) bool { return len(vals[i]) > len(vals[j]) })
		q := make([]string, len(vals))
		for i, v := range vals {
			q[i] = regexp.QuoteMeta(v)
		}
		r.detectors = append(r.detectors, &Detector{
			ID: "term", Label: l, Normalize: lower, Priority: 110,
			Re: regexp.MustCompile(`(?i)(?:` + strings.Join(q, "|") + `)`),
		})
	}
	return r, nil
}

func orDefault(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}

// genericPlaceholder matches placeholders in the default style (IP_1),
// so already redacted text is not flagged even without its mapping.
var genericPlaceholder = regexp.MustCompile(`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*_\d+$`)

// Detectors returns the active detectors.
func (r *Redactor) Detectors() []*Detector { return r.detectors }

func (r *Redactor) scan(text string) []span {
	var spans []span
	add := func(d *Detector, s, e int, label string) {
		if s < 0 || e <= s {
			return
		}
		v := text[s:e]
		if r.allow[strings.ToLower(v)] || r.Mapping.IsPlaceholder(v) || (d.ID != "term" && genericPlaceholder.MatchString(v)) {
			return
		}
		if (d.Validate != nil && !d.Validate(v)) || (d.Context != nil && !d.Context(text, s, e)) {
			return
		}
		norm := v
		if d.Normalize != nil {
			norm = d.Normalize(v)
		}
		spans = append(spans, span{start: s, end: e, label: label, key: norm, detector: d.ID, prio: d.Priority})
	}
	for _, d := range r.detectors {
		for _, m := range d.Re.FindAllStringSubmatchIndex(text, -1) {
			switch {
			case len(d.GroupLabels) > 0:
				for g, l := range d.GroupLabels {
					add(d, m[2*g], m[2*g+1], l)
				}
			default:
				add(d, m[2*d.Group], m[2*d.Group+1], d.Label)
			}
		}
	}
	return spans
}

// resolve turns overlapping candidate spans into disjoint ones. When a span
// covers its whole overlapping cluster it wins; otherwise the cluster is
// merged so that no partial value is left behind.
func resolve(text string, spans []span) []span {
	if len(spans) == 0 {
		return nil
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start != spans[j].start {
			return spans[i].start < spans[j].start
		}
		return spans[i].end > spans[j].end
	})
	var out []span
	flush := func(cluster []span, start, end int) {
		var best *span
		covering := false
		for i := range cluster {
			s := &cluster[i]
			full := s.start == start && s.end == end
			switch {
			case best == nil:
				best, covering = s, full
			case full && !covering:
				best, covering = s, true
			case full == covering && s.prio > best.prio:
				best = s
			}
		}
		res := *best
		if !covering {
			res.start, res.end = start, end
			res.key = text[start:end]
			res.detector = "merged"
		}
		out = append(out, res)
	}
	cluster := []span{spans[0]}
	cs, ce := spans[0].start, spans[0].end
	for _, s := range spans[1:] {
		if s.start < ce {
			cluster = append(cluster, s)
			if s.end > ce {
				ce = s.end
			}
			continue
		}
		flush(cluster, cs, ce)
		cluster = []span{s}
		cs, ce = s.start, s.end
	}
	flush(cluster, cs, ce)
	return out
}

// propagate adds spans for every other occurrence of an already detected
// value, so a password found in "password=x" is also caught where it
// appears on its own.
func propagate(text string, spans []span) []span {
	vals := map[string]span{}
	for _, s := range spans {
		v := text[s.start:s.end]
		if len(v) >= minPropagateLen {
			if _, ok := vals[v]; !ok {
				vals[v] = s
			}
		}
	}
	if len(vals) == 0 {
		return spans
	}
	keys := make([]string, 0, len(vals))
	for v := range vals {
		keys = append(keys, v)
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	q := make([]string, len(keys))
	for i, k := range keys {
		q[i] = regexp.QuoteMeta(k)
	}
	re := regexp.MustCompile(strings.Join(q, "|"))
	extra := append([]span(nil), spans...)
	for _, loc := range re.FindAllStringIndex(text, -1) {
		if !atBoundary(text, loc[0], loc[1]) {
			continue
		}
		s := vals[text[loc[0]:loc[1]]]
		s.start, s.end = loc[0], loc[1]
		s.prio = 0 // never beats a real detection
		extra = append(extra, s)
	}
	return resolve(text, extra)
}

// Redact replaces every sensitive value in text and runs the leak check.
func (r *Redactor) Redact(text string) *Result {
	spans := propagate(text, resolve(text, r.scan(text)))
	res := &Result{Counts: map[string]int{}}
	lines := newLineIndex(text)
	seen := map[string]bool{}
	var b strings.Builder
	last := 0
	for _, s := range spans {
		p := r.Mapping.placeholderFor(s.key, s.label, text[s.start:s.end])
		b.WriteString(text[last:s.start])
		b.WriteString(p)
		last = s.end
		res.Findings = append(res.Findings, Finding{Detector: s.detector, Label: s.label, Placeholder: p, Line: lines.line(s.start)})
		if !seen[p] {
			seen[p] = true
			res.Counts[sanitizeLabel(s.label)]++
		}
	}
	b.WriteString(text[last:])
	res.Output = b.String()
	res.Leaks = r.Check(res.Output)
	return res
}

// Check scans text that should already be safe and reports anything that
// still looks sensitive: known original values, user terms, or fresh
// detector hits that are not placeholders.
func (r *Redactor) Check(text string) []Leak {
	var leaks []Leak
	lines := newLineIndex(text)
	lowerText := strings.ToLower(text)
	reported := map[int]bool{}
	inPlaceholder := r.Mapping.placeholderMask(text)
	report := func(pos int, reason, val string) {
		if reported[pos] || inPlaceholder[pos] {
			return
		}
		reported[pos] = true
		leaks = append(leaks, Leak{Reason: reason, Line: lines.line(pos), Hint: mask(val)})
	}

	for _, t := range r.terms {
		lv := strings.ToLower(t.Value)
		for i := 0; ; {
			j := strings.Index(lowerText[i:], lv)
			if j < 0 {
				break
			}
			report(i+j, "sensitive word", t.Value)
			i += j + len(lv)
		}
	}
	for _, e := range r.Mapping.Entries {
		if len(e.Value) < minPropagateLen {
			continue
		}
		for i := 0; ; {
			j := strings.Index(text[i:], e.Value)
			if j < 0 {
				break
			}
			if atBoundary(text, i+j, i+j+len(e.Value)) {
				report(i+j, "original value of "+e.Placeholder, e.Value)
			}
			i += j + len(e.Value)
		}
	}
	for _, s := range r.scan(text) {
		report(s.start, "detector "+s.detector, text[s.start:s.end])
	}
	sort.Slice(leaks, func(i, j int) bool { return leaks[i].Line < leaks[j].Line })
	return leaks
}

func mask(s string) string {
	rs := []rune(s)
	switch {
	case len(rs) <= 2:
		return strings.Repeat("*", len(rs))
	case len(rs) <= 6:
		return string(rs[0]) + strings.Repeat("*", len(rs)-1)
	default:
		return string(rs[:2]) + strings.Repeat("*", len(rs)-3) + string(rs[len(rs)-1])
	}
}

type lineIndex []int

func newLineIndex(text string) lineIndex {
	idx := lineIndex{0}
	for i := 0; i < len(text); i++ {
		if text[i] == '\n' {
			idx = append(idx, i+1)
		}
	}
	return idx
}

func (l lineIndex) line(pos int) int {
	return sort.Search(len(l), func(i int) bool { return l[i] > pos })
}
