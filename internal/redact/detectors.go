package redact

import (
	"math"
	"net"
	"regexp"
	"strings"
	"unicode"
)

// Detector finds one kind of sensitive value.
type Detector struct {
	ID          string
	Description string
	Label       string // placeholder label, e.g. IP -> IP_1
	Re          *regexp.Regexp
	// Group is the submatch to redact. 0 redacts the whole match.
	Group int
	// GroupLabels overrides Group: redact each listed submatch with its own label.
	GroupLabels map[int]string
	Validate    func(string) bool
	// Context can reject a match by looking at the surrounding text.
	Context   func(text string, start, end int) bool
	Normalize func(string) string
	Priority  int
	Default   bool // enabled unless the config disables it
}

func lower(s string) string { return strings.ToLower(s) }

// BuiltinDetectors returns the detectors shipped with PromptSafe.
func BuiltinDetectors() []*Detector {
	return []*Detector{
		{
			ID: "private_key", Description: "PEM private key blocks", Label: "PRIVATE_KEY",
			Re:       regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`),
			Priority: 100, Default: true,
		},
		{
			ID: "jwt", Description: "JSON Web Tokens", Label: "TOKEN",
			Re:       regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*`),
			Priority: 90, Default: true,
		},
		{
			ID: "api_key", Description: "Well-known API keys (AWS, GitHub, Slack, Google, Stripe, OpenAI, Anthropic)", Label: "API_KEY",
			Re:       regexp.MustCompile(`\b(?:(?:AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,}|xox[abposr]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|[sr]k_(?:live|test)_[0-9A-Za-z]{16,}|sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,})`),
			Priority: 90, Default: true,
		},
		{
			ID: "url_credentials", Description: "user:password inside URLs (scheme://user:pass@host)", Label: "PASSWORD",
			Re:          regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://([^\s:/@]+):([^\s@/]+)@`),
			GroupLabels: map[int]string{1: "USER", 2: "PASSWORD"},
			Priority:    85, Default: true,
		},
		{
			ID: "auth_header", Description: "Bearer/Basic tokens in Authorization headers", Label: "TOKEN",
			Re:       regexp.MustCompile(`(?i)\b(?:bearer|basic|token)\s+([A-Za-z0-9._~+/=-]{8,})`),
			Group:    1,
			Priority: 80, Default: true,
		},
		{
			ID: "password_kv", Description: "password=..., pwd: ..., passwd ... in configs, logs, connection strings", Label: "PASSWORD",
			Re:       regexp.MustCompile(`(?i)\b(?:password|passwd|passphrase|pass|pwd)\b["']?\s*[:=]\s*["']?([^\s"',;&}]+)`),
			Group:    1,
			Priority: 80, Default: true,
		},
		{
			ID: "secret_kv", Description: "secret=..., token: ..., api_key=... and similar keys", Label: "SECRET",
			Re:       regexp.MustCompile(`(?i)\b(?:[a-z0-9_.-]*(?:secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credentials?|auth))\b["']?\s*[:=]\s*["']?([^\s"',;&}]+)`),
			Group:    1,
			Priority: 79, Default: true,
		},
		{
			ID: "user_kv", Description: "user=..., username: ..., login=... values", Label: "USER",
			Re:       regexp.MustCompile(`(?i)\b(?:user(?:name)?|login|uid|user[ _]id|account)\b["']?\s*[:=]\s*["']?([^\s"',;&}]+)`),
			Group:    1,
			Priority: 60, Default: true,
		},
		{
			ID: "email", Description: "Email addresses", Label: "EMAIL",
			Re:        regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`),
			Normalize: lower,
			Context:   notURLPassword,
			Priority:  70, Default: true,
		},
		{
			ID: "ipv4", Description: "IPv4 addresses", Label: "IP",
			Re:       regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
			Validate: validIPv4,
			Priority: 65, Default: true,
		},
		{
			ID: "ipv6", Description: "IPv6 addresses", Label: "IP",
			Re:        regexp.MustCompile(`(?i)(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}`),
			Validate:  validIPv6,
			Normalize: func(s string) string { return net.ParseIP(s).String() },
			Priority:  65, Default: true,
		},
		{
			ID: "mac", Description: "MAC addresses", Label: "MAC",
			Re:        regexp.MustCompile(`(?i)\b[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}\b`),
			Normalize: func(s string) string { return strings.ReplaceAll(lower(s), "-", ":") },
			Priority:  66, Default: true,
		},
		{
			ID: "internal_host", Description: "Hostnames on internal suffixes (.local, .internal, .corp, .lan, .intranet)", Label: "HOST",
			Re:        regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:local|localdomain|internal|corp|lan|intranet|home\.arpa)\b`),
			Normalize: lower,
			Priority:  60, Default: true,
		},
		{
			ID: "home_path", Description: "Usernames inside home directory paths (/home/x, C:\\Users\\x)", Label: "USER",
			Re:       regexp.MustCompile(`(?i)(?:/home/|/Users/|[A-Z]:\\Users\\)([^/\\\s"']+)`),
			Group:    1,
			Validate: func(s string) bool { l := lower(s); return l != "public" && l != "default" && l != "shared" },
			Priority: 55, Default: true,
		},
		{
			ID: "credit_card", Description: "Payment card numbers (Luhn-checked)", Label: "CARD",
			Re:        regexp.MustCompile(`\b(?:\d[ -]?){12,18}\d\b`),
			Validate:  luhn,
			Normalize: digitsOnly,
			Priority:  75, Default: true,
		},
		{
			ID: "high_entropy", Description: "Long random-looking strings (likely keys, tokens, hashes)", Label: "SECRET",
			Re:       regexp.MustCompile(`[A-Za-z0-9+_-]{24,}={0,2}`),
			Validate: looksRandom,
			Priority: 40, Default: true,
		},
		{
			ID: "uuid", Description: "UUIDs (off by default)", Label: "ID",
			Re:        regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`),
			Normalize: lower,
			Priority:  50, Default: false,
		},
		{
			ID: "phone", Description: "International phone numbers like +33 6 12 34 56 78 (off by default)", Label: "PHONE",
			Re:        regexp.MustCompile(`\+\d{1,3}[ .-]?(?:\(?\d{1,4}\)?[ .-]?){2,5}\d{2,4}\b`),
			Normalize: digitsOnly,
			Priority:  50, Default: false,
		},
	}
}

// notURLPassword rejects "pass@host" inside scheme://user:pass@host, which
// url_credentials already splits into USER and PASSWORD.
func notURLPassword(text string, start, _ int) bool {
	i := start
	for i > 0 && !unicode.IsSpace(rune(text[i-1])) {
		i--
	}
	return !strings.Contains(text[i:start], "://")
}

func validIPv4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}

func validIPv6(s string) bool {
	if strings.Count(s, ":") < 2 {
		return false
	}
	ip := net.ParseIP(s)
	return ip != nil && strings.Contains(s, ":")
}

func digitsOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func luhn(s string) bool {
	d := digitsOnly(s)
	if len(d) < 13 || len(d) > 19 {
		return false
	}
	sum, double := 0, false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if double {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		double = !double
	}
	return sum%10 == 0
}

// looksRandom flags strings that mix letters and digits and have high
// Shannon entropy, which is typical of keys, tokens and hashes.
func looksRandom(s string) bool {
	var letters, digits int
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digits++
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			letters++
		}
	}
	if digits < 2 || letters < 2 {
		return false
	}
	return entropy(s) >= 3.7
}

func entropy(s string) float64 {
	freq := map[rune]float64{}
	for _, r := range s {
		freq[r]++
	}
	n := float64(len([]rune(s)))
	var h float64
	for _, c := range freq {
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}
