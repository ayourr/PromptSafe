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
	// Find replaces Re for detectors that need more than a regex.
	Find     func(text string) []Hit
	Priority int
	Default  bool // enabled unless the config disables it
}

func lower(s string) string { return strings.ToLower(s) }

// apiKeyPattern lists token formats with a fixed, documented prefix, so
// they are found with almost no false positives.
var apiKeyPattern = `\b(?:` + strings.Join([]string{
	`(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}`,                        // AWS access key id
	`gh[pousr]_[A-Za-z0-9]{36,}`, `github_pat_[A-Za-z0-9_]{40,}`, // GitHub
	`gl(?:pat|dt|rt|soat|ptt|cbt|imt|ffct|agent|oas)-[0-9A-Za-z_-]{20,}`, // GitLab
	`xox[abposre]-[A-Za-z0-9-]{10,}`, `xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+`,  // Slack
	`AIza[0-9A-Za-z_-]{35}`, `ya29\.[0-9A-Za-z_-]{20,}`, `GOCSPX-[A-Za-z0-9_-]{28}`, // Google
	`[sr]k_(?:live|test)_[0-9A-Za-z]{16,}`, `whsec_[A-Za-z0-9]{32,}`, // Stripe
	`sk-(?:ant-|proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}`, // OpenAI, Anthropic
	`npm_[A-Za-z0-9]{36}`, `pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}`, `hf_[A-Za-z]{34}`,
	`do[opr]_v1_[a-f0-9]{64}`, `shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}`,
	`hv[sb]\.[A-Za-z0-9_-]{24,}`, `[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_=-]{60,}`, // Vault, Terraform
	`dckr_pat_[A-Za-z0-9_-]{27,}`, `SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`,
	`SK[0-9a-fA-F]{32}`, `key-[0-9a-zA-Z]{32}`, // Twilio, Mailgun
	`\d{8,10}:AA[0-9A-Za-z_-]{33}`, // Telegram bot
	`ATATT3[A-Za-z0-9_=-]{100,}`, `glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}`, `glc_[A-Za-z0-9+/]{32,}={0,2}`,
	`PMAK-[a-f0-9]{24}-[a-f0-9]{34}`, `lin_api_[A-Za-z0-9]{40}`,
	`AGE-SECRET-KEY-1[0-9A-Z]{58}`, `dp\.(?:st|ct|sa|scim|audit)\.[A-Za-z0-9_-]{40,}`,
	`sq0(?:atp|csp)-[0-9A-Za-z_-]{22,}`, `EAAA[A-Za-z0-9_-]{60}`, // Square
	`[A-Za-z0-9_~.]{3}\dQ~[A-Za-z0-9_~.-]{31,34}`,     // Azure AD client secret
	`AccountKey=[A-Za-z0-9+/]{86}==`,                  // Azure storage
	`(?:pk|sk)\.[a-zA-Z0-9]{60,}\.[a-zA-Z0-9_-]{20,}`, // Mapbox
	`rubygems_[a-f0-9]{48}`, `pscale_(?:tkn|pw|oauth)_[A-Za-z0-9_.-]{32,}`, `fly[a-z]?_[A-Za-z0-9_+/=-]{40,}`,
	`(?:sntrys|sntryu)_[A-Za-z0-9+/=_-]{40,}`, `nfp_[A-Za-z0-9]{36}`, `FLWSECK-[A-Za-z0-9]{32}-X`,
	`dapi[a-f0-9]{32}`,                                                                            // Databricks
	`gsk_[A-Za-z0-9]{48,}`, `xai-[A-Za-z0-9]{60,}`, `r8_[A-Za-z0-9]{37}`, `pplx-[A-Za-z0-9]{40,}`, // Groq, xAI, Replicate, Perplexity
}, "|") + `)`

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
			ID: "api_key", Description: "Well-known API keys and tokens (AWS, GitHub, GitLab, Slack, Google, Stripe, OpenAI, Anthropic, npm, PyPI, Hugging Face, DigitalOcean, Shopify, Vault, Docker, SendGrid, Twilio, Mailgun, Telegram, Atlassian, Grafana, Postman, Linear, Azure, age, Doppler, Square...)", Label: "API_KEY",
			Re:       regexp.MustCompile(apiKeyPattern),
			Priority: 90, Default: true,
		},
		{
			ID: "webhook_url", Description: "Slack, Discord, Teams and Zapier webhook URLs", Label: "SECRET",
			Re:       regexp.MustCompile(`https://(?:hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9/_-]+|(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+|[a-z0-9-]+\.webhook\.office\.com/webhookb2/\S+|hooks\.zapier\.com/hooks/catch/\S+)`),
			Priority: 91, Default: true,
		},
		{
			ID: "password_hash", Description: "Password hashes (bcrypt, crypt $1$/$5$/$6$/$y$, argon2, NTLM pwdump lines)", Label: "HASH",
			Re:       regexp.MustCompile(`\$(?:2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}|[156]\$(?:rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{22,86}|y\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{43}|argon2(?:id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+)|\b[0-9a-fA-F]{32}:[0-9a-fA-F]{32}\b`),
			Priority: 92, Default: true,
		},
		{
			ID: "cli_password", Description: "Passwords given on command lines: mysql -pX, sshpass -p X, -P/--pass X", Label: "PASSWORD",
			Re:          regexp.MustCompile(`\b(?:(?:mysql|mysqldump|mysqladmin|mariadb)\b[^\n]*?\s-p([^\s'"]+)|sshpass\s+-p\s*['"]?([^\s'"]+)|(?:smbclient|rdesktop|xfreerdp|net\s+use)\b[^\n]*?\s(?:-p\s+|/p:|%)['"]?([^\s'"]+))`),
			GroupLabels: map[int]string{1: "PASSWORD", 2: "PASSWORD", 3: "PASSWORD"},
			Priority:    82, Default: true,
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
		keywordDetector("password_kv", "PASSWORD", "Values after password words: password=, pwd:, pass, pin, mdp, DB_PASSWORD=, --password x", PasswordKeywords, 80, false),
		keywordDetector("secret_kv", "SECRET", "Values after secret words: sec:, secret=, token, key, auth, cred, clientSecret, X-Api-Key:", SecretKeywords, 79, false),
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
			ID: "person_name", Description: "People's names: common first names (+ surname), names after Mr/Mrs/Dr/Mme..., values of name:/customer:/author= keys", Label: "NAME",
			Find:     findNames,
			Priority: 45, Default: true,
		},
		{
			ID: "uuid", Description: "UUIDs (off by default)", Label: "ID",
			Re:        regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`),
			Normalize: lower,
			Priority:  50, Default: false,
		},
		{
			ID: "phone", Description: "International phone numbers like +33 6 12 34 56 78", Label: "PHONE",
			Re:        regexp.MustCompile(`\+\d{1,3}[ .-]?(?:\(?\d{1,4}\)?[ .-]?){2,5}\d{2,4}\b`),
			Validate:  func(s string) bool { n := len(digitsOnly(s)); return n >= 8 && n <= 15 },
			Normalize: digitsOnly,
			Priority:  50, Default: true,
		},
		{
			ID: "phone_context", Description: "Phone numbers after phone/tel/mobile/fax/GSM/WhatsApp words, any format", Label: "PHONE",
			Re:        regexp.MustCompile(`(?i)\b(?:phone|tel|t[ée]l[ée]phone|mobile|mob|cell|cellphone|fax|gsm|whatsapp|portable|handy|contact)\b\.?(?:\s*(?:number|num|no\.?|#|n°))?\s*[:=]?\s*(\+?\(?\d[\d ().-]{5,}\d)`),
			Group:     1,
			Validate:  func(s string) bool { n := len(digitsOnly(s)); return n >= 7 && n <= 15 },
			Normalize: digitsOnly,
			Priority:  51, Default: true,
		},
		{
			ID: "iban", Description: "Bank account numbers in IBAN format (checksum-verified)", Label: "IBAN",
			Re:        regexp.MustCompile(`\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b`),
			Validate:  validIBAN,
			Normalize: func(s string) string { return strings.ReplaceAll(s, " ", "") },
			Priority:  76, Default: true,
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

// validIBAN checks the ISO 13616 mod-97 checksum.
func validIBAN(s string) bool {
	s = strings.ReplaceAll(s, " ", "")
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	r := s[4:] + s[:4]
	rem := 0
	for _, c := range r {
		switch {
		case c >= '0' && c <= '9':
			rem = (rem*10 + int(c-'0')) % 97
		case c >= 'A' && c <= 'Z':
			rem = (rem*100 + int(c-'A') + 10) % 97
		default:
			return false
		}
	}
	return rem == 1
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
	if k8sPodRe.MatchString(s) {
		return false // Kubernetes pod names: deploy-<replicaset hash>-<id>
	}
	if uuidRe.MatchString(s) {
		return false // request/trace IDs like req-<uuid>; see the uuid detector
	}
	return entropy(s) >= 3.7
}

var k8sPodRe = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*-[bcdfghjklmnpqrstvwxz2456789]{6,10}-[bcdfghjklmnpqrstvwxz2456789]{5}$`)

var uuidRe = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

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
