package redact

import (
	"regexp"
	"strings"
	"unicode"
)

// Hit is one value found by a detector that uses Find instead of Re.
type Hit struct {
	Start, End int
	Label      string
}

// PasswordKeywords mark the value after them as a PASSWORD.
var PasswordKeywords = []string{
	"password", "passwd", "passphrase", "passcode", "passwort", "pass", "pwd", "pw", "pword",
	"pin", "mdp", "motdepasse", "contrasena", "contrasenya", "senha", "parola", "wachtwoord",
}

// SecretKeywords mark the value after them as a SECRET.
var SecretKeywords = []string{
	"secret", "secrets", "sec", "token", "tokens", "key", "keys", "apikey", "auth", "authorization",
	"cred", "creds", "credential", "credentials", "otp", "totp", "mfa", "cvv", "cvc", "sig",
	"signature", "salt", "seed", "mnemonic", "session", "sessionid", "sid", "cookie", "jwt",
	"bearer", "privatekey", "private", "hmac", "nonce", "cle", "clef", "secreto", "geheim",
}

// shortNumericOK lists keywords whose value may be a short number (PIN codes).
var shortNumericOK = map[string]bool{"pin": true, "otp": true, "totp": true, "mfa": true, "cvv": true, "cvc": true, "passcode": true}

// notSecretValues are values that are never secrets on their own.
var notSecretValues = map[string]bool{
	"null": true, "none": true, "nil": true, "true": true, "false": true, "undefined": true,
	"empty": true, "yes": true, "no": true, "on": true, "off": true, "required": true, "optional": true,
	"bearer": true, "basic": true, "digest": true, "token": true, "negotiate": true, "ntlm": true,
	"simple": true, "kerberos": true, "oauth": true, "oauth2": true, "ldap": true, "saml": true,
	"sasl": true, "plain": true, "password": true, "anonymous": true,
}

var identRe = regexp.MustCompile(`[A-Za-z][A-Za-z0-9_.-]*`)

// keywordDetector finds values written after a keyword: "sec: x",
// "DB_PASSWORD=x", "clientSecret": "x", "--token x", "<password>x</password>".
// The keyword may be any part of the key, split on _ . - and camelCase.
func keywordDetector(id, label, desc string, words []string, prio int, anyNumber bool) *Detector {
	set := map[string]bool{}
	for _, w := range words {
		w = normKeyword(w)
		if w != "" {
			set[w] = true
		}
	}
	return &Detector{
		ID: id, Label: label, Description: desc, Priority: prio, Default: true,
		Find: func(text string) []Hit { return findKeywordValues(text, set, label, anyNumber) },
	}
}

func normKeyword(w string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(w) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// keyComponents splits "DB_PASSWORD", "clientSecret", "x-api-key" into lower
// case parts.
func keyComponents(key string) []string {
	var parts []string
	cur := []rune{}
	flush := func() {
		if len(cur) > 0 {
			parts = append(parts, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	rs := []rune(key)
	for i, r := range rs {
		if r == '_' || r == '.' || r == '-' {
			flush()
			continue
		}
		if i > 0 && unicode.IsUpper(r) {
			prev := rs[i-1]
			nextLower := i+1 < len(rs) && unicode.IsLower(rs[i+1])
			if unicode.IsLower(prev) || unicode.IsDigit(prev) || (unicode.IsUpper(prev) && nextLower) {
				flush()
			}
		}
		cur = append(cur, r)
	}
	flush()
	return parts
}

// matchKeyword returns the keyword found in key, or "".
func matchKeyword(key string, set map[string]bool) string {
	parts := keyComponents(key)
	for i, p := range parts {
		if set[p] {
			return p
		}
		if i+1 < len(parts) && set[p+parts[i+1]] {
			return p + parts[i+1]
		}
		if i+2 < len(parts) && set[p+parts[i+1]+parts[i+2]] {
			return p + parts[i+1] + parts[i+2]
		}
	}
	return ""
}

func isValueEnd(c byte) bool {
	switch c {
	case ' ', '\t', '\r', '\n', '"', '\'', ',', ';', '&', '}', '<':
		return true
	}
	return false
}

func findKeywordValues(text string, set map[string]bool, label string, anyNumber bool) []Hit {
	var hits []Hit
	for _, m := range identRe.FindAllStringIndex(text, -1) {
		ks, ke := m[0], m[1]
		if ks > 0 {
			if c := text[ks-1]; c >= '0' && c <= '9' {
				continue
			}
		}
		key := strings.TrimRight(text[ks:ke], ".-")
		ke = ks + len(key)
		kw := matchKeyword(key, set)
		if kw == "" {
			continue
		}
		if anyNumber {
			kw = "pin"
		}
		if h, ok := keywordValue(text, ks, ke, kw, label); ok {
			hits = append(hits, h)
		}
	}
	return hits
}

func keywordValue(text string, ks, ke int, kw, label string) (Hit, bool) {
	i := ke
	n := len(text)
	// XML: <password>value</password>
	if ks > 0 && text[ks-1] == '<' && i < n && text[i] == '>' {
		j := strings.IndexByte(text[i+1:], '<')
		if j <= 0 || strings.ContainsAny(text[i+1:i+1+j], "\n") {
			return Hit{}, false
		}
		return checkValue(text, i+1, i+1+j, kw, label, false)
	}
	if i < n && (text[i] == '"' || text[i] == '\'') {
		i++
	}
	ws := i
	for i < n && (text[i] == ' ' || text[i] == '\t') {
		i++
	}
	punct := false
	switch {
	case strings.HasPrefix(text[i:], "=>"), strings.HasPrefix(text[i:], ":="):
		i += 2
		punct = true
	case i < n && (text[i] == ':' || text[i] == '='):
		i++
		punct = true
	}
	if !punct && i == ws {
		return Hit{}, false // nothing between key and value
	}
	for i < n && (text[i] == ' ' || text[i] == '\t') {
		i++
	}
	if i >= n {
		return Hit{}, false
	}
	if q := text[i]; q == '"' || q == '\'' {
		j := strings.IndexByte(text[i+1:], q)
		if j <= 0 || strings.Contains(text[i+1:i+1+j], "\n") {
			return Hit{}, false
		}
		return checkValue(text, i+1, i+1+j, kw, label, !punct)
	}
	j := i
	for j < n && !isValueEnd(text[j]) {
		j++
	}
	return checkValue(text, i, j, kw, label, !punct)
}

func checkValue(text string, s, e int, kw, label string, spaceOnly bool) (Hit, bool) {
	v := text[s:e]
	// "auth:SIMPLE)": drop an unmatched closing bracket.
	for len(v) > 0 && (v[len(v)-1] == ')' && !strings.Contains(v, "(") || v[len(v)-1] == ']' && !strings.Contains(v, "[")) {
		v = v[:len(v)-1]
		e--
	}
	// "Cookie: sessionid=abc": the value is itself name=value; the inner
	// key is handled on its own, so keep the name visible.
	if i := strings.IndexByte(v, '='); i > 0 && strings.Trim(v[i:], "=") != "" {
		return Hit{}, false
	}
	if v == "" || notSecretValues[strings.ToLower(v)] {
		return Hit{}, false
	}
	if strings.Trim(v, "*xX•.") == "" || strings.HasPrefix(v, "${") || strings.HasPrefix(v, "{{") {
		return Hit{}, false
	}
	digits, symbols := 0, 0
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
			digits++
		case !unicode.IsLetter(r):
			symbols++
		}
	}
	// "timeout_sec=30", "key=5": short plain numbers are not secrets,
	// except for PIN-like keywords.
	if digits == len(v) && len(v) < 6 && !shortNumericOK[kw] {
		return Hit{}, false
	}
	if spaceOnly {
		// "password reset", "the key point": with no ':' or '=' only
		// password-looking values count.
		if len([]rune(v)) < 6 || (digits == 0 && symbols == 0) {
			return Hit{}, false
		}
		if strings.ContainsAny(v, "=:") || strings.HasSuffix(v, ".") {
			return Hit{}, false
		}
	}
	return Hit{Start: s, End: e, Label: label}, true
}
