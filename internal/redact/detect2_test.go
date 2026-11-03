package redact

import (
	"strings"
	"testing"
)

func expectAll(t *testing.T, cfg *Config, cases map[string]string) {
	t.Helper()
	for in, want := range cases {
		if got := mustRedact(t, cfg, in).Output; got != want {
			t.Errorf("%q:\n got %q\nwant %q", in, got, want)
		}
	}
}

func TestKeywordValues(t *testing.T) {
	expectAll(t, nil, map[string]string{
		"sec: Zk92!aa":                     "sec: SECRET_1",
		"SEC=topsecret":                    "SEC=SECRET_1",
		"DB_PASSWORD=hunter2xyz":           "DB_PASSWORD=PASSWORD_1",
		"curl --password abcDEF123 x":      "curl --password PASSWORD_1 x",
		"my pwd hunter22!":                 "my pwd PASSWORD_1",
		`"clientSecret": "s0me secret v",`: `"clientSecret": "SECRET_1",`,
		"X-Api-Key: 9f8e7d6c5b":            "X-Api-Key: SECRET_1",
		"<password>MyXmlPw1</password>":    "<password>PASSWORD_1</password>",
		"pin: 1234":                        "pin: PASSWORD_1",
		"mot_de_passe: Azerty123":          "mot_de_passe: PASSWORD_1",
		"AccountKey=abc+/def==;Endpoint":   "AccountKey=SECRET_1;Endpoint",
		"x?token=abc123&sig=Zm9vYmFy":      "x?token=SECRET_1&sig=SECRET_2",
		"mysql -u root -pS3cretPw db":      "mysql -u root -pPASSWORD_1 db",
		"sshpass -p 'Hunter2' ssh host":    "sshpass -p 'PASSWORD_1' ssh host",
	})
}

func TestKeywordNonSecrets(t *testing.T) {
	for _, in := range []string{
		"password reset requested",
		"the key point is simple",
		"timeout_sec=30 retries=5",
		"token_type: bearer",
		"private: true",
		"monkey=banana keyboard=qwerty bypass=yesyes passage=long",
		"password: ********",
		"password=${DB_PASS}",
		"(auth:SIMPLE) ok",
		"sudo: x : TTY=pts/0 ; PWD=/tmp ; COMMAND=/bin/ls",
		`OLDPWD=~/src PWD=C:\\work`,
	} {
		if got := mustRedact(t, nil, in).Output; got != in {
			t.Errorf("changed %q -> %q", in, got)
		}
	}
}

func TestCustomKeywords(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Keywords = []string{"codeword", "vault_pin => PIN"}
	expectAll(t, cfg, map[string]string{
		"codeword: blue42":  "codeword: SECRET_1",
		"Codeword = indigo": "Codeword = SECRET_1",
		"vault_pin=12":      "vault_pin=PIN_1",
	})
}

func TestProviderTokens(t *testing.T) {
	toks := []string{
		"glpat-" + strings.Repeat("a1B2", 5),
		"npm_" + strings.Repeat("a1B2c3", 6),
		"hf_" + strings.Repeat("abcDEFghiJ", 3) + "abcd",
		"dop_v1_" + strings.Repeat("0123456789abcdef", 4),
		"shpat_" + strings.Repeat("0123456789abcdef", 2),
		"hvs." + strings.Repeat("Ab1_", 7),
		"dckr_pat_" + strings.Repeat("Ab1-x", 6),
		"SG." + strings.Repeat("a", 22) + "." + strings.Repeat("B", 43),
		"xoxb-123456789012-abcdefABCDEF",
		"sk-ant-api03-" + strings.Repeat("Zx9_", 10),
		"123456789:AA" + strings.Repeat("b", 33),
		"AGE-SECRET-KEY-1" + strings.Repeat("Q", 58),
	}
	for _, tok := range toks {
		res := mustRedact(t, nil, "value "+tok+" end")
		if res.Output != "value API_KEY_1 end" {
			t.Errorf("%s: got %q", tok, res.Output)
		}
	}
	got := mustRedact(t, nil, "post to https://hooks.slack.com/services/T000/B000/XXXXyyyyZZZZ now").Output
	if got != "post to SECRET_1 now" {
		t.Errorf("webhook: %q", got)
	}
}

func TestHashesIBANPhones(t *testing.T) {
	expectAll(t, nil, map[string]string{
		"root:$6$saltsalt$" + strings.Repeat("aB3./", 17) + "x:19000:0": "root:HASH_1:19000:0",
		"iban FR1420041010050500013M02606 ok":                           "iban IBAN_1 ok",
		"iban DE89 3704 0044 0532 0130 00 ok":                           "iban IBAN_1 ok",
		"bad FR1420041010050500013M02607 ok":                            "bad FR1420041010050500013M02607 ok",
		"call +212 6 61 23 45 67 now":                                   "call PHONE_1 now",
		"tel: 06 61 23 45 67":                                           "tel: PHONE_1",
		"Phone number: (555) 123-4567":                                  "Phone number: PHONE_1",
		"updated +12345 lines, tz +0100":                                "updated +12345 lines, tz +0100",
	})
}

func TestNames(t *testing.T) {
	expectAll(t, nil, map[string]string{
		"Contact: Mr. John Smith, ok":                           "Contact: Mr. NAME_1, ok",
		"Fatima Zahra El Amrani called":                         "NAME_1 called",
		"assigned to Jean-Pierre DUPONT by Hélène":              "assigned to NAME_1 by NAME_2",
		"customer: Grace Hopper":                                "customer: NAME_1",
		`{"name": "web-server-01", "author": "Linus Torvalds"}`: `{"name": "web-server-01", "author": "NAME_1"}`,
		"Dr Benali was notified":                                "Dr NAME_1 was notified",
		"Mohamed ERROR occurred":                                "NAME_1 ERROR occurred",
	})
	for _, in := range []string{
		"Will this work? May be. Mark the build as Error.",
		"Apache Kafka on Ubuntu with Jenkins and Grafana.",
		"Samsung and Mariadb",
	} {
		if got := mustRedact(t, nil, in).Output; got != in {
			t.Errorf("changed %q -> %q", in, got)
		}
	}
}

func TestEntropySkipsIDs(t *testing.T) {
	for _, in := range []string{
		"req-3f2b8c1e-9a4d-4e2b-8f1a-0c9d8e7f6a5b done",
		"pod payments-api-7d9f8b6c5-x2kzq restarted",
	} {
		if got := mustRedact(t, nil, in).Output; got != in {
			t.Errorf("got %q", got)
		}
	}
}

func TestPlaceholderIsNotKeyword(t *testing.T) {
	for _, in := range []string{
		`"GET /cb?access_token=ya29.a0AfB_byC3x9Qm2LpT7 HTTP/1.1" 200`,
		`"POST /login;jsessionid=8F3A2B1C9D0E7F6A HTTP/1.1" 302`,
	} {
		res := mustRedact(t, nil, in)
		if !res.Safe() || !strings.Contains(res.Output, " HTTP/1.1") {
			t.Errorf("%q -> %q leaks=%+v", in, res.Output, res.Leaks)
		}
	}
}
