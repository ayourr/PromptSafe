package redact

import (
	"path/filepath"
	"strings"
	"testing"
)

func mustRedact(t *testing.T, cfg *Config, in string) *Result {
	t.Helper()
	r, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r.Redact(in)
}

func TestConsistentPlaceholders(t *testing.T) {
	res := mustRedact(t, nil, "from 10.0.0.1 to 10.0.0.2, again 10.0.0.1")
	want := "from IP_1 to IP_2, again IP_1"
	if res.Output != want {
		t.Fatalf("got %q want %q", res.Output, want)
	}
}

func TestNotIPs(t *testing.T) {
	in := "version 2.4.1 at 12:30:45 took 999.1.1.1ms"
	res := mustRedact(t, nil, in)
	if res.Output != in {
		t.Fatalf("unexpected change: %q", res.Output)
	}
}

func TestDetectors(t *testing.T) {
	cases := map[string]string{
		"mail bob@example.org now":                     "mail EMAIL_1 now",
		"password=hunter22 ok":                         "password=PASSWORD_1 ok",
		`{"api_key": "AKIAIOSFODNN7EXAMPLE"}`:          `{"api_key": "API_KEY_1"}`,
		"addr fe80::1ff:fe23:4567:890a up":             "addr IP_1 up",
		"mac 3c:22:fb:9a:11:0e":                        "mac MAC_1",
		"card 4111 1111 1111 1111.":                    "card CARD_1.",
		"card 4111 1111 1111 1112.":                    "card 4111 1111 1111 1112.",
		"cd /home/alice/src":                           "cd /home/USER_1/src",
		"redis://default:pa55word@cache.internal:6379": "redis://USER_1:PASSWORD_1@HOST_1:6379",
	}
	for in, want := range cases {
		if got := mustRedact(t, nil, in).Output; got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestPrivateKey(t *testing.T) {
	in := "key:\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\ndone"
	if got := mustRedact(t, nil, in).Output; got != "key:\nPRIVATE_KEY_1\ndone" {
		t.Fatalf("got %q", got)
	}
}

func TestPropagation(t *testing.T) {
	res := mustRedact(t, nil, "password: s3cretVal\nlater someone typed s3cretVal again")
	if strings.Contains(res.Output, "s3cretVal") {
		t.Fatalf("password leaked: %q", res.Output)
	}
	if strings.Count(res.Output, "PASSWORD_1") != 2 {
		t.Fatalf("expected both occurrences replaced: %q", res.Output)
	}
}

func TestTerms(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Terms = []Term{{Value: "Acme Corp", Label: "company"}, {Value: "falcon"}}
	res := mustRedact(t, cfg, "ACME CORP runs Project Falcon and falconry")
	want := "COMPANY_1 runs Project TERM_1 and TERM_1ry"
	if res.Output != want {
		t.Fatalf("got %q want %q", res.Output, want)
	}
	if !res.Safe() {
		t.Fatalf("unexpected leaks: %+v", res.Leaks)
	}
}

func TestOverlapMergeLeavesNothing(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Terms = []Term{{Value: "corp.example"}}
	// The term overlaps the start of the email; the merged span must cover both.
	res := mustRedact(t, cfg, "x mycorp.example@mail.com y")
	if strings.Contains(res.Output, "mail.com") || strings.Contains(res.Output, "corp") {
		t.Fatalf("partial leak: %q", res.Output)
	}
}

func TestAllow(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Allow = []string{"127.0.0.1"}
	if got := mustRedact(t, cfg, "bind 127.0.0.1 and 10.1.2.3").Output; got != "bind 127.0.0.1 and IP_1" {
		t.Fatalf("got %q", got)
	}
}

func TestLowercaseFormat(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PlaceholderFormat = "{label}{N}"
	if got := mustRedact(t, cfg, "ip 10.1.2.3 pwd=abcdefg1").Output; got != "ip ip1 pwd=password1" {
		t.Fatalf("got %q", got)
	}
}

func TestCheckFindsLeaks(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Terms = []Term{{Value: "Falcon"}}
	r, _ := New(cfg, nil)
	leaks := r.Check("about falcon from 10.0.0.9")
	if len(leaks) != 2 {
		t.Fatalf("want 2 leaks, got %+v", leaks)
	}
	for _, l := range leaks {
		if strings.Contains(l.Hint, "10.0.0.9") || strings.Contains(l.Hint, "falcon") {
			t.Fatalf("hint exposes the value: %q", l.Hint)
		}
	}
}

func TestCheckIgnoresPlaceholders(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Terms = []Term{{Value: "company"}}
	r, _ := New(cfg, nil)
	res := r.Redact("the company at 10.0.0.1")
	if !res.Safe() {
		t.Fatalf("placeholder TERM_1 / IP_1 flagged as leak: %+v (%q)", res.Leaks, res.Output)
	}
}

func TestMappingRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "map.json")
	r, _ := New(nil, nil)
	var in strings.Builder
	for i := 1; i <= 12; i++ {
		in.WriteString("10.0.0." + itoa(i) + " ")
	}
	res := r.Redact(in.String())
	if err := r.Mapping.Save(path); err != nil {
		t.Fatal(err)
	}
	m, err := LoadMapping(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Restore(res.Output); got != in.String() {
		t.Fatalf("restore mismatch:\n got %q\nwant %q", got, in.String())
	}
	if got := m.Restore("IP_12, IP_1, IP_123, XIP_1"); got != "10.0.0.12, 10.0.0.1, IP_123, XIP_1" {
		t.Fatalf("restore boundaries: %q", got)
	}

	// A second run with the same mapping keeps old numbers and continues counting.
	r2, _ := New(nil, m)
	if got := r2.Redact("10.0.0.5 and 10.9.9.9").Output; got != "IP_5 and IP_13" {
		t.Fatalf("second run: %q", got)
	}
}

func TestUnknownDetector(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Detectors = map[string]bool{"nope": true}
	if _, err := New(cfg, nil); err == nil {
		t.Fatal("expected error for unknown detector")
	}
}

func itoa(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return itoa(i/10) + string(rune('0'+i%10))
}
