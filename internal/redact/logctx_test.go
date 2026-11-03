package redact

import "testing"

func TestLogContextDetectors(t *testing.T) {
	cases := map[string]string{
		"Invalid user oracle9 from 192.0.2.1":                       "Invalid user USER_1 from IP_1",
		"Access denied for user 'bob'@'10.0.0.5'":                   "Access denied for user 'USER_1'@'IP_1'",
		"sudo:  alice : TTY=pts/0 ; COMMAND=/bin/ls":                "sudo:  USER_1 : TTY=pts/0 ; COMMAND=/bin/ls",
		`whoami => CORP\jdoe`:                                       `whoami => HOST_1\USER_1`,
		"owner is S-1-5-21-1004336348-1177238915-682003330-512":     "owner is SID_1",
		`open 'C:\\Users\\bob\\x.txt'`:                              `open 'C:\\Users\\USER_1\\x.txt'`,
		"Mar  3 04:12:09 db-07 kernel: oops":                        "Mar  3 04:12:09 HOST_1 kernel: oops",
		"node ip-10-0-1-23 ready":                                   "node ip-IP_1 ready",
		"GET /x?token=abcdef123&page=2":                             "GET /x?token=SECRET_1&page=2",
		"arn:aws:iam::123456789012:role/admin":                      "arn:aws:iam::ACCOUNT_1:role/admin",
		"see https://www.github.com/acme and api.globex-corp.co.uk": "see https://www.github.com/acme and HOST_1",
		"retry msra-sa-41:8030":                                     "retry HOST_1:8030",
	}
	for in, want := range cases {
		if got := mustRedact(t, nil, in).Output; got != want {
			t.Errorf("%q:\n got %q\nwant %q", in, got, want)
		}
	}
}

// Bugs found by running v0.1 over the loghub sample logs.
func TestLoghubRegressions(t *testing.T) {
	unchanged := []string{
		"AirPort_Brcm43xx::syncPowerState: WWEN[enabled]",       // "::" was an IPv6 address
		"Package_for_KB2603229~31bf3856ad364e35~amd64~~6.1.1.3", // version was an IP
		"Assembly Version=4.0.0.0 and 1.2.3.4.5",
		"- 1117838570 2005.06.03 R02-M1-N0-C:J12-U11", // Unix time + date was a card
		"block blk_-5078186985701364847 size 67108864",
		"setLightsOn(true) uid=1000",
	}
	for _, in := range unchanged {
		if got := mustRedact(t, nil, in).Output; got != in {
			t.Errorf("changed: %q -> %q", in, got)
		}
	}
	// user=sshd is redacted where it is, but sshd elsewhere is not spread to.
	in := "sshd[1]: auth failure user=sshd\nsshd[2]: Connection closed"
	res := mustRedact(t, nil, in)
	if want := "sshd[1]: auth failure user=USER_1\nsshd[2]: Connection closed"; res.Output != want || !res.Safe() {
		t.Errorf("got %q (safe=%v)", res.Output, res.Safe())
	}
}

func TestCookieValues(t *testing.T) {
	in := "Set-Cookie: sid=9a8b7c6d5e4f; Path=/; HttpOnly"
	if got := mustRedact(t, nil, in).Output; got != "Set-Cookie: sid=COOKIE_1; Path=/; HttpOnly" && got != "Set-Cookie: sid=SECRET_1; Path=/; HttpOnly" {
		t.Errorf("got %q", got)
	}
}
