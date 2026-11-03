package redact

import (
	"regexp"
	"strings"
)

// Log-context detectors. These catch values that have no fixed shape but
// sit in a predictable place in common logs: the user in an sshd line, the
// host in a syslog header or shell prompt, cookie and query-string values,
// Windows DOMAIN\user pairs and SIDs, AWS account IDs, and public domains.
// The samples behind them are in testdata/corpus.

func logContextDetectors() []*Detector {
	return []*Detector{
		{
			ID: "login_user", Description: "Usernames in sshd/PAM/sudo/su, MySQL and PostgreSQL auth lines", Label: "USER",
			Re:       regexp.MustCompile(`(?i)(?:\b(?:invalid|illegal) user|\bfailed (?:password|publickey|none|keyboard-interactive/pam|hostbased) for(?: invalid user)?|\baccepted (?:password|publickey|keyboard-interactive/pam|gssapi-with-mic|hostbased) for|\bsession (?:opened|closed) for user|\bfor user|\bauthenticating user|\b(?:connection closed|disconnected) by(?: invalid| authenticating)? user|\bdisconnected from(?: invalid| authenticating)? user|\blogged in as|\blogin as|\bpassword changed for|\bnew user: name=)\s+["'(\x60]?([A-Za-z_][A-Za-z0-9._@$-]{0,63})`),
			Group:    1,
			Validate: notAuthFiller,
			Priority: 62, Default: true,
		},
		{
			ID: "login_user_kv", Description: "PAM and audit user fields: logname=, ruser=, euser=, acct=, by alice(uid=...)", Label: "USER",
			Re:          regexp.MustCompile(`(?i)\b(?:(?:logname|ruser|euser|luser|sudo_user|acct|auid_name)=["']?([A-Za-z_][A-Za-z0-9._@$-]{0,63})|by ([A-Za-z_][A-Za-z0-9._@$-]{0,63})\(uid=)`),
			GroupLabels: map[int]string{1: "USER", 2: "USER"},
			Validate:    notAuthFiller,
			Priority:    62, Default: true,
		},
		{
			ID: "sudo_user", Description: `The invoking user in sudo lines ("sudo: alice : TTY=pts/0 ; ...")`, Label: "USER",
			Re:       regexp.MustCompile(`\bsudo(?:\[\d+\])?:\s+([A-Za-z_][A-Za-z0-9._$-]{0,63})\s*:\s*(?:TTY=|\d+ incorrect|command not allowed|user NOT in sudoers|a password is required)`),
			Group:    1,
			Priority: 62, Default: true,
		},
		{
			ID: "windows_account", Description: "Windows event fields: Account Name, User Name, Logon Account", Label: "USER",
			Re:       regexp.MustCompile(`(?im)\b(?:account name|user ?name|logon account|target user ?name|subject user ?name)\s*:[ \t]*(` + winValue + `)[ \t]*$`),
			Group:    1,
			Validate: notWindowsFiller,
			Priority: 62, Default: true,
		},
		{
			ID: "windows_host", Description: "Windows event fields: Account Domain, Workstation Name, Client Name, Computer", Label: "HOST",
			Re:        regexp.MustCompile(`(?im)\b(?:account domain|workstation(?: name)?|source workstation|client name|computer(?: ?name)?|caller computer name|target domain ?name)\s*:[ \t]*(` + winValue + `)[ \t]*$`),
			Group:     1,
			Validate:  notWindowsFiller,
			Normalize: lower,
			Priority:  62, Default: true,
		},
		{
			ID: "windows_domain_user", Description: `DOMAIN\user pairs (CORP\jdoe)`, Label: "USER",
			Re:          regexp.MustCompile(`\b([A-Z][A-Z0-9-]{1,14})\\([A-Za-z][A-Za-z0-9._$-]{0,63})\b`),
			GroupLabels: map[int]string{1: "HOST", 2: "USER"},
			Context:     realDomainUser,
			Priority:    62, Default: true,
		},
		{
			ID: "windows_sid", Description: "Windows account SIDs (S-1-5-21-...)", Label: "SID",
			Re:       regexp.MustCompile(`\bS-1-5-21(?:-\d{1,10}){3,4}\b`),
			Priority: 70, Default: true,
		},
		{
			ID: "home_path_escaped", Description: `Usernames in escaped or forward-slash Windows paths (C:\\Users\\x, C:/Users/x, Documents and Settings)`, Label: "USER",
			Re:    regexp.MustCompile(`(?i)\b[A-Z]:(?:\\{1,4}|/)(?:Users|Documents and Settings)(?:\\{1,4}|/)([^\\/\s"':*?<>|]+)`),
			Group: 1,
			Validate: func(s string) bool {
				l := lower(s)
				return l != "public" && l != "default" && l != "default user" && l != "all users" && l != "shared"
			},
			Priority: 56, Default: true,
		},
		{
			ID: "unc_host", Description: `Server names in UNC paths (\\fileserver\share)`, Label: "HOST",
			Re:        regexp.MustCompile(`(?:^|[\s"'=(])\\\\([A-Za-z0-9][A-Za-z0-9._-]{0,62})\\[A-Za-z0-9$._ -]`),
			Group:     1,
			Normalize: lower,
			Priority:  58, Default: true,
		},
		{
			ID: "shell_prompt", Description: "user@host in shell prompts (alice@web01:~$, [alice@web01 ~]#)", Label: "USER",
			Re:          regexp.MustCompile(`(?m)(?:^|\s|\])\[?([a-z_][a-z0-9_.-]{0,31})@([A-Za-z0-9][A-Za-z0-9.-]{0,62})(?::\s?[~/][^\s$#]*\s?[$#%]|\s[^\]\n]{0,64}\][$#%]|\s?[$#%]\s)`),
			GroupLabels: map[int]string{1: "USER", 2: "HOST"},
			Priority:    58, Default: true,
		},
		{
			ID: "ssh_target", Description: "user@host targets of ssh, scp, sftp and rsync", Label: "USER",
			Re:          regexp.MustCompile(`\b(?:ssh|scp|sftp|rsync|mosh|ssh-copy-id)\b[^\n]*?[\s'"]([a-z_][a-z0-9_.-]{0,31})@([A-Za-z0-9][A-Za-z0-9.-]{0,62})`),
			GroupLabels: map[int]string{1: "USER", 2: "HOST"},
			Priority:    58, Default: true,
		},
		{
			ID: "syslog_host", Description: "The hostname field of syslog and journald lines", Label: "HOST",
			Re:        regexp.MustCompile(`(?m)^(?:<\d{1,3}>\d? ?)?(?:[A-Z][a-z]{2} +\d{1,2} \d\d:\d\d:\d\d|\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:[.,]\d+)?(?:Z|[+-]\d\d:?\d\d)?) ([A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?) [A-Za-z0-9_./@()-]+(?:\[\d+\])?:`),
			Group:     1,
			Validate:  notLocalHost,
			Normalize: lower,
			Priority:  58, Default: true,
		},
		{
			ID: "host_kv", Description: "host=, hostname:, rhost=, server_name=, nodename= and HTTP Host: values", Label: "HOST",
			Re:        regexp.MustCompile(`(?i)\b(?:host(?:_?name)?|rhost|remote_host|server_?name|node_?name|fqdn|upstream_host)["']?\s*[:=]\s*["']?([A-Za-z0-9](?:[A-Za-z0-9._-]{0,252}[A-Za-z0-9])?)`),
			Group:     1,
			Validate:  hostValue,
			Normalize: lower,
			Priority:  57, Default: true,
		},
		{
			ID: "host_port", Description: "Dashed hostnames followed by a port (msra-sa-41:8030)", Label: "HOST",
			Re:       regexp.MustCompile(`\b([a-z][a-z0-9]*(?:-[a-z0-9]+)+):(\d{2,5})\b`),
			Group:    1,
			Validate: func(s string) bool { return !notHostWords[s] },
			Priority: 56, Default: true,
		},
		{
			ID: "ip_in_hostname", Description: "IPv4 addresses written with dashes inside hostnames (ip-10-0-1-23, customer-187-141-143-180)", Label: "IP",
			Re:        regexp.MustCompile(`(?i)\b[a-z][a-z0-9]*-((?:\d{1,3}-){3}\d{1,3})\b`),
			Group:     1,
			Validate:  func(s string) bool { return validIPv4(strings.ReplaceAll(s, "-", ".")) },
			Normalize: func(s string) string { return strings.ReplaceAll(s, "-", ".") },
			Priority:  64, Default: true,
		},
		{
			ID: "domain", Description: "Public hostnames and domains (well-known public sites are kept)", Label: "HOST",
			Re:        regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:` + publicTLDs + `)\b`),
			Validate:  notWellKnownDomain,
			Context:   domainContext,
			Normalize: lower,
			Priority:  59, Default: true,
		},
		{
			ID: "cookie", Description: "Every value in Cookie: and Set-Cookie: headers, curl -b/--cookie and cookie: fields", Label: "COOKIE",
			Find:     findCookies,
			Priority: 82, Default: true,
		},
		{
			ID: "url_secret", Description: "Secrets in URL query strings (?token=, &sig=, X-Amz-Signature=, ;jsessionid=)", Label: "SECRET",
			Re:       regexp.MustCompile(`(?i)[?&;](?:access_token|refresh_token|id_token|auth_token|token|api_?key|apikey|key|sig|signature|x-amz-signature|x-amz-credential|x-amz-security-token|x-goog-signature|x-goog-credential|client_secret|code|password|passwd|pwd|secret|auth|session_?id|session|sid|jsessionid|phpsessid|ticket|otp|access_key|awsaccesskeyid)=([^&\s#"'<>]{3,})`),
			Group:    1,
			Priority: 81, Default: true,
		},
		{
			ID: "access_log_user", Description: "The authenticated user field of Apache/nginx combined access logs", Label: "USER",
			Re:       regexp.MustCompile(`(?m)^\S+ \S+ ([^\s\[\]"-][^\s\[\]"]{0,63}) \[\d{2}/[A-Z][a-z]{2}/\d{4}:`),
			Group:    1,
			Priority: 62, Default: true,
		},
		{
			ID: "aws_principal", Description: "IAM user, role session and federated user names inside AWS ARNs", Label: "USER",
			Re:       regexp.MustCompile(`\barn:aws[a-z-]*:(?:iam|sts)::\d{12}:(?:user(?:/[A-Za-z0-9+=,.@_-]+)*/|assumed-role/[A-Za-z0-9+=,.@_-]+/|federated-user/)([A-Za-z0-9+=,.@_-]+)`),
			Group:    1,
			Priority: 73, Default: true,
		},
		{
			ID: "aws_account", Description: "AWS account IDs in ARNs, ECR hosts and account_id fields", Label: "ACCOUNT",
			Re:          regexp.MustCompile(`(?i)(?:\barn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:|\b(?:aws_?)?account[ _-]?id["']?\s*[:=]\s*["']?|\bowner[ _-]?id["']?\s*[:=]\s*["']?)(\d{12})\b|\b(\d{12})\.dkr\.ecr\.`),
			GroupLabels: map[int]string{1: "ACCOUNT", 2: "ACCOUNT"},
			Priority:    72, Default: true,
		},
	}
}

// commonAccounts are system and service account names. They are still
// redacted where a detector finds them, but they are not spread to every
// other occurrence: "user=sshd" must not turn the sshd process name in every
// line into USER_1.
var commonAccounts = map[string]bool{}

func init() {
	for _, a := range strings.Fields(`root sshd nobody daemon bin sys sync games man lp mail news uucp proxy
		www-data backup list irc gnats syslog messagebus _apt postfix ntp chrony mysql postgres redis nginx
		apache httpd admin administrator guest test user users ubuntu debian centos ec2-user fedora
		git oracle unknown system localsystem service network jenkins docker kube elastic tomcat ftp
		anonymous support info pi vagrant azureuser opc cloud-user sshd-session`) {
		commonAccounts[a] = true
	}
}

// spreadable reports whether a detected value is also replaced everywhere
// else it appears, and checked for in the output.
func spreadable(v string) bool {
	if len(v) < minPropagateLen || commonAccounts[strings.ToLower(v)] {
		return false
	}
	if len(v) < 6 && strings.Trim(v, "0123456789") == "" {
		return false // uid=1000, port 5432: spreading would hit unrelated numbers
	}
	return true
}

var authFiller = map[string]bool{"unknown": true, "from": true, "by": true, "invalid": true, "for": true, "none": true, "null": true, "the": true, "user": true, "with": true, "to": true}

func notAuthFiller(s string) bool { return !authFiller[strings.ToLower(s)] }

var windowsFiller = map[string]bool{"-": true, "n/a": true, "none": true, "null": true, "unknown": true, "system": true, "local system": true, "local service": true, "network service": true, "anonymous logon": true, "nt authority": true, "window manager": true, "font driver host": true}

// winValue is one Windows event field value: a name, possibly with spaces
// or a trailing $ (machine accounts like WEB01$).
const winValue = `[A-Za-z0-9_][A-Za-z0-9._$ -]{0,63}[A-Za-z0-9_$]|[A-Za-z0-9_$]`

func notWindowsFiller(s string) bool { return !windowsFiller[strings.ToLower(strings.TrimSpace(s))] }

// Registry roots, log levels and well-known Windows authorities that look
// like DOMAIN\ but are not a user's domain.
var notDomains = map[string]bool{"HKLM": true, "HKCU": true, "HKCR": true, "HKU": true, "HKCC": true, "HKEY_LOCAL_MACHINE": true,
	"SOFTWARE": true, "SYSTEM": true, "AUTHORITY": true, "BUILTIN": true, "SERVICE": true, "WINDOWS": true, "MICROSOFT": true,
	"ERROR": true, "WARN": true, "WARNING": true, "INFO": true, "DEBUG": true, "FATAL": true, "TRACE": true, "NOTICE": true,
	"FONT": true, "WINDOW": true, "IIS": true, "APPPOOL": true, "NT": true}

func realDomainUser(text string, start, end int) bool {
	// Find the whole DOMAIN\user token around this group.
	i := start
	for i > 0 && !strings.ContainsRune(" \t\r\n\"'(=,;[<", rune(text[i-1])) {
		i--
	}
	tok := text[i:]
	if j := strings.IndexAny(tok, " \t\r\n\"')],;>"); j >= 0 {
		tok = tok[:j]
	}
	parts := strings.Split(tok, `\`)
	// Exactly DOMAIN\user: paths (C:\Users\x, \\?\GLOBALROOT\Device\...),
	// registry keys and escapes like "ERROR\n" have other shapes.
	if len(parts) != 2 || parts[0] == "" || strings.ContainsAny(parts[0], ":%?.") {
		return false
	}
	return !notDomains[parts[0]]
}

func notLocalHost(s string) bool {
	l := strings.ToLower(s)
	return l != "localhost" && l != "-" && !strings.HasPrefix(l, "localhost.")
}

var notHostWords = map[string]bool{
	"utf-8": true, "utf-16": true, "iso-8859-1": true, "sha-1": true, "sha-256": true, "sha-512": true, "x86-64": true,
	"aes-128": true, "aes-256": true, "rfc-3339": true, "en-us": true, "base-64": true, "ipv4-only": true,
}

func hostValue(s string) bool {
	l := strings.ToLower(s)
	if !notLocalHost(l) || strings.Trim(l, "0123456789.") == "" || len(l) < 2 || l == "true" || l == "false" || l == "null" || l == "none" || l == "yes" || l == "no" {
		return false
	}
	switch l {
	case "nginx", "apache", "envoy", "gunicorn", "uvicorn", "cloudflare", "kestrel", "iis", "jetty", "tomcat", "caddy", "traefik", "any", "all", "default", "unknown":
		return false
	}
	return true
}

// publicTLDs is a conservative list. It leaves out TLDs that are also common
// file extensions or code words (.py, .sh, .md, .rs, .so, .in, .id, .name, .app ...).
const publicTLDs = `com|net|org|edu|gov|mil|int|info|biz|io|co|ai|dev|cloud|tech|online|site|xyz|top|tv|ly|gg|fm|us|uk|eu|asia|pro|me|` +
	`de|fr|es|nl|ch|se|ru|cn|jp|kr|hk|tw|sg|au|nz|ca|mx|br|ar|ma|za|ie|pt|gr|tr|il|ae|sa|eg|dz|tn|ng|ke|ua|cz|sk|hu|ro|bg|dk|fi|lu|vn|th|ph|pk|bd|lk|ir|cl|pe|ve|lt|lv|ee|hr|si|rs|qa|kw|om|jo|lb`

// wellKnownDomains are public sites whose names reveal nothing about the
// person or company sharing the log. Hosting domains where the subdomain
// names a customer (amazonaws.com, azurewebsites.net, herokuapp.com ...)
// are deliberately missing.
var wellKnownDomains = map[string]bool{}

func init() {
	for _, d := range strings.Fields(`google.com googleapis.com gstatic.com googleusercontent.com github.com githubusercontent.com github.io
		gitlab.com bitbucket.org microsoft.com windows.com windowsupdate.com live.com office.com msft.net apple.com icloud.com
		amazon.com aws.amazon.com cloudflare.com ubuntu.com canonical.com launchpad.net debian.org fedoraproject.org redhat.com
		centos.org archlinux.org alpinelinux.org kernel.org gnu.org python.org pypi.org pythonhosted.org npmjs.org npmjs.com
		yarnpkg.com docker.com docker.io k8s.io kubernetes.io golang.org go.dev proxy.golang.org rust-lang.org crates.io
		maven.org apache.org mozilla.org stackoverflow.com stackexchange.com example.com example.org example.net openai.com
		anthropic.com claude.ai letsencrypt.org nodejs.org java.com oracle.com mysql.com postgresql.org nginx.org nginx.com
		w3.org schema.org json-schema.org wikipedia.org youtube.com facebook.com twitter.com x.com linkedin.com reddit.com
		gradle.org jetbrains.com visualstudio.com vscode.dev hashicorp.com terraform.io helm.sh quay.io gcr.io ghcr.io
		sentry.io mongodb.com mongodb.org redis.io elastic.co grafana.com prometheus.io jsdelivr.net unpkg.com cdnjs.com
		cloudfront.net.invalid digicert.com sectigo.com ietf.org iana.org mit.edu apple.news`) {
		wellKnownDomains[d] = true
	}
}

func notWellKnownDomain(s string) bool {
	l := strings.ToLower(strings.TrimSuffix(s, "."))
	labels := strings.Split(l, ".")
	if len(labels) < 2 {
		return false
	}
	// Java/Kotlin/Android packages: com.example.Foo, org.apache.hadoop ...
	switch labels[0] {
	case "com", "org", "net", "io", "android", "androidx", "java", "javax", "kotlin", "edu", "gov":
		if len(labels) >= 3 || labels[0] == "android" || labels[0] == "java" || labels[0] == "javax" {
			return false
		}
	}
	for i := 0; i < len(labels)-1; i++ {
		if wellKnownDomains[strings.Join(labels[i:], ".")] {
			return false
		}
	}
	// Need at least one letter outside the TLD, so "1.2.3.co" style noise is skipped.
	return strings.ContainsAny(strings.Join(labels[:len(labels)-1], ""), "abcdefghijklmnopqrstuvwxyz")
}

// domainContext rejects dotted names that are really code: method calls
// (foo.co()), longer dotted identifiers (a.com.Bar), file names
// (report.co.xlsx) and paths inside identifiers.
func domainContext(text string, start, end int) bool {
	if end < len(text) {
		switch c := text[end]; {
		case c == '(' || c == '_':
			return false
		case c == '.' && end+1 < len(text) && isWordChar(text[end+1]):
			return false
		case c == '-' && end+1 < len(text) && isWordChar(text[end+1]):
			return false
		}
	}
	if start > 0 && (text[start-1] == '.' || text[start-1] == '_' || text[start-1] == '$') {
		return false
	}
	return true
}

var cookieHeaderRe = regexp.MustCompile(`(?im)(?:(?:^|[\s"'{,<])(set-)?cookie["']?\s*[:=]\s*|\s(?:-b|--cookie)\s+)["']?`)

// cookieAttrs are Set-Cookie attributes, which are not secret.
var cookieAttrs = map[string]bool{"path": true, "expires": true, "max-age": true, "domain": true, "samesite": true, "secure": true, "httponly": true, "priority": true, "partitioned": true, "version": true, "comment": true}

// findCookies returns the value of every name=value pair in a cookie
// header. For Set-Cookie only the first pair is the cookie; the rest are
// attributes like Path=/ and are kept.
func findCookies(text string) []Hit {
	var hits []Hit
	for _, m := range cookieHeaderRe.FindAllStringSubmatchIndex(text, -1) {
		setCookie := m[2] >= 0
		i := m[1]
		end := i
		for end < len(text) && text[end] != '\n' && text[end] != '\r' && text[end] != '"' && text[end] != '\'' {
			end++
		}
		for n := 0; i < end; n++ {
			j := strings.IndexByte(text[i:end], ';')
			if j < 0 {
				j = end - i
			}
			pair := text[i : i+j]
			if eq := strings.IndexByte(pair, '='); eq > 0 {
				name := strings.ToLower(strings.TrimSpace(pair[:eq]))
				vs, ve := i+eq+1, i+len(strings.TrimRight(pair, " \t"))
				if !(setCookie && n > 0) && !cookieAttrs[name] && ve > vs {
					hits = append(hits, Hit{Start: vs, End: ve})
				}
			}
			i += j + 1
			for i < end && text[i] == ' ' {
				i++
			}
		}
	}
	return hits
}
