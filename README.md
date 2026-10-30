# PromptSafe

PromptSafe removes sensitive data from text, logs and configs before you paste
them into an AI (external or internal). Every sensitive value is replaced with a
consistent placeholder (`IP_1`, `PASSWORD_1`, `EMAIL_2`, ...), a final check
blocks the output if anything sensitive is still there, and an optional mapping
file lets you put the real values back into the AI's answer.

It is a single binary with no dependencies, for Linux and Windows, with a CLI
and a GUI. Everything runs locally; nothing is sent anywhere.

## Quick start

```sh
make build                     # or: go build -o bin/promptsafe ./cmd/promptsafe
./bin/promptsafe redact app.log > safe.txt
cat app.log | ./bin/promptsafe redact -t "Acme Corp=>COMPANY" --report
./bin/promptsafe gui           # opens the GUI in your browser
```

Example:

```
in : Accepted password for johndoe from 192.168.10.45 port 52144
     connecting postgres://svc_app:Sup3rS3cret!@db01.acme.lan:5432/orders
out: Accepted password for USER_1 from IP_1 port 52144
     connecting postgres://USER_2:PASSWORD_1@HOST_1:5432/orders
```

The same value always gets the same placeholder, so the AI can still reason
about "IP_1 failed three times".

## Commands

| Command | What it does |
|---|---|
| `redact [file]` | Redact a file or stdin. Prints safe text, or exits 2 and prints nothing if the leak check fails. |
| `restore -m map.json [file]` | Replace placeholders in an AI answer with the original values. |
| `check [file]` | Report sensitive data without changing anything. Exits 2 if something is found (useful in scripts and CI). |
| `gui` | Start the GUI on `127.0.0.1` and open it in the browser. |
| `init [dir]` | Write a sample `config.json` and `words.txt`. |
| `detectors` | List built-in detectors and whether they are on by default. |

Common flags for `redact`, `check` and `gui`:

- `-c config.json` config file (default: `$PROMPTSAFE_CONFIG`, then
  `~/.config/promptsafe/config.json` on Linux or `%AppData%\promptsafe\config.json` on Windows)
- `-w words.txt` file of sensitive words, one per line, optionally `word => LABEL` (repeatable)
- `-t "word=>LABEL"` one sensitive word (repeatable)
- `-m mapping.json` load this mapping if it exists and save it after redacting
- `--enable uuid,phone` / `--disable high_entropy` turn detectors on or off
- `--format "{label}{N}"` placeholder style (`{LABEL}_{N}` gives `IP_1`, `{label}{N}` gives `ip1`)
- `redact` only: `-o file`, `--report` (summary on stderr), `--json`

## Round trip with an AI

```sh
promptsafe redact -m case42.json -w words.txt incident.log > prompt.txt
# paste prompt.txt into the AI, save its answer as answer.txt
promptsafe restore -m case42.json answer.txt
```

The mapping file contains the real values, so it is written with owner-only
permissions. Keep it local and delete it when you are done.

## Built-in detectors

On by default: private keys (PEM), JWTs, API keys (AWS, GitHub, Slack, Google,
Stripe, OpenAI, Anthropic), credentials in URLs, Authorization headers,
`password=` / `secret=` / `token=` / `user=` style values (configs, JSON,
connection strings), emails, IPv4, IPv6, MAC addresses, internal hostnames
(`.local`, `.internal`, `.corp`, `.lan`, `.intranet`), usernames in home paths,
card numbers (Luhn-checked), and long random-looking strings (keys, hashes).

Off by default: UUIDs, phone numbers.

Your own words always win over built-in detectors. A value found once (for
example a password in `password=...`) is also replaced everywhere else it
appears in the text.

## Config file

```json
{
  "placeholder_format": "{LABEL}_{N}",
  "detectors": { "uuid": false, "phone": false },
  "terms": [ { "value": "Acme Corp", "label": "COMPANY" } ],
  "terms_files": ["words.txt"],
  "patterns": [ { "regex": "EMP-\\d{6}", "label": "EMPLOYEE_ID" } ],
  "internal_domains": ["acme.com", "acme.lan"],
  "allow": ["127.0.0.1", "localhost"]
}
```

- `terms` are matched case-insensitively, also inside longer words.
- `patterns` are Go regular expressions; if one has a capture group, only group 1 is replaced.
- `internal_domains` redacts the domain and all its subdomains as `HOST_n`.
- `allow` lists values that are never redacted.

## The leak check

After redacting, PromptSafe scans its own output again for:

1. any of your sensitive words,
2. any original value it replaced (4+ characters),
3. anything a detector still matches that is not a placeholder.

If any of these is found, the output is blocked (CLI exit code 2, GUI shows
"Blocked" with the line numbers). Hints only show a masked value, such as `hu*****x`.

## GUI

`promptsafe gui` serves a local page on `127.0.0.1` with a random port and a
random per-launch token, and opens your browser. It refuses requests without
the token or for other host names. Paste or drop a file, add your words, pick
detectors, then copy the safe output. The Restore tab puts the originals back
into the AI's answer using the session's mapping.

## Building

```sh
make test      # go vet + unit tests
make dist      # dist/promptsafe-linux-amd64, -linux-arm64, -windows-amd64.exe
```

Requires Go 1.22+. No cgo, no third-party modules.

## Limits

Pattern-based detection cannot know every secret format. Names of people and
free-text personal data are only caught if you list them as words. Add
anything specific to your organisation to `words.txt` or `patterns`, and use
`check` on the output when in doubt.
