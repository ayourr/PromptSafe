# Real-world log corpus

Each `.txt` file copies the shape of logs that people paste when they ask for
help: Server Fault and Stack Overflow questions, GitHub issues, forum and
Reddit posts, and the public loghub datasets (github.com/logpai/loghub).
All values are synthetic: documentation IP ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24), private ranges, made-up names, hosts and
keys. No real leaked secret is stored here.

File format:

    # free-text notes
    === input
    the log text
    === secrets
    one value per line that must NOT appear in the redacted output
    === keep
    one value per line that MUST still appear (guards against false positives)

`go test ./internal/redact -run Corpus` redacts every input with the default
config, checks both lists, and checks that the leak check passes.
