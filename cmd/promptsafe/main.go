// Command promptsafe removes sensitive data from text before it is sent to
// an AI, and can put it back into the AI's answer.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"promptsafe/internal/gui"
	"promptsafe/internal/redact"
)

var version = "0.1.0-dev"

const usage = `PromptSafe: redact sensitive data before it goes to an AI.

Usage:
  promptsafe redact  [flags] [file]   Redact a file or stdin, print the safe text
  promptsafe restore -m map.json [file]  Put original values back into an AI answer
  promptsafe check   [flags] [file]   Report sensitive data without changing it
  promptsafe gui     [flags]          Open the desktop GUI in your browser
  promptsafe init    [dir]            Write a sample config.json and words.txt
  promptsafe detectors                List built-in detectors
  promptsafe version

Run "promptsafe <command> -h" for the flags of a command.

Exit codes: 0 ok, 1 error, 2 sensitive data found (check) or leak blocked (redact).
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}
	var err error
	code := 0
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "redact":
		code, err = runRedact(args)
	case "restore":
		err = runRestore(args)
	case "check":
		code, err = runCheck(args)
	case "gui":
		err = runGUI(args)
	case "init":
		err = runInit(args)
	case "detectors":
		runDetectors()
	case "version", "--version", "-v":
		fmt.Println("promptsafe", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		code = 1
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "promptsafe:", err)
		code = 1
	}
	os.Exit(code)
}

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

type common struct {
	config  string
	words   listFlag
	terms   listFlag
	keys    listFlag
	enable  string
	disable string
	format  string
	mapping string
}

func (c *common) register(fs *flag.FlagSet) {
	fs.StringVar(&c.config, "c", "", "config file (default: $PROMPTSAFE_CONFIG or the user config dir)")
	fs.Var(&c.words, "w", "words file, one sensitive word per line (repeatable)")
	fs.Var(&c.terms, "t", `sensitive word, optionally "word=>LABEL" (repeatable)`)
	fs.Var(&c.keys, "k", `extra keyword whose value is redacted, e.g. "sec" for "sec: x" (repeatable, comma-separated)`)
	fs.StringVar(&c.enable, "enable", "", "comma-separated detectors to turn on")
	fs.StringVar(&c.disable, "disable", "", "comma-separated detectors to turn off")
	fs.StringVar(&c.format, "format", "", `placeholder format, e.g. "{LABEL}_{N}" or "{label}{N}"`)
	fs.StringVar(&c.mapping, "m", "", "mapping file: loaded if it exists, updated after redaction")
}

func defaultConfigPath() string {
	if p := os.Getenv("PROMPTSAFE_CONFIG"); p != "" {
		return p
	}
	if dir, err := os.UserConfigDir(); err == nil {
		p := filepath.Join(dir, "promptsafe", "config.json")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func (c *common) build() (*redact.Redactor, error) {
	cfg := redact.DefaultConfig()
	path := c.config
	if path == "" {
		path = defaultConfigPath()
	}
	if path != "" {
		var err error
		if cfg, err = redact.LoadConfig(path); err != nil {
			return nil, err
		}
	}
	for _, w := range c.words {
		t, err := redact.LoadTermsFile(w)
		if err != nil {
			return nil, err
		}
		cfg.Terms = append(cfg.Terms, t...)
	}
	for _, t := range c.terms {
		cfg.Terms = append(cfg.Terms, redact.ParseTermsText(t)...)
	}
	for _, k := range c.keys {
		cfg.Keywords = append(cfg.Keywords, splitList(k)...)
	}
	if cfg.Detectors == nil {
		cfg.Detectors = map[string]bool{}
	}
	for _, id := range splitList(c.enable) {
		cfg.Detectors[id] = true
	}
	for _, id := range splitList(c.disable) {
		cfg.Detectors[id] = false
	}
	if c.format != "" {
		cfg.PlaceholderFormat = c.format
	}
	var m *redact.Mapping
	if c.mapping != "" {
		var err error
		if m, err = redact.LoadMapping(c.mapping, cfg.PlaceholderFormat); err != nil {
			return nil, err
		}
	}
	return redact.New(cfg, m)
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func readInput(args []string) (string, error) {
	var data []byte
	var err error
	if len(args) == 0 || args[0] == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(args[0])
	}
	return string(data), err
}

func writeOutput(path, s string) error {
	if path == "" || path == "-" {
		_, err := io.WriteString(os.Stdout, s)
		return err
	}
	return os.WriteFile(path, []byte(s), 0o600)
}

func runRedact(args []string) (int, error) {
	fs := flag.NewFlagSet("redact", flag.ExitOnError)
	var c common
	c.register(fs)
	out := fs.String("o", "", "write safe text to this file instead of stdout")
	report := fs.Bool("report", false, "print a summary of what was redacted to stderr")
	asJSON := fs.Bool("json", false, "print a JSON result (output, findings, leaks) instead of text")
	fs.Parse(args)

	r, err := c.build()
	if err != nil {
		return 1, err
	}
	text, err := readInput(fs.Args())
	if err != nil {
		return 1, err
	}
	res := r.Redact(text)

	if c.mapping != "" {
		if err := r.Mapping.Save(c.mapping); err != nil {
			return 1, err
		}
	}
	if *asJSON {
		if !res.Safe() {
			res.Output = ""
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			return 1, err
		}
		return exitFor(res.Safe()), nil
	}
	if *report {
		printReport(res)
	}
	if !res.Safe() {
		printLeaks(res.Leaks)
		fmt.Fprintln(os.Stderr, "promptsafe: output BLOCKED, sensitive data would still be exposed")
		return 2, nil
	}
	return 0, writeOutput(*out, res.Output)
}

func exitFor(safe bool) int {
	if safe {
		return 0
	}
	return 2
}

func printReport(res *redact.Result) {
	labels := make([]string, 0, len(res.Counts))
	for l := range res.Counts {
		labels = append(labels, l)
	}
	sort.Strings(labels)
	fmt.Fprintf(os.Stderr, "promptsafe: %d replacements\n", len(res.Findings))
	for _, l := range labels {
		fmt.Fprintf(os.Stderr, "  %-14s %d unique\n", l, res.Counts[l])
	}
}

func printLeaks(leaks []redact.Leak) {
	for _, l := range leaks {
		fmt.Fprintf(os.Stderr, "  line %d: %s (%s)\n", l.Line, l.Reason, l.Hint)
	}
}

func runRestore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	mapping := fs.String("m", "", "mapping file written by redact (required)")
	out := fs.String("o", "", "write restored text to this file instead of stdout")
	fs.Parse(args)
	if *mapping == "" {
		return errors.New("restore needs -m mapping.json")
	}
	if _, err := os.Stat(*mapping); err != nil {
		return err
	}
	m, err := redact.LoadMapping(*mapping, "")
	if err != nil {
		return err
	}
	text, err := readInput(fs.Args())
	if err != nil {
		return err
	}
	return writeOutput(*out, m.Restore(text))
}

func runCheck(args []string) (int, error) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	var c common
	c.register(fs)
	fs.Parse(args)
	r, err := c.build()
	if err != nil {
		return 1, err
	}
	text, err := readInput(fs.Args())
	if err != nil {
		return 1, err
	}
	leaks := r.Check(text)
	if len(leaks) == 0 {
		fmt.Fprintln(os.Stderr, "promptsafe: no sensitive data found")
		return 0, nil
	}
	fmt.Fprintf(os.Stderr, "promptsafe: %d sensitive item(s) found\n", len(leaks))
	printLeaks(leaks)
	return 2, nil
}

func runGUI(args []string) error {
	fs := flag.NewFlagSet("gui", flag.ExitOnError)
	var c common
	c.register(fs)
	addr := fs.String("addr", "127.0.0.1:0", "address to listen on (keep it on localhost)")
	noBrowser := fs.Bool("no-browser", false, "do not open the browser automatically")
	fs.Parse(args)
	build := func(extraTerms string, disabled []string, format string) (*redact.Redactor, error) {
		cc := c
		cc.terms = append(append(listFlag{}, c.terms...), strings.Split(extraTerms, "\n")...)
		cc.disable = strings.Join(append(splitList(c.disable), disabled...), ",")
		if format != "" {
			cc.format = format
		}
		cc.mapping = ""
		return cc.build()
	}
	return gui.Serve(gui.Options{Addr: *addr, OpenBrowser: !*noBrowser, Build: build, MappingPath: c.mapping, Version: version})
}

func runInit(args []string) error {
	dir := "."
	if len(args) > 0 {
		dir = args[0]
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for name, body := range map[string]string{"config.json": redact.SampleConfig, "words.txt": redact.SampleWords} {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			fmt.Fprintf(os.Stderr, "skip %s (already exists)\n", p)
			continue
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", p)
	}
	return nil
}

func runDetectors() {
	for _, d := range redact.BuiltinDetectors() {
		state := "on "
		if !d.Default {
			state = "off"
		}
		fmt.Printf("%-16s %s  %-12s %s\n", d.ID, state, d.Label, d.Description)
	}
}
