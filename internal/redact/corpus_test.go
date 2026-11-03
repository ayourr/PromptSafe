package redact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type corpusCase struct {
	input         string
	secrets, keep []string
}

func parseCorpus(t *testing.T, path string) corpusCase {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var c corpusCase
	var section string
	var in []string
	for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		if strings.HasPrefix(line, "=== ") {
			section = strings.TrimSpace(strings.TrimPrefix(line, "=== "))
			continue
		}
		switch section {
		case "input":
			in = append(in, line)
		case "secrets", "keep":
			if strings.TrimSpace(line) == "" {
				continue
			}
			if section == "secrets" {
				c.secrets = append(c.secrets, line)
			} else {
				c.keep = append(c.keep, line)
			}
		}
	}
	c.input = strings.Join(in, "\n")
	if c.input == "" {
		t.Fatalf("%s: no === input section", path)
	}
	return c
}

// TestCorpus redacts log samples shaped like the ones people paste when
// asking for help, and checks that every listed secret is gone, every
// listed keep string survives, and the output passes the leak check.
func TestCorpus(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "corpus", "*.txt"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no corpus files: %v", err)
	}
	for _, f := range files {
		f := f
		t.Run(strings.TrimSuffix(filepath.Base(f), ".txt"), func(t *testing.T) {
			c := parseCorpus(t, f)
			res := mustRedact(t, nil, c.input)
			out := strings.ToLower(res.Output)
			for _, s := range c.secrets {
				if strings.Contains(out, strings.ToLower(s)) {
					t.Errorf("secret %q still in output", s)
				}
			}
			for _, k := range c.keep {
				if !strings.Contains(res.Output, k) {
					t.Errorf("lost %q (false positive)", k)
				}
			}
			if !res.Safe() {
				t.Errorf("leak check blocked the output: %+v", res.Leaks)
			}
			if t.Failed() {
				t.Logf("output:\n%s", res.Output)
			}
		})
	}
}
