// Package gui serves PromptSafe's graphical interface as a local web page.
// It listens on localhost only and every request must carry a random
// per-launch token, so other sites and users cannot drive it.
package gui

import (
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"

	"promptsafe/internal/redact"
)

//go:embed static/index.html
var indexHTML string

// BuildFunc builds a redactor from the GUI's extra words, the detectors
// turned off in the GUI, and the placeholder format.
type BuildFunc func(extraTerms string, disabled []string, format string) (*redact.Redactor, error)

type Options struct {
	Addr string
	// FallbackAddr is tried when Addr is busy (e.g. the default port is taken).
	FallbackAddr string
	// Strict requires the per-launch token in the page URL too, so other
	// users of the same machine cannot open the page.
	Strict      bool
	OpenBrowser bool
	Build       BuildFunc
	MappingPath string // optional: load at start, save after each redaction
	Version     string
}

type server struct {
	opts    Options
	token   string
	mu      sync.Mutex
	mapping *redact.Mapping
	quit    chan struct{}
}

type request struct {
	Text     string   `json:"text"`
	Terms    string   `json:"terms"`
	Disabled []string `json:"disabled"`
	Format   string   `json:"format"`
}

// Serve runs the GUI until the user quits it or the process is stopped.
func Serve(opts Options) error {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return err
	}
	s := &server{opts: opts, token: hex.EncodeToString(buf), quit: make(chan struct{})}
	if opts.MappingPath != "" {
		m, err := redact.LoadMapping(opts.MappingPath, "")
		if err != nil {
			return err
		}
		s.mapping = m
	}

	ln, err := net.Listen("tcp", opts.Addr)
	if err != nil && opts.FallbackAddr != "" {
		fmt.Fprintf(os.Stderr, "%s is busy, using another port\n", opts.Addr)
		ln, err = net.Listen("tcp", opts.FallbackAddr)
	}
	if err != nil {
		return err
	}
	url := fmt.Sprintf("http://%s/", ln.Addr().String())
	if opts.Strict {
		url += "?t=" + s.token
	}
	fmt.Fprintf(os.Stderr, "PromptSafe GUI running at:\n  %s\nPress Ctrl+C (or Quit in the page) to stop.\n", url)
	if opts.OpenBrowser {
		if err := openBrowser(url); err != nil {
			fmt.Fprintln(os.Stderr, "could not open a browser, open the link above yourself:", err)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.index)
	mux.HandleFunc("/api/detectors", s.api(s.detectors))
	mux.HandleFunc("/api/redact", s.api(s.redact))
	mux.HandleFunc("/api/check", s.api(s.check))
	mux.HandleFunc("/api/restore", s.api(s.restore))
	mux.HandleFunc("/api/mapping", s.api(s.getMapping))
	mux.HandleFunc("/api/reset", s.api(s.reset))
	mux.HandleFunc("/api/quit", s.api(func(*request) (any, error) {
		close(s.quit)
		return map[string]bool{"ok": true}, nil
	}))

	srv := &http.Server{Handler: s.guard(mux)}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-s.quit:
		return srv.Close()
	}
}

// guard rejects requests that do not target localhost (DNS rebinding).
func (s *server) guard(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		if host != "127.0.0.1" && host != "localhost" && host != "::1" && host != "[::1]" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	})
}

func (s *server) tokenOK(got string) bool {
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) == 1
}

func (s *server) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" || (s.opts.Strict && !s.tokenOK(r.URL.Query().Get("t"))) {
		http.Error(w, "forbidden: open the link printed in the terminal", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
	page := strings.Replace(indexHTML, "__TOKEN__", s.token, 1)
	page = strings.Replace(page, "__VERSION__", s.opts.Version, 1)
	fmt.Fprint(w, page)
}

func (s *server) api(fn func(*request) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.tokenOK(r.Header.Get("X-PromptSafe-Token")) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		req := &request{}
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, 64<<20)
			if err := json.NewDecoder(r.Body).Decode(req); err != nil {
				http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
				return
			}
		}
		s.mu.Lock()
		out, err := fn(req)
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			out = map[string]string{"error": err.Error()}
		}
		json.NewEncoder(w).Encode(out)
	}
}

func (s *server) build(req *request) (*redact.Redactor, error) {
	r, err := s.opts.Build(req.Terms, req.Disabled, req.Format)
	if err != nil {
		return nil, err
	}
	format := req.Format
	if format == "" {
		format = r.Mapping.Format
	}
	if s.mapping == nil || (req.Format != "" && s.mapping.Format != req.Format && s.mapping.Len() == 0) {
		s.mapping = redact.NewMapping(format)
	}
	r.Mapping = s.mapping
	return r, nil
}

func (s *server) detectors(*request) (any, error) {
	type det struct {
		ID, Label, Description string
		Default                bool
	}
	var out []det
	for _, d := range redact.BuiltinDetectors() {
		out = append(out, det{d.ID, d.Label, d.Description, d.Default})
	}
	return out, nil
}

func (s *server) redact(req *request) (any, error) {
	r, err := s.build(req)
	if err != nil {
		return nil, err
	}
	res := r.Redact(req.Text)
	if !res.Safe() {
		res.Output = ""
	}
	if s.opts.MappingPath != "" {
		if err := s.mapping.Save(s.opts.MappingPath); err != nil {
			return nil, err
		}
	}
	return map[string]any{"result": res, "safe": res.Safe(), "mappingSize": s.mapping.Len(), "format": s.mapping.Format}, nil
}

func (s *server) check(req *request) (any, error) {
	r, err := s.build(req)
	if err != nil {
		return nil, err
	}
	return map[string]any{"leaks": r.Check(req.Text)}, nil
}

func (s *server) restore(req *request) (any, error) {
	if s.mapping == nil {
		return map[string]string{"output": req.Text}, nil
	}
	return map[string]string{"output": s.mapping.Restore(req.Text)}, nil
}

func (s *server) getMapping(*request) (any, error) {
	if s.mapping == nil {
		return redact.NewMapping(""), nil
	}
	return s.mapping, nil
}

func (s *server) reset(*request) (any, error) {
	s.mapping = nil
	return map[string]bool{"ok": true}, nil
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}
