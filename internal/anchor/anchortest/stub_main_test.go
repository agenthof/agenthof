package anchortest

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// stubFlag re-executes this test binary as a standalone Rekor v1 stand-in: the
// scripted acceptance run builds the binary (go test -c) and starts it as
//
//	rekor-fake -rekor-test-stub -url-file F -pubkey-file F -request-log F
//
// so a real agenthof process anchors against a log it can reach over HTTP.
// The shipped code has no such mode; this is test-tree code only.
const stubFlag = "-rekor-test-stub"

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == stubFlag {
		os.Exit(runStub(os.Args[2:]))
	}
	os.Exit(m.Run())
}

// runStub serves a fresh fake until it is killed. The pubkey file is written
// before the url file, each by rename, so a reader that sees the url sees the
// key. Every request is appended to the request log as one "METHOD /path"
// line BEFORE the fake answers, so the line count is exact once a client call
// returns.
func runStub(args []string) int {
	fs := flag.NewFlagSet("rekor-stub", flag.ContinueOnError)
	urlFile := fs.String("url-file", "", "where to write the stand-in's URL")
	keyFile := fs.String("pubkey-file", "", "where to write the log's public key (PEM)")
	reqLog := fs.String("request-log", "", "where to append one line per request")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *urlFile == "" || *keyFile == "" || *reqLog == "" {
		fmt.Fprintln(os.Stderr, "rekor-stub: -url-file, -pubkey-file and -request-log are all required")
		return 2
	}
	logf, err := os.OpenFile(*reqLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rekor-stub:", err)
		return 1
	}
	defer func() { _ = logf.Close() }()

	f := NewRekorV1()
	f.server.Close() // replaced below by the same handler behind the request log
	var logMu sync.Mutex
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logMu.Lock()
		_, werr := fmt.Fprintf(logf, "%s %s\n", r.Method, r.URL.Path)
		logMu.Unlock()
		if werr != nil {
			http.Error(w, "request log unwritable", http.StatusInternalServerError)
			return
		}
		f.handle(w, r)
	}))
	f.URL = f.server.URL

	if err := writeFileAtomic(*keyFile, f.PublicKeyPEM()); err != nil {
		fmt.Fprintln(os.Stderr, "rekor-stub:", err)
		return 1
	}
	if err := writeFileAtomic(*urlFile, []byte(f.URL)); err != nil {
		fmt.Fprintln(os.Stderr, "rekor-stub:", err)
		return 1
	}
	select {} // until killed
}

func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// TestStubMainWritesURLAndKey runs this test binary as the stand-in and
// checks what the acceptance script relies on: the url and key files appear,
// the url answers GET /api/v1/log/publicKey with the key written to disk, and
// the request is in the request log.
func TestStubMainWritesURLAndKey(t *testing.T) {
	dir := t.TempDir()
	urlFile, keyFile, reqLog := filepath.Join(dir, "url"), filepath.Join(dir, "key.pem"), filepath.Join(dir, "requests")
	cmd := exec.Command(os.Args[0], stubFlag, "-url-file", urlFile, "-pubkey-file", keyFile, "-request-log", reqLog)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

	var url string
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if b, err := os.ReadFile(urlFile); err == nil && len(b) > 0 {
			url = string(b)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no url file; stub stderr: %s", stderr.String())
		}
	}
	key, err := os.ReadFile(keyFile)
	if err != nil || !strings.HasPrefix(string(key), "-----BEGIN PUBLIC KEY-----") {
		t.Fatalf("pubkey file = %q, %v", key, err)
	}
	resp, err := http.Get(url + "/api/v1/log/publicKey")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	served, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !bytes.Equal(bytes.TrimSpace(served), bytes.TrimSpace(key)) {
		t.Fatalf("GET publicKey = %d %q, want 200 and the key on disk", resp.StatusCode, served)
	}
	lines, err := os.ReadFile(reqLog)
	if err != nil || string(lines) != "GET /api/v1/log/publicKey\n" {
		t.Fatalf("request log = %q, %v", lines, err)
	}
}
