package refspawn

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSupervisor serves the provision wire contract on a Unix socket in a
// private (0700) directory, as refspawn would. mode picks the answer; a
// held provision ends when release is closed or the client hangs up.
type fakeSupervisor struct {
	dir     string
	sock    string
	mode    string
	release chan struct{}

	mu      sync.Mutex
	gotBody string
	held    int // provisions currently held open
	ended   int // provisions whose handler returned
}

func newFakeSupervisor(t *testing.T, mode string) *fakeSupervisor {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "sp") // short: socket path limit; MkdirTemp makes it 0700
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	f := &fakeSupervisor{dir: dir, sock: filepath.Join(dir, "refspawn.sock"), mode: mode, release: make(chan struct{})}
	ln, err := net.Listen("unix", f.sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(f.serve)}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return f
}

func (f *fakeSupervisor) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/provision" {
		http.Error(w, "not the provision route", http.StatusNotFound)
		return
	}
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.gotBody = string(b)
	f.mu.Unlock()
	line := map[string]any{
		"child_dir":     "/tmp/sp/r-child",
		"agent_sockets": map[string]string{"a": "/tmp/sp/r-child/a.sock", "b": "/tmp/sp/r-child/b.sock"},
		"exec_socket":   "/tmp/sp/r-child-exec/refexec.sock",
	}
	switch f.mode {
	case "refuse":
		http.Error(w, "refspawn: compartment cap reached", http.StatusServiceUnavailable)
		return
	case "hang":
		<-r.Context().Done()
		return
	case "malformed":
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{not json\n"))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		return
	case "missing-agent":
		delete(line["agent_sockets"].(map[string]string), "b")
	case "relative-exec":
		line["exec_socket"] = "r-child-exec/refexec.sock"
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	enc, _ := json.Marshal(line)
	_, _ = w.Write(append(enc, '\n'))
	w.(http.Flusher).Flush()
	f.mu.Lock()
	f.held++
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.held--
		f.ended++
		f.mu.Unlock()
	}()
	if f.mode == "die-early" {
		time.Sleep(50 * time.Millisecond)
		return // the set is gone: the body ends
	}
	select {
	case <-r.Context().Done(): // the client closed the body
	case <-f.release:
	}
}

func (f *fakeSupervisor) counts() (held, ended int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.held, f.ended
}

func (f *fakeSupervisor) url() string { return "unix://" + f.sock }

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func mustClient(t *testing.T, endpoint string) *Client {
	t.Helper()
	c, err := New(endpoint, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestProvisionReturnsLeaseAtFlushAndHoldsUntilRelease(t *testing.T) {
	f := newFakeSupervisor(t, "ok")
	c := mustClient(t, f.url())
	lease, err := c.Provision(context.Background(), "r-child", []string{"a", "b"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if lease.ChildDir != "/tmp/sp/r-child" || lease.ExecSocket != "/tmp/sp/r-child-exec/refexec.sock" ||
		lease.AgentSockets["a"] != "/tmp/sp/r-child/a.sock" || lease.AgentSockets["b"] != "/tmp/sp/r-child/b.sock" {
		t.Fatalf("lease = %+v", lease)
	}
	f.mu.Lock()
	body := f.gotBody
	f.mu.Unlock()
	if body != `{"child_run_id":"r-child","agents":["a","b"]}`+"\n" && body != `{"child_run_id":"r-child","agents":["a","b"]}` {
		t.Fatalf("request body = %q, want the pinned shape", body)
	}
	// Provision returned at the flush: the supervisor is still holding.
	if held, ended := f.counts(); held != 1 || ended != 0 {
		t.Fatalf("held=%d ended=%d, want the provision held open", held, ended)
	}
	select {
	case <-lease.Done():
		t.Fatal("Done must not close while the supervisor holds the set")
	case <-time.After(100 * time.Millisecond):
	}
	// Closing the body is the teardown request: the supervisor's handler
	// sees its context cancelled and returns.
	lease.Release()
	lease.Release() // idempotent
	waitFor(t, "the supervisor to see the hang-up", func() bool { _, ended := f.counts(); return ended == 1 })
	select {
	case <-lease.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Done must close once the body is released")
	}
}

func TestLeaseDoneClosesWhenSupervisorEndsTheSet(t *testing.T) {
	f := newFakeSupervisor(t, "die-early")
	lease, err := mustClient(t, f.url()).Provision(context.Background(), "r-child", []string{"a", "b"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	defer lease.Release()
	select {
	case <-lease.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the set ended on the supervisor's side (body EOF) but Done did not close: a dead compartment would go unnoticed until step_timeout")
	}
}

func TestProvisionRefusalIsUnavailable(t *testing.T) {
	f := newFakeSupervisor(t, "refuse")
	lease, err := mustClient(t, f.url()).Provision(context.Background(), "r-child", []string{"a"})
	if !errors.Is(err, ErrUnavailable) || lease != nil {
		t.Fatalf("err=%v lease=%v, want ErrUnavailable and no lease", err, lease)
	}
	if strings.Contains(err.Error(), "cap reached") {
		t.Fatalf("the supervisor's text must not ride on the error (it reaches a ledger reason only as the fixed string): %v", err)
	}
}

func TestProvisionMalformedLineIsUnavailable(t *testing.T) {
	for _, mode := range []string{"malformed", "missing-agent", "relative-exec"} {
		f := newFakeSupervisor(t, mode)
		lease, err := mustClient(t, f.url()).Provision(context.Background(), "r-child", []string{"a", "b"})
		if !errors.Is(err, ErrUnavailable) || lease != nil {
			t.Fatalf("%s: err=%v lease=%v, want ErrUnavailable and no lease", mode, err, lease)
		}
		// A rejected answer still releases the set: the body was closed.
		waitFor(t, mode+": the supervisor to see the hang-up", func() bool { held, _ := f.counts(); return held == 0 })
	}
}

func TestProvisionUnreachableIsUnavailable(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "sp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	c := mustClient(t, "unix://"+filepath.Join(dir, "nobody.sock"))
	if _, err := c.Provision(context.Background(), "r-child", []string{"a"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
}

func TestProvisionRequiresPrivateSocketDir(t *testing.T) {
	f := newFakeSupervisor(t, "ok")
	if err := os.Chmod(f.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := mustClient(t, f.url()).Provision(context.Background(), "r-child", []string{"a"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable: a supervisor behind an open directory is not one only this user could have started", err)
	}
	if held, _ := f.counts(); held != 0 {
		t.Fatal("the supervisor must not have been dialed at all")
	}
}

func TestProvisionHonorsCallerContext(t *testing.T) {
	f := newFakeSupervisor(t, "hang")
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := mustClient(t, f.url()).Provision(ctx, "r-child", []string{"a"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("a provision that never answers must end with the caller's context, not hang")
	}
}

func TestNewRejectsNonUnixEndpoint(t *testing.T) {
	for _, bad := range []string{"", "https://x/", "unix://relative.sock", "/tmp/x.sock"} {
		if _, err := New(bad, nil); err == nil {
			t.Errorf("New(%q) must fail", bad)
		}
	}
}

func TestNewLeaseWatchesTheBody(t *testing.T) {
	pr, pw := io.Pipe()
	l := NewLease("/tmp/sp/r-x", map[string]string{"a": "/tmp/sp/r-x/a.sock"}, "/tmp/sp/r-x-exec/refexec.sock", pr)
	select {
	case <-l.Done():
		t.Fatal("Done closed before the body ended")
	case <-time.After(50 * time.Millisecond):
	}
	_ = pw.Close()
	select {
	case <-l.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("Done must close at body EOF")
	}
	l.Release() // closing an already-ended body is fine
}
