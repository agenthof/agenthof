package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func unixClient(sock string) *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}
}

func TestServesEchoOverUnixSocket(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "ea")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "agent.sock")

	ln, err := listenUnix(sock)
	if err != nil {
		t.Fatalf("listenUnix: %v", err)
	}
	srv := &http.Server{Handler: newMux(false)}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	body, err := json.Marshal(request{Input: "hello", Agent: "a"})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := unixClient(sock).Post("http://agenthof/", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out response
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !out.Success || out.Artifact != "hello" {
		t.Fatalf("got %+v, want echo of 'hello'", out)
	}
}

func TestProbesGatewayWhenEnabled(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "gw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	gwSock := filepath.Join(dir, "gw.sock")

	gwLn, err := listenUnix(gwSock)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var gotAuth string
	gw := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuth = r.Header.Get("Authorization")
		mu.Unlock()
		if r.URL.Path != "/exec/authorize" {
			http.Error(w, "no", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"allowed": true})
	})}
	go func() { _ = gw.Serve(gwLn) }()
	t.Cleanup(func() { _ = gw.Close() })

	agentSock := filepath.Join(dir, "agent.sock")
	aLn, err := listenUnix(agentSock)
	if err != nil {
		t.Fatal(err)
	}
	asrv := &http.Server{Handler: newMux(true)}
	go func() { _ = asrv.Serve(aLn) }()
	t.Cleanup(func() { _ = asrv.Close() })

	body, err := json.Marshal(request{Input: "hi", Agent: "a"})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, "http://agenthof/", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Agenthof-Proxy-URL", "unix://"+gwSock)
	req.Header.Set("X-Agenthof-Run-Token", "tok123")
	resp, err := unixClient(agentSock).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out response
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !out.Success {
		t.Fatalf("step failed: %q", out.Reason)
	}
	mu.Lock()
	auth := gotAuth
	mu.Unlock()
	if auth != "Bearer tok123" {
		t.Fatalf("gateway saw auth %q, want Bearer tok123", auth)
	}
}

func TestProbeFailsStepWhenGatewayUnreachable(t *testing.T) {
	asrv := httptestUnix(t, newMux(true))
	body, err := json.Marshal(request{Input: "hi", Agent: "a"})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, "http://agenthof/", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Agenthof-Proxy-URL", "unix:///tmp/does-not-exist.sock")
	req.Header.Set("X-Agenthof-Run-Token", "tok")
	resp, err := unixClient(asrv.sock).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out response
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Success {
		t.Fatal("step should fail when the gateway socket is unreachable")
	}
}

type unixSrv struct{ sock string }

func httptestUnix(t *testing.T, h http.Handler) unixSrv {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "u")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s.sock")
	ln, err := listenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return unixSrv{sock: sock}
}

func TestHandleStepRejectsGET(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://agenthof/", nil)
	rec := httptest.NewRecorder()
	newMux(false).ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET status = %d, want 405", rec.Code)
	}
}

func TestHandleStepRejectsBadJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://agenthof/", strings.NewReader("{not json"))
	rec := httptest.NewRecorder()
	newMux(false).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad-JSON status = %d, want 400", rec.Code)
	}
}

func TestDialTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := dialTCP(addr); err != nil {
		t.Fatalf("dial open listener: %v", err)
	}
	_ = ln.Close()
	if err := dialTCP(addr); err == nil {
		t.Fatal("dial of a closed port succeeded")
	}
}

func TestTouchCreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "marker")
	if err := touch(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}
