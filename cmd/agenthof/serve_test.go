package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoopbackAddr(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:0": true, "localhost:8080": true, "[::1]:8080": true,
		"0.0.0.0:8080": false, ":8080": false, "10.0.0.5:80": false, "nonsense": false,
	} {
		if got := loopbackAddr(addr); got != want {
			t.Errorf("loopbackAddr(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestServeRefusesToStartWithoutAnIssuer(t *testing.T) {
	t.Setenv("AGENTHOF_OIDC_ISSUER", "")
	var out bytes.Buffer
	if code := cmdServe(context.Background(), []string{"--addr", "127.0.0.1:0"}, &out, io.Discard); code != 2 {
		t.Fatalf("code %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "AGENTHOF_OIDC_ISSUER") {
		t.Fatalf("must say what is missing: %s", out.String())
	}
}

func TestServeRefusesNonLoopbackWithoutTheFlag(t *testing.T) {
	t.Setenv("AGENTHOF_OIDC_ISSUER", "https://idp.test")
	var out bytes.Buffer
	if code := cmdServe(context.Background(), []string{"--addr", "0.0.0.0:0"}, &out, io.Discard); code != 2 {
		t.Fatalf("code %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "--allow-non-loopback") {
		t.Fatalf("must name the flag: %s", out.String())
	}
}

func TestServeWritesAddrFileAnswersHealthzAndStopsOnContext(t *testing.T) {
	t.Chdir(t.TempDir())
	root := writeSample(t)
	t.Setenv("AGENTHOF_OIDC_ISSUER", "https://idp.test") // never dialed: /healthz is unauthenticated
	addrFile := filepath.Join(t.TempDir(), "addr")
	ctx, cancel := context.WithCancel(context.Background())
	var out bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- cmdServe(ctx, []string{"--addr", "127.0.0.1:0", "--addr-file", addrFile, "--config", root, "--log-dir", t.TempDir()}, &out, io.Discard)
	}()
	var addr string
	deadline := time.Now().Add(5 * time.Second)
	for addr == "" && time.Now().Before(deadline) {
		if b, err := os.ReadFile(addrFile); err == nil {
			addr = strings.TrimSpace(string(b))
		}
		time.Sleep(10 * time.Millisecond)
	}
	if addr == "" {
		t.Fatalf("addr file never appeared\n%s", out.String())
	}
	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz = %d", resp.StatusCode)
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("serve exited %d\n%s", code, out.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not stop after its context ended")
	}
	if !strings.Contains(out.String(), "serving on "+addr) {
		t.Fatalf("stdout must announce the address:\n%s", out.String())
	}
}

func TestResolveRunConfigReportsErrorsInLoadThenValidateOrder(t *testing.T) {
	root := writeSample(t)
	cfg, reg, hash, errs := resolveRunConfig(root)
	if len(errs) != 0 || reg == nil || hash == "" || len(cfg.Agents) == 0 {
		t.Fatalf("errs=%v reg=%v hash=%q", errs, reg, hash)
	}
	bad := t.TempDir()
	if err := os.WriteFile(filepath.Join(bad, "gateway.yaml"), []byte("models: {\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, reg, _, errs = resolveRunConfig(bad)
	if reg != nil || len(errs) == 0 {
		t.Fatalf("a broken config must yield errors and no registry: errs=%v", errs)
	}
}
