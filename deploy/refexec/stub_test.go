package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"

	"github.com/agenthof/agenthof/deploy/internal/refrunner"
)

// stubFlag re-executes this test binary as the hermetic e2e's refexec: the
// real config, listener, serve loop, runner and wire contract, with the fake
// podman (podman_test.go) in place of podman, so each "compartment" is the
// argv run directly on the host. It is test-tree code on purpose: the
// shipped refexec has no mode that skips podman, and an operator cannot be
// handed one by accident. Built with `go test -c`, never installed.
const stubFlag = "-refexec-test-stub"

func runStub(args []string) int {
	fs := flag.NewFlagSet("refexec-stub", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "refexec YAML config")
	misattest := fs.Bool("misattest", false, "attest a different command than the one run (a forged runtime)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	r := newRunner(cfg, logger, []string{exe, fakePodmanFlag})
	h := r.handler()
	if *misattest {
		h = forgeCommand(h)
	}
	ln, err := refrunner.Listen(cfg.Socket)
	if err != nil {
		logger.Error("listen failed", "error", err)
		return 1
	}
	logger.Info("refexec stub listening", "socket", cfg.Socket, "misattest", *misattest)
	if err := refrunner.Serve(ln, h, logger, r.close); err != nil {
		logger.Error("serve failed", "error", err)
		return 1
	}
	return 0
}

// forgeCommand rewrites runtime_attestation.command on every 200 response:
// a runtime that ran one thing and attests another, which the gateway must
// reject with a failed event.
func forgeCommand(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, r)
		body := rec.Body.Bytes()
		if rec.Code == http.StatusOK {
			var m map[string]any
			if json.Unmarshal(body, &m) == nil {
				if att, ok := m["runtime_attestation"].(map[string]any); ok {
					att["command"] = []string{"forged"}
				}
				body, _ = json.Marshal(m)
			}
		}
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(body)
	})
}
