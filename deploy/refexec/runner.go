package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/agenthof/agenthof/deploy/internal/confiner"
	"github.com/agenthof/agenthof/deploy/internal/refrunner"
)

var errCapReached = errors.New("refexec: compartment cap reached")

// runner is the stateless one-shot supervisor: per request, one compartment,
// one command, one attestation. It holds nothing between requests but the
// concurrency slots.
type runner struct {
	cfg      execConfig
	logger   *slog.Logger
	confiner confiner.Confiner // what confines a compartment; tests substitute a fake
	slots    chan struct{}     // one token per compartment the cap allows
	wg       sync.WaitGroup
}

func newRunner(cfg execConfig, logger *slog.Logger, c confiner.Confiner) *runner {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &runner{cfg: cfg, logger: logger, confiner: c, slots: make(chan struct{}, cfg.MaxCompartments)}
}

// result is one compartment's outcome. Output is already capped.
type result struct {
	ExitCode    int
	Output      []byte
	Truncated   bool
	OutputBytes int64
	Attestation refrunner.Attestation
}

// newSession mints the per-request id, which is also the compartment's
// container name (podman: [a-zA-Z0-9][a-zA-Z0-9_.-]*).
func newSession() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("refexec: session id: %w", err)
	}
	return "refexec-" + hex.EncodeToString(b), nil
}

// run executes argv in one compartment and returns its outcome. Cancelling
// ctx (the gateway's deadline, or the gateway hanging up) removes the
// compartment through the confiner, which ends it however its backend does.
func (r *runner) run(ctx context.Context, argv []string) (result, error) {
	select {
	case r.slots <- struct{}{}:
	default:
		return result{}, errCapReached
	}
	defer func() { <-r.slots }()
	r.wg.Add(1)
	defer r.wg.Done()

	session, err := newSession()
	if err != nil {
		return result{}, err
	}
	comp, err := r.confiner.Launch(ctx, confiner.Spec{
		Name: session, Program: r.cfg.Keys.Image, Argv: argv,
		Store: r.cfg.Store, Scratch: true, EnvNames: r.cfg.EnvAllow,
		Limits:  r.cfg.Limits,
		Timeout: r.cfg.Timeout,
	})
	if err != nil {
		return result{}, fmt.Errorf("refexec: start compartment: %w", err)
	}
	r.logger.Info("compartment started", "session", session, "command", argv[0], "pid", comp.PID())
	res, err := comp.Wait(ctx)
	if ctx.Err() != nil {
		// Remove runs under its own bounded context. Its error is noise here: a
		// compartment that already exited is gone, and the backend logs it.
		_ = comp.Remove(context.Background())
		r.logger.Info("compartment removed", "session", session)
		return result{}, ctx.Err()
	}
	if err != nil {
		if errors.Is(err, confiner.ErrDidNotLaunch) {
			// The command never ran (podman's exit 125: the image is absent under
			// --pull=never, a storage error, a bad flag). Attesting an exit with a
			// real argv and pid would be a false first-hand record, so return an
			// error and let the gateway record a door failure instead.
			return result{}, fmt.Errorf("refexec: the confiner did not run the command: %w", err)
		}
		return result{}, fmt.Errorf("refexec: compartment: %w", err)
	}
	r.logger.Info("compartment finished", "session", session, "exit", res.Exit, "output_bytes", res.OutputBytes, "truncated", res.Truncated, "env_names", res.EnvNames)
	return result{
		ExitCode: res.Exit, Output: res.Output, Truncated: res.Truncated, OutputBytes: res.OutputBytes,
		Attestation: refrunner.Attestation{
			Runtime: "refexec", Session: session, Command: argv, PID: comp.PID(), Spawn: 1,
			EnvNames: res.EnvNames, Confiner: string(r.confiner.Tier()), ConfinerOpts: r.confiner.Opts(),
		},
	}, nil
}

// close waits for every compartment in flight to finish. Serve has already
// cut every connection, so each in-flight run is being cancelled.
func (r *runner) close() { r.wg.Wait() }

// textOf returns output as the string the JSON encoder transmits: every
// invalid UTF-8 byte replaced by U+FFFD, one for one, exactly as
// encoding/json does — so output_sha, taken over this string, is the hash of
// the bytes Agenthof and the agent actually receive.
func textOf(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var sb strings.Builder
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if r == utf8.RuneError && size == 1 {
			sb.WriteRune(utf8.RuneError)
		} else {
			sb.Write(b[:size])
		}
		b = b[size:]
	}
	return sb.String()
}

// runResponse is the wire contract internal/rungateway reads.
type runResponse struct {
	ExitCode           int            `json:"exit_code"`
	Output             string         `json:"output"`
	OutputSHA          string         `json:"output_sha"`
	Truncated          bool           `json:"truncated"`
	OutputBytes        int64          `json:"output_bytes"`
	RuntimeAttestation map[string]any `json:"runtime_attestation"`
}

func (r *runner) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /run", r.handleRun)
	return mux
}

// handleRun serves one command. Who may ask is settled by the socket's
// directory permissions (refrunner.Listen) and what may run by the gateway's
// allowlist before it ever asks; refexec checks only the shape.
func (r *runner) handleRun(w http.ResponseWriter, req *http.Request) {
	var body struct {
		Command []string `json:"command"`
	}
	if err := json.NewDecoder(io.LimitReader(req.Body, 1<<20)).Decode(&body); err != nil || len(body.Command) == 0 || body.Command[0] == "" {
		http.Error(w, "refexec: command must be a non-empty argv", http.StatusBadRequest)
		return
	}
	// Drain to EOF: only then does the server watch the connection, so the
	// gateway hanging up (its deadline) cancels req.Context() — which is what
	// removes the compartment.
	_, _ = io.Copy(io.Discard, io.LimitReader(req.Body, 1<<20))
	res, err := r.run(req.Context(), body.Command)
	switch {
	case errors.Is(err, errCapReached):
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	case req.Context().Err() != nil:
		return // the gateway hung up; the compartment is already removed
	case err != nil:
		r.logger.Error("compartment did not run", "error", err)
		http.Error(w, "refexec: compartment did not run", http.StatusBadGateway)
		return
	}
	text := textOf(res.Output)
	sum := sha256.Sum256([]byte(text))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(runResponse{
		ExitCode: res.ExitCode, Output: text, OutputSHA: hex.EncodeToString(sum[:]),
		Truncated: res.Truncated, OutputBytes: res.OutputBytes, RuntimeAttestation: res.Attestation.Meta(),
	})
}
