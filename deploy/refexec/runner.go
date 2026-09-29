package main

import (
	"bytes"
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
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/agenthof/agenthof/deploy/internal/refrunner"
)

// maxOutput caps the combined stdout+stderr a compartment can hand back:
// what is returned is what the agent gets and what output_sha covers.
const maxOutput = 1 << 20

// truncationMarker ends a capped output, so the agent sees that it is
// partial without parsing the response's truncated flag.
const truncationMarker = "\n[output truncated by refexec]\n"

var errCapReached = errors.New("refexec: compartment cap reached")

// runner is the stateless one-shot supervisor: per request, one compartment,
// one command, one attestation. It holds nothing between requests but the
// concurrency slots.
type runner struct {
	cfg     execConfig
	logger  *slog.Logger
	podman  []string // the podman client's argv prefix: {"podman"}; tests substitute a fake
	environ func() []string
	slots   chan struct{} // one token per compartment the cap allows
	wg      sync.WaitGroup
}

func newRunner(cfg execConfig, logger *slog.Logger, podman []string) *runner {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &runner{cfg: cfg, logger: logger, podman: podman, environ: os.Environ, slots: make(chan struct{}, cfg.MaxCompartments)}
}

// result is one compartment's outcome. Output is already capped.
type result struct {
	ExitCode    int
	Output      []byte
	Truncated   bool
	OutputBytes int64
	Attestation refrunner.Attestation
}

// envNames lists the env_allow names refexec's own environment holds, sorted.
// Each is passed to podman as `-e NAME`, so podman copies the value from the
// client's environment: the value never appears in an argv or a log. These
// are what refexec attests it injected; an image's own ENV layer adds names
// refexec never sees.
func (r *runner) envNames() []string {
	own := map[string]bool{}
	for _, kv := range r.environ() {
		name, _, _ := strings.Cut(kv, "=")
		own[name] = true
	}
	names := []string{}
	for _, name := range r.cfg.EnvAllow {
		if own[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// podmanRunArgs builds the one `podman run` for a compartment: no network,
// a read-only root, a tmpfs scratch, every capability dropped, no new
// privileges, the host user's id, the operator's resource caps, the
// per-command wall clock as a backstop to the gateway's deadline, the
// workspace volume — and nothing else — mounted at the workspace path,
// which is also the working directory, the allowlisted environment names,
// then the image and the argv. --pull=never: the operator fetches the
// image; refexec never does, so a compartment is offline by construction.
func podmanRunArgs(cfg execConfig, session string, envNames, argv []string) []string {
	secs := int(cfg.Timeout / time.Second)
	if secs < 1 {
		secs = 1
	}
	args := []string{"run", "--rm", "--name", session,
		"--pull=never", "--network", "none", "--read-only", "--tmpfs", "/tmp",
		"--cap-drop=ALL", "--security-opt", "no-new-privileges",
		"--userns=keep-id", "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"--memory=" + cfg.Memory, "--cpus=" + cfg.CPUs, "--pids-limit=" + strconv.Itoa(cfg.PIDs),
		"--timeout=" + strconv.Itoa(secs),
		"-v", cfg.WorkspaceVolume + ":" + cfg.WorkspacePath, "-w", cfg.WorkspacePath,
	}
	for _, name := range envNames {
		args = append(args, "-e", name)
	}
	args = append(args, cfg.Image)
	return append(args, argv...)
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

// capWriter keeps the first max bytes written and counts every byte. It is
// the compartment's combined stdout+stderr: exec.Cmd serializes writes to a
// shared non-*os.File writer, so no lock is needed.
type capWriter struct {
	max   int
	buf   bytes.Buffer
	total int64
}

func (c *capWriter) Write(p []byte) (int, error) {
	c.total += int64(len(p))
	if room := c.max - c.buf.Len(); room > 0 {
		keep := p
		if len(keep) > room {
			keep = keep[:room]
		}
		c.buf.Write(keep)
	}
	return len(p), nil
}

// output returns what is handed back: the kept bytes, plus the marker when
// anything was dropped.
func (c *capWriter) output() ([]byte, bool) {
	if c.total > int64(c.max) {
		return append(c.buf.Bytes(), truncationMarker...), true
	}
	return c.buf.Bytes(), false
}

// run executes argv in one compartment and returns its outcome. Cancelling
// ctx (the gateway's deadline, or the gateway hanging up) removes the
// CONTAINER with `podman rm -f`: killing the podman client's process group
// would leave the container running under conmon. The client then exits on
// its own; WaitDelay is the backstop if it does not.
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
	names := r.envNames()
	args := append(append([]string{}, r.podman[1:]...), podmanRunArgs(r.cfg, session, names, argv)...)
	cmd := exec.CommandContext(ctx, r.podman[0], args...)
	cmd.Cancel = func() error {
		r.logger.Info("compartment removed", "session", session)
		r.remove(session)
		return nil
	}
	cmd.WaitDelay = 10 * time.Second
	out := &capWriter{max: maxOutput}
	cmd.Stdout, cmd.Stderr = out, out
	cmd.Env = r.environ() // the podman CLIENT's environment (its storage, PATH, the values -e copies); the command's is only what -e names
	if err := cmd.Start(); err != nil {
		return result{}, fmt.Errorf("refexec: start podman: %w", err)
	}
	r.logger.Info("compartment started", "session", session, "command", argv[0], "pid", cmd.Process.Pid, "env_names", names)
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return result{}, ctx.Err()
	}
	exit := 0
	if waitErr != nil {
		var ee *exec.ExitError
		if !errors.As(waitErr, &ee) {
			return result{}, fmt.Errorf("refexec: podman: %w", waitErr)
		}
		exit = ee.ExitCode()
	}
	output, truncated := out.output()
	r.logger.Info("compartment finished", "session", session, "exit", exit, "output_bytes", out.total, "truncated", truncated)
	return result{
		ExitCode: exit, Output: output, Truncated: truncated, OutputBytes: out.total,
		Attestation: refrunner.Attestation{Runtime: "refexec", Session: session, Command: argv, PID: cmd.Process.Pid, Spawn: 1, EnvNames: names},
	}, nil
}

// remove stops and deletes the compartment. Best effort: a container that
// already exited under --rm is gone, and podman's complaint about that is
// noise. podman's text may name the container; it never carries a value.
func (r *runner) remove(session string) {
	args := append(append([]string{}, r.podman[1:]...), "rm", "-f", session)
	rmCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(rmCtx, r.podman[0], args...)
	cmd.Env = r.environ()
	if err := cmd.Run(); err != nil {
		r.logger.Warn("compartment not removed", "session", session, "error", err)
	}
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
