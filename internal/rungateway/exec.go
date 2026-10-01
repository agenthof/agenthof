package rungateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/engine"
)

// The exec door's ledger reasons are fixed strings, so no path can put a
// runtime's, the OS's or the agent's text into an event.
const (
	reasonExecNotAllowlisted       = "command is not on the exec allowlist"
	reasonExecCommandUnrecordable  = "command exceeds the ledger's argv bounds"
	reasonExecRunNotDeclared       = "first-hand exec is not declared for this agent"
	reasonExecFirstHandOnly        = "exec on this agent is first-hand: authorize and attest are not available"
	reasonExecSocketDir            = "exec runtime socket directory is not a private (0700) directory owned by this user"
	reasonExecUnreachable          = "exec runtime unreachable"
	reasonExecTimedOut             = "exec runtime call timed out"
	reasonExecCancelled            = "exec runtime call was cancelled"
	reasonExecErrorStatus          = "exec runtime returned an error status"
	reasonExecResponseTooLarge     = "exec runtime response too large"
	reasonExecResponseMalformed    = "exec runtime response malformed"
	reasonExecCommandMismatch      = "runtime attestation names a different command"
	reasonExecOutputHash           = "exec runtime output hash does not match the output"
	reasonExecAttestationMissing   = "runtime attestation missing"
	reasonExecAttestationMalformed = "runtime attestation malformed"
)

// maxExecRunResponse bounds what the gateway reads back from refexec. refexec
// caps the output it returns at 1 MiB of raw bytes; JSON string escaping can
// expand a byte to six (`\u0000`), and the attestation and the other members
// ride alongside, so the bound is generous but fixed.
const maxExecRunResponse = 8 << 20

// execRunRoute is refexec's one route. The url in config names the socket
// path only (config.UnixScheme); the host here is a placeholder the dialer
// ignores, as for every other unix:// leg.
const execRunRoute = "http://refexec/run"

// execRunResponse is refexec's answer: the pinned wire contract
// (deploy/refexec). RuntimeAttestation stays untyped for decodeAttestation.
type execRunResponse struct {
	ExitCode           *int   `json:"exit_code"`
	Output             string `json:"output"`
	OutputSHA          string `json:"output_sha"`
	Truncated          bool   `json:"truncated"`
	OutputBytes        int    `json:"output_bytes"`
	RuntimeAttestation any    `json:"runtime_attestation"`
}

// execAuthorizeHandler is the attested door's permission check. On an agent
// whose exec is first-hand it refuses and records: the agent must not be
// able to land an agent-asserted line on a door a runtime serves.
func (p *Gateway) execAuthorizeHandler(bind engine.Binding, agent config.AgentDef, appendEvent func(engine.Event)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Command []string `json:"command"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if agent.Exec.FirstHand() {
			p.refuseAssertedExec(w, bind, agent, appendEvent, req.Command)
			return
		}
		allowed := agent.Exec.Allows(req.Command)
		if !allowed {
			p.guardedAppend(appendEvent, engine.Event{
				Type: "exec", Agent: agent.Name, Status: "refused",
				Reason:  reasonExecNotAllowlisted,
				Command: req.Command,
				Mode:    "attested", Binding: bind,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"allowed": allowed})
	}
}

// execAttestHandler records the agent's own report of a command it ran. On
// a first-hand agent it is refused and recorded, like authorize.
func (p *Gateway) execAttestHandler(bind engine.Binding, agent config.AgentDef, appendEvent func(engine.Event)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Command   []string `json:"command"`
			Exit      *int     `json:"exit"`
			OutputSHA string   `json:"output_sha"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if agent.Exec.FirstHand() {
			p.refuseAssertedExec(w, bind, agent, appendEvent, req.Command)
			return
		}
		if req.Exit == nil {
			http.Error(w, "exit is required", http.StatusBadRequest)
			return
		}
		status := "succeeded"
		if *req.Exit != 0 {
			status = "failed"
		}
		exit := *req.Exit
		p.guardedAppend(appendEvent, engine.Event{
			Type: "exec", Agent: agent.Name, Status: status,
			Command: req.Command, ExitCode: &exit, OutputSHA: req.OutputSHA,
			Mode: "attested", Binding: bind,
		})
		w.WriteHeader(http.StatusNoContent)
	}
}

// refuseAssertedExec records and answers the refusal of /exec/authorize or
// /exec/attest on an agent whose exec door is first-hand. The event's mode
// is the door the agent was refused at — the runtime's — so the line cannot
// be read as an agent's report.
func (p *Gateway) refuseAssertedExec(w http.ResponseWriter, bind engine.Binding, agent config.AgentDef, appendEvent func(engine.Event), argv []string) {
	p.guardedAppend(appendEvent, engine.Event{
		Type: "exec", Agent: agent.Name, Status: "refused",
		Reason: reasonExecFirstHandOnly, Command: argv, Mode: "runtime", Binding: bind,
	})
	http.Error(w, reasonExecFirstHandOnly, http.StatusForbidden)
}

// execRunHandler is the first-hand door. The agent asks Agenthof to have the
// declared runtime run argv; Agenthof authorizes argv against the allowlist
// (config is law: refexec is never asked to run what the operator did not
// allow), checks the runtime's socket directory is private to this user
// (the gate the runtime itself insists on at listen), calls refexec over
// its socket under the agent's exec timeout, verifies the runtime's
// attestation names exactly the argv that was authorized and that the
// output hash covers the output returned, and records one exec event with
// mode "runtime". Every way the call can fail after the allowlist check
// records a failed event and answers 502: a door that ran nothing still
// leaves a line. The whole call runs under the proxy's closing/inflight
// bookkeeping — the same hold forward uses — so Stop waits for it and for
// its append, and no append can race the run's log.Close; guardedAppend is
// not used here because it drops an event once closing is set, and a call
// Stop is waiting on must still be recorded.
func (p *Gateway) execRunHandler(bind engine.Binding, agent config.AgentDef, appendEvent func(engine.Event), logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Command []string `json:"command"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		// Drain to EOF: only then does the server watch the connection, so a
		// closed one — Stop cutting it, or the agent gone — cancels r.Context()
		// and with it the call to the runtime.
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
		p.mu.Lock()
		if p.closing {
			p.mu.Unlock()
			http.Error(w, "gateway is shutting down", http.StatusServiceUnavailable)
			return
		}
		p.inflight.Add(1)
		p.mu.Unlock()
		defer p.inflight.Done()

		argv := req.Command
		refuse := func(reason string) {
			logger.Warn("exec run refused", "reason", reason)
			appendEvent(engine.Event{Type: "exec", Agent: agent.Name, Status: "refused", Reason: reason, Command: argv, Mode: "runtime", Binding: bind})
			http.Error(w, reason, http.StatusForbidden)
		}
		fail := func(reason string) {
			logger.Error("exec run failed", "reason", reason)
			appendEvent(engine.Event{Type: "exec", Agent: agent.Name, Status: "failed", Reason: reason, Command: argv, Mode: "runtime", Binding: bind})
			http.Error(w, reason, http.StatusBadGateway)
		}

		if !agent.Exec.FirstHand() {
			refuse(reasonExecRunNotDeclared)
			return
		}
		if !agent.Exec.Allows(argv) {
			refuse(reasonExecNotAllowlisted)
			return
		}
		// A command the ledger cannot carry must be refused BEFORE it runs:
		// otherwise the attestation validation below would reject the
		// (truthful) attestation of a command that already ran, recording a
		// false first-hand failure of a completed action and blaming the
		// runtime for a gateway bound. Same bounds validAttestation enforces.
		if !argvRecordable(argv) {
			refuse(reasonExecCommandUnrecordable)
			return
		}
		sockPath := strings.TrimPrefix(agent.Exec.URL, config.UnixScheme)
		if err := CheckPrivateDir(filepath.Dir(sockPath)); err != nil {
			logger.Error("exec runtime socket dir rejected", "class", errClass(err))
			fail(reasonExecSocketDir)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), agent.Exec.Timeout)
		defer cancel()
		body, err := json.Marshal(map[string]any{"command": argv})
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		out, err := http.NewRequestWithContext(ctx, http.MethodPost, execRunRoute, bytes.NewReader(body))
		if err != nil {
			fail(reasonExecUnreachable)
			return
		}
		out.Header.Set("Content-Type", "application/json")
		client := &http.Client{Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sockPath)
			},
			DisableKeepAlives: true, // one call, one connection: nothing to pool, nothing to drain
		}}
		logger.Debug("exec run routed", "command", argv[0])
		resp, err := client.Do(out)
		if err != nil {
			fail(ctxReason(ctx, reasonExecUnreachable))
			logger.Error("exec runtime call failed", "class", errClass(err))
			return
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			fail(reasonExecErrorStatus)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, maxExecRunResponse+1))
		if err != nil {
			fail(ctxReason(ctx, reasonExecUnreachable))
			return
		}
		if len(raw) > maxExecRunResponse {
			fail(reasonExecResponseTooLarge)
			return
		}
		var res execRunResponse
		if err := json.Unmarshal(raw, &res); err != nil || res.ExitCode == nil {
			fail(reasonExecResponseMalformed)
			return
		}
		att, err := decodeAttestation(res.RuntimeAttestation, agent.Exec.Runtime)
		if err != nil {
			switch {
			case errors.Is(err, errAttestationMissing):
				fail(reasonExecAttestationMissing)
			default:
				fail(reasonExecAttestationMalformed)
			}
			return
		}
		if !slices.Equal(att.Command, argv) {
			fail(reasonExecCommandMismatch)
			return
		}
		if sum := sha256.Sum256([]byte(res.Output)); hex.EncodeToString(sum[:]) != res.OutputSHA {
			fail(reasonExecOutputHash)
			return
		}

		status := "succeeded"
		if *res.ExitCode != 0 {
			status = "failed"
		}
		exit := *res.ExitCode
		appendEvent(engine.Event{
			Type: "exec", Agent: agent.Name, Status: status,
			Command: argv, ExitCode: &exit, OutputSHA: res.OutputSHA,
			Mode: "runtime", RuntimeAttestation: att, Binding: bind,
		})
		logger.Info("exec run recorded", "command", argv[0], "exit", exit, "session", att.Session)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"exit": exit, "output": res.Output, "truncated": res.Truncated})
	}
}

// ctxReason picks the reason for a failed runtime call: the deadline, a
// cancel (the agent hung up, or Stop cut the connection), or fallback.
func ctxReason(ctx context.Context, fallback string) string {
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return reasonExecTimedOut
	case ctx.Err() != nil:
		return reasonExecCancelled
	}
	return fallback
}

// CheckPrivateDir is the gateway's side of the socket-directory gate the
// runtime applies at listen (deploy/internal/refrunner.Listen): a directory,
// mode 0700, owned by the user Agenthof runs as. Failing it means whatever
// answers on that socket is not a runtime only this user could have started.
func CheckPrivateDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return errors.New("not a directory")
	}
	if fi.Mode().Perm() != 0o700 {
		return errors.New("mode is not 0700")
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return errors.New("not owned by this user")
	}
	return nil
}
