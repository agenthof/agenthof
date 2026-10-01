// Package refspawn is the spawn door's client of the compartment
// supervisor, refspawn (deploy/refspawn): the operator-side runtime that
// provisions a spawned child's isolated set — one workspace volume, one
// refbox compartment per agent, one refexec — and tears it down. Core never
// runs podman; it asks over a Unix socket and holds the answer open. The
// wire contract is pinned by hand on both sides; nothing is imported across
// the internal/deploy boundary.
//
// Contract: POST /provision {"child_run_id", "agents": [...]}. A status
// other than 200 (sent before anything is flushed) is a refusal. 200 is
// followed by exactly one JSON line {"child_dir", "agent_sockets",
// "exec_socket"} once every socket is dialable; the body then stays open
// for as long as the set lives — its EOF means the set is gone, and the
// client closing it asks for the teardown.
package refspawn

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/obs"
	"github.com/agenthof/agenthof/internal/rungateway"
)

// ErrUnavailable is every way a provision can fail, as one error: the
// Spawner maps it to the fixed refusal "spawn compartment unavailable" and
// never starts the child. Details go to the operational log by class.
var ErrUnavailable = errors.New("spawn compartment unavailable")

// provisionRoute is the one route; the host is a placeholder the dialer
// ignores, as for every other unix:// leg.
const provisionRoute = "http://refspawn/provision"

// connectTimeout bounds the dial of the supervisor's socket. The provision
// itself runs under the caller's context — the parent step's — so a slow
// start lands inside step_timeout, never beyond it.
const connectTimeout = 5 * time.Second

// maxFirstLine caps the one line the supervisor answers with.
const maxFirstLine = 64 << 10

// Provisioner is what the Spawner needs from a supervisor. The Client is
// the real one; a test substitutes its own.
type Provisioner interface {
	Provision(ctx context.Context, childRunID string, agents []string) (*Lease, error)
}

type provisionRequest struct {
	ChildRunID string   `json:"child_run_id"`
	Agents     []string `json:"agents"`
}

type provisionLine struct {
	ChildDir     string            `json:"child_dir"`
	AgentSockets map[string]string `json:"agent_sockets"`
	ExecSocket   string            `json:"exec_socket"`
}

// Lease is one provisioned set, alive for as long as the held body is
// open. ChildDir is the child's socket directory (its agents' sockets and
// its own gateway sockets live there; it is mounted into the child's
// compartments); AgentSockets maps every requested agent to its socket;
// ExecSocket is the child's own refexec, in a directory that is NOT under
// ChildDir — the Spawner checks that before use.
type Lease struct {
	ChildDir     string
	AgentSockets map[string]string
	ExecSocket   string

	body io.Closer
	done chan struct{}
	once sync.Once
}

// NewLease wraps a held body: it drains body until it ends and then closes
// Done. The Client uses it on the response body; a test uses it on a pipe.
func NewLease(childDir string, agentSockets map[string]string, execSocket string, body io.ReadCloser) *Lease {
	l := &Lease{ChildDir: childDir, AgentSockets: agentSockets, ExecSocket: execSocket, body: body, done: make(chan struct{})}
	go func() {
		_, _ = io.Copy(io.Discard, body) // the supervisor writes nothing more; EOF or an error is "the set is gone"
		close(l.done)
	}()
	return l
}

// Done is closed when the supervisor ends the set — a compartment or the
// refexec exited, or the supervisor shut down. A child still running then
// has nothing to run on; the Spawner cancels it.
func (l *Lease) Done() <-chan struct{} { return l.done }

// Release closes the held body, which is the teardown request: the
// supervisor sees the hang-up and removes the set in order. Idempotent.
func (l *Lease) Release() { l.once.Do(func() { _ = l.body.Close() }) }

// Client provisions through one supervisor socket.
type Client struct {
	sock   string
	logger *slog.Logger
}

// New builds a Client for endpoint, which must be unix://<absolute path>
// (registry validation guarantees the shape; New fails closed anyway).
func New(endpoint string, logger *slog.Logger) (*Client, error) {
	path, ok := strings.CutPrefix(endpoint, config.UnixScheme)
	if !ok || !filepath.IsAbs(path) {
		return nil, fmt.Errorf("refspawn: endpoint must be %s<absolute socket path>", config.UnixScheme)
	}
	return &Client{sock: path, logger: obs.OrDiscard(logger)}, nil
}

// Provision asks the supervisor for childRunID's set — one compartment per
// name in agents — and returns once every socket in the answer is up. Any
// failure is ErrUnavailable: the socket's directory not private, the
// supervisor unreachable, a refusal, the caller's context ending, or an
// answer that is not the pinned shape. On success the returned Lease holds
// the body open; the caller MUST Release it when the child is over.
func (c *Client) Provision(ctx context.Context, childRunID string, agents []string) (*Lease, error) {
	logger := c.logger.With("child_run", childRunID)
	if err := rungateway.CheckPrivateDir(filepath.Dir(c.sock)); err != nil {
		// Not the error text: a stat failure names the path.
		logger.Error("refspawn socket dir rejected", "reason", "not a private (0700) directory owned by this user")
		return nil, fmt.Errorf("%w: supervisor socket directory is not private", ErrUnavailable)
	}
	body, err := json.Marshal(provisionRequest{ChildRunID: childRunID, Agents: agents})
	if err != nil {
		return nil, fmt.Errorf("%w: encode request", ErrUnavailable)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, provisionRoute, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: build request", ErrUnavailable)
	}
	req.Header.Set("Content-Type", "application/json")
	// One call, one connection, held for the child's whole life: nothing to
	// pool. No Client.Timeout — the body must stay open indefinitely; the
	// connect is bounded by the dialer and the provision by ctx.
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: connectTimeout}).DialContext(ctx, "unix", c.sock)
		},
		DisableKeepAlives: true,
	}}
	resp, err := client.Do(req) // returns at the supervisor's first flush
	if err != nil {
		logger.Error("refspawn provision failed", "class", errClass(ctx, err))
		return nil, fmt.Errorf("%w: supervisor unreachable", ErrUnavailable)
	}
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		// The supervisor's text names an agent or a cap, never a value; it
		// is logged so the operator can see why, and goes nowhere else.
		logger.Warn("refspawn provision refused", "status", resp.StatusCode, "detail", strings.TrimSpace(string(msg)))
		return nil, fmt.Errorf("%w: supervisor refused", ErrUnavailable)
	}
	rd := bufio.NewReaderSize(resp.Body, maxFirstLine)
	line, err := rd.ReadSlice('\n')
	if err != nil { // io.EOF, bufio.ErrBufferFull, or the connection dropped
		_ = resp.Body.Close()
		logger.Error("refspawn answer unreadable", "class", errClass(ctx, err))
		return nil, fmt.Errorf("%w: supervisor answer unreadable", ErrUnavailable)
	}
	var pl provisionLine
	if err := json.Unmarshal(line, &pl); err != nil || !validLine(pl, agents) {
		_ = resp.Body.Close()
		logger.Error("refspawn answer malformed")
		return nil, fmt.Errorf("%w: supervisor answer malformed", ErrUnavailable)
	}
	logger.Info("refspawn set provisioned", "agents", len(pl.AgentSockets))
	// The body is wrapped in the buffered reader (it may hold bytes past the
	// line); the lease drains that reader and closes the underlying body.
	return NewLease(pl.ChildDir, pl.AgentSockets, pl.ExecSocket, readCloser{Reader: rd, Closer: resp.Body}), nil
}

// readCloser pairs the buffered reader with the body's Close.
type readCloser struct {
	io.Reader
	io.Closer
}

// validLine is the shape check on the supervisor's one line: absolute
// paths throughout, and a socket for every agent that was asked for.
func validLine(pl provisionLine, agents []string) bool {
	if !filepath.IsAbs(pl.ChildDir) || !filepath.IsAbs(pl.ExecSocket) {
		return false
	}
	for _, a := range agents {
		sock, ok := pl.AgentSockets[a]
		if !ok || !filepath.IsAbs(sock) {
			return false
		}
	}
	return true
}

// errClass names a failure without its text (a transport error can carry a
// path): the caller's deadline, a cancel, or "transport".
func errClass(ctx context.Context, err error) string {
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case ctx.Err() != nil:
		return "cancelled"
	}
	return "transport"
}
