package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"
)

// Wire contract — pinned by hand with internal/refspawn (never imported
// across): POST /provision {"child_run_id", "agents": [...]}. A status
// other than 200, sent before anything is flushed, is a refusal. 200 is
// followed by exactly one JSON line {"child_dir", "agent_sockets",
// "exec_socket"} once every socket is dialable; the body then stays open
// for as long as the set lives and ends when the set is gone. The client
// closing the body asks for the teardown.
type provisionRequest struct {
	ChildRunID string   `json:"child_run_id"`
	Agents     []string `json:"agents"`
}

type provisionLine struct {
	ChildDir     string            `json:"child_dir"`
	AgentSockets map[string]string `json:"agent_sockets"`
	ExecSocket   string            `json:"exec_socket"`
}

const (
	maxRequest    = 1 << 20
	maxName       = 64
	stopGrace     = 30 * time.Second // SIGTERM to refexec, then SIGKILL
	readyInterval = 100 * time.Millisecond
)

// errCapReached and errChildLive are the two ways admit refuses: the set
// will not fit under max_compartments, or that child already has one.
var (
	errCapReached = errors.New("compartment cap reached")
	errChildLive  = errors.New("a set for this child is already provisioned")
)

// supervisor holds nothing between provisions but the slot count, the live
// children and the set of held requests it must wait for at shutdown.
type supervisor struct {
	cfg        spawnConfig
	logger     *slog.Logger
	podmanArgv []string // {"podman"}; tests substitute a fake
	environ    func() []string
	mu         sync.Mutex
	used       int             // agent compartments reserved across every live child
	live       map[string]bool // child run ids with a set: one per child, never two
	wg         sync.WaitGroup
}

func newSupervisor(cfg spawnConfig, logger *slog.Logger, podman []string) *supervisor {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &supervisor{cfg: cfg, logger: logger, podmanArgv: podman, environ: os.Environ, live: map[string]bool{}}
}

func (s *supervisor) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /provision", s.handleProvision)
	return mux
}

// admit claims the child and takes n slots in one step, or neither: a set
// that will not fit whole is refused before anything starts, and a child
// that already has a set never gets a second one over the top of it.
func (s *supervisor) admit(id string, n int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.live[id] {
		return errChildLive
	}
	if s.used+n > s.cfg.MaxCompartments {
		return errCapReached
	}
	s.live[id] = true
	s.used += n
	return nil
}

// release drops the child and hands its slots back. It runs only once the
// set is gone, so a slot is free exactly when its compartment is.
func (s *supervisor) release(id string, n int) {
	s.mu.Lock()
	delete(s.live, id)
	s.used -= n
	s.mu.Unlock()
}

// close is Serve's onShutdown: every held connection has already been cut,
// so every handler is tearing its set down; wait for them, then reap
// whatever is left by prefix.
func (s *supervisor) close() {
	s.wg.Wait()
	s.reap()
}

// handleProvision serves one child's set for its whole life. A failure after
// the set was started answers 502 and returns, and the deferred teardown and
// slot release run BEFORE that small body leaves the response buffer: the
// refusal reaches the client only once the set is gone and the slots are
// back. Never Flush before the teardown on a failure path.
func (s *supervisor) handleProvision(w http.ResponseWriter, req *http.Request) {
	var body provisionRequest
	if err := json.NewDecoder(io.LimitReader(req.Body, maxRequest)).Decode(&body); err != nil {
		http.Error(w, "refspawn: bad request", http.StatusBadRequest)
		return
	}
	// Drain to EOF: only then does the server watch the connection, so the
	// gateway hanging up cancels req.Context() — which is the teardown.
	_, _ = io.Copy(io.Discard, io.LimitReader(req.Body, maxRequest))
	if !nameRE.MatchString(body.ChildRunID) || len(body.ChildRunID) > maxName {
		http.Error(w, "refspawn: child_run_id is not a valid name", http.StatusBadRequest)
		return
	}
	if len(body.Agents) == 0 {
		http.Error(w, "refspawn: agents must name at least one agent", http.StatusBadRequest)
		return
	}
	seen := map[string]bool{}
	images := map[string]string{}
	for _, a := range body.Agents {
		if !nameRE.MatchString(a) || len(a) > maxName || seen[a] {
			http.Error(w, "refspawn: agents must be distinct valid names", http.StatusBadRequest)
			return
		}
		seen[a] = true
		img, ok := s.cfg.Images[a]
		if !ok {
			// Fail closed: the whole set is refused, nothing starts.
			s.logger.Warn("provision refused", "child", body.ChildRunID, "reason", "no image for agent", "agent", a)
			http.Error(w, "refspawn: no image for agent "+a, http.StatusForbidden)
			return
		}
		images[a] = img
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "refspawn: streaming unsupported", http.StatusInternalServerError)
		return
	}
	n := len(body.Agents)
	switch err := s.admit(body.ChildRunID, n); {
	case errors.Is(err, errChildLive):
		s.logger.Warn("provision refused", "child", body.ChildRunID, "reason", "child already provisioned")
		http.Error(w, "refspawn: "+errChildLive.Error(), http.StatusConflict)
		return
	case err != nil:
		s.logger.Warn("provision refused", "child", body.ChildRunID, "reason", "compartment cap reached", "wanted", n)
		http.Error(w, "refspawn: "+errCapReached.Error(), http.StatusServiceUnavailable)
		return
	}
	s.wg.Add(1)
	defer s.wg.Done()
	defer s.release(body.ChildRunID, n) // after the teardown below (defers run last-in first-out)
	set := s.newSet(body.ChildRunID, body.Agents, images)
	defer set.teardown()
	if err := set.start(); err != nil {
		s.logger.Error("provision failed", "child", set.id, "error", err)
		http.Error(w, "refspawn: provision failed", http.StatusBadGateway)
		return
	}
	if err := set.waitReady(req.Context(), s.cfg.ReadyTimeout); err != nil {
		s.logger.Error("provision not ready", "child", set.id, "error", err)
		http.Error(w, "refspawn: compartments not ready", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	line, _ := json.Marshal(set.line())
	_, _ = w.Write(append(line, '\n'))
	flusher.Flush()
	s.logger.Info("set provisioned", "child", set.id, "agents", body.Agents)
	select {
	case <-req.Context().Done():
		s.logger.Info("set released by the gateway", "child", set.id)
	case name := <-set.agentExit:
		s.logger.Warn("agent compartment exited; tearing the set down", "child", set.id, "compartment", name)
	case <-set.refexecExit:
		s.logger.Warn("refexec exited; tearing the set down", "child", set.id)
	}
}

// childSet is one child's isolated set: its volume, its directories, its
// refexec process and its agent compartments.
type childSet struct {
	s        *supervisor
	id       string
	agents   []string
	images   map[string]string
	volume   string
	childDir string
	execDir  string
	sockets  map[string]string
	execSock string

	volumeMade   bool
	refexec      *exec.Cmd
	refexecExit  chan struct{}
	cancelAgents context.CancelFunc
	agentWait    sync.WaitGroup
	agentExit    chan string
}

func (s *supervisor) newSet(id string, agents []string, images map[string]string) *childSet {
	set := &childSet{s: s, id: id, agents: agents, images: images,
		volume:   containerPrefix + id + "-work",
		childDir: filepath.Join(s.cfg.SpawnRoot, id),
		execDir:  filepath.Join(s.cfg.SpawnRoot, id+"-exec"),
		sockets:  map[string]string{}, refexecExit: make(chan struct{}), agentExit: make(chan string, len(agents))}
	for _, a := range agents {
		set.sockets[a] = filepath.Join(set.childDir, a+".sock")
	}
	set.execSock = filepath.Join(set.execDir, "refexec.sock")
	return set
}

func (set *childSet) line() provisionLine {
	return provisionLine{ChildDir: set.childDir, AgentSockets: set.sockets, ExecSocket: set.execSock}
}

// start creates the directories and the volume, forks the child's refexec,
// and starts one compartment per agent. On any error the caller tears
// down what was started.
func (set *childSet) start() error {
	for _, d := range []string{set.childDir, set.execDir} {
		if err := os.RemoveAll(d); err != nil { // a leftover from a crash
			return err
		}
		if err := os.Mkdir(d, 0o700); err != nil {
			return err
		}
		if err := os.Chmod(d, 0o700); err != nil { // the umask does not get a say
			return err
		}
	}
	if _, err := set.s.podman(context.Background(), 30*time.Second, "volume", "create", set.volume); err != nil {
		return err
	}
	set.volumeMade = true
	cfgPath := filepath.Join(set.execDir, "refexec.yaml")
	if err := os.WriteFile(cfgPath, []byte(renderRefexecConfig(set.s.cfg.Refexec, set.execSock, set.volume)), 0o600); err != nil {
		return err
	}
	argv := set.s.cfg.Refexec.Command
	rx := exec.Command(argv[0], append(append([]string{}, argv[1:]...), "-config", cfgPath)...)
	rx.Stderr = os.Stderr
	rx.Env = set.s.environ()
	if err := rx.Start(); err != nil {
		return fmt.Errorf("start refexec: %w", err)
	}
	set.refexec = rx
	go func() { _ = rx.Wait(); close(set.refexecExit) }()
	set.s.logger.Info("refexec started", "child", set.id, "pid", rx.Process.Pid)

	ctx, cancel := context.WithCancel(context.Background())
	set.cancelAgents = cancel
	for _, a := range set.agents {
		name := containerPrefix + set.id + "-" + a
		args := append(append([]string{}, set.s.podmanArgv[1:]...), refboxRunArgs(set.s.cfg, name, set.images[a], set.volume, set.childDir, set.sockets[a])...)
		c := exec.CommandContext(ctx, set.s.podmanArgv[0], args...)
		// Cancelling removes the CONTAINER; killing the podman client would
		// leave it running under conmon.
		c.Cancel = func() error { set.s.remove(name); return nil }
		c.WaitDelay = 10 * time.Second
		c.Env = set.s.environ()
		c.Stdout, c.Stderr = os.Stderr, os.Stderr
		if err := c.Start(); err != nil {
			return fmt.Errorf("start compartment %s: %w", name, err)
		}
		set.agentWait.Add(1)
		go func() {
			defer set.agentWait.Done()
			_ = c.Wait()
			set.agentExit <- name
		}()
		set.s.logger.Info("compartment started", "child", set.id, "compartment", name, "pid", c.Process.Pid)
	}
	return nil
}

// waitReady returns once every agent socket and the exec socket accept a
// connection — a real dial, not a stat — or fails when the caller gives
// up, a compartment or the refexec exits first, or timeout passes.
func (set *childSet) waitReady(ctx context.Context, timeout time.Duration) error {
	paths := make([]string, 0, len(set.sockets)+1)
	for _, p := range set.sockets {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	paths = append(paths, set.execSock)
	deadline := time.Now().Add(timeout)
	for {
		ready := 0
		for _, p := range paths {
			c, err := net.DialTimeout("unix", p, time.Second)
			if err == nil {
				_ = c.Close()
				ready++
			}
		}
		if ready == len(paths) {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("readiness timeout")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case name := <-set.agentExit:
			return fmt.Errorf("compartment %s exited before it was ready", name)
		case <-set.refexecExit:
			return errors.New("refexec exited before it was ready")
		case <-time.After(readyInterval):
		}
	}
}

// teardown removes the set IN ORDER: refexec first (it owns the transient
// exec compartments that still mount the volume, and removes them on
// SIGTERM), then the agent compartments, then the volume — podman refuses
// to remove a volume any container still mounts — then the directories.
func (set *childSet) teardown() {
	l := set.s.logger.With("child", set.id)
	if set.refexec != nil {
		_ = set.refexec.Process.Signal(syscall.SIGTERM)
		select {
		case <-set.refexecExit:
		case <-time.After(stopGrace):
			l.Warn("refexec did not stop on SIGTERM; killing it (an exec compartment it held may outlive it until its own --timeout)")
			_ = set.refexec.Process.Kill()
			<-set.refexecExit
		}
	}
	if set.cancelAgents != nil {
		set.cancelAgents()
		set.agentWait.Wait()
	}
	if set.volumeMade {
		var err error
		for range 5 {
			if _, err = set.s.podman(context.Background(), 30*time.Second, "volume", "rm", "-f", set.volume); err == nil {
				break
			}
			time.Sleep(time.Second)
		}
		if err != nil {
			l.Warn("volume not removed; the next start reaps it", "volume", set.volume, "error", err)
		}
	}
	_ = os.RemoveAll(set.childDir)
	_ = os.RemoveAll(set.execDir)
	l.Info("set torn down")
}
