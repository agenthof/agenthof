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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/agenthof/agenthof/deploy/internal/confiner"
)

// Wire contract — pinned by hand with internal/refspawn (never imported
// across): POST /provision {"child_run_id", "agents": [...]}. A status
// other than 200, sent before anything is flushed, is a refusal. 200 is
// followed by exactly one JSON line {"child_dir", "agent_sockets",
// "exec_socket", "tier", "tier_opts"} once every socket is dialable; the
// body then stays open for as long as the set lives and ends when the set
// is gone. The client closing the body asks for the teardown. tier and
// tier_opts name the confinement the set runs under; tier_opts is omitted
// when there are none.
type provisionRequest struct {
	ChildRunID string   `json:"child_run_id"`
	Agents     []string `json:"agents"`
}

type provisionLine struct {
	ChildDir     string            `json:"child_dir"`
	AgentSockets map[string]string `json:"agent_sockets"`
	ExecSocket   string            `json:"exec_socket"`
	Tier         string            `json:"tier"`
	TierOpts     []string          `json:"tier_opts,omitempty"`
}

const (
	maxRequest    = 1 << 20
	maxName       = 64
	stopGrace     = 30 * time.Second // SIGTERM to refexec, then SIGKILL
	readyInterval = 100 * time.Millisecond
)

// errCapReached, errChildLive and errNameTaken are the three ways admit
// refuses: the set will not fit under max_compartments, that child already
// has one, or one of its compartment names belongs to a live sibling.
var (
	errCapReached = errors.New("compartment cap reached")
	errChildLive  = errors.New("a set for this child is already provisioned")
	errNameTaken  = errors.New("a live child already holds a compartment name this set needs")
)

// supervisor holds nothing between provisions but the slot count, the live
// children and their compartment names, and the set of held requests it
// must wait for at shutdown.
type supervisor struct {
	cfg      spawnConfig
	logger   *slog.Logger
	confiner confiner.Confiner // what confines a compartment; tests substitute a fake
	environ  func() []string   // the environment each child's refexec is started with
	mu       sync.Mutex
	used     int             // agent compartments reserved across every live child
	live     map[string]bool // child run ids with a set: one per child, never two
	names    map[string]bool // compartment names in use: one owner each, never two
	wg       sync.WaitGroup
}

func newSupervisor(cfg spawnConfig, logger *slog.Logger, c confiner.Confiner) *supervisor {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &supervisor{cfg: cfg, logger: logger, confiner: c, environ: os.Environ,
		live: map[string]bool{}, names: map[string]bool{}}
}

func (s *supervisor) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /provision", s.handleProvision)
	return mux
}

// admit claims the child, its compartment names and one slot per name in
// one step, or none of them: a set that will not fit whole is refused
// before anything starts, a child that already has a set never gets a
// second one over the top of it, and no two live children ever share a
// compartment name. Both an id and an agent name may contain "-", so
// <id>-<agent> alone is not unique — "r-1" with agent "a-b" and "r-1-a"
// with agent "b" name the same container — and tearing one set down would
// otherwise rm -f a sibling's live compartment.
func (s *supervisor) admit(id string, names []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.live[id] {
		return errChildLive
	}
	for _, name := range names {
		if s.names[name] {
			return errNameTaken
		}
	}
	if s.used+len(names) > s.cfg.MaxCompartments {
		return errCapReached
	}
	s.live[id] = true
	for _, name := range names {
		s.names[name] = true
	}
	s.used += len(names)
	return nil
}

// release drops the child, its names and its slots. It runs only once the
// set is gone, so a slot is free exactly when its compartment is.
func (s *supervisor) release(id string, names []string) {
	s.mu.Lock()
	delete(s.live, id)
	for _, name := range names {
		delete(s.names, name)
	}
	s.used -= len(names)
	s.mu.Unlock()
}

// close is Serve's onShutdown: every held connection has already been cut,
// so every handler is tearing its set down; wait for them, then reap
// whatever is left by prefix. A failed reap is only warned about: this is
// best-effort cleanup on the way out, and the next start's reap refuses to
// serve if leftovers still cannot be listed.
func (s *supervisor) close() {
	s.wg.Wait()
	if err := s.reap(); err != nil {
		s.logger.Warn("shutdown reap incomplete; the next start reaps what is left", "error", err)
	}
}

// handleProvision serves one child's set for its whole life. A failure after
// the set was started answers 502 and returns, and the deferred teardown and
// slot release run BEFORE that small body leaves the response buffer: the
// refusal reaches the client only once the set is gone and the slots are
// back. Never Flush before the teardown on a failure path.
func (s *supervisor) handleProvision(w http.ResponseWriter, req *http.Request) {
	// Count the handler in BEFORE admit: close() waits on s.wg, so a handler
	// that has claimed slots/names but not yet reached the set-up below must
	// already be visible, or shutdown could reap concurrently with start().
	// Harmless for requests that refuse early — they Done and return.
	s.wg.Add(1)
	defer s.wg.Done()
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
	// <spawn_root>/<id> and <spawn_root>/<id>-exec share one namespace: an
	// id ending in the exec suffix would place this child's socket
	// directory exactly where a live sibling's exec directory is — and
	// start() opens with RemoveAll(childDir). Refusing the suffix is what
	// makes the two directory names one-to-one with the id.
	if strings.HasSuffix(body.ChildRunID, execDirSuffix) {
		http.Error(w, "refspawn: child_run_id must not end in "+execDirSuffix, http.StatusBadRequest)
		return
	}
	if len(body.Agents) == 0 {
		http.Error(w, "refspawn: agents must name at least one agent", http.StatusBadRequest)
		return
	}
	seen := map[string]bool{}
	images := map[string]string{}
	names := make([]string, 0, len(body.Agents))
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
		names = append(names, compartmentName(body.ChildRunID, a))
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "refspawn: streaming unsupported", http.StatusInternalServerError)
		return
	}
	switch err := s.admit(body.ChildRunID, names); {
	case errors.Is(err, errChildLive), errors.Is(err, errNameTaken):
		s.logger.Warn("provision refused", "child", body.ChildRunID, "reason", err.Error())
		http.Error(w, "refspawn: "+err.Error(), http.StatusConflict)
		return
	case err != nil: // errCapReached, and any later refusal fails closed the same way
		s.logger.Warn("provision refused", "child", body.ChildRunID, "reason", err.Error(), "wanted", len(names))
		http.Error(w, "refspawn: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer s.release(body.ChildRunID, names) // after the teardown below (defers run last-in first-out)
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

// childSet is one child's isolated set: its workspace store, its
// directories, its refexec process and its agent compartments.
type childSet struct {
	s        *supervisor
	id       string
	agents   []string
	images   map[string]string
	store    string
	childDir string
	execDir  string
	sockets  map[string]string
	execSock string

	storeMade   bool
	refexec     *exec.Cmd
	refexecExit chan struct{}
	comps       map[string]confiner.Compartment // by agent name, filled as each one launches
	agentExit   chan string
}

func (s *supervisor) newSet(id string, agents []string, images map[string]string) *childSet {
	set := &childSet{s: s, id: id, agents: agents, images: images,
		store:    containerPrefix + id + "-work",
		comps:    map[string]confiner.Compartment{},
		childDir: filepath.Join(s.cfg.SpawnRoot, id),
		execDir:  filepath.Join(s.cfg.SpawnRoot, id+execDirSuffix),
		sockets:  map[string]string{}, refexecExit: make(chan struct{}), agentExit: make(chan string, len(agents))}
	for _, a := range agents {
		set.sockets[a] = filepath.Join(set.childDir, a+".sock")
	}
	set.execSock = filepath.Join(set.execDir, "refexec.sock")
	return set
}

func (set *childSet) line() provisionLine {
	return provisionLine{ChildDir: set.childDir, AgentSockets: set.sockets, ExecSocket: set.execSock,
		Tier: string(set.s.confiner.Tier()), TierOpts: set.s.confiner.Opts()}
}

// start creates the directories and the workspace store, forks the child's
// refexec, and starts one compartment per agent. On any error the caller
// tears down what was started.
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
	if err := set.s.confiner.CreateStore(context.Background(), set.store); err != nil {
		return err
	}
	set.storeMade = true
	cfgPath := filepath.Join(set.execDir, "refexec.yaml")
	if err := os.WriteFile(cfgPath, []byte(renderRefexecConfig(set.s.cfg.Refexec, set.execSock, set.store, set.s.confiner.Tier())), 0o600); err != nil {
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

	// The agent runs with the workspace as its working directory and the
	// child's socket directory (read-write) at its own path; the supervisor's
	// --timeout is the backstop. Its socket path follows the program, so it
	// overrides the image's own -socket (last wins).
	lim := confiner.Limits(set.s.cfg.Limits)
	for _, a := range set.agents {
		name := compartmentName(set.id, a)
		comp, err := set.s.confiner.Launch(context.Background(), confiner.Spec{
			Name: name, Program: set.images[a], Argv: []string{"-socket", set.sockets[a]},
			Store: set.store, Paths: []confiner.Path{{Path: set.childDir, RW: true}},
			Limits: lim, Timeout: set.s.cfg.Timeout, Output: os.Stderr,
		})
		if err != nil {
			return fmt.Errorf("start compartment %s: %w", name, err)
		}
		set.comps[a] = comp
		go func() {
			<-comp.Done()
			set.agentExit <- name
		}()
		set.s.logger.Info("compartment started", "child", set.id, "compartment", name, "pid", comp.PID())
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
// exec compartments that still use the workspace store, and removes them on
// SIGTERM), then the agent compartments, then the store — podman refuses
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
	// Remove returns once the compartment is gone, so every agent is stopped
	// before the store is touched. Its error is noise here: a compartment that
	// already exited is gone, and the backend logs the complaint.
	for _, a := range set.agents {
		if comp, ok := set.comps[a]; ok {
			_ = comp.Remove(context.Background())
		}
	}
	if set.storeMade {
		// Not forced: a store still in use is refused, so this removal
		// succeeding IS the proof that the order above did its work and
		// nothing holds the child's workspace any more. The retries cover the
		// moment between a compartment's removal and the engine releasing the
		// mount; a store still held after them — an exec compartment that
		// outlived a killed refexec — is left for the next start's reap rather
		// than pulled out from under whatever is still writing to it.
		var err error
		for range 5 {
			if err = set.s.confiner.RemoveStore(context.Background(), set.store, false); err == nil {
				break
			}
			time.Sleep(time.Second)
		}
		if err != nil {
			l.Warn("workspace store not removed; the next start reaps it", "store", set.store, "error", err)
		}
	}
	_ = os.RemoveAll(set.childDir)
	_ = os.RemoveAll(set.execDir)
	l.Info("set torn down")
}
