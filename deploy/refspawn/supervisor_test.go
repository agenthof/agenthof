package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// testConfig is a supervisor whose "images" are host programs (the fake
// podman runs them directly) and whose refexec is the fake. images maps
// agent name -> program; the test binary itself means the fake agent.
func testConfig(t *testing.T, images map[string]string) spawnConfig {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "sp") // short: socket path limit
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return spawnConfig{
		Socket: filepath.Join(root, "sup", "refspawn.sock"), SpawnRoot: filepath.Join(root, "children"),
		Images: images, Timeout: 10 * time.Minute, ReadyTimeout: 10 * time.Second,
		Limits: limits{Memory: "256m", CPUs: "1", PIDs: 64}, MaxCompartments: 4,
		Refexec: refexecConfig{Command: []string{exe, fakeRefexecFlag}, Image: "example.test/exec:1", Timeout: 2 * time.Minute,
			Limits: limits{Memory: "256m", CPUs: "1", PIDs: 64}, MaxCompartments: 2, EnvAllow: []string{}},
	}
}

func selfImages(t *testing.T, agents ...string) map[string]string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	for _, a := range agents {
		m[a] = exe
	}
	return m
}

// fakeSupervisor is a supervisor over the fake podman, served by httptest,
// with the fake's log and volume root in temp dirs.
func fakeSupervisor(t *testing.T, cfg spawnConfig) (*supervisor, *httptest.Server, string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	volroot := filepath.Join(filepath.Dir(cfg.SpawnRoot), "volumes")
	if err := os.MkdirAll(volroot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cfg.SpawnRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(filepath.Dir(cfg.SpawnRoot), "podman.jsonl")
	t.Setenv("REFSPAWN_TEST_ARGLOG", log)
	t.Setenv("REFSPAWN_TEST_VOLROOT", volroot)
	s := newSupervisor(cfg, slog.New(slog.DiscardHandler), []string{exe, fakePodmanFlag})
	srv := httptest.NewServer(s.handler())
	t.Cleanup(srv.Close)
	t.Cleanup(s.close)
	return s, srv, log
}

func records(t *testing.T, log string) []fakeRecord {
	t.Helper()
	f, err := os.Open(log)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	var out []fakeRecord
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var r fakeRecord
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			continue
		}
		out = append(out, r)
	}
	return out
}

func ops(recs []fakeRecord) []string {
	var out []string
	for _, r := range recs {
		out = append(out, r.Op+" "+r.Name)
	}
	return out
}

// held is one provision kept open: the response (its Body is the lease)
// and the first line decoded.
type held struct {
	s    *supervisor
	id   string
	resp *http.Response
	rd   *bufio.Reader
	line provisionLine
}

// provision POSTs the pinned request and reads the one line; a non-200 is
// returned with a nil line and the body closed.
func provision(t *testing.T, s *supervisor, srv *httptest.Server, id string, agents []string) (int, *held) {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"child_run_id": id, "agents": agents})
	resp, err := srv.Client().Post(srv.URL+"/provision", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST /provision: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return resp.StatusCode, nil
	}
	rd := bufio.NewReader(resp.Body)
	raw, err := rd.ReadBytes('\n')
	if err != nil {
		t.Fatalf("first line: %v", err)
	}
	var line provisionLine
	if err := json.Unmarshal(raw, &line); err != nil {
		t.Fatalf("first line %q: %v", raw, err)
	}
	return resp.StatusCode, &held{s: s, id: id, resp: resp, rd: rd, line: line}
}

// release closes the body: the hang-up that asks for the teardown.
func (h *held) release(t *testing.T) {
	t.Helper()
	_ = h.resp.Body.Close()
}

// waitEnd waits for the set to be gone. The held body ends on its own when
// the supervisor tears the set down; a client that closed it first cannot
// see that, so the supervisor's own record of the child — dropped last,
// after the teardown and after the slots are back — is what is waited on.
func (h *held) waitEnd(t *testing.T) {
	t.Helper()
	done := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, h.rd); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the held body did not end: the set was not torn down")
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		h.s.mu.Lock()
		live := h.s.live[h.id]
		h.s.mu.Unlock()
		if !live {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the supervisor still holds the child: the set was not torn down")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func dialable(path string) bool {
	c, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func TestProvisionStartsSetAndAnswersOnceReady(t *testing.T) {
	cfg := testConfig(t, selfImages(t, "a", "b"))
	s, srv, log := fakeSupervisor(t, cfg)
	code, h := provision(t, s, srv, "r-0a0b0c0d", []string{"a", "b"})
	if code != http.StatusOK {
		t.Fatalf("code = %d", code)
	}
	defer h.release(t)
	childDir := filepath.Join(cfg.SpawnRoot, "r-0a0b0c0d")
	execDir := filepath.Join(cfg.SpawnRoot, "r-0a0b0c0d-exec")
	if h.line.ChildDir != childDir || h.line.ExecSocket != filepath.Join(execDir, "refexec.sock") ||
		h.line.AgentSockets["a"] != filepath.Join(childDir, "a.sock") || h.line.AgentSockets["b"] != filepath.Join(childDir, "b.sock") {
		t.Fatalf("line = %+v", h.line)
	}
	for _, p := range []string{h.line.AgentSockets["a"], h.line.AgentSockets["b"], h.line.ExecSocket} {
		if !dialable(p) {
			t.Fatalf("%s is not dialable after Provision answered: readiness is a real connect, not a stat", p)
		}
	}
	for _, d := range []string{childDir, execDir} {
		fi, err := os.Stat(d)
		if err != nil || fi.Mode().Perm() != 0o700 {
			t.Fatalf("%s: %v mode %v, want a 0700 directory", d, err, fi.Mode())
		}
	}
	recs := records(t, log)
	var runs []fakeRecord
	for _, r := range recs {
		if r.Op == "run" {
			runs = append(runs, r)
		}
	}
	if len(runs) != 2 || !strings.Contains(strings.Join(ops(recs), "\n"), "volume-create agenthof-spawn-r-0a0b0c0d-work") || !strings.Contains(strings.Join(ops(recs), "\n"), "refexec-start "+h.line.ExecSocket) {
		t.Fatalf("ops = %v, want one volume, two compartments and a refexec", ops(recs))
	}
	for _, r := range runs {
		joined := " " + strings.Join(r.Args, " ") + " "
		for _, want := range []string{
			" run --rm --name agenthof-spawn-r-0a0b0c0d-", " --pull=never ", " --network none ", " --read-only ",
			" -v agenthof-spawn-r-0a0b0c0d-work:/work ", " --cap-drop=ALL ", " --security-opt no-new-privileges ", " --userns=keep-id ",
			" --user " + strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid()) + " ",
			" --memory=256m ", " --cpus=1 ", " --pids-limit=64 ", " --timeout=600 ",
			" -v " + childDir + ":" + childDir + " ", " -socket " + childDir + "/",
		} {
			if !strings.Contains(joined, want) {
				t.Fatalf("compartment args lack %q:\n%s", want, joined)
			}
		}
		if strings.Contains(joined, execDir) {
			t.Fatalf("the exec dir must never be mounted into a compartment:\n%s", joined)
		}
		if strings.Count(joined, " -v ") != 2 {
			t.Fatalf("exactly two mounts (the volume and the child dir):\n%s", joined)
		}
	}
	// The rendered refexec config is refexec's full key set, bound to this
	// child's volume and the sibling exec dir.
	data, err := os.ReadFile(filepath.Join(execDir, "refexec.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var rendered struct {
		Socket    string `yaml:"socket"`
		Image     string `yaml:"image"`
		Workspace struct {
			Volume string `yaml:"volume"`
			Path   string `yaml:"path"`
		} `yaml:"workspace"`
		Timeout string `yaml:"timeout"`
		Limits  struct {
			Memory string `yaml:"memory"`
			CPUs   string `yaml:"cpus"`
			PIDs   int    `yaml:"pids"`
		} `yaml:"limits"`
		Compartments struct {
			Max int `yaml:"max"`
		} `yaml:"compartments"`
		EnvAllow []string `yaml:"env_allow"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&rendered); err != nil {
		t.Fatalf("rendered refexec config does not decode under refexec's strict shape: %v\n%s", err, data)
	}
	if rendered.Socket != h.line.ExecSocket || rendered.Image != "example.test/exec:1" || rendered.Workspace.Volume != "agenthof-spawn-r-0a0b0c0d-work" ||
		rendered.Workspace.Path != "/work" || rendered.Timeout != "2m0s" || rendered.Limits.CPUs != "1" || rendered.Limits.PIDs != 64 ||
		rendered.Compartments.Max != 2 || rendered.EnvAllow == nil {
		t.Fatalf("rendered = %+v", rendered)
	}
	s.mu.Lock()
	used := s.used
	s.mu.Unlock()
	if used != 2 {
		t.Fatalf("used = %d, want the two agent compartments reserved", used)
	}
}

func TestProvisionTearsDownInOrder(t *testing.T) {
	cfg := testConfig(t, selfImages(t, "a", "b"))
	s, srv, log := fakeSupervisor(t, cfg)
	_, h := provision(t, s, srv, "r-11111111", []string{"a", "b"})
	before := len(records(t, log))
	h.release(t)
	h.waitEnd(t)
	after := records(t, log)[before:]
	seq := ops(after)
	idx := func(prefix string) int {
		for i, o := range seq {
			if strings.HasPrefix(o, prefix) {
				return i
			}
		}
		return -1
	}
	term, rm, vol := idx("refexec-term"), idx("rm "), idx("volume-rm")
	lastRm := -1
	for i, o := range seq {
		if strings.HasPrefix(o, "rm ") {
			lastRm = i
		}
	}
	if term < 0 || rm < 0 || vol < 0 || term >= rm || lastRm >= vol {
		t.Fatalf("teardown order must be refexec SIGTERM -> rm -f the agent compartments -> volume rm, got %v", seq)
	}
	removed := 0
	for _, o := range seq {
		if strings.HasPrefix(o, "rm agenthof-spawn-r-11111111-") { // "volume-rm …" has a different prefix
			removed++
		}
	}
	if removed != 2 {
		t.Fatalf("want both compartments removed, got %v", seq)
	}
	for _, d := range []string{filepath.Join(cfg.SpawnRoot, "r-11111111"), filepath.Join(cfg.SpawnRoot, "r-11111111-exec")} {
		if _, err := os.Stat(d); !os.IsNotExist(err) {
			t.Fatalf("%s still exists after teardown", d)
		}
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("REFSPAWN_TEST_VOLROOT"), "agenthof-spawn-r-11111111-work")); !os.IsNotExist(err) {
		t.Fatal("the volume still exists after teardown")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used != 0 {
		t.Fatalf("used = %d after teardown, want 0", s.used)
	}
}

func TestProvisionRefusesWhenSlotsWontFit(t *testing.T) {
	cfg := testConfig(t, selfImages(t, "a", "b"))
	cfg.MaxCompartments = 3
	s, srv, log := fakeSupervisor(t, cfg)
	_, first := provision(t, s, srv, "r-aaaaaaaa", []string{"a", "b"})
	defer first.release(t)
	runsBefore := len(records(t, log))
	if code, h := provision(t, s, srv, "r-bbbbbbbb", []string{"a", "b"}); code != http.StatusServiceUnavailable || h != nil {
		t.Fatalf("a second pair under max_compartments 3: code=%d, want 503 and nothing started", code)
	}
	if len(records(t, log)) != runsBefore {
		t.Fatalf("a refused set must start nothing: %v", ops(records(t, log)))
	}
	// One agent still fits beside the pair.
	code, one := provision(t, s, srv, "r-cccccccc", []string{"a"})
	if code != http.StatusOK {
		t.Fatalf("a single compartment must fit in the remaining slot: %d", code)
	}
	one.release(t)
	one.waitEnd(t)
	first.release(t)
	first.waitEnd(t)
	// Everything released: the pair fits again.
	code, again := provision(t, s, srv, "r-dddddddd", []string{"a", "b"})
	if code != http.StatusOK {
		t.Fatalf("after release the pair must fit again: %d", code)
	}
	again.release(t)
}

func TestProvisionRefusesAgentWithoutImage(t *testing.T) {
	cfg := testConfig(t, selfImages(t, "a"))
	s, srv, log := fakeSupervisor(t, cfg)
	if code, _ := provision(t, s, srv, "r-aaaaaaaa", []string{"a", "ghost"}); code != http.StatusForbidden {
		t.Fatalf("an agent with no image: code=%d, want 403", code)
	}
	if recs := records(t, log); len(recs) != 0 {
		t.Fatalf("nothing may start when any agent has no image: %v", ops(recs))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used != 0 {
		t.Fatalf("used = %d, want 0: a refused set reserves nothing", s.used)
	}
}

func TestProvisionRejectsBadNames(t *testing.T) {
	cfg := testConfig(t, selfImages(t, "a"))
	s, srv, log := fakeSupervisor(t, cfg)
	for _, c := range []struct {
		id     string
		agents []string
	}{
		{"../escape", []string{"a"}},
		{"r-ok", []string{"a;b"}},
		{"r-ok", []string{"a", "a"}},
		{"r-ok", nil},
		{"", []string{"a"}},
	} {
		if code, _ := provision(t, s, srv, c.id, c.agents); code != http.StatusBadRequest {
			t.Errorf("id=%q agents=%v: code=%d, want 400", c.id, c.agents, code)
		}
	}
	if recs := records(t, log); len(recs) != 0 {
		t.Fatalf("a bad request must start nothing: %v", ops(recs))
	}
}

// A child gets one set. A second provision for the same id is refused
// whole: starting it would reuse the volume and the container names and
// delete the live child's socket directory out from under it.
func TestProvisionRefusesASecondSetForTheSameChild(t *testing.T) {
	cfg := testConfig(t, selfImages(t, "a"))
	s, srv, log := fakeSupervisor(t, cfg)
	_, h := provision(t, s, srv, "r-aaaaaaaa", []string{"a"})
	defer h.release(t)
	before := len(records(t, log))
	if code, dup := provision(t, s, srv, "r-aaaaaaaa", []string{"a"}); code != http.StatusConflict || dup != nil {
		t.Fatalf("a second set for the same child: code=%d, want 409", code)
	}
	if len(records(t, log)) != before {
		t.Fatalf("a refused duplicate must start nothing: %v", ops(records(t, log)))
	}
	if !dialable(h.line.AgentSockets["a"]) {
		t.Fatal("the live set must be untouched by the refusal")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used != 1 {
		t.Fatalf("used = %d, want only the live child's one slot", s.used)
	}
}

// A run id ending in "-exec" would name its socket directory exactly where
// a live sibling's exec directory is, and start() opens with a RemoveAll
// of that directory. The suffix is refused outright.
func TestProvisionRejectsAnExecSuffixRunID(t *testing.T) {
	cfg := testConfig(t, selfImages(t, "a"))
	s, srv, log := fakeSupervisor(t, cfg)
	_, sibling := provision(t, s, srv, "r-aaaaaaaa", []string{"a"})
	defer sibling.release(t)
	before := len(records(t, log))
	if code, h := provision(t, s, srv, "r-aaaaaaaa-exec", []string{"a"}); code != http.StatusBadRequest || h != nil {
		t.Fatalf("a run id ending in -exec: code=%d, want 400", code)
	}
	if len(records(t, log)) != before {
		t.Fatalf("a refused run id must start nothing: %v", ops(records(t, log)))
	}
	if !dialable(sibling.line.ExecSocket) {
		t.Fatal("the sibling's exec socket is gone: its directory was removed by the refused provision")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used != 1 || s.live["r-aaaaaaaa-exec"] {
		t.Fatalf("used = %d, live = %v: a refused run id reserves nothing", s.used, s.live)
	}
}

// <id>-<agent> is not unique on its own: "r-1" with agent "a-b" and "r-1-a"
// with agent "b" name the same container, and tearing one set down would
// rm -f the other's live compartment. The second set is refused whole.
func TestProvisionRefusesACompartmentNameALiveChildHolds(t *testing.T) {
	cfg := testConfig(t, selfImages(t, "a-b", "b"))
	s, srv, log := fakeSupervisor(t, cfg)
	_, first := provision(t, s, srv, "r-1", []string{"a-b"})
	defer first.release(t)
	before := len(records(t, log))
	if code, h := provision(t, s, srv, "r-1-a", []string{"b"}); code != http.StatusConflict || h != nil {
		t.Fatalf("a set whose compartment name is already live: code=%d, want 409", code)
	}
	if len(records(t, log)) != before {
		t.Fatalf("a refused name must start nothing: %v", ops(records(t, log)))
	}
	if !dialable(first.line.AgentSockets["a-b"]) {
		t.Fatal("the live set must be untouched by the refusal")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used != 1 {
		t.Fatalf("used = %d, want only the live child's one slot", s.used)
	}
}

func TestProvisionFailsClosedWhenACompartmentExits(t *testing.T) {
	cfg := testConfig(t, map[string]string{"a": "false"}) // the "image" exits 1 at once
	s, srv, log := fakeSupervisor(t, cfg)
	if code, _ := provision(t, s, srv, "r-aaaaaaaa", []string{"a"}); code != http.StatusBadGateway {
		t.Fatalf("code=%d, want 502", code)
	}
	seq := strings.Join(ops(records(t, log)), "\n")
	if !strings.Contains(seq, "volume-create") || !strings.Contains(seq, "run ") || !strings.Contains(seq, "volume-rm") || !strings.Contains(seq, "refexec-term") {
		t.Fatalf("a failed start still tears down what it started: %v", strings.Split(seq, "\n"))
	}
	if _, err := os.Stat(filepath.Join(cfg.SpawnRoot, "r-aaaaaaaa")); !os.IsNotExist(err) {
		t.Fatal("the child dir must be gone after a failed start")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used != 0 {
		t.Fatalf("used = %d, want 0", s.used)
	}
}

func TestAgentDeathEndsTheLease(t *testing.T) {
	cfg := testConfig(t, selfImages(t, "a"))
	s, srv, log := fakeSupervisor(t, cfg)
	_, h := provision(t, s, srv, "r-aaaaaaaa", []string{"a"})
	var child int
	for _, r := range records(t, log) {
		if r.Op == "run" {
			child = r.Child
		}
	}
	if child == 0 {
		t.Fatal("no compartment pid recorded")
	}
	if err := syscall.Kill(child, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	h.waitEnd(t) // the body ends: the set is gone
	if !strings.Contains(strings.Join(ops(records(t, log)), "\n"), "volume-rm agenthof-spawn-r-aaaaaaaa-work") {
		t.Fatalf("a dead compartment must tear the whole set down: %v", ops(records(t, log)))
	}
}

func TestConcurrentChildrenGetDistinctSets(t *testing.T) {
	cfg := testConfig(t, selfImages(t, "a"))
	s, srv, _ := fakeSupervisor(t, cfg)
	_, one := provision(t, s, srv, "r-11111111", []string{"a"})
	defer one.release(t)
	_, two := provision(t, s, srv, "r-22222222", []string{"a"})
	defer two.release(t)
	if one.line.ChildDir == two.line.ChildDir || one.line.ExecSocket == two.line.ExecSocket || one.line.AgentSockets["a"] == two.line.AgentSockets["a"] {
		t.Fatalf("siblings share a path: %+v vs %+v", one.line, two.line)
	}
	volroot := os.Getenv("REFSPAWN_TEST_VOLROOT")
	v1, v2 := filepath.Join(volroot, "agenthof-spawn-r-11111111-work"), filepath.Join(volroot, "agenthof-spawn-r-22222222-work")
	if err := os.WriteFile(filepath.Join(v1, "note.txt"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(v2, "note.txt")); !os.IsNotExist(err) {
		t.Fatal("a write in one child's volume is visible in its sibling's")
	}
}

func TestReapRemovesLeftoversByPrefix(t *testing.T) {
	cfg := testConfig(t, selfImages(t, "a"))
	s, _, log := fakeSupervisor(t, cfg)
	volroot := os.Getenv("REFSPAWN_TEST_VOLROOT")
	for _, d := range []string{filepath.Join(volroot, "agenthof-spawn-stale-work"), filepath.Join(volroot, "other-work"), filepath.Join(cfg.SpawnRoot, "stale"), filepath.Join(volroot, ".pids")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	sleeper := exec.Command("sleep", "60")
	if err := sleeper.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sleeper.Process.Kill() }()
	if err := os.WriteFile(filepath.Join(volroot, ".pids", "agenthof-spawn-stale-a.pid"), []byte(strconv.Itoa(sleeper.Process.Pid)), 0o600); err != nil {
		t.Fatal(err)
	}
	s.reap()
	seq := strings.Join(ops(records(t, log)), "\n")
	if !strings.Contains(seq, "rm agenthof-spawn-stale-a") || !strings.Contains(seq, "volume-rm agenthof-spawn-stale-work") {
		t.Fatalf("reap must remove containers and volumes with the prefix: %v", strings.Split(seq, "\n"))
	}
	if strings.Contains(seq, "other-work") {
		t.Fatal("reap must leave volumes without the prefix alone")
	}
	// The sleeper is this test's child: killed, it is a zombie until waited
	// for, so wait (bounded) rather than probe it with kill 0.
	waited := make(chan error, 1)
	go func() { waited <- sleeper.Wait() }()
	select {
	case err := <-waited:
		if err == nil {
			t.Fatal("the stale compartment exited normally; reap must have killed it")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("reap did not kill the stale compartment")
	}
	if _, err := os.Stat(filepath.Join(cfg.SpawnRoot, "stale")); !os.IsNotExist(err) {
		t.Fatal("reap must clear spawn_root")
	}
}

func TestRefboxRunArgsShape(t *testing.T) {
	cfg := testConfig(t, nil)
	cfg.Timeout = 1500 * time.Millisecond
	args := refboxRunArgs(cfg, "agenthof-spawn-r-x-a", "img:1", "agenthof-spawn-r-x-work", "/tmp/sp/r-x", "/tmp/sp/r-x/a.sock")
	joined := strings.Join(args, " ")
	if !strings.HasSuffix(joined, " -v /tmp/sp/r-x:/tmp/sp/r-x img:1 -socket /tmp/sp/r-x/a.sock") || !strings.Contains(joined, " --timeout=1 ") || !strings.HasPrefix(joined, "run --rm --name agenthof-spawn-r-x-a --pull=never ") {
		t.Fatalf("args = %q", joined)
	}
}

// TestPodmanRealSet drives real rootless podman: skipped unless the
// operator names a built agent image and a refexec binary. The podman e2e
// (scripts/e2e-refspawn.sh) is the full proof; this is the unit-level smoke.
func TestPodmanRealSet(t *testing.T) {
	image, refexecBin := os.Getenv("REFSPAWN_PODMAN_IMAGE"), os.Getenv("REFSPAWN_PODMAN_REFEXEC")
	if image == "" || refexecBin == "" {
		t.Skip("set REFSPAWN_PODMAN_IMAGE (a built refbox image) and REFSPAWN_PODMAN_REFEXEC (a refexec binary) to run against podman")
	}
	cfg := testConfig(t, map[string]string{"a": image})
	cfg.Refexec.Command = []string{refexecBin}
	cfg.Refexec.Image = "docker.io/library/busybox:1.36.1"
	if err := os.MkdirAll(cfg.SpawnRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	s := newSupervisor(cfg, slog.New(slog.NewTextHandler(os.Stderr, nil)), []string{"podman"})
	srv := httptest.NewServer(s.handler())
	t.Cleanup(srv.Close)
	t.Cleanup(s.close)
	_, h := provision(t, s, srv, "r-podman01", []string{"a"})
	out, _ := exec.Command("podman", "ps", "--format", "{{.Names}}", "--filter", "name=^agenthof-spawn-r-podman01-").Output()
	if !strings.Contains(string(out), "agenthof-spawn-r-podman01-a") {
		t.Fatalf("compartment not running: %q", out)
	}
	h.release(t)
	h.waitEnd(t)
	out, _ = exec.Command("podman", "ps", "-aq", "--filter", "name=^agenthof-spawn-r-podman01-").Output()
	vols, _ := exec.Command("podman", "volume", "ls", "-q", "--filter", "name=^agenthof-spawn-r-podman01-").Output()
	if strings.TrimSpace(string(out)) != "" || strings.TrimSpace(string(vols)) != "" {
		t.Fatalf("orphans after teardown: containers %q volumes %q", out, vols)
	}
}
