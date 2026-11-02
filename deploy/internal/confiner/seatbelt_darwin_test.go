//go:build darwin

package confiner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The re-exec modes the Seatbelt tests run this test binary in, registered
// with TestMain's dispatch table. The shipped binaries have no such modes.
const (
	// escapeeFlag is the teardown escapee: it daemonizes a grandchild (via
	// escapeeMidFlag, which exits at once, and escapeeLeafFlag, which calls
	// setsid and sleeps) and then sleeps itself so the session is live when
	// Remove runs.
	escapeeFlag     = "-confiner-test-escapee"
	escapeeMidFlag  = "-confiner-test-escapee-mid"
	escapeeLeafFlag = "-confiner-test-escapee-leaf"
	// setsidChildFlag starts the same leaf but stays its parent, so the leaf
	// has left the session yet is still reachable through the descendant walk.
	setsidChildFlag = "-confiner-test-setsid-child"
)

func init() {
	testModes[escapeeFlag] = escapeeMain
	testModes[escapeeMidFlag] = escapeeMidMain
	testModes[escapeeLeafFlag] = escapeeLeafMain
	testModes[setsidChildFlag] = setsidChildMain
}

func selfExe() string {
	exe, err := os.Executable()
	if err != nil {
		panic(err)
	}
	return exe
}

// escapeeMain: run the intermediate to completion (it leaves a daemonized
// leaf behind, reparented to launchd), then keep the session alive.
func escapeeMain(args []string) int {
	mid := exec.Command(selfExe(), escapeeMidFlag, args[0])
	if err := mid.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "escapee mid:", err)
		return 1
	}
	time.Sleep(60 * time.Second)
	return 0
}

// escapeeMidMain starts the leaf and exits without waiting, so the leaf's
// parent is gone (ppid 1) before any teardown runs.
func escapeeMidMain(args []string) int {
	leaf := exec.Command(selfExe(), escapeeLeafFlag, args[0], "orphan")
	if err := leaf.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "escapee leaf:", err)
		return 1
	}
	return 0
}

// escapeeLeafMain leaves the compartment's session with setsid, records its
// pid in the marker file and sleeps. With a second argument "orphan" it
// records the pid only once its parent has exited and launchd has adopted
// it, so the marker means "setsid done AND reparented", not merely started.
func escapeeLeafMain(args []string) int {
	if _, err := syscall.Setsid(); err != nil {
		fmt.Fprintln(os.Stderr, "setsid:", err)
		return 1
	}
	if len(args) > 1 && args[1] == "orphan" {
		deadline := time.Now().Add(10 * time.Second)
		for os.Getppid() != 1 {
			if time.Now().After(deadline) {
				fmt.Fprintln(os.Stderr, "the leaf was not reparented to launchd")
				return 1
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	if err := os.WriteFile(args[0], []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "marker:", err)
		return 1
	}
	time.Sleep(60 * time.Second)
	return 0
}

// setsidChildMain starts the leaf and waits for it: the leaf is in its own
// session but its parent is still alive and in the compartment's session.
func setsidChildMain(args []string) int {
	leaf := exec.Command(selfExe(), escapeeLeafFlag, args[0])
	if err := leaf.Run(); err != nil {
		return 1
	}
	return 0
}

// newTestSeatbelt builds a backend over fresh StoreRoot/PIDDir/Home dirs under
// t.TempDir(). It skips when sandbox-exec is absent. mutate may adjust the
// config before construction.
func newTestSeatbelt(t *testing.T, mutate func(*SeatbeltConfig)) *Seatbelt {
	t.Helper()
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skip("sandbox-exec is not installed")
	}
	root := t.TempDir()
	cfg := SeatbeltConfig{
		StoreRoot: filepath.Join(root, "store"),
		PIDDir:    filepath.Join(root, "pid"),
		Home:      filepath.Join(root, "home"),
		Logger:    slog.New(slog.DiscardHandler),
	}
	for _, d := range []string{cfg.StoreRoot, cfg.PIDDir, cfg.Home} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if mutate != nil {
		mutate(&cfg)
	}
	s, err := NewSeatbelt(cfg)
	if err != nil {
		t.Fatalf("NewSeatbelt: %v", err)
	}
	return s
}

func mustCreateStore(t *testing.T, s *Seatbelt, name string) {
	t.Helper()
	if err := s.CreateStore(context.Background(), name); err != nil {
		t.Fatalf("CreateStore %s: %v", name, err)
	}
}

// run launches spec and waits for it under a 30s bound.
func run(t *testing.T, s *Seatbelt, spec Spec) Result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := s.Launch(ctx, spec)
	if err != nil {
		t.Fatalf("Launch %v: %v", spec.Argv, err)
	}
	res, err := c.Wait(ctx)
	if err != nil {
		t.Fatalf("Wait %v: %v (output %q)", spec.Argv, err, res.Output)
	}
	return res
}

// alive: the kernel knows the pid and it is not a zombie. kill(pid, 0) still
// succeeds for a zombie, and a test-owned child stays one until the test
// reaps it, so liveness here means "the kernel knows the pid and it is not a
// zombie".
func alive(pid int) bool {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	return err == nil && kp.Proc.P_stat != szomb
}

// assertAlive gives a wrongly-sent SIGKILL time to land, then requires pid to
// be running.
func assertAlive(t *testing.T, pid int, what string) {
	t.Helper()
	time.Sleep(200 * time.Millisecond)
	if !alive(pid) {
		t.Fatal(what)
	}
}

// waitGone polls until pid no longer exists, for up to limit.
func waitGone(t *testing.T, pid int, limit time.Duration) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for alive(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("pid %d is still alive after %v", pid, limit)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// waitFile polls until path exists and is non-empty, returning its content.
func waitFile(t *testing.T, path string, limit time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(limit)
	for {
		if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
			return strings.TrimSpace(string(b))
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not appear within %v", path, limit)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func devNull(t *testing.T) *os.File {
	t.Helper()
	f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// startSleeper starts an unrelated, unsandboxed `sleep 60` the test owns, as
// its own session leader: a wrongly-signalled kill(-pid) would then reach it,
// exactly as it would reach an operator's terminal or editor that leads its
// own group.
func startSleeper(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("/bin/sleep", "60")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd.Process.Pid
}

// startSibling stands in for ANOTHER running instance (a second refexec on
// the same store root and pid dir): a live process the test owns, as the
// owner stamp a backend would carry, plus a way to end it — killed AND
// reaped, so what remains is no process at all, not a zombie.
func startSibling(t *testing.T) (owner ownerRef, end func()) {
	t.Helper()
	cmd := exec.Command("/bin/sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	end = func() {
		once.Do(func() {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		})
	}
	t.Cleanup(end)
	start, err := ownerStart(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	return ownerRef{pid: cmd.Process.Pid, start: start}, end
}

// siblingSeatbelt is a second backend over the SAME store root and pid dir as
// s, stamping its compartments as owner: what a second instance sharing the
// operator's directories looks like to the first.
func siblingSeatbelt(t *testing.T, s *Seatbelt, owner ownerRef) *Seatbelt {
	t.Helper()
	sib := newTestSeatbelt(t, func(c *SeatbeltConfig) { c.StoreRoot, c.PIDDir = s.cfg.StoreRoot, s.cfg.PIDDir })
	sib.owner = owner
	return sib
}

// mustExist fails when any of paths is missing.
func mustExist(t *testing.T, what string, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s: %s: %v", what, p, err)
		}
	}
}

// mustBeGone fails when any of paths still exists.
func mustBeGone(t *testing.T, what string, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: %s: %v", what, p, err)
		}
	}
}

func TestSeatbeltResolvesSymlinkedRoots(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skip("sandbox-exec is not installed")
	}
	// /tmp is a symlink to /private/tmp on macOS; the kernel matches an SBPL
	// rule against the real path, so the backend must hold the real one.
	root, err := os.MkdirTemp("/tmp", "confiner-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	store, pid, home := filepath.Join(root, "s"), filepath.Join(root, "p"), filepath.Join(root, "h")
	for _, d := range []string{store, pid, home, filepath.Join(home, ".ssh")} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	s, err := NewSeatbelt(SeatbeltConfig{StoreRoot: store, PIDDir: pid, Home: home, SpawnRoot: filepath.Join(root, "sp"), DenyRead: []string{filepath.Join(root, "ledger")}})
	if err != nil {
		t.Fatalf("NewSeatbelt: %v", err)
	}
	for name, got := range map[string]string{"StoreRoot": s.cfg.StoreRoot, "PIDDir": s.cfg.PIDDir, "StorePath": s.StorePath("w"), "scratchDir": s.scratchDir("x"), "pidFile": s.pidFile("x")} {
		if !strings.HasPrefix(got, "/private/tmp/") {
			t.Errorf("%s = %q, want the resolved /private/tmp/ path", name, got)
		}
	}
	// Every deny entry is resolved individually: the existing ~/.ssh, the
	// roots, and the entries that do not exist yet (spawn root, operator
	// deny) keep their name under the resolved parent.
	real := strings.Replace(root, "/tmp/", "/private/tmp/", 1)
	want := []string{
		real + "/h/.ssh", real + "/h/.aws", real + "/h/.gnupg", real + "/h/.config/gh", real + "/h/Library/Keychains",
		real + "/s", real + "/p", real + "/sp", real + "/ledger",
	}
	if !slices.Equal(s.denyRead, want) {
		t.Fatalf("denyRead = %q\nwant %q", s.denyRead, want)
	}
}

// An unsafe or relative path is an ERROR from the constructor or from Launch,
// never a panic from the profile generator.
func TestSeatbeltRejectsAnUnsafePath(t *testing.T) {
	root := t.TempDir()
	base := SeatbeltConfig{StoreRoot: filepath.Join(root, "s"), PIDDir: filepath.Join(root, "p"), Home: filepath.Join(root, "h")}
	for _, d := range []string{base.StoreRoot, base.PIDDir, base.Home} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	injected := `/x")) (allow network* (subpath "/`
	cases := map[string]func(c *SeatbeltConfig){
		"deny_read injected":  func(c *SeatbeltConfig) { c.DenyRead = []string{injected} },
		"deny_read relative":  func(c *SeatbeltConfig) { c.DenyRead = []string{"rel/path"} },
		"spawn_root injected": func(c *SeatbeltConfig) { c.SpawnRoot = injected },
		"spawn_root relative": func(c *SeatbeltConfig) { c.SpawnRoot = "rel" },
		"store_root relative": func(c *SeatbeltConfig) { c.StoreRoot = "rel" },
		"pid_dir relative":    func(c *SeatbeltConfig) { c.PIDDir = "rel" },
		"store_root empty":    func(c *SeatbeltConfig) { c.StoreRoot = "" },
		"pid_dir empty":       func(c *SeatbeltConfig) { c.PIDDir = "" },
		"home injected":       func(c *SeatbeltConfig) { c.Home = injected },
		"store_root newline":  func(c *SeatbeltConfig) { c.StoreRoot = "/a\nb" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := base
			mutate(&cfg)
			var s *Seatbelt
			var err error
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("NewSeatbelt panicked: %v", r)
					}
				}()
				s, err = NewSeatbelt(cfg)
			}()
			if err == nil {
				t.Fatalf("NewSeatbelt accepted %+v (%v)", cfg, s)
			}
		})
	}

	s := newTestSeatbelt(t, nil)
	mustCreateStore(t, s, "w")
	for name, spec := range map[string]Spec{
		"path injected":   {Name: "n", Store: "w", Argv: []string{"true"}, Paths: []Path{{Path: injected, RW: true}}},
		"path relative":   {Name: "n", Store: "w", Argv: []string{"true"}, Paths: []Path{{Path: "rel"}}},
		"name traverses":  {Name: "../n", Store: "w", Argv: []string{"true"}},
		"store traverses": {Name: "n", Store: "../w", Argv: []string{"true"}},
		"no program":      {Name: "n", Store: "w"},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Launch panicked: %v", r)
				}
			}()
			c, err := s.Launch(context.Background(), spec)
			if err == nil {
				_ = c.Remove(context.Background())
				t.Fatalf("Launch accepted %+v", spec)
			}
			if entries, _ := os.ReadDir(s.cfg.PIDDir); len(entries) != 0 {
				t.Fatalf("a refused Launch left %v in the PID dir", entries)
			}
		})
	}
}

func TestSeatbeltProbePasses(t *testing.T) {
	s := newTestSeatbelt(t, nil)
	if err := s.Probe(context.Background()); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	for _, dir := range []string{s.cfg.StoreRoot, s.cfg.PIDDir} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".probe-") {
				t.Errorf("probe leftover %s in %s", e.Name(), dir)
			}
		}
	}
}

// Enforcement is never inferred from a permission error. When the
// unsandboxed control write cannot succeed, Probe fails and says so.
// Probe sweeps the probe dirs a refexec that died mid-Probe left under both
// roots — its own, those of an instance that is gone, and those from before
// the stamp — and leaves another RUNNING instance's probe in flight alone.
func TestSeatbeltProbeSweepsStaleProbeDirs(t *testing.T) {
	s := newTestSeatbelt(t, nil)
	sibling, _ := startSibling(t)
	var keep, gone []string
	for _, root := range []string{s.cfg.PIDDir, s.cfg.StoreRoot} {
		keep = append(keep, filepath.Join(root, probePrefix+sibling.String()+"-aaaaaaaaaaaa"))
		gone = append(gone,
			filepath.Join(root, probePrefix+s.owner.String()+"-bbbbbbbbbbbb"),
			filepath.Join(root, probePrefix+"2000000000-1-cccccccccccc"),
			filepath.Join(root, probePrefix+"dddddddddddd"))
	}
	for _, d := range append(append([]string{}, keep...), gone...) {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Probe(context.Background()); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	mustExist(t, "Probe removed a running instance's probe dir", keep...)
	mustBeGone(t, "Probe left a stale probe dir", gone...)
	for _, root := range []string{s.cfg.PIDDir, s.cfg.StoreRoot} {
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 {
			t.Fatalf("%s after Probe: %v, want only the sibling's probe dir", root, entries)
		}
	}
}

func TestSeatbeltProbeFailsWhenTheControlWriteFails(t *testing.T) {
	s := newTestSeatbelt(t, nil)
	if err := os.Chmod(s.cfg.PIDDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(s.cfg.PIDDir, 0o700) })
	err := s.Probe(context.Background())
	if err == nil || !strings.Contains(err.Error(), "control") {
		t.Fatalf("Probe = %v, want a control-write error", err)
	}
}

func TestSeatbeltLaunchRunsAndPassesExitThrough(t *testing.T) {
	s := newTestSeatbelt(t, nil)
	mustCreateStore(t, s, "w")
	res := run(t, s, Spec{Name: "refexec-01", Store: "w", Argv: []string{"sh", "-c", "printf hi; exit 3"}, Scratch: true})
	if res.Exit != 3 || string(res.Output) != "hi" || !slices.Equal(res.EnvNames, []string{"TMPDIR"}) {
		t.Fatalf("Result = %+v", res)
	}
	if _, err := os.Stat(s.pidFile("refexec-01")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("PID file after exit: %v", err)
	}
	if _, err := os.Stat(s.scratchDir("refexec-01")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("scratch dir after exit: %v", err)
	}

	// Without Scratch nothing is applied and no TMPDIR reaches the program.
	res = run(t, s, Spec{Name: "refexec-02", Store: "w", Argv: []string{"sh", "-c", `echo "${TMPDIR:-unset}"`}})
	if string(res.Output) != "unset\n" || len(res.EnvNames) != 0 || res.EnvNames == nil {
		t.Fatalf("no-scratch Result = %+v", res)
	}

	// The attested PID is the sandboxed program itself, not a wrapper.
	ctx := context.Background()
	c, err := s.Launch(ctx, Spec{Name: "refexec-03", Store: "w", Argv: []string{"sh", "-c", "echo $$"}})
	if err != nil {
		t.Fatal(err)
	}
	res, err = c.Wait(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(res.Output)); got != strconv.Itoa(c.PID()) {
		t.Fatalf("sh printed $$=%s, PID()=%d", got, c.PID())
	}
}

// The store and the scratch dir sit under the read-denied store root;
// the compartment's own allows re-open them, and that must hold for READS of
// files that already exist as well as for files the program writes.
func TestSeatbeltReadsBackFilesUnderTheStoreAndScratch(t *testing.T) {
	s := newTestSeatbelt(t, nil)
	mustCreateStore(t, s, "w")
	if err := os.WriteFile(filepath.Join(s.StorePath("w"), "pre"), []byte("pre\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res := run(t, s, Spec{Name: "refexec-01", Store: "w", Scratch: true, Argv: []string{"sh", "-c",
		`cat pre && echo x > in && cat in && echo s > "$TMPDIR/t" && cat "$TMPDIR/t" && ls "$TMPDIR"`}})
	if res.Exit != 0 || string(res.Output) != "pre\nx\ns\nt\n" {
		t.Fatalf("Result = %+v (output %q)", res, res.Output)
	}
	// A sibling store stays unreadable, and the PID dir too.
	mustCreateStore(t, s, "w2")
	if err := os.WriteFile(filepath.Join(s.StorePath("w2"), "key"), []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	res = run(t, s, Spec{Name: "refexec-02", Store: "w", Argv: []string{"sh", "-c", `cat "$1"; echo rc=$?; ls "$2"; echo rc=$?`, "sh", filepath.Join(s.StorePath("w2"), "key"), s.cfg.PIDDir}})
	if strings.Contains(string(res.Output), "k\n") || !strings.Contains(string(res.Output), "rc=1\n") || strings.Contains(string(res.Output), "refexec-02.pid") {
		t.Fatalf("sibling read: %q", res.Output)
	}
}

func TestSeatbeltCwdIsTheStore(t *testing.T) {
	s := newTestSeatbelt(t, nil)
	mustCreateStore(t, s, "w")
	res := run(t, s, Spec{Name: "refexec-01", Store: "w", Argv: []string{"pwd"}})
	if res.Exit != 0 || string(res.Output) != s.StorePath("w")+"\n" {
		t.Fatalf("pwd = %q (exit %d), want %q", res.Output, res.Exit, s.StorePath("w"))
	}
}

func writeStub(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "sandbox-exec-stub")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSeatbeltDidNotLaunch65And71(t *testing.T) {
	ctx := context.Background()

	// 71 pre-empted: a Program that is a regular file without the exec bit
	// never reaches sandbox-exec and leaves no PID file.
	s := newTestSeatbelt(t, nil)
	mustCreateStore(t, s, "w")
	noexec := filepath.Join(t.TempDir(), "notaprogram")
	if err := os.WriteFile(noexec, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := s.Launch(ctx, Spec{Name: "refexec-01", Store: "w", Program: noexec})
	if !errors.Is(err, ErrDidNotLaunch) || !strings.Contains(err.Error(), "not found or not executable") {
		t.Fatalf("non-executable Program: %v", err)
	}
	if _, err := s.Launch(ctx, Spec{Name: "refexec-01", Store: "w", Argv: []string{"no-such-program-agenthof"}}); !errors.Is(err, ErrDidNotLaunch) {
		t.Fatalf("missing program: %v", err)
	}
	if entries, _ := os.ReadDir(s.cfg.PIDDir); len(entries) != 0 {
		t.Fatalf("PID dir after a pre-empted launch: %v", entries)
	}

	// 65 pre-empted: a sandbox-exec that rejects every profile fails the
	// per-profile dry-run before anything is started, and fails Probe naming
	// the profile compile.
	s65 := newTestSeatbelt(t, func(c *SeatbeltConfig) { c.SandboxExec = writeStub(t, "exit 65") })
	mustCreateStore(t, s65, "w")
	if _, err := s65.Launch(ctx, Spec{Name: "refexec-01", Store: "w", Argv: []string{"sh", "-c", "exit 3"}}); !errors.Is(err, ErrDidNotLaunch) {
		t.Fatalf("always-65 dry-run: %v", err)
	}
	if entries, _ := os.ReadDir(s65.cfg.PIDDir); len(entries) != 0 {
		t.Fatalf("PID dir after a failed dry-run: %v", entries)
	}
	if err := s65.Probe(ctx); err == nil || !strings.Contains(err.Error(), "rejects the generated profile") {
		t.Fatalf("Probe with an always-65 sandbox-exec: %v", err)
	}

	// Genuine codes: a stub that passes the dry-run (its last word is
	// /usr/bin/true) but exits N for the real launch maps to ErrDidNotLaunch
	// carrying N; the real sandbox-exec passes a program's own exit through.
	for _, code := range []int{65, 71} {
		sN := newTestSeatbelt(t, func(c *SeatbeltConfig) {
			c.SandboxExec = writeStub(t, fmt.Sprintf(`[ "${@: -1}" = /usr/bin/true ] && exit 0; exit %d`, code))
		})
		mustCreateStore(t, sN, "w")
		c, err := sN.Launch(ctx, Spec{Name: "refexec-01", Store: "w", Argv: []string{"sh", "-c", "exit 3"}})
		if err != nil {
			t.Fatalf("stub %d Launch: %v", code, err)
		}
		res, err := c.Wait(ctx)
		if !errors.Is(err, ErrDidNotLaunch) || res.Exit != code {
			t.Fatalf("stub %d: Wait = (%+v, %v), want (Exit %d, ErrDidNotLaunch)", code, res, err, code)
		}
	}
	res := run(t, s, Spec{Name: "refexec-02", Store: "w", Argv: []string{"sh", "-c", "exit 3"}})
	if res.Exit != 3 {
		t.Fatalf("own exit: %+v", res)
	}
}

// A Launch under a Name a LIVE compartment already holds is refused by the
// claim, before anything starts, and must not touch that compartment's PID
// record: the record is what keeps the live one visible to RemoveStore and
// Reap. A Launch under a FREE name that then fails to start leaves nothing
// behind: its claim goes with it.
func TestSeatbeltStartFailureKeepsALiveCompartmentsRecord(t *testing.T) {
	s := newTestSeatbelt(t, nil)
	mustCreateStore(t, s, "w")
	ctx := context.Background()
	live, err := s.Launch(ctx, Spec{Name: "refexec-01", Store: "w", Argv: []string{"sleep", "60"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = live.Remove(ctx) })
	_, err = s.Launch(ctx, Spec{Name: "refexec-01", Store: "w", Argv: []string{"sleep", "60"}})
	if err == nil || !errors.Is(err, os.ErrExist) {
		t.Fatalf("Launch under a live compartment's name: %v, want the record to refuse it", err)
	}
	rec, err := readPIDRecord(s.pidFile("refexec-01"))
	if err != nil || rec.PID != live.PID() {
		t.Fatalf("the live compartment's record after a refused launch: %+v, %v (want pid %d)", rec, err, live.PID())
	}
	if err := s.RemoveStore(ctx, "w", false); !errors.Is(err, ErrStoreInUse) {
		t.Fatalf("RemoveStore after a refused launch = %v, want ErrStoreInUse", err)
	}

	// The profile text is already accepted (same Scratch/Paths), so a Launch
	// under a free name skips the dry-run and reaches cmd.Start, which fails:
	// the sandbox-exec path no longer exists.
	real := s.cfg.SandboxExec
	s.cfg.SandboxExec = filepath.Join(t.TempDir(), "missing-sandbox-exec")
	_, err = s.Launch(ctx, Spec{Name: "refexec-02", Store: "w", Scratch: true, Argv: []string{"sleep", "60"}})
	s.cfg.SandboxExec = real
	if err == nil {
		t.Fatal("Launch with a missing sandbox-exec succeeded")
	}
	mustBeGone(t, "after a failed start", s.pidFile("refexec-02"), s.scratchDir("refexec-02"))
	assertAlive(t, live.PID(), "a failed start under another name ended the live compartment")
	mustExist(t, "after a failed start", s.pidFile("refexec-01"))
}

// The verdict on the probe's outside write: only a real denial (a non-zero
// exit that is not sandbox-exec's own, and no file) counts as enforcement.
func TestSeatbeltProbeDenialVerdict(t *testing.T) {
	target := filepath.Join(t.TempDir(), "out")
	for code, wantErr := range map[int]string{0: "did not deny", 65: "did not run", 71: "did not run", -1: "did not run", 1: ""} {
		err := denialVerdict(code, []byte("Operation not permitted"), target)
		switch {
		case wantErr == "" && err != nil:
			t.Errorf("exit %d: %v, want a denial", code, err)
		case wantErr != "" && (err == nil || !strings.Contains(err.Error(), wantErr)):
			t.Errorf("exit %d: %v, want an error containing %q", code, err, wantErr)
		}
	}
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := denialVerdict(1, nil, target); err == nil || !strings.Contains(err.Error(), "exists") {
		t.Fatalf("a denial with the file present = %v", err)
	}
}

// Launch never creates the store: the caller provisions it.
func TestSeatbeltLaunchRequiresAnExistingStore(t *testing.T) {
	s := newTestSeatbelt(t, nil)
	_, err := s.Launch(context.Background(), Spec{Name: "refexec-01", Store: "missing", Argv: []string{"true"}})
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("Launch on a missing store: %v", err)
	}
	if _, err := os.Stat(s.StorePath("missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Launch created the store: %v", err)
	}
	if entries, _ := os.ReadDir(s.cfg.PIDDir); len(entries) != 0 {
		t.Fatalf("PID dir: %v", entries)
	}
}

func TestSeatbeltTimeoutKillsSessionAndOrdinaryChildren(t *testing.T) {
	s := newTestSeatbelt(t, nil)
	mustCreateStore(t, s, "w")
	ctx := context.Background()
	start := time.Now()
	c, err := s.Launch(ctx, Spec{Name: "refexec-01", Store: "w", Timeout: time.Second, Argv: []string{"sh", "-c", "sleep 60 & echo $!; wait"}})
	if err != nil {
		t.Fatal(err)
	}
	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	res, err := c.Wait(wctx)
	if err != nil {
		t.Fatalf("Wait after Timeout: %v (elapsed %v)", err, time.Since(start))
	}
	sleepPid, err := strconv.Atoi(strings.TrimSpace(string(res.Output)))
	if err != nil {
		t.Fatalf("sh printed %q", res.Output)
	}
	waitGone(t, sleepPid, 3*time.Second)
	waitGone(t, c.PID(), 3*time.Second)
	if _, err := os.Stat(s.pidFile("refexec-01")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("PID file after Timeout: %v", err)
	}
}

// A background child that keeps the captured output pipe open after the
// program exits must not hold Wait indefinitely: the program's own exit comes
// back once the pipe grace period has passed.
func TestSeatbeltWaitReturnsWhenADescendantKeepsTheOutputOpen(t *testing.T) {
	s := newTestSeatbelt(t, nil)
	mustCreateStore(t, s, "w")
	ctx := context.Background()
	c, err := s.Launch(ctx, Spec{Name: "refexec-01", Store: "w", Argv: []string{"sh", "-c", "sleep 30 & echo $!; exit 0"}})
	if err != nil {
		t.Fatal(err)
	}
	wctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	res, err := c.Wait(wctx)
	if err != nil || res.Exit != 0 {
		t.Fatalf("Wait = (%+v, %v)", res, err)
	}
	sleepPid, err := strconv.Atoi(strings.TrimSpace(string(res.Output)))
	if err != nil {
		t.Fatalf("sh printed %q", res.Output)
	}
	_ = syscall.Kill(sleepPid, syscall.SIGKILL)
}

// A child that called setsid but whose parent is still in the session is
// reached by the descendant walk, which runs before the group is signalled.
func TestSeatbeltTeardownReachesASetsidChildOfALiveParent(t *testing.T) {
	s := newTestSeatbelt(t, nil)
	mustCreateStore(t, s, "w")
	marker := filepath.Join(s.StorePath("w"), "leaf.pid")
	ctx := context.Background()
	c, err := s.Launch(ctx, Spec{Name: "refexec-01", Store: "w", Argv: []string{selfExe(), setsidChildFlag, marker}, Output: devNull(t)})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := strconv.Atoi(waitFile(t, marker, 10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Kill(leaf, syscall.SIGKILL) })
	if !alive(leaf) {
		t.Fatal("the leaf is not running")
	}
	if err := c.Remove(ctx); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	waitGone(t, leaf, 3*time.Second)
	waitGone(t, c.PID(), 3*time.Second)
}

// The stated teardown limit, MEASURED: a descendant that leaves the
// session with setsid and whose parent has already exited is reparented to
// launchd; neither the session-group kill nor the parent-walk reaches it, and
// SBPL has no operation that governs setsid. It outlives Remove, still under
// the inherited profile. Process teardown on this tier is best-effort. Remove
// this assertion only when a mechanism closes the gap.
func TestSeatbeltSetsidEscapeeSurvives(t *testing.T) {
	s := newTestSeatbelt(t, nil)
	mustCreateStore(t, s, "w")
	marker := filepath.Join(s.StorePath("w"), "escapee.pid")
	ctx := context.Background()
	c, err := s.Launch(ctx, Spec{Name: "refexec-01", Store: "w", Argv: []string{selfExe(), escapeeFlag, marker}, Output: devNull(t)})
	if err != nil {
		t.Fatal(err)
	}
	escapee, err := strconv.Atoi(waitFile(t, marker, 10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Kill(escapee, syscall.SIGKILL) })
	if !alive(escapee) {
		t.Fatal("the escapee is not running")
	}
	if err := c.Remove(ctx); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	waitGone(t, c.PID(), 3*time.Second)
	select {
	case <-c.Done():
	default:
		t.Fatal("Done is not closed after Remove")
	}
	assertAlive(t, escapee, "the setsid escapee did not survive Remove: a mechanism now closes the gap, so update the stated limit before changing this test")
}

func TestSeatbeltRemoveStoreInUseThenForce(t *testing.T) {
	s := newTestSeatbelt(t, nil)
	mustCreateStore(t, s, "w")
	ctx := context.Background()
	if err := s.CreateStore(ctx, "w"); err == nil {
		t.Fatal("CreateStore accepted an existing store")
	}
	if err := s.CreateStore(ctx, ".scratch"); err == nil {
		t.Fatal("CreateStore accepted an illegal name")
	}
	c, err := s.Launch(ctx, Spec{Name: "refexec-01", Store: "w", Argv: []string{"sleep", "60"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveStore(ctx, "w", false); !errors.Is(err, ErrStoreInUse) {
		t.Fatalf("RemoveStore of a busy store = %v, want ErrStoreInUse", err)
	}
	if _, err := os.Stat(s.StorePath("w")); err != nil {
		t.Fatalf("a refused RemoveStore touched the store: %v", err)
	}
	if err := s.RemoveStore(ctx, "w", true); err != nil {
		t.Fatalf("RemoveStore force: %v", err)
	}
	if _, err := os.Stat(s.StorePath("w")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("store after force: %v", err)
	}
	if err := c.Remove(ctx); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	mustCreateStore(t, s, "w")
	if err := s.RemoveStore(ctx, "w", false); err != nil {
		t.Fatalf("RemoveStore after exit: %v", err)
	}
}

// The caller's OWN compartments are leftovers to it: an instance that reaps
// on its way out (refspawn's shutdown sweep) has already torn its sets down,
// so whatever still carries its stamp is something it failed to remove. The
// sweep stays scoped to the prefix: another prefix's live record is not
// touched.
func TestSeatbeltReapSweepsTheCallersOwnLeftovers(t *testing.T) {
	s := newTestSeatbelt(t, nil)
	mustCreateStore(t, s, "w")
	mustCreateStore(t, s, "refexec-stale-store")
	ctx := context.Background()
	c, err := s.Launch(ctx, Spec{Name: "refexec-a", Store: "w", Scratch: true, Argv: []string{"sleep", "60"}})
	if err != nil {
		t.Fatal(err)
	}
	pid := c.PID()
	// Another runtime's record, with a prefix Reap must not touch: a live
	// process whose start time matches, so a wrong sweep would be visible.
	other := startSleeper(t)
	otherStart, err := processStart(other)
	if err != nil {
		t.Fatal(err)
	}
	otherFile := filepath.Join(s.cfg.PIDDir, "agenthof-spawn-x.pid")
	if err := writePIDRecord(otherFile, pidRecord{PID: other, StartUnixMicro: otherStart, Store: "w"}); err != nil {
		t.Fatal(err)
	}

	if err := s.Reap(ctx, "refexec-"); err != nil {
		t.Fatalf("Reap: %v", err)
	}
	waitGone(t, pid, 3*time.Second)
	mustBeGone(t, "after Reap", s.pidFile("refexec-a"), s.scratchDir("refexec-a"), s.StorePath("refexec-stale-store"))
	mustExist(t, "Reap touched", otherFile, s.StorePath("w"))
	assertAlive(t, other, "Reap killed a process another prefix owns")
	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := c.Wait(wctx); err != nil {
		t.Fatalf("Wait after Reap: %v", err)
	}
	if err := s.Reap(ctx, ""); err == nil {
		t.Fatal("Reap accepted an empty prefix")
	}
}

// Two instances share one store root and pid dir (what refspawn's children
// do). Instance B's startup Reap must leave instance A's compartment in
// flight exactly as it is — its process, its record, its scratch dir, the
// store it runs on and a claim A has made but not yet completed — because A
// is still running: A's command would otherwise end with a killed exit that
// A attests as the command's own. Once A is gone, the same compartment IS a
// leftover and B's next Reap removes all of it.
func TestSeatbeltReapSparesALiveSiblingsCompartment(t *testing.T) {
	sibling, endSibling := startSibling(t)
	a := newTestSeatbelt(t, nil)
	a.owner = sibling
	mustCreateStore(t, a, "w")
	mustCreateStore(t, a, "refexec-set-work") // a prefixed store A's record names
	ctx := context.Background()
	c, err := a.Launch(ctx, Spec{Name: "refexec-a", Store: "refexec-set-work", Scratch: true, Argv: []string{"sleep", "60"}})
	if err != nil {
		t.Fatal(err)
	}
	// A claim A has made and not yet completed: the moment between the
	// record and the process, frozen.
	pending := a.pidFile("refexec-pending")
	if err := writePIDRecord(pending, pidRecord{Store: "w", OwnerPID: sibling.pid, OwnerStartUnixMicro: sibling.start}); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(a.scratchDir("refexec-pending"), 0o700); err != nil {
		t.Fatal(err)
	}
	// A's own leftover beside them: a record whose owner is A but whose
	// process is long gone. Still A's, so still not B's to touch.
	stale := a.pidFile("refexec-a-old")
	if err := writePIDRecord(stale, pidRecord{PID: 2_000_000_000, StartUnixMicro: 1, Store: "w", OwnerPID: sibling.pid, OwnerStartUnixMicro: sibling.start}); err != nil {
		t.Fatal(err)
	}
	aLeaves := []string{a.pidFile("refexec-a"), a.scratchDir("refexec-a"), a.StorePath("refexec-set-work"), pending, a.scratchDir("refexec-pending"), stale}

	b := siblingSeatbelt(t, a, mustSelfOwner(t))
	if err := b.Reap(ctx, "refexec-"); err != nil {
		t.Fatalf("B's Reap: %v", err)
	}
	assertAlive(t, c.PID(), "B's startup Reap killed A's compartment in flight")
	mustExist(t, "B's Reap touched what A, still running, owns", aLeaves...)
	select {
	case <-c.Done():
		t.Fatal("A's compartment ended during B's Reap")
	default:
	}

	// A is gone: now they are leftovers.
	endSibling()
	if err := b.Reap(ctx, "refexec-"); err != nil {
		t.Fatalf("B's second Reap: %v", err)
	}
	waitGone(t, c.PID(), 3*time.Second)
	mustBeGone(t, "after A exited, B's Reap left", aLeaves...)
	mustExist(t, "B's Reap removed an unprefixed store", a.StorePath("w"))
	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := c.Wait(wctx); err != nil {
		t.Fatalf("Wait after Reap: %v", err)
	}
}

// A record from before the owner stamp existed names no owner. Only an
// instance that predates the stamp could have written it and that instance
// has exited, so the record is a leftover: its process, if still the one
// recorded, is ended, and its files go.
func TestSeatbeltReapSweepsAnUnstampedRecord(t *testing.T) {
	s := newTestSeatbelt(t, nil)
	ctx := context.Background()
	orphan := startSleeper(t)
	start, err := processStart(orphan)
	if err != nil {
		t.Fatal(err)
	}
	// Written as an old binary would: the pid, its start time, the store.
	path := s.pidFile("refexec-old")
	if err := os.WriteFile(path, []byte(fmt.Sprintf(`{"pid":%d,"start_unix_micro":%d,"store":"w"}`+"\n", orphan, start)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(s.scratchDir("refexec-old"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.Reap(ctx, "refexec-"); err != nil {
		t.Fatalf("Reap: %v", err)
	}
	waitGone(t, orphan, 3*time.Second)
	mustBeGone(t, "after Reap", path, s.scratchDir("refexec-old"))
}

func mustSelfOwner(t *testing.T) ownerRef {
	t.Helper()
	o, err := selfOwner()
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// A stale record whose pid is now an unrelated process
// (a reused pid, simulated by a wrong start time) is deleted without a signal.
func TestSeatbeltReapNeverKillsAnUnrelatedProcess(t *testing.T) {
	s := newTestSeatbelt(t, nil)
	ctx := context.Background()
	sleeper := startSleeper(t)
	stale := filepath.Join(s.cfg.PIDDir, "refexec-stale.pid")
	if err := writePIDRecord(stale, pidRecord{PID: sleeper, StartUnixMicro: 1, Store: "w"}); err != nil {
		t.Fatal(err)
	}
	// A record whose pid does not exist, and an unreadable one.
	gone := filepath.Join(s.cfg.PIDDir, "refexec-gone.pid")
	if err := writePIDRecord(gone, pidRecord{PID: 2_000_000_000, StartUnixMicro: 1, Store: "w"}); err != nil {
		t.Fatal(err)
	}
	garbage := filepath.Join(s.cfg.PIDDir, "refexec-garbage.pid")
	if err := os.WriteFile(garbage, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Reap(ctx, "refexec-"); err != nil {
		t.Fatalf("Reap: %v", err)
	}
	for _, p := range []string{stale, gone, garbage} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s after Reap: %v", p, err)
		}
	}
	assertAlive(t, sleeper, "Reap killed an unrelated process whose start time did not match the record")

	// RemoveStore applies the same check: the stale record does not make the
	// store busy.
	mustCreateStore(t, s, "w")
	if err := writePIDRecord(stale, pidRecord{PID: sleeper, StartUnixMicro: 1, Store: "w"}); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveStore(ctx, "w", false); err != nil {
		t.Fatalf("RemoveStore with a stale record: %v", err)
	}
	assertAlive(t, sleeper, "RemoveStore killed an unrelated process")
}

// recordingHandler keeps every record's message.
type recordingHandler struct {
	mu   sync.Mutex
	msgs []string
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.msgs = append(h.msgs, r.Message)
	return nil
}
func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

// Limits are consumed, not enforced, and that is said once, at
// construction, not per launch.
func TestSeatbeltLimitsLoggedOnceNotEnforced(t *testing.T) {
	h := &recordingHandler{}
	s := newTestSeatbelt(t, func(c *SeatbeltConfig) { c.Logger = slog.New(h) })
	mustCreateStore(t, s, "w")
	for _, name := range []string{"refexec-01", "refexec-02"} {
		run(t, s, Spec{Name: name, Store: "w", Argv: []string{"true"}, Limits: Limits{Memory: "1g", CPUs: "1", PIDs: 10}})
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, m := range h.msgs {
		if m == "limits not enforced on this tier" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("limits message logged %d times in %q, want exactly once", n, h.msgs)
	}
}

func TestSeatbeltTierOptsAndValidateProgram(t *testing.T) {
	s := newTestSeatbelt(t, nil)
	if s.Tier() != TierSeatbelt || s.Opts() != nil {
		t.Fatalf("Tier %q Opts %v", s.Tier(), s.Opts())
	}
	shared := newTestSeatbelt(t, func(c *SeatbeltConfig) { c.SharedHostScratch = true })
	if !slices.Equal(shared.Opts(), []string{OptSharedHostScratch}) {
		t.Fatalf("Opts = %v", shared.Opts())
	}
	if err := s.ValidateProgram(""); err != nil {
		t.Fatalf(`ValidateProgram(""): %v`, err)
	}
	if err := s.ValidateProgram("/usr/bin/true"); err != nil {
		t.Fatalf("ValidateProgram(abs): %v", err)
	}
	if err := s.ValidateProgram("true"); err == nil {
		t.Fatal("ValidateProgram accepted a bare name")
	}
	mustCreateStore(t, s, "w")
	var buf bytes.Buffer
	res := run(t, s, Spec{Name: "refexec-01", Store: "w", Argv: []string{"sh", "-c", "echo out"}, Output: &buf})
	if buf.String() != "out\n" || res.Output != nil {
		t.Fatalf("Output sink: buf %q, res %+v", buf.String(), res)
	}
}
