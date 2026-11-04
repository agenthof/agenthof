package confiner

import (
	"context"
	"errors"
	"fmt"
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
)

// fakePodmanFlag re-executes this test binary as `podman`, so the Podman
// backend runs against a "podman" whose compartments are the argv run directly
// on the host. The shipped binaries have no such mode; this is test-tree code.
const fakePodmanFlag = "-confiner-test-podman"

// testModes are the re-exec modes of this test binary, keyed by their first
// argument; OS-specific test files register theirs from an init.
var testModes = map[string]func(args []string) int{fakePodmanFlag: fakePodman}

func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		if mode, ok := testModes[os.Args[1]]; ok {
			os.Exit(mode(os.Args[2:]))
		}
	}
	os.Exit(m.Run())
}

// The fake keeps its state under CONFINER_TEST_ROOT:
//
//	log                one line per invocation: its args, space-joined
//	<name>.client      the pid of the fake client that ran container <name>
//	<name>.pid         the pid of that container's "process"
//	ctr/<name>         a marker for each running container (what `ps` lists);
//	                   its content is the container's owner label value, if any
//	vol/<name>         one entry per volume (what `volume ls` lists); for a
//	                   volume create --label, its content is the owner label value
//	mounted-<volume>   marks a volume as in use, so `volume rm` without -f fails
func testRoot() string { return os.Getenv("CONFINER_TEST_ROOT") }

func appendLog(args []string) {
	f, err := os.OpenFile(filepath.Join(testRoot(), "log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = f.WriteString(strings.Join(args, " ") + "\n")
}

// twoArgFlags are the `podman run` flags the backend passes with a separate value.
var twoArgFlags = map[string]bool{"--name": true, "--label": true, "--network": true, "--tmpfs": true, "--security-opt": true, "--user": true, "-v": true, "-e": true, "-w": true}

// fakePodman answers info, run, rm -f NAME, volume create|rm|ls and ps;
// anything else is a podman usage error (125).
func fakePodman(args []string) int {
	if len(args) == 0 || testRoot() == "" {
		return 125
	}
	appendLog(args)
	switch args[0] {
	case "info":
		if v, ok := os.LookupEnv("CONFINER_TEST_INFO"); ok {
			fmt.Println(v)
		} else {
			fmt.Println("linux true false")
		}
		return 0
	case "run":
		return fakeRun(args[1:])
	case "rm":
		name := args[len(args)-1]
		if b, err := os.ReadFile(filepath.Join(testRoot(), name+".pid")); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid > 1 {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
		_ = os.Remove(filepath.Join(testRoot(), "ctr", name))
		return 0
	case "ps":
		if os.Getenv("CONFINER_TEST_PS_FAIL") == "1" {
			fmt.Fprintln(os.Stderr, "Error: ps is broken")
			return 125
		}
		// With the backend's --format, each line is the name and the owner
		// label value (the marker's content); without, names alone.
		return listPrefix(filepath.Join(testRoot(), "ctr"), filterPrefix(args), slices.Contains(args, "--format"))
	case "volume":
		if len(args) < 2 {
			return 125
		}
		name := args[len(args)-1]
		switch args[1] {
		case "create":
			owner := ""
			for i, a := range args {
				if a == "--label" && i+1 < len(args) {
					if v, ok := strings.CutPrefix(args[i+1], ownerLabel+"="); ok {
						owner = v
					}
				}
			}
			if err := os.MkdirAll(filepath.Join(testRoot(), "vol"), 0o755); err != nil {
				return 125
			}
			if err := os.WriteFile(filepath.Join(testRoot(), "vol", name), []byte(owner), 0o600); err != nil {
				return 125
			}
			return 0
		case "rm":
			if !slices.Contains(args, "-f") {
				if _, err := os.Stat(filepath.Join(testRoot(), "mounted-"+name)); err == nil {
					fmt.Fprintf(os.Stderr, "Error: volume %s is being used by a container\n", name)
					return 125
				}
			}
			_ = os.RemoveAll(filepath.Join(testRoot(), "vol", name))
			return 0
		case "ls":
			return listPrefix(filepath.Join(testRoot(), "vol"), filterPrefix(args), slices.Contains(args, "--format"))
		}
	}
	return 125
}

func filterPrefix(args []string) string {
	for i, a := range args {
		if a == "--filter" && i+1 < len(args) {
			return strings.TrimPrefix(strings.TrimPrefix(args[i+1], "name="), "^")
		}
	}
	return ""
}

func listPrefix(dir, prefix string, withOwner bool) int {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		if !withOwner {
			fmt.Println(e.Name())
			continue
		}
		owner, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		fmt.Println(e.Name(), strings.TrimSpace(string(owner)))
	}
	return 0
}

// fakeRun starts the argv after the image with an environment of exactly the
// -e entries (NAME takes its value from the fake's own environment, as podman
// does; NAME=VALUE is verbatim) and -w DIR as its working directory, records
// its own pid and the child's under the container name and the owner label
// in the container marker, and exits with the child's status.
func fakeRun(rest []string) int {
	var name, image, workdir, owner string
	var argv []string
	env := []string{} // non-nil: an empty environment, never an inherited one
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		if !strings.HasPrefix(a, "-") {
			image, argv = a, rest[i+1:]
			break
		}
		if twoArgFlags[a] {
			if i+1 >= len(rest) {
				return 125
			}
			switch a {
			case "--name":
				name = rest[i+1]
			case "--label":
				if v, ok := strings.CutPrefix(rest[i+1], ownerLabel+"="); ok {
					owner = v
				}
			case "-w":
				workdir = rest[i+1]
			case "-e":
				if strings.Contains(rest[i+1], "=") {
					env = append(env, rest[i+1])
				} else {
					env = append(env, rest[i+1]+"="+os.Getenv(rest[i+1]))
				}
			}
			i++
		}
	}
	if image == "" || name == "" || len(argv) == 0 {
		return 125
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = env
	cmd.Dir = workdir
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "fake podman:", err)
		return 125
	}
	_ = os.MkdirAll(filepath.Join(testRoot(), "ctr"), 0o755)
	_ = os.WriteFile(filepath.Join(testRoot(), name+".client"), []byte(strconv.Itoa(os.Getpid())), 0o600)
	_ = os.WriteFile(filepath.Join(testRoot(), name+".pid"), []byte(strconv.Itoa(cmd.Process.Pid)), 0o600)
	_ = os.WriteFile(filepath.Join(testRoot(), "ctr", name), []byte(owner), 0o600)
	err := cmd.Wait()
	_ = os.Remove(filepath.Join(testRoot(), "ctr", name))
	_ = os.Remove(filepath.Join(testRoot(), name+".pid"))
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if code := ee.ExitCode(); code >= 0 {
			return code
		}
		return 137 // killed
	}
	if err != nil {
		return 125
	}
	return 0
}

// newTestPodman returns a Podman whose client is the fake, and the fake's root.
func newTestPodman(t *testing.T) (*Podman, string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	t.Setenv("CONFINER_TEST_ROOT", root)
	return NewPodman(PodmanConfig{Argv: []string{exe, fakePodmanFlag}, GuestWorkspace: t.TempDir()}), root
}

func readLog(t *testing.T, root string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "log"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func readPid(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if b, err := os.ReadFile(path); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
				return pid
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never appeared", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestPodmanRunArgsGolden(t *testing.T) {
	p := NewPodman(PodmanConfig{Environ: func() []string { return []string{"A=1", "B=2", "LEAK=x"} }})
	args, applied := p.runArgs(Spec{Name: "refexec-00", Program: "example.test/exec:1", Argv: []string{"cat", "x"}, Store: "work",
		Paths:    []Path{{Path: "/tmp/sp/r-x", RW: true}, {Path: "/opt/ro", RW: false}},
		Scratch:  true,
		EnvNames: []string{"B", "A", "UNSET"},
		Limits:   Limits{Memory: "256m", CPUs: "1", PIDs: 64}, Timeout: 1500 * time.Millisecond})
	want := "run --rm --name refexec-00 --label agenthof.owner=" + p.owner.String() + " --pull=never --network none --read-only --tmpfs /tmp --cap-drop=ALL --security-opt no-new-privileges --userns=keep-id --user " +
		fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()) + " --memory=256m --cpus=1 --pids-limit=64 --timeout=1 -v work:/work -w /work -v /tmp/sp/r-x:/tmp/sp/r-x -v /opt/ro:/opt/ro:ro -e A -e B -e TMPDIR=/tmp example.test/exec:1 cat x"
	if strings.Join(args, " ") != want || !slices.Equal(applied, []string{"A", "B", "TMPDIR"}) {
		t.Fatalf("%q\n%v", strings.Join(args, " "), applied)
	}
}

func TestPodmanRunArgsNoScratchNoTmpfsNoTMPDIR(t *testing.T) {
	p := NewPodman(PodmanConfig{Environ: func() []string { return []string{"A=1"} }})
	args, applied := p.runArgs(Spec{Name: "n", Program: "img", Store: "work", Timeout: time.Minute})
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "--tmpfs") || strings.Contains(joined, "TMPDIR") {
		t.Fatalf("no scratch must mean no tmpfs and no TMPDIR: %q", joined)
	}
	if applied == nil || len(applied) != 0 {
		t.Fatalf("applied = %#v, want a non-nil empty list", applied)
	}
}

func TestPodmanValidateProgram(t *testing.T) {
	p, root := newTestPodman(t)
	if err := p.ValidateProgram(""); !errors.Is(err, ErrEmptyProgram) {
		t.Fatalf("empty program: %v", err)
	}
	if err := p.ValidateProgram("busy box"); err == nil {
		t.Fatal("an image ref with a space must be refused")
	}
	for _, ok := range []string{"docker.io/library/busybox:1.36.1", "/tmp/x/echo-agent"} {
		if err := p.ValidateProgram(ok); err != nil {
			t.Fatalf("%q: %v", ok, err)
		}
	}
	if _, err := p.Launch(context.Background(), Spec{Name: "n", Store: "work", Argv: []string{"true"}}); !errors.Is(err, ErrEmptyProgram) {
		t.Fatalf("launch with no program: %v", err)
	}
	if log := readLog(t, root); len(log) != 0 {
		t.Fatalf("nothing may start for an empty program: %v", log)
	}
}

func TestPodmanProbeRequiresLocalRootlessLinuxEngine(t *testing.T) {
	p, root := newTestPodman(t)
	t.Setenv("CONFINER_TEST_INFO", "linux true false")
	if err := p.Probe(context.Background()); err != nil {
		t.Fatalf("local rootless linux: %v", err)
	}
	if log := readLog(t, root); !slices.Contains(log, "info --format {{.Host.OS}} {{.Host.Security.Rootless}} {{.Host.ServiceIsRemote}}") {
		t.Fatalf("probe argv: %v", log)
	}

	t.Setenv("CONFINER_TEST_INFO", "linux true true")
	err := p.Probe(context.Background())
	if !errors.Is(err, ErrNotLocalEngine) || !strings.Contains(err.Error(), "podman-machine is the reserved `wsl2`-class backend, not built") {
		t.Fatalf("remote engine: %v", err)
	}
	t.Setenv("CONFINER_TEST_INFO", "darwin true true")
	if err := p.Probe(context.Background()); !errors.Is(err, ErrNotLocalEngine) {
		t.Fatalf("a remote engine is refused on every OS: %v", err)
	}
	for _, info := range []string{"linux false false", "darwin true false", "", "linux true"} {
		t.Setenv("CONFINER_TEST_INFO", info)
		err := p.Probe(context.Background())
		if err == nil || errors.Is(err, ErrNotLocalEngine) || !strings.Contains(err.Error(), "podman info") {
			t.Fatalf("%q: %v", info, err)
		}
	}
	t.Setenv("CONFINER_TEST_ROOT", "") // the fake now fails `info` outright
	if err := p.Probe(context.Background()); err == nil || !strings.Contains(err.Error(), "podman info") {
		t.Fatalf("probe failure: %v", err)
	}
}

func TestPodmanLaunchWaitCapturesAndAttestsClientPID(t *testing.T) {
	p, root := newTestPodman(t)
	c, err := p.Launch(context.Background(), Spec{Name: "c1", Program: "example.test/exec:1", Store: "work", Scratch: true,
		EnvNames: []string{"TMPDIR"}, Timeout: time.Minute,
		Argv: []string{"sh", "-c", "printf hi; exit 3"}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Wait(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Exit != 3 || string(res.Output) != "hi" || res.OutputBytes != 2 || res.Truncated || !slices.Equal(res.EnvNames, []string{"TMPDIR"}) {
		t.Fatalf("%+v", res)
	}
	select {
	case <-c.Done():
	default:
		t.Fatal("Done must be closed once Wait has returned")
	}
	client := readPid(t, filepath.Join(root, "c1.client"))
	if c.PID() != client {
		t.Fatalf("PID() = %d, want the fake client's pid %d", c.PID(), client)
	}
}

func TestPodmanLaunchGivesTheChildOnlyTheNamedEnvAndWorkspace(t *testing.T) {
	p, _ := newTestPodman(t)
	t.Setenv("CONFINER_TEST_SECRET", "s3cret")
	t.Setenv("CONFINER_TEST_PASSED", "v1")
	c, err := p.Launch(context.Background(), Spec{Name: "c2", Program: "img", Store: "work", Scratch: true,
		EnvNames: []string{"CONFINER_TEST_PASSED"}, Timeout: time.Minute,
		Argv: []string{"sh", "-c", `printf '%s|%s|%s|' "$CONFINER_TEST_PASSED" "${CONFINER_TEST_SECRET-unset}" "$TMPDIR"; pwd`}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Wait(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "v1|unset|/tmp|"
	out := string(res.Output)
	if !strings.HasPrefix(out, prefix) {
		t.Fatalf("%q", out)
	}
	got, _ := filepath.EvalSymlinks(strings.TrimSpace(strings.TrimPrefix(out, prefix)))
	want, _ := filepath.EvalSymlinks(p.StorePath("work"))
	if got != want {
		t.Fatalf("working directory %q, want %q", got, want)
	}
	if !slices.Equal(res.EnvNames, []string{"CONFINER_TEST_PASSED", "TMPDIR"}) {
		t.Fatalf("%v", res.EnvNames)
	}
}

func TestPodmanExit125IsDidNotLaunch(t *testing.T) {
	p, _ := newTestPodman(t)
	c, err := p.Launch(context.Background(), Spec{Name: "c3", Program: "img", Store: "work", Timeout: time.Minute,
		Argv: []string{"sh", "-c", "exit 125"}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Wait(context.Background())
	if !errors.Is(err, ErrDidNotLaunch) || res.Exit != 125 {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestPodmanRemoveRunsRmFAndUnblocksWait(t *testing.T) {
	p, root := newTestPodman(t)
	c, err := p.Launch(context.Background(), Spec{Name: "c4", Program: "img", Store: "work", Timeout: time.Minute,
		EnvNames: []string{"PATH"}, Argv: []string{"sleep", "30"}})
	if err != nil {
		t.Fatal(err)
	}
	child := readPid(t, filepath.Join(root, "c4.pid"))
	waited := make(chan error, 1)
	go func() { _, err := c.Wait(context.Background()); waited <- err }()
	if err := c.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
	if log := readLog(t, root); !slices.Contains(log, "rm -f c4") {
		t.Fatalf("Remove must run `rm -f NAME`: %v", log)
	}
	select {
	case <-waited:
	case <-time.After(15 * time.Second):
		t.Fatal("Wait did not return after Remove")
	}
	if err := syscall.Kill(child, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("the container's process must be gone: %v", err)
	}
}

func TestPodmanWaitReturnsOnCtxWithoutRemoving(t *testing.T) {
	p, root := newTestPodman(t)
	c, err := p.Launch(context.Background(), Spec{Name: "c5", Program: "img", Store: "work", Timeout: time.Minute,
		EnvNames: []string{"PATH"}, Argv: []string{"sleep", "30"}})
	if err != nil {
		t.Fatal(err)
	}
	readPid(t, filepath.Join(root, "c5.pid"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait on a cancelled ctx: %v", err)
	}
	for _, l := range readLog(t, root) {
		if strings.HasPrefix(l, "rm ") {
			t.Fatalf("a cancelled Wait must remove nothing: %v", l)
		}
	}
	if err := c.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-c.Done():
	case <-time.After(15 * time.Second):
		t.Fatal("Remove must end the compartment")
	}
}

func TestPodmanStoreAndReap(t *testing.T) {
	ctx := context.Background()
	p, root := newTestPodman(t)
	if err := p.CreateStore(ctx, "S"); err != nil {
		t.Fatal(err)
	}
	// CreateStore must stamp the store with this instance's owner, or a later
	// reap cannot tell it from a leftover (the sweep below relies on the label).
	if log := readLog(t, root); len(log) != 1 || log[0] != "volume create --label "+ownerLabel+"="+p.owner.String()+" S" {
		t.Fatalf("CreateStore did not stamp the store with its owner: %q", log)
	}
	if err := os.WriteFile(filepath.Join(root, "mounted-S"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.RemoveStore(ctx, "S", false); !errors.Is(err, ErrStoreInUse) {
		t.Fatalf("a mounted store: %v", err)
	}
	if err := p.RemoveStore(ctx, "S", true); err != nil {
		t.Fatal(err)
	}
	if err := p.CreateStore(ctx, "-bad"); err == nil {
		t.Fatal("a store name that podman would read as a flag must be refused")
	}
	if got := p.StorePath("anything"); got != p.cfg.GuestWorkspace {
		t.Fatalf("StorePath = %q", got)
	}

	// The containers under the prefix: one with no owner label (from before
	// stamps existed), one whose owner has exited, one the caller itself
	// owns, and one ANOTHER RUNNING instance owns — a compartment in flight,
	// not a leftover. Plus one under another prefix, and the volumes.
	sibling, endSibling := startSiblingProcess(t)
	for d, owner := range map[string]string{
		"ctr/agenthof-spawn-a": "", "ctr/agenthof-spawn-b": "", "ctr/agenthof-spawn-dead": "2000000000-1",
		"ctr/agenthof-spawn-self": p.owner.String(), "ctr/agenthof-spawn-sibling": sibling.String(),
		"ctr/refexec-keep": "", "vol/agenthof-spawn-v": "", "vol/other": "",
	} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, d)), 0o755); err != nil {
			t.Fatal(err)
		}
		var err error
		if strings.HasPrefix(d, "vol/") {
			err = os.Mkdir(filepath.Join(root, d), 0o755)
		} else {
			err = os.WriteFile(filepath.Join(root, d), []byte(owner), 0o600)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "log"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.Reap(ctx, "agenthof-spawn-"); err != nil {
		t.Fatal(err)
	}
	ps := "ps -a --filter name=^agenthof-spawn- --format " + psOwnerFormat
	want := []string{
		ps, "rm -f agenthof-spawn-a", "rm -f agenthof-spawn-b", "rm -f agenthof-spawn-dead", "rm -f agenthof-spawn-self",
		"volume ls --filter name=^agenthof-spawn- --format " + volOwnerFormat, "volume rm -f agenthof-spawn-v",
	}
	if log := readLog(t, root); !slices.Equal(log, want) {
		t.Fatalf("%q", log)
	}
	if _, err := os.Stat(filepath.Join(root, "ctr/agenthof-spawn-sibling")); err != nil {
		t.Fatalf("the running sibling's compartment after Reap: %v", err)
	}

	// The sibling exits: its compartment is now a leftover.
	endSibling()
	if err := os.WriteFile(filepath.Join(root, "log"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.Reap(ctx, "agenthof-spawn-"); err != nil {
		t.Fatal(err)
	}
	if log := readLog(t, root); !slices.Equal(log, []string{ps, "rm -f agenthof-spawn-sibling", "volume ls --filter name=^agenthof-spawn- --format " + volOwnerFormat}) {
		t.Fatalf("after the sibling exited: %q", log)
	}

	if err := p.Reap(ctx, ""); err == nil {
		t.Fatal("an empty prefix would match everything and must be refused")
	}
	t.Setenv("CONFINER_TEST_PS_FAIL", "1")
	if err := p.Reap(ctx, "agenthof-spawn-"); err == nil || !strings.Contains(err.Error(), "ps") {
		t.Fatalf("a failed ps must be returned: %v", err)
	}
}

// A store volume stamped with a running sibling's owner is left in place by a
// reap: podman volume rm -f would stop and remove the container mounting it,
// ending that sibling's child run. A gone-owner or unstamped store is a
// leftover and is reaped. (The container sweep already spares the live
// sibling's compartment; the volume sweep must not undo that.)
func TestPodmanReapSparesLiveOwnerVolume(t *testing.T) {
	ctx := context.Background()
	p, root := newTestPodman(t)
	sibling, _ := startSiblingProcess(t)
	if err := os.MkdirAll(filepath.Join(root, "vol"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, owner := range map[string]string{
		"agenthof-spawn-live-work":  sibling.String(), // a running sibling's child store
		"agenthof-spawn-dead-work":  "2000000000-1",   // a gone owner's leftover
		"agenthof-spawn-plain-work": "",               // unstamped (pre-owner-stamp)
	} {
		if err := os.WriteFile(filepath.Join(root, "vol", name), []byte(owner), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.Reap(ctx, "agenthof-spawn-"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "vol/agenthof-spawn-live-work")); err != nil {
		t.Fatalf("a running sibling's store was reaped: %v", err)
	}
	for _, gone := range []string{"agenthof-spawn-dead-work", "agenthof-spawn-plain-work"} {
		if _, err := os.Stat(filepath.Join(root, "vol", gone)); !os.IsNotExist(err) {
			t.Fatalf("leftover store %s survived the reap (err=%v)", gone, err)
		}
	}
}

// startSiblingProcess stands in for another running instance: a live process
// the test owns, as the owner stamp its backend would carry, and a way to end
// it — killed and reaped, so nothing is left, not even a zombie.
func startSiblingProcess(t *testing.T) (owner ownerRef, end func()) {
	t.Helper()
	cmd := exec.Command("sleep", "60")
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
	self, err := selfOwner()
	if err != nil {
		t.Fatal(err)
	}
	return ownerRef{pid: cmd.Process.Pid, start: start, boot: self.boot}, end
}

// The owner stamp names one process for the life of a boot: this process is
// alive by its own stamp, a reused pid (a wrong start time) and an exited
// process are not, and a stamp from before stamps existed is reapable.
func TestOwnerStampLiveness(t *testing.T) {
	self, err := selfOwner()
	if err != nil {
		t.Fatal(err)
	}
	if self.pid != os.Getpid() || !self.alive(self.boot) {
		t.Fatalf("own stamp %+v is not alive", self)
	}
	parsed, ok := parseOwner(self.String())
	if !ok || parsed != self {
		t.Fatalf("parse(%q) = %+v, %v", self.String(), parsed, ok)
	}
	if (ownerRef{pid: self.pid, start: self.start + 1, boot: self.boot}).alive(self.boot) {
		t.Fatal("a wrong start time matched a live process")
	}
	if (ownerRef{pid: self.pid, start: self.start, boot: self.boot + "x"}).alive(self.boot) {
		t.Fatal("a stamp from another boot matched a live process")
	}
	if (ownerRef{pid: 2_000_000_000, start: 1}).alive(self.boot) {
		t.Fatal("a pid that does not exist is alive")
	}
	for _, bad := range []string{"", "x", "7", "0-1", "1-5", "a-b", "12-x"} {
		if _, ok := parseOwner(bad); ok {
			t.Errorf("parseOwner(%q) accepted it", bad)
		}
	}
	if !(ownerRef{}).reapableBy(self) || self.reapableBy(self) != true {
		t.Fatal("an unstamped owner and the caller itself must both be reapable")
	}
	sibling, end := startSiblingProcess(t)
	if sibling.reapableBy(self) {
		t.Fatal("a running sibling is reapable")
	}
	end()
	if !sibling.reapableBy(self) {
		t.Fatal("an exited sibling is not reapable")
	}
}

func TestOutputIsCappedAndCounted(t *testing.T) {
	p, _ := newTestPodman(t)
	c, err := p.Launch(context.Background(), Spec{Name: "c6", Program: "img", Store: "work", Timeout: time.Minute,
		EnvNames: []string{"PATH"}, Argv: []string{"sh", "-c", "yes | head -c 1200000"}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Wait(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated || res.OutputBytes != 1200000 || len(res.Output) != MaxOutput+len(TruncationMarker) {
		t.Fatalf("truncated=%v bytes=%d len=%d", res.Truncated, res.OutputBytes, len(res.Output))
	}
}
