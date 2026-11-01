//go:build darwin

package confiner

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// These tests measure what the generated profile DENIES and what it still
// lets a realistic toolset do, on a real macOS with sandbox-exec. Every
// denial is paired with a no-sandbox control of the same action, so a
// sandboxed failure is attributable to the sandbox and not to a dead network,
// a missing tool or a permission the test user lacks. They are the macOS
// counterpart of the real-podman acceptance run: local, by judgment, skipped
// where sandbox-exec is absent.

// The unix-socket re-exec modes: a server that accepts exactly one
// connection and echoes, and a client that sends one line and reads the echo.
const (
	sockServeFlag  = "-confiner-test-sockserve"
	sockClientFlag = "-confiner-test-sockclient"
)

func init() {
	testModes[sockServeFlag] = sockServeMain
	testModes[sockClientFlag] = sockClientMain
}

// sockServeMain listens on args[0], accepts one connection, reads a line and
// answers "pong". It prints what it received, so a test can tell which client
// reached it.
func sockServeMain(args []string) int {
	l, err := net.Listen("unix", args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		return 1
	}
	defer func() { _ = l.Close() }()
	if ul, ok := l.(*net.UnixListener); ok {
		_ = ul.SetDeadline(time.Now().Add(20 * time.Second))
	}
	c, err := l.Accept()
	if err != nil {
		fmt.Fprintln(os.Stderr, "accept:", err)
		return 1
	}
	defer func() { _ = c.Close() }()
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		return 1
	}
	fmt.Printf("server got: %s", line)
	if _, err := io.WriteString(c, "pong\n"); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		return 1
	}
	return 0
}

// sockClientMain dials args[0], sends "ping" and prints the reply.
func sockClientMain(args []string) int {
	c, err := net.Dial("unix", args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "dial:", err)
		return 1
	}
	defer func() { _ = c.Close() }()
	if _, err := io.WriteString(c, "ping\n"); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		return 1
	}
	reply, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		return 1
	}
	fmt.Printf("client got: %s", reply)
	return 0
}

// control runs program unsandboxed, from dir (or the test's cwd when ""),
// with the same empty environment a compartment gets, and returns its
// combined output and exit code. A program that cannot be run at all fails
// the test: a control that did not run proves nothing about the sandbox.
func control(t *testing.T, dir string, program string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(program, args...)
	cmd.Dir = dir
	cmd.Env = []string{}
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		t.Fatalf("control %s %v did not run: %v", program, args, err)
	}
	return string(out), cmd.ProcessState.ExitCode()
}

// requireTool skips the test when a tool the host is expected to have is
// absent, and returns its path.
func requireTool(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s is not installed", name)
	}
	return p
}

// shellScript is the Argv for running script under /bin/sh with positional
// arguments, so no path is ever spliced into shell text.
func shellScript(script string, args ...string) []string {
	return append([]string{"sh", "-c", script, "sh"}, args...)
}

// denied asserts a sandboxed command failed with the sandbox's refusal: a
// non-zero exit of the command's own and "Operation not permitted" in its
// output.
func denied(t *testing.T, what string, res Result) {
	t.Helper()
	if res.Exit == 0 {
		t.Fatalf("%s was NOT denied (exit 0): %q", what, res.Output)
	}
	if !strings.Contains(strings.ToLower(string(res.Output)), "operation not permitted") {
		t.Fatalf("%s failed (exit %d) but not with the sandbox's refusal: %q", what, res.Exit, res.Output)
	}
}

func mustNotExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s exists after a denied write (%v)", path, err)
	}
}

// waitPath polls until path exists (a socket file is empty, so existence is
// the signal).
func waitPath(t *testing.T, path string, limit time.Duration) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for {
		if _, err := os.Lstat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not appear within %v", path, limit)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A direct TCP connect is refused by the sandbox at once, not after a
// timeout: the time to a non-zero exit is the assertion. The control may
// succeed or time out; it exists to show nc ran and that the host has a
// route, because a host with no route also fails immediately and could not
// be told from a denial.
func TestEnforceDirectNetworkDeniedImmediately(t *testing.T) {
	nc := requireTool(t, "nc")
	s := newTestSeatbelt(t, nil)
	mustCreateStore(t, s, "w")

	start := time.Now()
	_, code := control(t, "", nc, "-z", "-w", "3", "1.1.1.1", "80")
	if code != 0 && time.Since(start) < 2*time.Second {
		t.Skip("the unsandboxed connect failed at once too (no route): a sandboxed refusal could not be attributed")
	}

	start = time.Now()
	res := run(t, s, Spec{Name: "refexec-01", Store: "w", Argv: []string{"nc", "-z", "-w", "3", "1.1.1.1", "80"}})
	elapsed := time.Since(start)
	if res.Exit == 0 {
		t.Fatalf("the sandboxed connect SUCCEEDED: %q", res.Output)
	}
	if elapsed >= 2*time.Second {
		t.Fatalf("the sandboxed connect took %v to fail (exit %d): a timeout, not a refusal", elapsed, res.Exit)
	}
}

// A write outside the store is denied and leaves no file; a write inside the
// store works.
func TestEnforceWriteOutsideDeniedAndAbsent(t *testing.T) {
	s := newTestSeatbelt(t, nil)
	mustCreateStore(t, s, "w")
	leak := filepath.Join(s.cfg.PIDDir, "..", "leak")

	if err := os.WriteFile(leak, []byte("x\n"), 0o600); err != nil {
		t.Fatalf("control write: %v", err)
	}
	if err := os.Remove(leak); err != nil {
		t.Fatal(err)
	}

	res := run(t, s, Spec{Name: "refexec-01", Store: "w", Argv: shellScript(`echo x > "$1"`, leak)})
	denied(t, "write outside the store", res)
	mustNotExist(t, leak)

	res = run(t, s, Spec{Name: "refexec-02", Store: "w", Argv: shellScript(`echo x > in && cat in`)})
	if res.Exit != 0 || string(res.Output) != "x\n" {
		t.Fatalf("write inside the store: exit %d, %q", res.Exit, res.Output)
	}
	if _, err := os.Stat(filepath.Join(s.StorePath("w"), "in")); err != nil {
		t.Fatalf("the write inside the store left no file: %v", err)
	}
}

// The /dev allow-list is literal: a compartment cannot write into the
// operator's live terminals (/dev/ttys*, same uid), while /dev/null works.
// The control opens the TTY for writing WITHOUT writing to it, which proves
// this uid may write there without putting a stray character into a shell.
func TestEnforceTTYWriteDeniedDevNullAllowed(t *testing.T) {
	s := newTestSeatbelt(t, nil)
	mustCreateStore(t, s, "w")

	ttys, err := filepath.Glob("/dev/ttys*")
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(ttys)
	var tty string
	for _, p := range ttys {
		fd, err := unix.Open(p, unix.O_WRONLY|unix.O_NOCTTY|unix.O_NONBLOCK, 0)
		if err != nil {
			continue
		}
		_ = unix.Close(fd)
		tty = p
		break
	}
	if tty == "" {
		t.Skip("no /dev/ttys* is open for writing by this uid")
	}

	res := run(t, s, Spec{Name: "refexec-01", Store: "w", Argv: shellScript(`echo x > "$1"`, tty)})
	denied(t, "write to "+tty, res)

	res = run(t, s, Spec{Name: "refexec-02", Store: "w", Argv: shellScript(`echo x > /dev/null`)})
	if res.Exit != 0 {
		t.Fatalf("write to /dev/null: exit %d, %q", res.Exit, res.Output)
	}
}

// Unix sockets are governed by the network rules: a compartment may bind and
// connect under an RW Path and nowhere else. A sandboxed server accepts a
// sandboxed client's connection on an RW-path socket with the profile as
// generated (network-bind and network-outbound; no network-inbound was
// needed). Every directory here sits under /private/tmp because a t.TempDir
// path does not fit sun_path on macOS.
func TestEnforceUnixSocketUnderRWPathOnly(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skip("sandbox-exec is not installed")
	}
	root, err := os.MkdirTemp("/private/tmp", "confiner-sock-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	cfg := SeatbeltConfig{StoreRoot: filepath.Join(root, "s"), PIDDir: filepath.Join(root, "p"), Home: filepath.Join(root, "h")}
	rw, outside := filepath.Join(root, "rw"), filepath.Join(root, "out")
	for _, d := range []string{cfg.StoreRoot, cfg.PIDDir, cfg.Home, rw, outside} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	s, err := NewSeatbelt(cfg)
	if err != nil {
		t.Fatal(err)
	}
	mustCreateStore(t, s, "w")
	ctx := context.Background()
	inRW := filepath.Join(rw, "a.sock")
	underStoreRoot := filepath.Join(s.StorePath("w"), "..", "x.sock")
	outsideSock := filepath.Join(outside, "o.sock")
	for _, p := range []string{inRW, underStoreRoot, outsideSock} {
		if err := CheckSunPath(p, "darwin"); err != nil {
			t.Fatal(err)
		}
	}
	paths := []Path{{Path: rw, RW: true}}

	// Sandboxed server and sandboxed client on the RW path.
	srv, err := s.Launch(ctx, Spec{Name: "refexec-srv", Store: "w", Paths: paths, Argv: []string{selfExe(), sockServeFlag, inRW}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Remove(ctx) })
	waitPath(t, inRW, 10*time.Second)
	res := run(t, s, Spec{Name: "refexec-cli", Store: "w", Paths: paths, Argv: []string{selfExe(), sockClientFlag, inRW}})
	if res.Exit != 0 || string(res.Output) != "client got: pong\n" {
		t.Fatalf("sandboxed client on the RW path: exit %d, %q", res.Exit, res.Output)
	}
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	sres, err := srv.Wait(wctx)
	if err != nil || sres.Exit != 0 || string(sres.Output) != "server got: ping\n" {
		t.Fatalf("sandboxed server on the RW path: %+v, %v (output %q)", sres, err, sres.Output)
	}

	// Bind under the store root (not an RW Path): the control binds there
	// unsandboxed, the compartment is refused.
	ctl := exec.Command(selfExe(), sockServeFlag, underStoreRoot)
	var ctlOut bytes.Buffer
	ctl.Stdout, ctl.Stderr = &ctlOut, &ctlOut
	if err := ctl.Start(); err != nil {
		t.Fatal(err)
	}
	waitPath(t, underStoreRoot, 10*time.Second)
	if out, code := control(t, "", selfExe(), sockClientFlag, underStoreRoot); code != 0 || out != "client got: pong\n" {
		t.Fatalf("control client under the store root: exit %d, %q", code, out)
	}
	if err := ctl.Wait(); err != nil || ctlOut.String() != "server got: ping\n" {
		t.Fatalf("control server under the store root: %v, %q", err, ctlOut.String())
	}
	// The listener unlinks its socket on close; make sure it is gone.
	if err := os.Remove(underStoreRoot); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	res = run(t, s, Spec{Name: "refexec-bind", Store: "w", Paths: paths, Argv: []string{selfExe(), sockServeFlag, underStoreRoot}})
	denied(t, "bind under the store root", res)
	mustNotExist(t, underStoreRoot)

	// Connect to an unconfined server's socket outside every RW Path: the
	// compartment is refused and the server never sees it; the control client
	// is the one connection it accepts.
	outsideSrv := exec.Command(selfExe(), sockServeFlag, outsideSock)
	var outsideOut bytes.Buffer
	outsideSrv.Stdout, outsideSrv.Stderr = &outsideOut, &outsideOut
	if err := outsideSrv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outsideSrv.Process.Kill() })
	waitPath(t, outsideSock, 10*time.Second)
	res = run(t, s, Spec{Name: "refexec-conn", Store: "w", Paths: paths, Argv: []string{selfExe(), sockClientFlag, outsideSock}})
	denied(t, "connect outside the RW path", res)
	if o, code := control(t, "", selfExe(), sockClientFlag, outsideSock); code != 0 || o != "client got: pong\n" {
		t.Fatalf("control client outside the RW path: exit %d, %q", code, o)
	}
	if err := outsideSrv.Wait(); err != nil || outsideOut.String() != "server got: ping\n" {
		t.Fatalf("the outside server saw something other than the control client: %v, %q", err, outsideOut.String())
	}
}

// Cross-compartment invisibility, and the proof that re-opening the root
// directories' metadata opened nothing else. The store root and the spawn
// root carry (allow file-read-metadata (literal <root>)) so a path THROUGH
// them resolves (a shell's cd into the store, git init); their subtrees stay
// read-denied. So: a sibling store's file, the compartment's own PID record
// and another child's socket dir are unreadable; listing the store root and
// stat on a sibling store are refused; a hard link into the sibling cannot be
// made and a symlink into it cannot be read through; the own store reads and
// writes. The PID dir and the home credential stores get no metadata allow.
func TestEnforceSiblingStoreSocketDirAndPIDDirUnreadable(t *testing.T) {
	var spawnRoot string
	s := newTestSeatbelt(t, func(c *SeatbeltConfig) {
		spawnRoot = filepath.Join(filepath.Dir(c.StoreRoot), "spawn")
		if err := os.MkdirAll(filepath.Join(spawnRoot, "other"), 0o700); err != nil {
			t.Fatal(err)
		}
		c.SpawnRoot = spawnRoot
	})
	mustCreateStore(t, s, "w")
	mustCreateStore(t, s, "w2")
	siblingKey := filepath.Join(s.StorePath("w2"), "key")
	otherSock := filepath.Join(spawnRoot, "other", "k")
	for p, body := range map[string]string{siblingKey: "SIBLING-SECRET\n", otherSock: "SPAWN-SECRET\n"} {
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ownPID := s.pidFile("refexec-01")

	ctx := context.Background()
	script := `
cat "$1"; echo sibling=$?
cat "$2"; echo pidfile=$?
cat "$3"; echo spawn=$?
ls "$4"; echo lsroot=$?
stat -f %N "$5"; echo statsibling=$?
ln "$1" hl; echo hardlink=$?
cat hl; echo hardlinkread=$?
ln -s "$1" sl; echo symlink=$?
cat sl; echo symlinkread=$?
echo own > own && cat own; echo own=$?
`
	c, err := s.Launch(ctx, Spec{Name: "refexec-01", Store: "w", Argv: shellScript(script, siblingKey, ownPID, otherSock, s.cfg.StoreRoot, s.StorePath("w2"))})
	if err != nil {
		t.Fatal(err)
	}
	// Controls, while the compartment runs and its PID record exists.
	pidBody, err := os.ReadFile(ownPID)
	if err != nil || !strings.Contains(string(pidBody), `"pid"`) {
		t.Fatalf("control read of the PID record: %q, %v", pidBody, err)
	}
	for _, p := range []string{siblingKey, otherSock} {
		if _, err := os.ReadFile(p); err != nil {
			t.Fatalf("control read of %s: %v", p, err)
		}
	}
	wctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	res, err := c.Wait(wctx)
	if err != nil {
		t.Fatal(err)
	}
	out := string(res.Output)
	for _, secret := range []string{"SIBLING-SECRET", "SPAWN-SECRET", `"pid"`, "w2\n"} {
		if strings.Contains(out, secret) {
			t.Errorf("the compartment read %q:\n%s", secret, out)
		}
	}
	for _, want := range []string{"sibling=1", "pidfile=1", "spawn=1", "lsroot=1", "statsibling=1", "hardlink=1", "hardlinkread=1", "symlink=0", "symlinkread=1", "own=0"} {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Count(strings.ToLower(out), "operation not permitted") < 7 {
		t.Errorf("fewer refusals than denied reads:\n%s", out)
	}
	if !strings.Contains(out, "own\nown=0\n") {
		t.Errorf("own store read+write:\n%s", out)
	}
	if res.Exit != 0 {
		t.Errorf("exit %d", res.Exit)
	}
}

// The credential stores under the backend's home are unreadable even though
// reads are otherwise host-wide. Home here is a temp dir with the files the
// deny names.
func TestEnforceHomeSecretsUnreadable(t *testing.T) {
	s := newTestSeatbelt(t, nil)
	mustCreateStore(t, s, "w")
	secrets := map[string]string{
		filepath.Join(s.cfg.Home, ".ssh", "id"):             "SSH-SECRET\n",
		filepath.Join(s.cfg.Home, ".aws", "credentials"):    "AWS-SECRET\n",
		filepath.Join(s.cfg.Home, ".config", "gh", "hosts"): "GH-SECRET\n",
	}
	for p, body := range secrets {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, err := os.ReadFile(p); err != nil || string(got) != body {
			t.Fatalf("control read of %s: %q, %v", p, got, err)
		}
	}
	i := 0
	for p, body := range secrets {
		i++
		res := run(t, s, Spec{Name: fmt.Sprintf("refexec-%02d", i), Store: "w", Argv: []string{"cat", p}})
		denied(t, "read of "+p, res)
		if strings.Contains(string(res.Output), strings.TrimSpace(body)) {
			t.Fatalf("the secret in %s was read: %q", p, res.Output)
		}
	}
}

var lsCodeRE = regexp.MustCompile(`Code=(-?\d+)`)

// The LaunchServices deny cuts the path by which a confined `open` would make
// the user's unconfined browser carry a request. Both runs fail on an
// unregistered scheme, but the control fails in LaunchServices' evaluator
// (-10814, no application claims the scheme) and the sandboxed run fails
// earlier, with a different code (-10661 observed), because the service
// could not be reached.
func TestEnforceOpenDelegationFails(t *testing.T) {
	if _, err := os.Stat("/usr/bin/open"); err != nil {
		t.Skip("/usr/bin/open is not available")
	}
	s := newTestSeatbelt(t, nil)
	mustCreateStore(t, s, "w")
	const url = "agenthof-nonexistent-scheme://x"

	ctlOut, ctlCode := control(t, "", "/usr/bin/open", url)
	ctlMatch := lsCodeRE.FindStringSubmatch(ctlOut)
	if ctlCode == 0 || ctlMatch == nil {
		t.Fatalf("control open: exit %d, %q (want a LaunchServices error code)", ctlCode, ctlOut)
	}

	res := run(t, s, Spec{Name: "refexec-01", Store: "w", Argv: []string{"/usr/bin/open", url}})
	match := lsCodeRE.FindStringSubmatch(string(res.Output))
	if res.Exit == 0 || match == nil {
		t.Fatalf("sandboxed open: exit %d, %q", res.Exit, res.Output)
	}
	if match[1] == ctlMatch[1] {
		t.Fatalf("sandboxed open reached LaunchServices' evaluator like the control (code %s): the delegation path is open", match[1])
	}
}

// A bare program name in Argv[0] resolves in the backend's own environment,
// and the compartment itself gets no PATH. The shell form of that check is
// not usable: /bin/sh substitutes a built-in default when PATH is absent, so
// `echo ${PATH:-unset}` never prints "unset"; `env`, exec'd directly, prints
// the real environment, and sh does not export its default.
func TestEnforceBareProgramResolvesWithNoPATH(t *testing.T) {
	requireTool(t, "git")
	s := newTestSeatbelt(t, nil)
	mustCreateStore(t, s, "w")

	res := run(t, s, Spec{Name: "refexec-01", Store: "w", Argv: []string{"git", "--version"}, EnvNames: []string{}})
	if res.Exit != 0 || !strings.HasPrefix(string(res.Output), "git version") || len(res.EnvNames) != 0 {
		t.Fatalf("bare git: %+v (output %q)", res, res.Output)
	}
	res = run(t, s, Spec{Name: "refexec-02", Store: "w", Argv: []string{"env"}, EnvNames: []string{}})
	if res.Exit != 0 || len(res.Output) != 0 {
		t.Fatalf("the compartment's environment is not empty: exit %d, %q", res.Exit, res.Output)
	}
	res = run(t, s, Spec{Name: "refexec-03", Store: "w", Argv: shellScript(`env`)})
	if res.Exit != 0 || strings.Contains("\n"+string(res.Output), "\nPATH=") {
		t.Fatalf("sh exported a PATH: exit %d, %q", res.Exit, res.Output)
	}
}

// Signals reach the compartment's own descendants: a pipeline whose reader
// exits first (head closes, yes gets SIGPIPE) and a shell that kills a child
// it started both work.
func TestEnforcePipelineAndChildSignals(t *testing.T) {
	s := newTestSeatbelt(t, nil)
	mustCreateStore(t, s, "w")

	if out, code := control(t, "", "/bin/sh", "-c", "yes | head -1"); code != 0 || out != "y\n" {
		t.Fatalf("control pipeline: exit %d, %q", code, out)
	}
	res := run(t, s, Spec{Name: "refexec-01", Store: "w", Argv: shellScript(`yes | head -1`)})
	if res.Exit != 0 || string(res.Output) != "y\n" {
		t.Fatalf("pipeline: exit %d, %q", res.Exit, res.Output)
	}

	if out, code := control(t, "", "/bin/sh", "-c", "sleep 5 & kill $!; wait $!; echo done"); code != 0 || !strings.HasSuffix(out, "done\n") {
		t.Fatalf("control child signal: exit %d, %q", code, out)
	}
	start := time.Now()
	res = run(t, s, Spec{Name: "refexec-02", Store: "w", Argv: shellScript(`sleep 5 & kill $!; wait $!; echo done`)})
	if res.Exit != 0 || !strings.HasSuffix(string(res.Output), "done\n") {
		t.Fatalf("child signal: exit %d, %q", res.Exit, res.Output)
	}
	if elapsed := time.Since(start); elapsed >= 4*time.Second {
		t.Fatalf("the child was not signalled (took %v)", elapsed)
	}
}

// The shared host scratch is opt-in: the baseline refuses a write under /tmp
// and leaves nothing behind; a backend with SharedHostScratch allows it and
// reports the loosening in Opts.
func TestEnforceSharedHostScratchOptIn(t *testing.T) {
	s := newTestSeatbelt(t, nil)
	mustCreateStore(t, s, "w")
	suffix, err := randomSuffix()
	if err != nil {
		t.Fatal(err)
	}
	target := "/tmp/agenthof-probe-" + suffix
	if err := os.WriteFile(target, []byte("x\n"), 0o600); err != nil {
		t.Fatalf("control write: %v", err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}

	res := run(t, s, Spec{Name: "refexec-01", Store: "w", Argv: shellScript(`echo x > "$1"`, target)})
	denied(t, "write under /tmp", res)
	mustNotExist(t, target)
	if s.Opts() != nil {
		t.Fatalf("baseline Opts = %v", s.Opts())
	}

	shared := newTestSeatbelt(t, func(c *SeatbeltConfig) { c.SharedHostScratch = true })
	mustCreateStore(t, shared, "w")
	res = run(t, shared, Spec{Name: "refexec-01", Store: "w", Argv: shellScript(`echo x > "$1"`, target)})
	if res.Exit != 0 {
		t.Fatalf("shared-host-scratch write: exit %d, %q", res.Exit, res.Output)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("shared-host-scratch write left no file: %v", err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(shared.Opts(), []string{OptSharedHostScratch}) {
		t.Fatalf("Opts = %v", shared.Opts())
	}
}

// A realistic toolset under the final profile. Each command first runs
// unsandboxed in a control directory, so a sandboxed failure is the
// sandbox's. The profile line this pass needed: (allow file-read-metadata
// (literal <store root>)) after the store root's read deny, because a shell's
// cd into the store and git init (which stats every ancestor of the work
// tree) resolve a path THROUGH the denied root; the same literal is given to
// the spawn root. No /dev literal and no signal scope had to be widened.
func TestEnforceCompatibilityPass(t *testing.T) {
	s := newTestSeatbelt(t, nil)
	mustCreateStore(t, s, "w")
	store := s.StorePath("w")
	ctl := t.TempDir()

	type step struct {
		name string
		tool string // skipped when absent
		argv []string
		// ctlArgv is the control's argv when it differs from argv (a path
		// that must point at the control directory instead of the store).
		ctlArgv  []string
		wantExit int
		check    func(t *testing.T, out string)
	}
	exact := func(want string) func(*testing.T, string) {
		return func(t *testing.T, out string) {
			if strings.TrimSpace(out) != want {
				t.Fatalf("output %q, want %q", out, want)
			}
		}
	}
	contains := func(want string) func(*testing.T, string) {
		return func(t *testing.T, out string) {
			if !strings.Contains(out, want) {
				t.Fatalf("output %q lacks %q", out, want)
			}
		}
	}
	steps := []step{
		{name: "cd into the store", argv: shellScript(`cd "$1" && pwd`, store), ctlArgv: shellScript(`cd "$1" && pwd`, ctl), check: exact(store)},
		{name: "git init", tool: "git", argv: []string{"git", "init", "-q"}},
		{name: "git commit", tool: "git", argv: []string{"git", "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-q", "--allow-empty", "-m", "x"}},
		{name: "git log", tool: "git", argv: []string{"git", "log", "--oneline"}, check: contains(" x\n")},
		{name: "python3 listdir", tool: "python3", argv: []string{"python3", "-c", `import json,os; print(json.dumps(sorted(os.listdir("."))))`}, check: contains(`".git"`)},
		{name: "tar create and list", tool: "tar", argv: shellScript(`tar -cf "$TMPDIR/t.tar" . && tar -tf "$TMPDIR/t.tar"`), check: contains("./.git/")},
		{name: "shell pipeline", argv: shellScript(`printf a | tr a b | wc -c`), check: exact("1")},
		{name: "ls -la /", argv: []string{"ls", "-la", "/"}, check: contains(" usr\n")},
		{name: "cat /etc/hosts", argv: []string{"cat", "/etc/hosts"}, check: contains("localhost")},
	}
	for i, st := range steps {
		t.Run(st.name, func(t *testing.T) {
			if st.tool != "" {
				requireTool(t, st.tool)
			}
			// The control runs the same argv in its own directory, with the
			// TMPDIR the sandboxed run will have replaced by its scratch dir.
			ctlArgv := st.argv
			if st.ctlArgv != nil {
				ctlArgv = st.ctlArgv
			}
			cmd := exec.Command(ctlArgv[0], ctlArgv[1:]...)
			cmd.Dir = ctl
			cmd.Env = []string{"TMPDIR=" + ctl}
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("control %v: %v, %q", st.argv, err, out)
			}
			res := run(t, s, Spec{Name: fmt.Sprintf("refexec-%02d", i), Store: "w", Scratch: true, Argv: st.argv})
			if res.Exit != st.wantExit {
				t.Fatalf("%v: exit %d, want %d; output %q", st.argv, res.Exit, st.wantExit, res.Output)
			}
			if st.check != nil {
				st.check(t, string(res.Output))
			}
		})
	}

	// curl to a denied address: exit 7 (could not connect), and at once. The
	// control shows the host can reach it; a host that cannot is skipped, not
	// read as enforcement.
	t.Run("curl denied", func(t *testing.T) {
		curl := requireTool(t, "curl")
		if out, code := control(t, ctl, curl, "-sS", "--max-time", "3", "http://1.1.1.1/"); code == 7 {
			t.Skipf("the unsandboxed curl could not connect either (%q): a sandboxed refusal could not be attributed", out)
		}
		start := time.Now()
		res := run(t, s, Spec{Name: "refexec-curl", Store: "w", Scratch: true, Argv: []string{"curl", "-sS", "--max-time", "3", "http://1.1.1.1/"}})
		if res.Exit != 7 {
			t.Fatalf("sandboxed curl: exit %d, want 7; %q", res.Exit, res.Output)
		}
		if elapsed := time.Since(start); elapsed >= 2*time.Second {
			t.Fatalf("sandboxed curl took %v: a timeout, not a refusal", elapsed)
		}
	})
}
