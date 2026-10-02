package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// The test binary re-executes itself in four roles so the real supervisor
// can be driven with no podman: as `podman` (fakePodmanFlag), as the agent
// image's entrypoint (fakeAgentFlag), as refexec (fakeRefexecFlag), and as
// the hermetic e2e's whole stub (stubFlag, stub_test.go). The shipped
// refspawn has none of these modes; this is test-tree code only.
const (
	fakePodmanFlag  = "-refspawn-test-podman"
	fakeAgentFlag   = "-refspawn-test-agent"
	fakeRefexecFlag = "-refspawn-test-refexec"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case fakePodmanFlag:
			os.Exit(fakePodman(os.Args[2:]))
		case fakeAgentFlag:
			os.Exit(fakeAgent(os.Args[2:]))
		case fakeRefexecFlag:
			os.Exit(fakeRefexec(os.Args[2:]))
		case stubFlag:
			os.Exit(runStub(os.Args[2:]))
		}
	}
	os.Exit(m.Run())
}

// fakeRecord is one line of the fake's log (REFSPAWN_TEST_ARGLOG): what
// podman — or the fake refexec — was asked, and which child it started.
type fakeRecord struct {
	Op    string   `json:"op"` // run | rm | volume-create | volume-rm | refexec-start | refexec-term
	PID   int      `json:"pid"`
	Child int      `json:"child,omitempty"`
	Name  string   `json:"name"`
	Args  []string `json:"args"`
}

func record(rec fakeRecord) {
	log := os.Getenv("REFSPAWN_TEST_ARGLOG")
	if log == "" {
		return
	}
	f, err := os.OpenFile(log, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	b, _ := json.Marshal(rec)
	_, _ = f.Write(append(b, '\n'))
}

// volroot is where the fake keeps "volumes" (a directory each) and the pid
// files of running "containers": REFSPAWN_TEST_VOLROOT, per test.
func volroot() string { return os.Getenv("REFSPAWN_TEST_VOLROOT") }

func pidfile(name string) string { return filepath.Join(volroot(), ".pids", name+".pid") }

// mountfile records which volume a running "container" has mounted, so the
// fake can refuse `volume rm` the way podman does. Written beside the pid
// file and removed with it.
func mountfile(name string) string { return filepath.Join(volroot(), ".pids", name+".vol") }

// mounted reports whether any running "container" still holds volume.
func mounted(volume string) bool {
	matches, _ := filepath.Glob(filepath.Join(volroot(), ".pids", "*.vol"))
	for _, m := range matches {
		if b, err := os.ReadFile(m); err == nil && strings.TrimSpace(string(b)) == volume {
			return true
		}
	}
	return false
}

// twoArgFlags are the `podman run` flags refspawn passes with a separate value.
var twoArgFlags = map[string]bool{"--name": true, "--network": true, "--tmpfs": true, "--security-opt": true, "--user": true, "-v": true, "-e": true, "-w": true}

// fakePodman answers `run` by starting the image as a host program with the
// argv after it (plus -workspace <dir> for a `-v <vol>:/work` mount, so a
// write to the workspace lands in the volume's directory), writing the
// child's pid under the container name and exiting with the child's
// status; `rm -f NAME` kills that child; `volume create|rm|ls` keep a
// directory per volume; `ps -aq --filter name=^P` lists running names.
// Anything else is a podman usage error (125). An image that is this test
// binary itself runs as the fake agent.
func fakePodman(args []string) int {
	if len(args) == 0 || volroot() == "" {
		return 125
	}
	switch args[0] {
	case "run":
		return fakeRun(args)
	case "rm":
		name := args[len(args)-1]
		record(fakeRecord{Op: "rm", PID: os.Getpid(), Name: name, Args: args})
		if b, err := os.ReadFile(pidfile(name)); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
			_ = os.Remove(pidfile(name))
			_ = os.Remove(mountfile(name))
		}
		return 0
	case "ps":
		prefix := filterPrefix(args)
		matches, _ := filepath.Glob(filepath.Join(volroot(), ".pids", "*.pid"))
		for _, m := range matches {
			name := strings.TrimSuffix(filepath.Base(m), ".pid")
			if strings.HasPrefix(name, prefix) {
				fmt.Println(name)
			}
		}
		return 0
	case "volume":
		if len(args) < 2 {
			return 125
		}
		switch args[1] {
		case "create":
			name := args[len(args)-1]
			record(fakeRecord{Op: "volume-create", PID: os.Getpid(), Name: name, Args: args})
			if err := os.MkdirAll(filepath.Join(volroot(), name), 0o755); err != nil {
				return 125
			}
			return 0
		case "rm":
			name := args[len(args)-1]
			record(fakeRecord{Op: "volume-rm", PID: os.Getpid(), Name: name, Args: args})
			// Like podman: a mounted volume goes only under -f.
			if !hasFlag(args, "-f") && mounted(name) {
				fmt.Fprintf(os.Stderr, "Error: volume %s is being used by a container\n", name)
				return 125
			}
			_ = os.RemoveAll(filepath.Join(volroot(), name))
			return 0
		case "ls":
			prefix := filterPrefix(args)
			entries, _ := os.ReadDir(volroot())
			for _, e := range entries {
				if e.IsDir() && strings.HasPrefix(e.Name(), prefix) {
					fmt.Println(e.Name())
				}
			}
			return 0
		}
	}
	return 125
}

func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

// filterPrefix reads `--filter name=^PREFIX` off a ps / volume ls argv.
func filterPrefix(args []string) string {
	for i, a := range args {
		if a == "--filter" && i+1 < len(args) {
			return strings.TrimPrefix(strings.TrimPrefix(args[i+1], "name="), "^")
		}
	}
	return ""
}

func fakeRun(args []string) int {
	var name, image, volume, workspace string
	var argv []string
	rest := args[1:]
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
			case "-v":
				if vol, ok := strings.CutSuffix(rest[i+1], ":/work"); ok {
					volume, workspace = vol, filepath.Join(volroot(), vol)
				}
			}
			i++
		}
	}
	if image == "" || name == "" {
		return 125
	}
	if exe, err := os.Executable(); err == nil && image == exe {
		argv = append([]string{fakeAgentFlag}, argv...)
	}
	if workspace != "" {
		if err := os.MkdirAll(workspace, 0o755); err != nil {
			return 125
		}
		argv = append(argv, "-workspace", workspace)
	}
	cmd := exec.Command(image, argv...)
	cmd.Env = os.Environ()
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "fake podman:", err)
		return 125
	}
	_ = os.MkdirAll(filepath.Join(volroot(), ".pids"), 0o755)
	_ = os.WriteFile(pidfile(name), []byte(strconv.Itoa(cmd.Process.Pid)), 0o600)
	if volume != "" {
		_ = os.WriteFile(mountfile(name), []byte(volume), 0o600)
	}
	record(fakeRecord{Op: "run", PID: os.Getpid(), Child: cmd.Process.Pid, Name: name, Args: args})
	err := cmd.Wait()
	_ = os.Remove(pidfile(name))
	_ = os.Remove(mountfile(name))
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if code := ee.ExitCode(); code >= 0 {
			return code
		}
		return 137
	}
	if err != nil {
		return 125
	}
	return 0
}

// fakeAgent is the "image": it serves the fronted step contract on -socket
// and ignores -workspace, like the echo agent would. It runs until killed.
func fakeAgent(args []string) int {
	fs := flag.NewFlagSet("fake-agent", flag.ContinueOnError)
	socket := fs.String("socket", "", "")
	fs.String("workspace", "", "")
	if err := fs.Parse(args); err != nil || *socket == "" {
		return 2
	}
	_ = os.Remove(*socket)
	ln, err := net.Listen("unix", *socket)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fake agent:", err)
		return 1
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"artifact":"fake","success":true}`))
	})}
	_ = srv.Serve(ln)
	return 0
}

// fakeRefexec stands in for the refexec host process: it reads the socket
// path off the rendered config, listens there, records that it started,
// and exits 0 on SIGTERM after recording that too — so a test can see the
// teardown order. The start is recorded BEFORE the listen: a socket is
// dialable the instant it exists, so recording after would let a
// provision answer before its own record landed.
func fakeRefexec(args []string) int {
	fs := flag.NewFlagSet("fake-refexec", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "")
	if err := fs.Parse(args); err != nil || *cfgPath == "" {
		return 2
	}
	data, err := os.ReadFile(*cfgPath)
	if err != nil {
		return 2
	}
	var socket string
	for _, l := range strings.Split(string(data), "\n") {
		if s, ok := strings.CutPrefix(l, "socket: "); ok {
			socket = strings.TrimSpace(s)
		}
	}
	if socket == "" {
		return 2
	}
	record(fakeRecord{Op: "refexec-start", PID: os.Getpid(), Name: socket, Args: args})
	ln, err := net.Listen("unix", socket)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fake refexec:", err)
		return 1
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM)
	go func() {
		<-stop
		record(fakeRecord{Op: "refexec-term", PID: os.Getpid(), Name: socket})
		_ = srv.Close()
	}()
	_ = srv.Serve(ln)
	return 0
}
