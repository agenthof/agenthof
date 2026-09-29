package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// fakePodmanFlag re-executes this test binary as `podman`: the tests and the
// hermetic e2e's stub run the real refexec with this in place of podman, so
// each "compartment" is the argv run directly on the host. The shipped
// refexec has no such mode; this is test-tree code only.
const fakePodmanFlag = "-refexec-test-podman"

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == fakePodmanFlag {
		os.Exit(fakePodman(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == stubFlag {
		os.Exit(runStub(os.Args[2:]))
	}
	os.Exit(m.Run())
}

// twoArgFlags are the `podman run` flags refexec passes with a separate value.
var twoArgFlags = map[string]bool{"--name": true, "--network": true, "--tmpfs": true, "--security-opt": true, "--user": true, "-v": true, "-e": true, "-w": true}

// fakeRecord is one line of the fake's log (REFEXEC_TEST_ARGLOG): what podman
// was asked, by which client process, and which child it started.
type fakeRecord struct {
	Op    string   `json:"op"`
	PID   int      `json:"pid"`
	Child int      `json:"child,omitempty"`
	Name  string   `json:"name"`
	Args  []string `json:"args"`
}

func pidfile(name string) string { return filepath.Join(os.TempDir(), "refexec-fake-"+name+".pid") }

func record(rec fakeRecord) {
	log := os.Getenv("REFEXEC_TEST_ARGLOG")
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

// fakePodman answers `run` by starting the argv after the image with an
// environment of exactly the -e names (their values from its own
// environment, as podman does), writing the child's pid under the container
// name, and exiting with the child's status; and `rm -f NAME` by killing
// that child. Everything else is a podman usage error (125).
func fakePodman(args []string) int {
	if len(args) == 0 {
		return 125
	}
	switch args[0] {
	case "rm":
		name := args[len(args)-1]
		record(fakeRecord{Op: "rm", PID: os.Getpid(), Name: name, Args: args})
		if b, err := os.ReadFile(pidfile(name)); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
			_ = os.Remove(pidfile(name))
		}
		return 0
	case "run":
		var name, image string
		var argv []string
		env := []string{} // non-nil: an empty environment, never an inherited one
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
				case "-e":
					env = append(env, rest[i+1]+"="+os.Getenv(rest[i+1]))
				}
				i++
			}
		}
		if image == "" || name == "" || len(argv) == 0 {
			return 125
		}
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Env = env
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Start(); err != nil {
			fmt.Fprintln(os.Stderr, "fake podman:", err)
			return 125
		}
		_ = os.WriteFile(pidfile(name), []byte(strconv.Itoa(cmd.Process.Pid)), 0o600)
		record(fakeRecord{Op: "run", PID: os.Getpid(), Child: cmd.Process.Pid, Name: name, Args: args})
		err := cmd.Wait()
		_ = os.Remove(pidfile(name))
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
	return 125
}
