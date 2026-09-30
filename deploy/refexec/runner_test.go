package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func testConfig() execConfig {
	return execConfig{
		Socket: "/tmp/never/refexec.sock", Image: "example.test/exec:1",
		WorkspaceVolume: "work", WorkspacePath: "/work", Timeout: 30 * time.Second,
		Memory: "256m", CPUs: "1", PIDs: 64, MaxCompartments: 2,
		EnvAllow: []string{"REFEXEC_TEST_UNSET", "REFEXEC_TEST_MARKER"},
	}
}

// fakeRunner is a runner over the fake podman, with its log in a temp file.
func fakeRunner(t *testing.T, cfg execConfig) (*runner, string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(t.TempDir(), "podman.jsonl")
	t.Setenv("REFEXEC_TEST_ARGLOG", log)
	return newRunner(cfg, slog.New(slog.DiscardHandler), []string{exe, fakePodmanFlag}), log
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
			continue // a line the fake is still writing; the next poll sees it whole
		}
		out = append(out, r)
	}
	return out
}

func waitForRun(t *testing.T, log string) fakeRecord {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, r := range records(t, log) {
			if r.Op == "run" {
				return r
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("podman run was never invoked")
	return fakeRecord{}
}

func TestRunReturnsExitOutputAndAttestation(t *testing.T) {
	t.Setenv("REFEXEC_TEST_MARKER", "1")
	t.Setenv("REFEXEC_TEST_LEAK", "not-for-the-command")
	r, log := fakeRunner(t, testConfig())
	argv := []string{"sh", "-c", "echo out-$REFEXEC_TEST_MARKER; echo leak=$REFEXEC_TEST_LEAK; exit 3"}
	res, err := r.run(context.Background(), argv)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.ExitCode != 3 || string(res.Output) != "out-1\nleak=\n" || res.Truncated || res.OutputBytes != 12 {
		t.Fatalf("result = %+v (output %q)", res, res.Output)
	}
	rec := waitForRun(t, log)
	att := res.Attestation
	if att.Runtime != "refexec" || !reflect.DeepEqual(att.Command, argv) || att.Spawn != 1 || att.CredentialEnv != "" || att.Materialization != "" ||
		!strings.HasPrefix(att.Session, "refexec-") || att.Session != rec.Name || att.PID != rec.PID || att.PID == rec.Child {
		t.Fatalf("attestation = %+v, want the podman client's pid %d (not the child %d) and session == container name %q", att, rec.PID, rec.Child, rec.Name)
	}
	if !reflect.DeepEqual(att.EnvNames, []string{"REFEXEC_TEST_MARKER"}) {
		t.Fatalf("env_names = %v, want only the allowlisted name that is set", att.EnvNames)
	}
}

func TestRunPodmanSelfFailureIsDoorFailure(t *testing.T) {
	r, _ := fakeRunner(t, testConfig())
	// 125 is podman's own reserved failure code (missing image, storage error):
	// the command never ran, so refexec must return an error — the gateway then
	// records a door failure — rather than attest 125 as the command's exit.
	if _, err := r.run(context.Background(), []string{"sh", "-c", "exit 125"}); err == nil {
		t.Fatal("exit 125 must be a runner error, not an attested exit")
	}
}

func TestPodmanRunIsLockedDown(t *testing.T) {
	t.Setenv("REFEXEC_TEST_MARKER", "1")
	r, log := fakeRunner(t, testConfig())
	if _, err := r.run(context.Background(), []string{"true"}); err != nil {
		t.Fatalf("run: %v", err)
	}
	rec := waitForRun(t, log)
	joined := " " + strings.Join(rec.Args, " ") + " "
	for _, want := range []string{
		" run --rm --name " + rec.Name + " ", " --pull=never ", " --network none ", " --read-only ", " --tmpfs /tmp ",
		" --cap-drop=ALL ", " --security-opt no-new-privileges ", " --userns=keep-id ",
		" --user " + fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()) + " ",
		" --memory=256m ", " --cpus=1 ", " --pids-limit=64 ", " --timeout=30 ",
		" -v work:/work ", " -w /work ", " -e REFEXEC_TEST_MARKER ", " example.test/exec:1 true ",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("podman args lack %q:\n%s", want, joined)
		}
	}
	if strings.Count(joined, " -v ") != 1 || strings.Contains(joined, " --mount") {
		t.Fatalf("exactly one -v and no --mount: %s", joined)
	}
	for _, never := range []string{"REFEXEC_TEST_UNSET", "REFEXEC_TEST_MARKER=1", "--privileged"} {
		if strings.Contains(joined, never) {
			t.Fatalf("podman args must not contain %q:\n%s", never, joined)
		}
	}
	if rec.Args[len(rec.Args)-1] != "true" || rec.Args[len(rec.Args)-2] != "example.test/exec:1" {
		t.Fatalf("image then argv must end the invocation: %v", rec.Args)
	}
}

func TestPodmanRunArgsShape(t *testing.T) {
	cfg := testConfig()
	cfg.Timeout = 1500 * time.Millisecond
	args := podmanRunArgs(cfg, "refexec-00", []string{"A", "B"}, []string{"cat", "/work/x"})
	joined := strings.Join(args, " ")
	if !strings.HasSuffix(joined, " -e A -e B example.test/exec:1 cat /work/x") || !strings.Contains(joined, " --timeout=1 ") {
		t.Fatalf("args = %q", joined)
	}
}

// The command runs with an EMPTY environment (the fake mirrors podman), so
// `sh -c` finds `yes` and `head` only through the shell's compiled-in default
// PATH — true for dash (Ubuntu) and for macOS's /bin/sh. A failure here on
// another /bin/sh is that, not the cap.
func TestOutputIsCappedAndCounted(t *testing.T) {
	r, _ := fakeRunner(t, testConfig())
	res, err := r.run(context.Background(), []string{"sh", "-c", "yes | head -c 1200000"})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !res.Truncated || res.OutputBytes != 1200000 || len(res.Output) != maxOutput+len(truncationMarker) || !strings.HasSuffix(string(res.Output), truncationMarker) {
		t.Fatalf("truncated=%v bytes=%d len=%d", res.Truncated, res.OutputBytes, len(res.Output))
	}
}

func TestCancelRemovesCompartment(t *testing.T) {
	r, log := fakeRunner(t, testConfig())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := r.run(ctx, []string{"sleep", "30"})
		done <- err
	}()
	rec := waitForRun(t, log)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("run err = %v, want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return after cancel")
	}
	var removed bool
	for _, x := range records(t, log) {
		if x.Op == "rm" && x.Name == rec.Name && strings.Join(x.Args, " ") == "rm -f "+rec.Name {
			removed = true
		}
	}
	if !removed {
		t.Fatalf("cancel must run `podman rm -f %s`; log: %+v", rec.Name, records(t, log))
	}
	if err := syscall.Kill(rec.Child, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("the compartment's process %d is still alive (kill 0 = %v)", rec.Child, err)
	}
}

func TestCapRefusesWhenFull(t *testing.T) {
	cfg := testConfig()
	cfg.MaxCompartments = 1
	r, log := fakeRunner(t, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _, _ = r.run(ctx, []string{"sleep", "30"}) }()
	waitForRun(t, log)
	if _, err := r.run(context.Background(), []string{"true"}); !errors.Is(err, errCapReached) {
		t.Fatalf("second run err = %v, want errCapReached", err)
	}
	cancel()
	r.close()
	if _, err := r.run(context.Background(), []string{"true"}); err != nil {
		t.Fatalf("after the slot is released a run must succeed: %v", err)
	}
}

func TestPodmanMissingIsAnError(t *testing.T) {
	r := newRunner(testConfig(), slog.New(slog.DiscardHandler), []string{"/nonexistent/podman"})
	if _, err := r.run(context.Background(), []string{"true"}); err == nil || !strings.Contains(err.Error(), "start podman") {
		t.Fatalf("err = %v, want a start podman failure", err)
	}
}

func TestTextOfReplacesInvalidBytesOneForOne(t *testing.T) {
	got := textOf([]byte("ok\xff\xfe!"))
	if got != "ok\uFFFD\uFFFD!" {
		t.Fatalf("textOf = %q", got)
	}
	if textOf([]byte("plain")) != "plain" {
		t.Fatal("valid UTF-8 must pass through")
	}
}

func TestHandlerServesRun(t *testing.T) {
	t.Setenv("REFEXEC_TEST_MARKER", "1")
	r, _ := fakeRunner(t, testConfig())
	srv := httptest.NewServer(r.handler())
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/run", "application/json", strings.NewReader(`{"command":["sh","-c","printf hi"]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var out struct {
		ExitCode    int            `json:"exit_code"`
		Output      string         `json:"output"`
		OutputSHA   string         `json:"output_sha"`
		Truncated   bool           `json:"truncated"`
		OutputBytes int            `json:"output_bytes"`
		Attestation map[string]any `json:"runtime_attestation"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("hi"))
	if out.ExitCode != 0 || out.Output != "hi" || out.OutputSHA != hex.EncodeToString(sum[:]) || out.Truncated || out.OutputBytes != 2 {
		t.Fatalf("response = %+v", out)
	}
	for _, k := range []string{"runtime", "session", "command", "pid", "spawn", "credential_env", "env_names", "materialization"} {
		if _, ok := out.Attestation[k]; !ok {
			t.Fatalf("attestation lacks %q: %v", k, out.Attestation)
		}
	}
	if out.Attestation["runtime"] != "refexec" || out.Attestation["credential_env"] != "" || out.Attestation["materialization"] != "" || out.Attestation["spawn"] != float64(1) {
		t.Fatalf("attestation = %v", out.Attestation)
	}
	if names, ok := out.Attestation["env_names"].([]any); !ok || len(names) != 1 || names[0] != "REFEXEC_TEST_MARKER" {
		t.Fatalf("env_names = %v, want a JSON array (never null) of the injected names", out.Attestation["env_names"])
	}
}

func TestHandlerHashesTheTransmittedOutput(t *testing.T) {
	r, _ := fakeRunner(t, testConfig())
	srv := httptest.NewServer(r.handler())
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/run", "application/json", strings.NewReader(`{"command":["sh","-c","printf '\\377\\376ok'"]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		Output    string `json:"output"`
		OutputSHA string `json:"output_sha"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(out.Output))
	if out.Output != "\uFFFD\uFFFDok" || out.OutputSHA != hex.EncodeToString(sum[:]) {
		t.Fatalf("output %q sha %s: the hash must cover exactly the string received", out.Output, out.OutputSHA)
	}
}

func TestHandlerRejectsBadRequests(t *testing.T) {
	r, _ := fakeRunner(t, testConfig())
	srv := httptest.NewServer(r.handler())
	defer srv.Close()
	for name, body := range map[string]string{"empty argv": `{"command":[]}`, "empty exe": `{"command":[""]}`, "not json": `nope`} {
		resp, err := http.Post(srv.URL+"/run", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Fatalf("%s: status = %d, want 400", name, resp.StatusCode)
		}
	}
	resp, err := http.Get(srv.URL + "/run")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 405 {
		t.Fatalf("GET status = %d, want 405", resp.StatusCode)
	}
}

func TestHandlerAnswers503AtTheCap(t *testing.T) {
	cfg := testConfig()
	cfg.MaxCompartments = 1
	r, log := fakeRunner(t, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _, _ = r.run(ctx, []string{"sleep", "30"}) }()
	waitForRun(t, log)
	srv := httptest.NewServer(r.handler())
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/run", "application/json", strings.NewReader(`{"command":["true"]}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Fatalf("status = %d, want 503 at the cap", resp.StatusCode)
	}
}

func TestForgeCommandRewritesTheAttestedArgv(t *testing.T) {
	r, _ := fakeRunner(t, testConfig())
	srv := httptest.NewServer(forgeCommand(r.handler()))
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/run", "application/json", strings.NewReader(`{"command":["true"]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		Attestation struct {
			Command []string `json:"command"`
		} `json:"runtime_attestation"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Attestation.Command) != 1 || out.Attestation.Command[0] != "forged" {
		t.Fatalf("attested command = %v, want [forged]", out.Attestation.Command)
	}
}
