// Command echo-agent is a minimal reference fronted agent: it implements
// Agenthof's fronted-agent HTTP contract and echoes each step's input back as
// the artifact. It holds no credentials and keeps no state — a starting point
// for writing a conforming agent, and what the quickstart/demo run against.
//
// A step whose input starts with a directive is a script instead of an echo:
//
//	write:<text>                         write <text> to <workspace>/agent-note.txt
//	read:                                the body of <workspace>/agent-note.txt, or "absent"
//	ls:                                  the names in <workspace>, sorted and comma-joined, or "empty"
//	touch-run:                           create <workspace>/<run id>.txt (the run id from X-Agenthof-Run-Id);
//	                                     the artifact is "touched <run id>.txt"
//	only:<agent>:<directive>             run <directive> only when this step's agent is <agent>; otherwise
//	                                     the artifact is "skipped" — how one script drives the different
//	                                     agents of a multi-step workflow
//	exec-run:<argv>                      ask Agenthof's exec door to run argv (first-hand, when
//	                                     the agent's exec is mode runtime); the output is the artifact
//	exec-attest:<argv>                   report argv through /exec/attest; the artifact is attest:<status>
//	spawn:<role>/<workflow>:<input>      ask Agenthof's spawn door to run a governed child run; the
//	                                     artifact is "spawn <status> <child run id> <preview>" (a refusal
//	                                     is an answer, reported the same way, not a failed step)
//	spawn-parallel:<n>:<role>/<workflow>:<input>
//	                                     n such spawns at once; one line each, sorted
//	sleep:<seconds>                      wait (cancelled with the step); the artifact is "slept <n>s"
//
// Directives are separated by ";" and the last one's result is the artifact.
// A child's own script, written inside a spawn directive, separates ITS
// directives with "|": the spawn directives turn each "|" into ";" before
// posting, since the parent's script was already split on ";". Every door
// call is made under the step request's context: when Agenthof gives up on
// the step, the agent's calls — and the children behind them — are
// cancelled too.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type request struct {
	Input     string            `json:"input"`
	Artifacts map[string]string `json:"artifacts"`
	Agent     string            `json:"agent"`
}

type response struct {
	Artifact string `json:"artifact"`
	Success  bool   `json:"success"`
	Reason   string `json:"reason,omitempty"`
}

func newMux(callGateway bool, workspace string) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleStep(w, r, callGateway, workspace)
	})
	return mux
}

func handleStep(w http.ResponseWriter, r *http.Request, callGateway bool, workspace string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req request
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	proxyURL, token := r.Header.Get("X-Agenthof-Proxy-URL"), r.Header.Get("X-Agenthof-Run-Token")
	if isScript(req.Input) {
		// The script reaches the gateway itself; no separate probe.
		env := stepEnv{proxyURL: proxyURL, token: token, workspace: workspace, agent: req.Agent, runID: r.Header.Get("X-Agenthof-Run-Id")}
		artifact, err := runScript(r.Context(), env, req.Input)
		if err != nil {
			_ = json.NewEncoder(w).Encode(response{Success: false, Reason: err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(response{Artifact: artifact, Success: true})
		return
	}
	if callGateway {
		if err := probeGateway(r.Context(), proxyURL, token); err != nil {
			_ = json.NewEncoder(w).Encode(response{Success: false, Reason: "gateway unreachable: " + err.Error()})
			return
		}
	}
	_ = json.NewEncoder(w).Encode(response{Artifact: req.Input, Success: true})
}

var directives = []string{"write:", "read:", "ls:", "touch-run:", "only:", "exec-run:", "exec-attest:", "spawn:", "spawn-parallel:", "sleep:"}

func isScript(input string) bool {
	input = strings.TrimSpace(input)
	for _, d := range directives {
		if strings.HasPrefix(input, d) {
			return true
		}
	}
	return false
}

// stepEnv is what one step's directives run with: the gateway coordinates,
// the workspace, and which agent and run this step is.
type stepEnv struct {
	proxyURL, token, workspace, agent, runID string
}

// runScript runs the ";"-separated directives in order and returns the last
// one's result. The first failure ends the script.
func runScript(ctx context.Context, env stepEnv, input string) (string, error) {
	artifact := ""
	for _, part := range strings.Split(input, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out, err := runOne(ctx, env, part)
		if err != nil {
			return "", err
		}
		artifact = out
	}
	return artifact, nil
}

// runOne runs a single directive.
func runOne(ctx context.Context, env stepEnv, part string) (string, error) {
	switch {
	case strings.HasPrefix(part, "write:"):
		path := filepath.Join(env.workspace, "agent-note.txt")
		if err := os.WriteFile(path, []byte(strings.TrimPrefix(part, "write:")+"\n"), 0o644); err != nil {
			return "", fmt.Errorf("write: %w", err)
		}
		return "wrote " + path, nil
	case strings.HasPrefix(part, "read:"):
		b, err := os.ReadFile(filepath.Join(env.workspace, "agent-note.txt"))
		if errors.Is(err, os.ErrNotExist) {
			return "absent", nil
		}
		if err != nil {
			return "", fmt.Errorf("read: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	case strings.HasPrefix(part, "ls:"):
		entries, err := os.ReadDir(env.workspace)
		if err != nil {
			return "", fmt.Errorf("ls: %w", err)
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		if len(names) == 0 {
			return "empty", nil
		}
		sort.Strings(names)
		return strings.Join(names, ","), nil
	case strings.HasPrefix(part, "touch-run:"):
		if env.runID == "" {
			return "", errors.New("touch-run: the request carries no X-Agenthof-Run-Id")
		}
		// The run id names a file, so it must stay one plain name inside the workspace.
		if strings.ContainsFunc(env.runID, func(r rune) bool {
			return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_'
		}) {
			return "", fmt.Errorf("touch-run: run id %q is not a plain name", env.runID)
		}
		name := env.runID + ".txt"
		if err := os.WriteFile(filepath.Join(env.workspace, name), nil, 0o644); err != nil {
			return "", fmt.Errorf("touch-run: %w", err)
		}
		return "touched " + name, nil
	case strings.HasPrefix(part, "only:"):
		target, rest, ok := strings.Cut(strings.TrimPrefix(part, "only:"), ":")
		if !ok || target == "" || strings.TrimSpace(rest) == "" {
			return "", fmt.Errorf("only: want <agent>:<directive>, got %q", part)
		}
		if target != env.agent {
			return "skipped", nil
		}
		return runOne(ctx, env, strings.TrimSpace(rest))
	case strings.HasPrefix(part, "exec-run:"):
		return execRun(ctx, env.proxyURL, env.token, strings.Fields(strings.TrimPrefix(part, "exec-run:")))
	case strings.HasPrefix(part, "exec-attest:"):
		status, err := execAttest(ctx, env.proxyURL, env.token, strings.Fields(strings.TrimPrefix(part, "exec-attest:")))
		if err != nil {
			return "", err
		}
		return "attest:" + strconv.Itoa(status), nil
	case strings.HasPrefix(part, "spawn:"):
		return spawnOne(ctx, env.proxyURL, env.token, strings.TrimPrefix(part, "spawn:"))
	case strings.HasPrefix(part, "spawn-parallel:"):
		lines, err := spawnParallel(ctx, env.proxyURL, env.token, strings.TrimPrefix(part, "spawn-parallel:"))
		if err != nil {
			return "", err
		}
		return strings.Join(lines, "\n"), nil
	case strings.HasPrefix(part, "sleep:"):
		secs, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(part, "sleep:")))
		if err != nil || secs < 0 || secs > 600 {
			return "", errors.New("sleep: want a whole number of seconds from 0 to 600")
		}
		select {
		case <-time.After(time.Duration(secs) * time.Second):
		case <-ctx.Done():
			return "", fmt.Errorf("sleep: %w", ctx.Err())
		}
		return "slept " + strconv.Itoa(secs) + "s", nil
	}
	return "", fmt.Errorf("unknown directive %q", part)
}

// execRun asks the exec door to run argv and returns the command's output.
func execRun(ctx context.Context, proxyURL, token string, argv []string) (string, error) {
	if len(argv) == 0 {
		return "", errors.New("exec-run: no command")
	}
	resp, err := postDoor(ctx, proxyURL, token, "/exec/run", map[string]any{"command": argv})
	if err != nil {
		return "", fmt.Errorf("exec-run: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("exec-run: gateway returned %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	var out struct {
		Exit      int    `json:"exit"`
		Output    string `json:"output"`
		Truncated bool   `json:"truncated"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&out); err != nil {
		return "", fmt.Errorf("exec-run: decode: %w", err)
	}
	if out.Exit != 0 {
		return "", fmt.Errorf("exec-run: %s exited %d", argv[0], out.Exit)
	}
	return out.Output, nil
}

// execAttest reports argv as run with exit 0 and returns the door's status:
// a first-hand agent is refused here, which the artifact then shows.
func execAttest(ctx context.Context, proxyURL, token string, argv []string) (int, error) {
	resp, err := postDoor(ctx, proxyURL, token, "/exec/attest", map[string]any{"command": argv, "exit": 0, "output_sha": ""})
	if err != nil {
		return 0, fmt.Errorf("exec-attest: %w", err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

// spawnOne asks the spawn door to run <role>/<workflow>:<input> and reports
// the door's answer as one line: "spawn <status> <child run id or -> <preview
// or reason>". A refusal (403) is an answer the line carries, not a failed
// step — the parent's ledger already records it; any other non-200 fails
// the step. The input runs to the end of the spec, colons included; its "|"
// become ";" so the child can run a script of its own.
func spawnOne(ctx context.Context, proxyURL, token, spec string) (string, error) {
	target, input, ok := strings.Cut(spec, ":")
	role, workflow, ok2 := strings.Cut(target, "/")
	if !ok || !ok2 || role == "" || workflow == "" {
		return "", fmt.Errorf("spawn: want <role>/<workflow>:<input>, got %q", spec)
	}
	// The child's script separates its directives with "|": this script was
	// already split on ";".
	input = strings.ReplaceAll(input, "|", ";")
	resp, err := postDoor(ctx, proxyURL, token, "/spawn", map[string]string{"role": role, "workflow": workflow, "input": input})
	if err != nil {
		return "", fmt.Errorf("spawn: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusForbidden {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("spawn: gateway returned %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	var out struct {
		Status        string `json:"status"`
		ChildRunID    string `json:"child_run_id"`
		OutputPreview string `json:"output_preview"`
		Reason        string `json:"reason"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", fmt.Errorf("spawn: decode: %w", err)
	}
	id := out.ChildRunID
	if id == "" {
		id = "-"
	}
	detail := out.OutputPreview
	if out.Status != "succeeded" {
		detail = out.Reason
	}
	return strings.TrimSpace(fmt.Sprintf("spawn %s %s %s", out.Status, id, detail)), nil
}

// spawnParallel runs <n>:<role>/<workflow>:<input> as n concurrent spawns of
// the same child and returns their lines sorted, so the artifact is stable
// however the children finish. The first error fails the step.
func spawnParallel(ctx context.Context, proxyURL, token, spec string) ([]string, error) {
	count, rest, ok := strings.Cut(spec, ":")
	n, err := strconv.Atoi(strings.TrimSpace(count))
	if !ok || err != nil || n < 1 || n > 32 {
		return nil, fmt.Errorf("spawn-parallel: want <n>:<role>/<workflow>:<input> with n from 1 to 32, got %q", spec)
	}
	lines := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			lines[i], errs[i] = spawnOne(ctx, proxyURL, token, rest)
		}(i)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(lines)
	return lines, nil
}

// probeGateway confirms the Agenthof gateway is reachable over the socket named
// by proxyURL, by POSTing to /exec/authorize with the run token. A 200 (any
// allowed value) means the socket path works end to end.
func probeGateway(ctx context.Context, proxyURL, token string) error {
	resp, err := postDoor(ctx, proxyURL, token, "/exec/authorize", map[string]any{"command": []string{"true"}})
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gateway returned %d", resp.StatusCode)
	}
	return nil
}

// postDoor POSTs a JSON body to one route of the per-run gateway, over the
// gateway's Unix socket when proxyURL is unix://, with the run token.
func postDoor(ctx context.Context, proxyURL, token, route string, body any) (*http.Response, error) {
	if proxyURL == "" {
		return nil, fmt.Errorf("no proxy URL")
	}
	client, base := http.DefaultClient, strings.TrimRight(proxyURL, "/")
	if p, ok := strings.CutPrefix(proxyURL, "unix://"); ok {
		client = &http.Client{Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", p)
			},
		}}
		base = "http://agenthof"
	}
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	rq, err := http.NewRequestWithContext(ctx, http.MethodPost, base+route, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	rq.Header.Set("Content-Type", "application/json")
	rq.Header.Set("Authorization", "Bearer "+token)
	return client.Do(rq)
}

// listenUnix listens on a Unix socket, removing any stale file first
// (net.Listen fails if a path already exists). The listener unlinks on Close.
func listenUnix(path string) (net.Listener, error) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return net.Listen("unix", path)
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "TCP listen address (ignored when -socket is set)")
	socket := flag.String("socket", "", "Unix socket path to listen on; overrides -addr")
	callGateway := flag.Bool("call-gateway", false, "probe the Agenthof gateway (X-Agenthof-Proxy-URL) on each plain step")
	workspace := flag.String("workspace", "/work", "directory the write: directive writes agent-note.txt into (the refbox workspace)")
	flag.Parse()

	srv := &http.Server{Handler: newMux(*callGateway, *workspace)}
	var ln net.Listener
	var err error
	if *socket != "" {
		ln, err = listenUnix(*socket)
		log.Printf("echo-agent listening on unix:%s", *socket)
	} else {
		ln, err = net.Listen("tcp", *addr)
		log.Printf("echo-agent listening on %s", *addr)
	}
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(srv.Serve(ln))
}
