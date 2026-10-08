package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/apiclient"
	"github.com/agenthof/agenthof/internal/config"
)

var fakeInstalledHash = "sha256:" + strings.Repeat("d", 64)

// fakeServeAPI is just enough of the serve API for the CLI client paths.
func fakeServeAPI(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.Method + " " + r.URL.Path {
		case "POST /v1/runs":
			var req apiclient.RunRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.Role == "locked" {
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(apiclient.RunAccepted{RunID: "r-ref", Status: apiclient.StatusRefused, Reason: `role "locked" does not own workflow "w"`})
				return
			}
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(apiclient.RunAccepted{RunID: "r-ok", Status: apiclient.StatusRunning})
		case "GET /v1/runs/r-ok":
			_ = json.NewEncoder(w).Encode(apiclient.RunStatus{RunID: "r-ok", Status: "succeeded"})
		case "GET /v1/runs/r-ok/audit":
			w.Header().Set(apiclient.IntegrityHeader, apiclient.IntegrityVerified)
			_, _ = w.Write([]byte("run r-ok — w (role se)\nstatus: succeeded\n"))
		case "GET /v1/investigate":
			if r.URL.Query().Get("run") == "r-torn" {
				_, _ = w.Write([]byte(`{"v":"investigate/1","query":{"run":"r-torn"},"sources":[{"path":".agenthof/runs/r-torn.jsonl","kind":"run","integrity":"torn","count":2}],"events":[],"integrity":{"ok":false,"issues":[".agenthof/runs/r-torn.jsonl: torn"]}}`))
				return
			}
			_, _ = w.Write([]byte(`{"v":"investigate/1","query":{},"sources":[],"events":[],"integrity":{"ok":true,"issues":[]}}`))
		case "POST /v1/config/apply":
			var req apiclient.ApplyRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			w.Header().Set("Content-Type", "application/json")
			answer := func(code int, res apiclient.ApplyResult) {
				w.WriteHeader(code)
				_ = json.NewEncoder(w).Encode(res)
			}
			head := &apiclient.Head{Hash: "abc", Count: 7}
			switch {
			case r.Header.Get("If-None-Match") == "*":
				answer(http.StatusOK, apiclient.ApplyResult{Status: apiclient.ApplyInstalled, ConfigHash: fakeInstalledHash, Bootstrap: true, Head: head, Agents: 1, Workflows: 2, Roles: 3})
			case r.Header.Get("If-Match") == "sha256:"+strings.Repeat("1", 64):
				answer(http.StatusPreconditionFailed, apiclient.ApplyResult{Status: apiclient.ApplyPreconditionFailed, CurrentHash: fakeInstalledHash})
			case r.Header.Get("If-Match") == "sha256:"+strings.Repeat("2", 64):
				answer(http.StatusPreconditionFailed, apiclient.ApplyResult{Status: apiclient.ApplyPreconditionFailed})
			case strings.Contains(req.Files["roles/ops.yaml"], "refuse-me"):
				answer(http.StatusForbidden, apiclient.ApplyResult{Status: apiclient.ApplyRefused, Reason: "not authorized: no role grants apply to the invoker", ConfigHash: "sha256:" + strings.Repeat("a", 64), Head: head})
			case strings.Contains(req.Files["roles/ops.yaml"], "reject-me"):
				answer(http.StatusUnprocessableEntity, apiclient.ApplyResult{Status: apiclient.ApplyRejected, Reason: "roles/ops.yaml: ops: bad", Errors: []string{"roles/ops.yaml: ops: bad", "roles/se.yaml: se: worse"}, ConfigHash: "sha256:" + strings.Repeat("b", 64), Head: head})
			case strings.Contains(req.Files["roles/ops.yaml"], "busy-me"):
				w.Header().Set("Retry-After", "1")
				answer(http.StatusConflict, apiclient.ApplyResult{Status: apiclient.ApplyBusy})
			case strings.Contains(req.Files["roles/ops.yaml"], "error-me"):
				answer(http.StatusInternalServerError, apiclient.ApplyResult{Status: apiclient.ApplyError, Reason: apiclient.ReasonStoreUnusable, Head: head})
			case strings.Contains(req.Files["roles/ops.yaml"], "damaged-me"):
				answer(http.StatusInternalServerError, apiclient.ApplyResult{Status: apiclient.ApplyLedgerDamaged, Reason: apiclient.ReasonLedgerDamaged})
			case strings.Contains(req.Files["roles/ops.yaml"], "unrecorded-me"):
				answer(http.StatusInternalServerError, apiclient.ApplyResult{Status: apiclient.ApplyInstalledNotRecorded, ConfigHash: fakeInstalledHash, Agents: 1, Workflows: 2, Roles: 3})
			default:
				answer(http.StatusOK, apiclient.ApplyResult{Status: apiclient.ApplyInstalled, ConfigHash: "sha256:" + strings.Repeat("c", 64), Head: head, Agents: 1, Workflows: 2, Roles: 3})
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestRunServerPrintsTheLocalShape(t *testing.T) {
	srv := fakeServeAPI(t)
	var out bytes.Buffer
	code := cmdRun([]string{"se", "w", "--input", "x", "--server", srv.URL, "--token", "tok"}, &out, &bytes.Buffer{})
	if code != 0 || out.String() != "run r-ok finished: succeeded\n" {
		t.Fatalf("code %d out %q", code, out.String())
	}
	out.Reset()
	code = cmdRun([]string{"locked", "w", "--input", "x", "--server", srv.URL, "--token", "tok"}, &out, &bytes.Buffer{})
	if code != 1 || out.String() != "run r-ref refused: role \"locked\" does not own workflow \"w\"\n" {
		t.Fatalf("code %d out %q", code, out.String())
	}
	out.Reset()
	t.Setenv("AGENTHOF_TOKEN", "")
	if code := cmdRun([]string{"se", "w", "--input", "x", "--server", srv.URL}, &out, &bytes.Buffer{}); code != 2 || !strings.Contains(out.String(), "--token") {
		t.Fatalf("no token: code %d out %q", code, out.String())
	}
}

func TestAuditAndInvestigateServer(t *testing.T) {
	srv := fakeServeAPI(t)
	t.Setenv("AGENTHOF_SERVER", srv.URL)
	t.Setenv("AGENTHOF_TOKEN", "tok")
	var out bytes.Buffer
	if code := cmdAudit([]string{"r-ok"}, &out); code != 0 || !strings.Contains(out.String(), "status: succeeded") {
		t.Fatalf("code %d out %q", code, out.String())
	}
	out.Reset()
	if code := cmdInvestigate([]string{"--json"}, &out); code != 0 || !strings.HasPrefix(out.String(), `{"v":"investigate/1"`) {
		t.Fatalf("code %d out %q", code, out.String())
	}
	out.Reset()
	if code := cmdInvestigate([]string{}, &out); code != 0 || !strings.Contains(out.String(), "investigation timeline: 0 event(s) across 0 source(s)") {
		t.Fatalf("text mode: code %d out %q", code, out.String())
	}
	// --json changes the rendering, never the exit code: a torn source
	// exits 1 even though the document itself is printed verbatim.
	out.Reset()
	if code := cmdInvestigate([]string{"--json", "--run", "r-torn"}, &out); code != 1 || !strings.HasPrefix(out.String(), `{"v":"investigate/1"`) {
		t.Fatalf("torn --json: code %d out %q", code, out.String())
	}
	out.Reset()
	if code := cmdInvestigate([]string{"--run", "r-torn"}, &out); code != 1 {
		t.Fatalf("torn text: code %d out %q", code, out.String())
	}
}

// applyDir writes a minimal config dir whose roles/ops.yaml carries marker.
func applyDir(t *testing.T, marker string) string {
	t.Helper()
	root := t.TempDir()
	writeFileIn(t, root, "roles/ops.yaml", "name: ops\ncontrol: [apply]\nallowed_groups: [x]\n# "+marker+"\n")
	writeFileIn(t, root, "agents/a.yaml", "name: a\nmodel: m\n")
	return root
}

func TestApplyServerPrintsEveryRow(t *testing.T) {
	srv := fakeServeAPI(t)
	t.Setenv("AGENTHOF_SERVER", srv.URL)
	t.Setenv("AGENTHOF_TOKEN", "tok")
	h1 := "sha256:" + strings.Repeat("1", 64)
	h2 := "sha256:" + strings.Repeat("2", 64)
	// hc is any If-Match the fake does not special-case (not h1/h2): it lets
	// the marker arm decide the status. A "none" here would send If-None-Match:
	// *, which the fake answers as a bootstrap before any marker is read.
	hc := "sha256:" + strings.Repeat("c", 64)
	cases := []struct {
		name, marker, ifInstalled string
		code                      int
		want                      string
	}{
		{"bootstrap", "ok", "none", 0, "registry ok: 1 agents, 2 workflows, 3 roles\ncontrol head: seq=7 sha256=abc\ninstalled: " + fakeInstalledHash + "\n"},
		{"installed", "ok", hc, 0, "registry ok: 1 agents, 2 workflows, 3 roles\ncontrol head: seq=7 sha256=abc\ninstalled: sha256:" + strings.Repeat("c", 64) + "\n"},
		{"412 stale", "ok", h1, 1, "apply: precondition failed: installed configuration is " + fakeInstalledHash + ", not " + h1 + "; retry with --if-installed " + fakeInstalledHash + "\n"},
		{"412 nothing installed", "ok", h2, 1, "apply: precondition failed: nothing is installed, not " + h2 + "; retry with --if-installed none\n"},
		{"403", "refuse-me", hc, 1, "apply: not authorized: no role grants apply to the invoker\ncontrol head: seq=7 sha256=abc\n"},
		{"422", "reject-me", hc, 1, "roles/ops.yaml: ops: bad\nroles/se.yaml: se: worse\ncontrol head: seq=7 sha256=abc\n"},
		{"409", "busy-me", hc, 1, "apply: another apply is in progress; retry\n"},
		{"500 error", "error-me", hc, 1, "apply: store unusable\ncontrol head: seq=7 sha256=abc\n"},
		{"500 ledger damaged", "damaged-me", hc, 1, "apply: control ledger damaged; an operator must run audit repair control on the server\n"},
		{"500 installed not recorded", "unrecorded-me", hc, 1, "registry ok: 1 agents, 2 workflows, 3 roles\ninstalled; event NOT recorded\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out bytes.Buffer
			code := cmdApply([]string{"--config", applyDir(t, c.marker), "--if-installed", c.ifInstalled}, &out)
			if code != c.code || out.String() != c.want {
				t.Fatalf("code %d (want %d)\nout  %q\nwant %q", code, c.code, out.String(), c.want)
			}
		})
	}
}

// The 412 "already installed" hint: the server's current_hash equals the
// bundle's own HashFiles.
func TestApplyServer412SaysWhenTheBytesAreAlreadyInstalled(t *testing.T) {
	root := applyDir(t, "ok")
	bundle, err := config.ReadBundle(root)
	if err != nil {
		t.Fatal(err)
	}
	local, _ := config.HashFiles(bundle)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPreconditionFailed)
		_ = json.NewEncoder(w).Encode(apiclient.ApplyResult{Status: apiclient.ApplyPreconditionFailed, CurrentHash: local})
	}))
	t.Cleanup(srv.Close)
	var out bytes.Buffer
	code := cmdApply([]string{"--config", root, "--server", srv.URL, "--token", "tok", "--if-installed", "none"}, &out)
	want := "apply: precondition failed: installed configuration is " + local + ", not none; retry with --if-installed " + local + " — these bytes are already installed\n"
	if code != 1 || out.String() != want {
		t.Fatalf("code %d\nout  %q\nwant %q", code, out.String(), want)
	}
}

func TestApplyServerUsageAndTransport(t *testing.T) {
	srv := fakeServeAPI(t)
	t.Setenv("AGENTHOF_TOKEN", "")
	t.Setenv("AGENTHOF_SERVER", "")
	root := applyDir(t, "ok")
	var out bytes.Buffer
	if code := cmdApply([]string{"--config", root, "--server", srv.URL, "--if-installed", "none"}, &out); code != 2 || !strings.Contains(out.String(), "--server needs --token") {
		t.Fatalf("no token: %d %q", code, out.String())
	}
	out.Reset()
	if code := cmdApply([]string{"--config", root, "--server", srv.URL, "--token", "tok"}, &out); code != 2 || !strings.Contains(out.String(), "apply --server needs --if-installed") {
		t.Fatalf("no --if-installed: %d %q", code, out.String())
	}
	out.Reset()
	if code := cmdApply([]string{"--config", root, "--bundle", "x.json"}, &out); code != 2 || !strings.Contains(out.String(), "--bundle needs --server") {
		t.Fatalf("local --bundle: %d %q", code, out.String())
	}
	out.Reset()
	if code := cmdApply([]string{"--config", root, "--server", srv.URL, "--token", "wrong", "--if-installed", "none"}, &out); code != 1 || out.String() != "apply: server rejected the token\n" {
		t.Fatalf("401: %d %q", code, out.String())
	}
	out.Reset()
	if code := cmdApply([]string{"--config", root, "--server", "http://127.0.0.1:1", "--token", "tok", "--if-installed", "none"}, &out); code != 1 || !strings.HasPrefix(out.String(), "apply: server: ") {
		t.Fatalf("transport error: %d %q", code, out.String())
	}
	out.Reset()
	if code := cmdApply([]string{"--config", filepath.Join(root, "nope"), "--server", srv.URL, "--token", "tok", "--if-installed", "none"}, &out); code != 1 || !strings.Contains(out.String(), "config root") {
		t.Fatalf("missing dir: %d %q", code, out.String())
	}
	// --as/--groups warn on stderr and are ignored; the apply still runs.
	out.Reset()
	if code := cmdApply([]string{"--config", root, "--server", srv.URL, "--token", "tok", "--if-installed", "none", "--as", "x", "--groups", "y"}, &out); code != 0 {
		t.Fatalf("--as with --server: %d %q", code, out.String())
	}
}

func TestLoadBundleReadsFileAndStdinAndRefusesBadInput(t *testing.T) {
	root := applyDir(t, "ok")
	fromDir, err := loadBundle(root, "", strings.NewReader(""))
	if err != nil || string(fromDir["agents/a.yaml"]) != "name: a\nmodel: m\n" {
		t.Fatalf("dir: %v %q", err, fromDir)
	}
	body := `{"files":{"roles/ops.yaml":"name: ops\n","agents/a.yaml":"name: a\n"}}`
	p := filepath.Join(t.TempDir(), "b.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	fromFile, err := loadBundle(root, p, strings.NewReader(""))
	if err != nil || len(fromFile) != 2 || string(fromFile["roles/ops.yaml"]) != "name: ops\n" {
		t.Fatalf("file: %v %q", err, fromFile)
	}
	fromStdin, err := loadBundle(root, "-", strings.NewReader(body))
	if err != nil || len(fromStdin) != 2 {
		t.Fatalf("stdin: %v %q", err, fromStdin)
	}
	for _, bad := range []struct{ body, want string }{
		{`{"files":{}}`, "files is required"},
		{`{"files":{"../x.yaml":"x"}}`, `invalid config path: "../x.yaml"`},
		{"{\"files\":{\"roles/a.yaml\":\"\xff\"}}", "not valid UTF-8"},
		{`not json`, "malformed bundle"},
	} {
		if _, err := loadBundle(root, "-", strings.NewReader(bad.body)); err == nil || !strings.Contains(err.Error(), bad.want) {
			t.Fatalf("%q: err %v, want %q", bad.body, err, bad.want)
		}
	}
	// a config file that is not valid UTF-8 is refused with its path
	writeFileIn(t, root, "agents/bin.yaml", "name: \xff\n")
	if _, err := loadBundle(root, "", strings.NewReader("")); err == nil || !strings.Contains(err.Error(), "agents/bin.yaml") || !strings.Contains(err.Error(), "not valid UTF-8") {
		t.Fatalf("non-UTF-8 config file: %v", err)
	}
}

// TestLoadBundleDuplicateKeyLastWins pins encoding/json's behavior as a
// documented choice: a bundle with the same key twice keeps the last value
// on the client AND the server, so nothing is unsafe — but it is silent.
func TestLoadBundleDuplicateKeyLastWins(t *testing.T) {
	b, err := loadBundle("", "-", strings.NewReader(`{"files":{"roles/a.yaml":"x","roles/a.yaml":"y"}}`))
	if err != nil || len(b) != 1 || string(b["roles/a.yaml"]) != "y" {
		t.Fatalf("got %q err %v, want the last value", b, err)
	}
}

// TestApplyServerRefusesOverCapBeforeSending: applyViaServer enforces the
// server's caps locally — for BOTH --config and --bundle, and against the
// bytes json.Marshal actually sends — so nothing goes over the wire. The
// --bundle case is the one loadBundle's raw check misses: json.Marshal
// HTML-escapes <, >, and & (each < becomes the six bytes \u003c), so a file
// under the raw cap can still encode above MaxApplyBody.
func TestApplyServerRefusesOverCapBeforeSending(t *testing.T) {
	var hit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		http.Error(w, "the cap must be enforced before sending", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("AGENTHOF_SERVER", srv.URL)
	t.Setenv("AGENTHOF_TOKEN", "tok")

	// --config with more files than MaxBundleFiles: refused with the server's
	// own words, before any request.
	root := t.TempDir()
	for i := 0; i <= apiclient.MaxBundleFiles; i++ {
		writeFileIn(t, root, "roles/r"+strconv.Itoa(i)+".yaml", "name: r\n")
	}
	var out bytes.Buffer
	if code := cmdApply([]string{"--config", root, "--if-installed", "none"}, &out); code != 1 || out.String() != "apply: too many files\n" {
		t.Fatalf("too many files: code %d out %q", code, out.String())
	}

	// --bundle whose raw bytes are under the cap but whose JSON re-encoding
	// exceeds it. The file carries literal '<' (one byte each); the encoder
	// expands every one to six, pushing the sent body over MaxApplyBody.
	val := strings.Repeat("<", apiclient.MaxApplyBody/2)
	raw := []byte(`{"files":{"roles/r.yaml":"` + val + `"}}`)
	if len(raw) > apiclient.MaxApplyBody {
		t.Fatalf("raw bundle must be under the cap for this test, got %d", len(raw))
	}
	p := filepath.Join(t.TempDir(), "b.json")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := cmdApply([]string{"--bundle", p, "--if-installed", "none"}, &out); code != 1 || out.String() != "apply: bundle exceeds 1 MiB\n" {
		t.Fatalf("over-encoded bundle: code %d out %q", code, out.String())
	}

	if hit {
		t.Fatal("a request reached the server; the cap must be enforced before sending")
	}
}

// TestLoadBundleEnforcesServerCaps: the client refuses with the server's
// own words rather than sending and getting a 400/413 it cannot explain.
func TestLoadBundleEnforcesServerCaps(t *testing.T) {
	files := make(map[string]string, apiclient.MaxBundleFiles+1)
	for i := 0; i <= apiclient.MaxBundleFiles; i++ {
		files["roles/r"+strconv.Itoa(i)+".yaml"] = "name: r\n"
	}
	raw, _ := json.Marshal(apiclient.ApplyRequest{Files: files})
	if _, err := loadBundle("", "-", bytes.NewReader(raw)); err == nil || !strings.Contains(err.Error(), "too many files") {
		t.Fatalf("too many: %v", err)
	}
	raw, _ = json.Marshal(apiclient.ApplyRequest{Files: map[string]string{"roles/r.yaml": strings.Repeat("a", apiclient.MaxApplyBody)}})
	if _, err := loadBundle("", "-", bytes.NewReader(raw)); err == nil || !strings.Contains(err.Error(), "bundle exceeds 1 MiB") {
		t.Fatalf("too big: %v", err)
	}
}
