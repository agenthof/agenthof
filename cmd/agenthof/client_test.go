package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/apiclient"
)

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
