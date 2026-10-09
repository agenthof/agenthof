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
	"time"

	"github.com/agenthof/agenthof/internal/apiclient"
	"github.com/agenthof/agenthof/internal/config"
)

// pulledSample is writeSample as the server would serve it.
func pulledSample(t *testing.T) apiclient.ConfigSnapshot {
	t.Helper()
	files, err := config.ReadBundle(writeSample(t))
	if err != nil {
		t.Fatal(err)
	}
	hash, err := config.HashFiles(files)
	if err != nil {
		t.Fatal(err)
	}
	snap := apiclient.ConfigSnapshot{Hash: hash, Version: 7, InstalledAt: time.Date(2026, 10, 9, 2, 12, 1, 0, time.UTC), Files: make(map[string]string, len(files))}
	for rel, data := range files {
		snap.Files[rel] = string(data)
	}
	return snap
}

// fakePullAPI answers GET /v1/config with code and body for the bearer tok;
// anything else is 401.
func fakePullAPI(t *testing.T, code int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet || r.URL.Path != "/v1/config" {
			http.NotFound(w, r)
			return
		}
		if code == http.StatusOK {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_, _ = w.Write([]byte(body))
			return
		}
		http.Error(w, body, code)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func snapshotJSON(t *testing.T, snap apiclient.ConfigSnapshot) string {
	t.Helper()
	b, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestConfigUsage(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := cmdConfig(nil, &out); code != 2 || !strings.Contains(out.String(), "config needs a subcommand: pull") {
		t.Fatalf("no verb: %d %q", code, out.String())
	}
	out.Reset()
	if code := cmdConfig([]string{"push"}, &out); code != 2 || !strings.Contains(out.String(), `unknown config subcommand "push"`) {
		t.Fatalf("unknown verb: %d %q", code, out.String())
	}
	out.Reset()
	if code := dispatch([]string{"config"}, &out, &errBuf); code != 2 {
		t.Fatalf("dispatch config: %d", code)
	}
	if !strings.Contains(usage, "agenthof config pull") {
		t.Fatal("usage must list config pull")
	}
}

func TestConfigPullServerUsageAndTransport(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	t.Setenv("AGENTHOF_SERVER", "")
	srv := fakePullAPI(t, http.StatusOK, snapshotJSON(t, pulledSample(t)))
	var out bytes.Buffer
	if code := cmdConfigPull([]string{"--server", srv.URL}, &out); code != 2 || !strings.Contains(out.String(), "config pull: --server needs --token or AGENTHOF_TOKEN") {
		t.Fatalf("no token: %d %q", code, out.String())
	}
	out.Reset()
	if code := cmdConfigPull([]string{"--server", srv.URL, "--token", "wrong"}, &out); code != 1 || out.String() != "config pull: server rejected the token\n" {
		t.Fatalf("401: %d %q", code, out.String())
	}
	out.Reset()
	if code := cmdConfigPull([]string{"--server", "http://127.0.0.1:1", "--token", "tok"}, &out); code != 1 || !strings.HasPrefix(out.String(), "config pull: server: ") {
		t.Fatalf("transport: %d %q", code, out.String())
	}
	// Flags through the environment, as every --server command accepts them.
	t.Setenv("AGENTHOF_SERVER", srv.URL)
	t.Setenv("AGENTHOF_TOKEN", "tok")
	out.Reset()
	if code := cmdConfigPull(nil, &out); code != 0 || !strings.HasPrefix(out.String(), "installed: ") {
		t.Fatalf("env: %d %q", code, out.String())
	}
}

func TestConfigPullServerPrintsEveryRow(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	snap := pulledSample(t)
	srv := fakePullAPI(t, http.StatusOK, snapshotJSON(t, snap))
	var out bytes.Buffer
	if code := cmdConfigPull([]string{"--server", srv.URL, "--token", "tok"}, &out); code != 0 {
		t.Fatalf("200: %d %q", code, out.String())
	}
	head := "installed: " + snap.Hash + "\nversion: 7  installed_at: 2026-10-09T02:12:01Z\nfiles: 6\n"
	if !strings.HasPrefix(out.String(), head) {
		t.Fatalf("summary head:\n%s", out.String())
	}
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 9 || !strings.HasPrefix(lines[3], "  agents/coder.yaml  ") || !strings.HasPrefix(lines[4], "  agents/planner.yaml  ") ||
		!strings.HasPrefix(lines[5], "  workflows/fix-bug.yaml  ") || !strings.HasPrefix(lines[6], "  roles/ops.yaml  ") ||
		!strings.HasPrefix(lines[7], "  roles/se.yaml  ") || !strings.HasPrefix(lines[8], "  gateway.yaml  ") || !strings.HasSuffix(lines[8], " bytes") {
		t.Fatalf("listing must be in the canon's order with sizes:\n%s", out.String())
	}

	// A 200 whose files do not hash to its hash: refused before anything is
	// printed or written.
	bad := snap
	bad.Hash = "sha256:" + strings.Repeat("0", 64)
	srvBad := fakePullAPI(t, http.StatusOK, snapshotJSON(t, bad))
	outDir := filepath.Join(t.TempDir(), "pulled")
	out.Reset()
	if code := cmdConfigPull([]string{"--server", srvBad.URL, "--token", "tok", "--out", outDir}, &out); code != 1 ||
		out.String() != "config pull: snapshot does not hash as its pointer: got "+snap.Hash+", want "+bad.Hash+"\n" {
		t.Fatalf("mismatch: %d %q", code, out.String())
	}
	if _, err := os.Stat(outDir); !os.IsNotExist(err) {
		t.Fatal("a mismatching snapshot must write nothing")
	}

	for _, c := range []struct {
		code int
		body string
	}{
		{http.StatusForbidden, apiclient.PullBodyRefused},
		{http.StatusNotFound, "no configuration installed"},
		{http.StatusInternalServerError, apiclient.ReasonStoreUnusable},
		{http.StatusInternalServerError, apiclient.PullBodyNotBundleable},
		{http.StatusInternalServerError, apiclient.ReasonLedgerDamaged},
		{http.StatusServiceUnavailable, apiclient.PullBodyNotRecorded},
		{http.StatusServiceUnavailable, apiclient.PullBodyBusy},
	} {
		srv := fakePullAPI(t, c.code, c.body)
		out.Reset()
		if code := cmdConfigPull([]string{"--server", srv.URL, "--token", "tok"}, &out); code != 1 ||
			out.String() != "config pull: server answered "+strconv.Itoa(c.code)+": "+c.body+"\n" {
			t.Fatalf("%d: code %d %q", c.code, code, out.String())
		}
	}
}

// TestConfigPullOutRoundTrip: --out writes a directory that hashes as the
// pulled hash and applies to the same hash on another control root.
func TestConfigPullOutRoundTrip(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	snap := pulledSample(t)
	srv := fakePullAPI(t, http.StatusOK, snapshotJSON(t, snap))
	outDir := filepath.Join(t.TempDir(), "pulled")
	var out bytes.Buffer
	if code := cmdConfigPull([]string{"--server", srv.URL, "--token", "tok", "--out", outDir}, &out); code != 0 || !strings.HasSuffix(out.String(), "wrote 6 files to "+outDir+"\n") {
		t.Fatalf("--out: %d %q", code, out.String())
	}
	if got, err := config.HashDir(outDir); err != nil || got != snap.Hash {
		t.Fatalf("HashDir(out) = %q err %v, want %q", got, err, snap.Hash)
	}
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	out.Reset()
	if code := cmdApply([]string{"--config", outDir, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("apply of the pulled directory: %d\n%s", code, out.String())
	}
	if readPointer(t, ctl) != snap.Hash {
		t.Fatalf("the round trip must install the same hash: %s vs %s", readPointer(t, ctl), snap.Hash)
	}
}

// TestConfigPullJSONFeedsApplyBundle: --json is the document apply --bundle
// reads; the extra keys are ignored and the files hash the same.
func TestConfigPullJSONFeedsApplyBundle(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	snap := pulledSample(t)
	srv := fakePullAPI(t, http.StatusOK, snapshotJSON(t, snap))
	var out bytes.Buffer
	if code := cmdConfigPull([]string{"--server", srv.URL, "--token", "tok", "--json"}, &out); code != 0 || !strings.HasPrefix(out.String(), `{"hash":"`+snap.Hash+`","version":7,`) {
		t.Fatalf("--json: %d %q", code, out.String())
	}
	p := filepath.Join(t.TempDir(), "b.json")
	if err := os.WriteFile(p, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	files, err := loadBundle("", p, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := config.HashFiles(files); got != snap.Hash {
		t.Fatalf("the --json document must hash as the pull: %q vs %q", got, snap.Hash)
	}

	// --json --out together: the "wrote …" confirmation goes to stderr, so
	// stdout stays a single document apply --bundle still accepts, and the
	// directory is written.
	srv2 := fakePullAPI(t, http.StatusOK, snapshotJSON(t, snap))
	outDir := filepath.Join(t.TempDir(), "d")
	var out2 bytes.Buffer
	if code := cmdConfigPull([]string{"--server", srv2.URL, "--token", "tok", "--json", "--out", outDir}, &out2); code != 0 {
		t.Fatalf("--json --out: %d %q", code, out2.String())
	}
	if _, err := os.Stat(outDir); err != nil {
		t.Fatalf("--out dir must be written: %v", err)
	}
	p2 := filepath.Join(t.TempDir(), "b2.json")
	if err := os.WriteFile(p2, out2.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	files2, err := loadBundle("", p2, strings.NewReader(""))
	if err != nil {
		t.Fatalf("stdout under --json --out must be valid apply --bundle input: %v\n%q", err, out2.String())
	}
	if got, _ := config.HashFiles(files2); got != snap.Hash {
		t.Fatalf("the --json --out document must hash as the pull: %q vs %q", got, snap.Hash)
	}
}

// TestConfigPullOutRefusals: an existing directory (even empty), an existing
// file and a dangling symlink are usage errors before anything is pulled; a
// missing parent is a write failure that leaves nothing behind.
func TestConfigPullOutRefusals(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	srv := fakePullAPI(t, http.StatusOK, snapshotJSON(t, pulledSample(t)))
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	if err := os.Mkdir(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink(filepath.Join(dir, "nowhere"), dangling); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{empty, file, dangling} {
		var out bytes.Buffer
		if code := cmdConfigPull([]string{"--server", srv.URL, "--token", "tok", "--out", p}, &out); code != 2 || out.String() != "config pull: --out "+p+" exists; name a new directory\n" {
			t.Fatalf("%s: %d %q", p, code, out.String())
		}
	}
	if ents, _ := os.ReadDir(empty); len(ents) != 0 {
		t.Fatal("an existing directory must be left untouched")
	}
	orphan := filepath.Join(dir, "missing-parent", "out")
	var out bytes.Buffer
	if code := cmdConfigPull([]string{"--server", srv.URL, "--token", "tok", "--out", orphan}, &out); code != 1 || !strings.HasPrefix(out.String(), "config pull: mkdir ") {
		t.Fatalf("missing parent: %d %q", code, out.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "missing-parent")); !os.IsNotExist(err) {
		t.Fatal("no parent may be created")
	}
}

func TestConfigPullLocal(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	t.Setenv("AGENTHOF_SERVER", "")
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	var out bytes.Buffer
	if code := cmdConfigPull([]string{"--control-log", ctl}, &out); code != 1 ||
		out.String() != "config pull: no configuration installed under "+installedStore(ctl)+"; run: agenthof apply --config <dir> --control-log "+ctl+"\n" {
		t.Fatalf("fresh root: %d %q", code, out.String())
	}
	root := writeSample(t)
	appliedAt(t, root, ctl)
	hash := readPointer(t, ctl)
	out.Reset()
	if code := cmdConfigPull([]string{"--control-log", ctl}, &out); code != 0 || !strings.HasPrefix(out.String(), "installed: "+hash+"\nversion: 1  installed_at: ") {
		t.Fatalf("applied root: %d %q", code, out.String())
	}
	out.Reset()
	if code := cmdConfigPull([]string{"--control-log", ctl, "--json"}, &out); code != 0 {
		t.Fatalf("--json: %d %q", code, out.String())
	}
	var doc apiclient.ConfigSnapshot
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil || doc.Hash != hash || doc.Version != 1 || len(doc.Files) != 6 {
		t.Fatalf("--json document: %v %+v", err, doc)
	}
	outDir := filepath.Join(t.TempDir(), "pulled")
	out.Reset()
	if code := cmdConfigPull([]string{"--control-log", ctl, "--out", outDir}, &out); code != 0 {
		t.Fatalf("--out: %d %q", code, out.String())
	}
	if got, _ := config.HashDir(outDir); got != hash {
		t.Fatalf("HashDir(out) = %q, want %q", got, hash)
	}
	ctl2 := filepath.Join(t.TempDir(), "control.jsonl")
	appliedAt(t, outDir, ctl2)
	if readPointer(t, ctl2) != hash {
		t.Fatal("the local round trip must install the same hash")
	}

	// A pointer the ledger does not vouch for prints the retry line.
	ctl3 := filepath.Join(t.TempDir(), "control.jsonl")
	installByHandWithPointer(t, ctl3, map[string]string{"roles/ops.yaml": "name: platform-admin\nallowed_groups: [platform-eng]\ncontrol: [apply]\n"})
	out.Reset()
	if code := cmdConfigPull([]string{"--control-log", ctl3}, &out); code != 1 || out.String() != "config pull: "+apiclient.PullBodyNotRecorded+"\n" {
		t.Fatalf("not on record: %d %q", code, out.String())
	}
}
