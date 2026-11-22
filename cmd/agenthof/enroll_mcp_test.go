package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/ledger"
)

const mcpGateway = `# operator notes
models:
  fast: {endpoint: https://example.test/v1, model: m, api_key_env: K}
tools:
  existing: {kind: mcp, url: https://mcp.example.test/x, credential_source: static_env, token_env: T, read_only_tools: [a]}
`

// mcpEnv installs a small configuration and returns its working dir (which
// the command then edits) and the control log.
func mcpEnv(t *testing.T) (cfgDir, controlLog string) {
	t.Helper()
	t.Setenv("AGENTHOF_TOKEN", "")
	cfgDir = t.TempDir()
	writeTree(t, cfgDir, map[string]string{
		"agents/orch.yaml":    "name: orch\nendpoint: http://localhost:9\n",
		"workflows/main.yaml": "name: main\nsteps:\n  - {name: s, agent: orch}\n",
		"roles/admin.yaml":    "name: admin\nworkflows: [main]\nallowed_groups: [ops]\ncontrol: [apply, enroll]\n",
		"gateway.yaml":        mcpGateway,
	})
	controlLog = filepath.Join(t.TempDir(), "control.jsonl")
	var out bytes.Buffer
	if code := cmdApply([]string{"--config", cfgDir, "--control-log", controlLog, "--as", "ops-user", "--groups", "ops"}, &out); code != 0 {
		t.Fatalf("apply: %d\n%s", code, out.String())
	}
	return cfgDir, controlLog
}

func runMCP(t *testing.T, cfgDir, controlLog string, extra ...string) (int, string, string) {
	t.Helper()
	// The name, when given, leads: flag parsing stops at the first positional.
	var args []string
	if len(extra) > 0 && !strings.HasPrefix(extra[0], "-") {
		args, extra = []string{extra[0]}, extra[1:]
	}
	args = append(args, "--config", cfgDir, "--control-log", controlLog, "--as", "ops-user", "--groups", "ops",
		"--socket", "/run/agenthof/m.sock", "--token-env", "MCP_TOKEN")
	args = append(args, extra...)
	var out, errb bytes.Buffer
	code := cmdEnrollMCP(args, &out, &errb)
	return code, out.String(), errb.String()
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func mcpDigestOf(t *testing.T, res config.ToolResource) string {
	t.Helper()
	d, err := mcpAcceptDigest(res)
	if err != nil {
		t.Fatal(err)
	}
	return "sha256:" + d
}

func goodRes(cmd ...string) config.ToolResource {
	return config.ToolResource{Kind: "mcp", Runtime: "refbridge", URL: "unix:///run/agenthof/m.sock", CredentialSource: "static_env",
		TokenEnv: "MCP_TOKEN", Command: cmd, ReadOnlyTools: []string{"search", "readGoogleDoc"}}
}

func lastEvent(t *testing.T, ctl string) string {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(readFile(t, ctl)), "\n")
	return lines[len(lines)-1]
}

func TestEnrollMCPDisclosureWritesNothing(t *testing.T) {
	cfg, ctl := mcpEnv(t)
	before := readFile(t, filepath.Join(cfg, "gateway.yaml"))
	ledgerBefore := readFile(t, ctl)
	code, out, errs := runMCP(t, cfg, ctl, "drive", "--command", "/opt/mcp/bin/drive --flag", "--env", "B_VAR,A_VAR", "--egress", "docs.example.com:443", "--tools", "search,readGoogleDoc")
	if code != 0 {
		t.Fatalf("exit %d: %s %s", code, out, errs)
	}
	res := goodRes("/opt/mcp/bin/drive", "--flag")
	res.EnvPassthrough = []string{"A_VAR", "B_VAR"}
	res.Egress = []string{"docs.example.com:443"}
	for _, want := range []string{`"/opt/mcp/bin/drive" "--flag"`, "A_VAR, B_VAR", "docs.example.com:443", "search, readGoogleDoc", mcpDigestOf(t, res), "inert"} {
		if !strings.Contains(out, want) {
			t.Errorf("disclosure missing %q:\n%s", want, out)
		}
	}
	if readFile(t, filepath.Join(cfg, "gateway.yaml")) != before || readFile(t, ctl) != ledgerBefore {
		t.Fatal("disclosure wrote config or ledger")
	}
}

func TestEnrollMCPWrongAcceptWritesNothing(t *testing.T) {
	cfg, ctl := mcpEnv(t)
	before := readFile(t, filepath.Join(cfg, "gateway.yaml"))
	code, _, errs := runMCP(t, cfg, ctl, "drive", "--command", "/opt/mcp/bin/drive", "--tools", "search", "--accept", "sha256:"+strings.Repeat("0", 64))
	if code == 0 || !strings.Contains(errs, "does not match") {
		t.Fatalf("want declined, got %d %s", code, errs)
	}
	if readFile(t, filepath.Join(cfg, "gateway.yaml")) != before {
		t.Fatal("gateway changed")
	}
	if strings.Contains(readFile(t, ctl), `"action":"enroll_mcp","outcome":"success"`) {
		t.Fatal("success recorded")
	}
}

func TestEnrollMCPNameCollisions(t *testing.T) {
	cfg, ctl := mcpEnv(t)
	for _, n := range []string{"orch", "main", "admin", "existing", "bad/name"} {
		code, out, errs := runMCP(t, cfg, ctl, n, "--command", "/opt/x", "--tools", "a")
		if code == 0 || (!strings.Contains(errs, "already") && !strings.Contains(errs, "must match")) {
			t.Errorf("name %q: exit %d, out %q, err %q", n, code, out, errs)
		}
	}
}

func TestEnrollMCPRefusesFetchAtSpawn(t *testing.T) {
	cfg, ctl := mcpEnv(t)
	before := readFile(t, filepath.Join(cfg, "gateway.yaml"))
	code, _, errs := runMCP(t, cfg, ctl, "drive", "--command", "/usr/bin/npx -y pkg", "--tools", "a")
	if code == 0 || !strings.Contains(errs, "fetch-at-spawn") {
		t.Fatalf("want fetch-at-spawn refusal: %d %s", code, errs)
	}
	if readFile(t, filepath.Join(cfg, "gateway.yaml")) != before {
		t.Fatal("gateway changed")
	}
}

func TestEnrollMCPMissingTokenEnvIsUsageError(t *testing.T) {
	cfg, ctl := mcpEnv(t)
	var out, errb bytes.Buffer
	code := cmdEnrollMCP([]string{"drive", "--config", cfg, "--control-log", ctl, "--socket", "/s", "--command", "/opt/x", "--tools", "a"}, &out, &errb)
	if code != 2 || !strings.Contains(errb.String(), "--token-env is required") {
		t.Fatalf("got %d %s", code, errb.String())
	}
	errb.Reset()
	code = cmdEnrollMCP([]string{"drive", "--url", "https://x.example"}, &out, &errb)
	if code == 0 || !strings.Contains(errb.String(), "remote enrollment is not supported yet") {
		t.Fatalf("url: %d %s", code, errb.String())
	}
}

func TestEnrollMCPAcceptNoGrantIsInert(t *testing.T) {
	cfg, ctl := mcpEnv(t)
	res := goodRes("/opt/mcp/bin/drive")
	code, out, errs := runMCP(t, cfg, ctl, "drive", "--command", "/opt/mcp/bin/drive", "--tools", "search,readGoogleDoc", "--accept", mcpDigestOf(t, res))
	if code != 0 {
		t.Fatalf("exit %d: %s %s", code, out, errs)
	}
	gw := readFile(t, filepath.Join(cfg, "gateway.yaml"))
	for _, want := range []string{"# operator notes", "drive:", "read_only_tools", "/opt/mcp/bin/drive", "unix:///run/agenthof/m.sock"} {
		if !strings.Contains(gw, want) {
			t.Errorf("gateway missing %q:\n%s", want, gw)
		}
	}
	if strings.Contains(readFile(t, filepath.Join(cfg, "agents/orch.yaml")), "drive") {
		t.Error("a grant was written")
	}
	if !strings.Contains(out, "inert") || !strings.Contains(out, "next: agenthof apply --config") {
		t.Errorf("message: %s", out)
	}
	ev := lastEvent(t, ctl)
	for _, want := range []string{`"action":"enroll_mcp"`, `"outcome":"success"`, `"resource":"drive"`, `"path":"gateway.yaml"`} {
		if !strings.Contains(ev, want) {
			t.Errorf("event missing %q: %s", want, ev)
		}
	}
	if strings.Contains(ev, "card_sha256") || strings.Contains(ev, "config_hash") {
		t.Errorf("event carries card/config_hash: %s", ev)
	}
	sum := sha256.Sum256([]byte(gw))
	if !strings.Contains(ev, hex.EncodeToString(sum[:])) {
		t.Errorf("event lacks post-edit gateway digest: %s", ev)
	}
	// Nothing installed: the installed configuration does not hold it.
	icfg, _, ok, ierrs := config.LoadInstalled(installedStore(ctl))
	if !ok || len(ierrs) > 0 {
		t.Fatalf("installed: %v", ierrs)
	}
	if _, there := icfg.Gateway.Tools["drive"]; there {
		t.Error("enroll installed the resource")
	}
}

func TestEnrollMCPGrantWritesNamedReadOnlyGrant(t *testing.T) {
	cfg, ctl := mcpEnv(t)
	res := goodRes("/opt/mcp/bin/drive")
	code, out, errs := runMCP(t, cfg, ctl, "drive", "--command", "/opt/mcp/bin/drive", "--tools", "search,readGoogleDoc", "--grant", "orch", "--accept", mcpDigestOf(t, res))
	if code != 0 {
		t.Fatalf("exit %d: %s %s", code, out, errs)
	}
	ag := readFile(t, filepath.Join(cfg, "agents/orch.yaml"))
	for _, want := range []string{"resource: drive", "read-only", "search", "readGoogleDoc"} {
		if !strings.Contains(ag, want) {
			t.Errorf("agent missing %q:\n%s", want, ag)
		}
	}
	if strings.Contains(ag, `"*"`) {
		t.Errorf("wildcard grant: %s", ag)
	}
	if !strings.Contains(lastEvent(t, ctl), `"path":"agents/orch.yaml"`) {
		t.Errorf("event lacks agent file: %s", lastEvent(t, ctl))
	}
	if _, loadErrs := config.LoadDir(cfg); len(loadErrs) > 0 {
		t.Fatalf("result does not load: %v", loadErrs)
	}
}

func TestEnrollMCPFromPasteLiftsEnvValues(t *testing.T) {
	cfg, ctl := mcpEnv(t)
	const secret = "sk-SUPERSECRET-123"
	paste := `{"command":"/opt/mcp/bin/drive","args":["--x"],"env":{"DRIVE_KEY":"` + secret + `"}}`
	old := enrollMCPStdin
	t.Cleanup(func() { enrollMCPStdin = old })
	enrollMCPStdin = strings.NewReader(paste)
	res := goodRes("/opt/mcp/bin/drive", "--x")
	res.EnvPassthrough = []string{"DRIVE_KEY"}
	res.ReadOnlyTools = []string{"search"}
	// The disclosure must not echo the value either.
	code, out, errs := runMCP(t, cfg, ctl, "drive", "--from-paste", "--tools", "search")
	if code != 0 || strings.Contains(out+errs, secret) || !strings.Contains(out, "DRIVE_KEY") || !strings.Contains(out, "discarded") {
		t.Fatalf("disclosure: %d %s %s", code, out, errs)
	}
	enrollMCPStdin = strings.NewReader(paste)
	code, out, errs = runMCP(t, cfg, ctl, "drive", "--from-paste", "--tools", "search", "--accept", mcpDigestOf(t, res))
	if code != 0 {
		t.Fatalf("exit %d: %s %s", code, out, errs)
	}
	_ = filepath.WalkDir(cfg, func(p string, d fs.DirEntry, _ error) error {
		if d != nil && !d.IsDir() && strings.Contains(readFile(t, p), secret) {
			t.Errorf("secret in %s", p)
		}
		return nil
	})
	if strings.Contains(readFile(t, ctl), secret) || strings.Contains(out+errs, secret) {
		t.Error("secret in ledger or output")
	}
	if !strings.Contains(readFile(t, filepath.Join(cfg, "gateway.yaml")), "DRIVE_KEY") {
		t.Error("env name not recorded")
	}
}

func TestEnrollMCPValidatesBeforeWriting(t *testing.T) {
	cfg, ctl := mcpEnv(t)
	gwPath := filepath.Join(cfg, "gateway.yaml")
	before := readFile(t, gwPath)
	bad := goodRes("/opt/mcp/bin/drive")
	bad.Egress = []string{"http://bad/host"}
	code, _, errs := runMCP(t, cfg, ctl, "drive", "--command", "/opt/mcp/bin/drive", "--egress", "http://bad/host", "--tools", "search,readGoogleDoc", "--accept", mcpDigestOf(t, bad))
	if code == 0 || !strings.Contains(errs, "nothing was written") {
		t.Fatalf("want validation refusal: %d %s", code, errs)
	}
	if readFile(t, gwPath) != before {
		t.Fatal("gateway.yaml changed on validation failure")
	}
}

func TestEnrollMCPAppendFailureRevertsEdits(t *testing.T) {
	cfg, ctl := mcpEnv(t)
	gwPath := filepath.Join(cfg, "gateway.yaml")
	agPath := filepath.Join(cfg, "agents/orch.yaml")
	gb, ab := readFile(t, gwPath), readFile(t, agPath)
	old := enrollMCPAppend
	t.Cleanup(func() { enrollMCPAppend = old })
	enrollMCPAppend = func(string, control.Event) (ledger.Head, error) { return ledger.Head{}, errors.New("boom") }
	code, _, _ := runMCP(t, cfg, ctl, "drive", "--command", "/opt/mcp/bin/drive", "--tools", "search,readGoogleDoc", "--grant", "orch", "--accept", mcpDigestOf(t, goodRes("/opt/mcp/bin/drive")))
	if code == 0 || readFile(t, gwPath) != gb || readFile(t, agPath) != ab {
		t.Fatalf("not reverted: %d", code)
	}
}

func TestEnrollMCPUnauthorizedRefused(t *testing.T) {
	cfg, ctl := mcpEnv(t)
	var out, errb bytes.Buffer
	code := cmdEnrollMCP([]string{"drive", "--config", cfg, "--control-log", ctl, "--as", "nobody", "--groups", "other", "--socket", "/s", "--token-env", "T", "--command", "/opt/x", "--tools", "a"}, &out, &errb)
	if code == 0 {
		t.Fatalf("unauthorized allowed: %s", out.String())
	}
}

// mutatingReader edits the working gateway.yaml the first time it is read,
// standing in for a file changing after the decision but before the write.
type mutatingReader struct {
	r    *strings.Reader
	path string
	done bool
}

func (m *mutatingReader) Read(p []byte) (int, error) {
	if !m.done {
		m.done = true
		_ = os.WriteFile(m.path, []byte(mcpGateway+"  drive: {kind: mcp, url: https://other.example.test/y, credential_source: static_env, token_env: T, read_only_tools: [a]}\n"), 0o644)
	}
	return m.r.Read(p)
}

// The write is judged against the working files as they are under the lock,
// not as they were when the decision was made.
func TestEnrollMCPReloadsWorkingConfigUnderLock(t *testing.T) {
	cfg, ctl := mcpEnv(t)
	gwPath := filepath.Join(cfg, "gateway.yaml")
	old := enrollMCPStdin
	t.Cleanup(func() { enrollMCPStdin = old })
	// The collision appears after the first (pre-lock) load, so only a reload
	// under the lock can refuse.
	enrollMCPStdin = &mutatingReader{r: strings.NewReader(`{"command":"/opt/mcp/bin/drive"}`), path: gwPath}
	res := goodRes("/opt/mcp/bin/drive")
	res.ReadOnlyTools = []string{"search"}
	code, _, errs := runMCP(t, cfg, ctl, "drive", "--from-paste", "--tools", "search", "--accept", mcpDigestOf(t, res))
	if code == 0 || !strings.Contains(errs, "already a tool resource") {
		t.Fatalf("want collision on reload: %d %s", code, errs)
	}
	if strings.Contains(readFile(t, gwPath), "unix://") {
		t.Fatal("resource written over a changed config")
	}
	if strings.Contains(readFile(t, ctl), `"action":"enroll_mcp","outcome":"success"`) {
		t.Fatal("success recorded")
	}
}
