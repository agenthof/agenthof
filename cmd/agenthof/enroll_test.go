package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/agentcard"
	"github.com/agenthof/agenthof/internal/config"
)

func TestFetchCardRejectsNonLocalNonHTTPS(t *testing.T) {
	for _, src := range []string{
		"http://example.com/card.json",
		"file:///etc/passwd",
		"ssh://git@example.com/cards.git",
		"git://example.com/cards.git",
		"git@example.com:acme/cards.git",
		"https://",
		"https://user:pw@example.com/card.json",
	} {
		if _, err := fetchCard(src, http.DefaultClient); err == nil {
			t.Errorf("fetchCard(%q) succeeded; want a refusal", src)
		}
	}
}

func TestFetchCardLocalAndHTTPS(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "card.json")
	if err := os.WriteFile(p, []byte(`{"name":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := fetchCard(p, http.DefaultClient)
	if err != nil || string(got) != `{"name":"x"}` {
		t.Fatalf("local fetch = %q, %v", got, err)
	}
	if _, err := fetchCard(dir, http.DefaultClient); err == nil {
		t.Error("a directory must not be accepted as a card")
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"name":"y"}`))
	}))
	defer srv.Close()
	got, err = fetchCard(srv.URL+"/card.json", srv.Client())
	if err != nil || string(got) != `{"name":"y"}` {
		t.Fatalf("https fetch = %q, %v", got, err)
	}
}

func TestFetchCardRefusesCrossHostRedirectAndOversize(t *testing.T) {
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"name":"evil"}`))
	}))
	defer other.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/big" {
			_, _ = w.Write([]byte(strings.Repeat("a", agentcard.MaxCardBytes+10)))
			return
		}
		http.Redirect(w, r, other.URL+"/card.json", http.StatusFound)
	}))
	defer srv.Close()

	// The test client trusts both servers' certificates, so only the redirect
	// policy can be what refuses the hop to a different host:port.
	client := srv.Client()
	client.Transport.(*http.Transport).TLSClientConfig.RootCAs.AddCert(other.Certificate())

	if _, err := fetchCard(srv.URL+"/card.json", client); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Errorf("cross-host redirect: err = %v, want a redirect refusal", err)
	}
	if _, err := fetchCard(srv.URL+"/big", client); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Errorf("oversize: err = %v, want a size refusal", err)
	}
}

func TestCheckAcceptGate(t *testing.T) {
	digest := strings.Repeat("a", 64)
	if err := checkAccept("sha256:"+digest, digest); err != nil {
		t.Errorf("matching digest refused: %v", err)
	}
	if err := checkAccept("sha256:"+strings.Repeat("b", 64), digest); err == nil {
		t.Error("a digest that differs from the card's was accepted")
	}
	if err := checkAccept("sha256:"+digest, ""); err == nil {
		t.Error("an empty card digest must never match")
	}
	for _, bad := range []string{"", digest, "sha256:ABC", "sha256:" + strings.ToUpper(digest), "md5:" + digest} {
		if _, ok := parseAccept(bad); ok {
			t.Errorf("parseAccept(%q) accepted a malformed digest", bad)
		}
	}
}

func TestCheckEnrollName(t *testing.T) {
	for _, bad := range []string{"", ".x", "-x", "_x", "a/b", "a b", "a\nb", "x.yaml/..", "é", strings.Repeat("a", 65)} {
		if err := checkEnrollName(bad); err == nil {
			t.Errorf("name %q accepted", bad)
		}
	}
	for _, ok := range []string{"triage", "Triage-Bot_2.v1", strings.Repeat("a", 64)} {
		if err := checkEnrollName(ok); err != nil {
			t.Errorf("name %q refused: %v", ok, err)
		}
	}
	cfg := config.Config{
		Agents:    []config.AgentDef{{Name: "taken-agent"}},
		Workflows: []config.WorkflowDef{{Name: "taken-wf"}},
		Roles:     []config.RoleDef{{Name: "taken-role"}},
	}
	for _, n := range []string{"taken-agent", "taken-wf", "taken-role"} {
		if err := checkEnrollName(n, cfg); err == nil || !strings.Contains(err.Error(), "already") {
			t.Errorf("existing name %q: err = %v", n, err)
		}
	}
	if err := checkEnrollName("fresh", cfg, cfg); err != nil {
		t.Errorf("fresh name refused: %v", err)
	}
}

func TestWriteNewFilesIsExclusiveAndRollsBack(t *testing.T) {
	root := t.TempDir()
	files := []enrollFile{
		{rel: "workflows/w.yaml", data: []byte("a: 1\n")},
		{rel: "agents/w.yaml", data: []byte("b: 2\n")},
	}
	rec, err := writeNewFiles(root, files)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec) != 2 || rec[0].Path != "workflows/w.yaml" || rec[1].Path != "agents/w.yaml" || len(rec[0].SHA256) != 64 {
		t.Fatalf("recorded files = %+v", rec)
	}
	// No temp litter beside the written files.
	ents, _ := os.ReadDir(filepath.Join(root, "agents"))
	if len(ents) != 1 {
		t.Fatalf("agents/ holds %d entries, want exactly the agent file", len(ents))
	}

	// A second run collides on the first file and must change nothing, and a
	// collision on the LAST file must remove what the run itself created.
	root2 := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root2, "agents"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root2, "agents", "w.yaml"), []byte("mine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := writeNewFiles(root2, files); err == nil {
		t.Fatal("overwrote an existing file")
	}
	if b, _ := os.ReadFile(filepath.Join(root2, "agents", "w.yaml")); string(b) != "mine\n" {
		t.Errorf("existing file changed: %q", b)
	}
	if _, err := os.Stat(filepath.Join(root2, "workflows", "w.yaml")); err == nil {
		t.Error("a file created before the collision was not rolled back")
	}
}

func enrollDescFixture(t *testing.T, desc string) (config.AgentDef, config.WorkflowDef) {
	t.Helper()
	def := config.AgentDef{Provenance: &config.Provenance{CardVersion: "1.0.0"}}
	files, err := enrollFiles("scribe", def, nil, desc)
	if err != nil {
		t.Fatalf("enrollFiles: %v", err)
	}
	ag, err := enrollReload[config.AgentDef](files[2].data, files[2].rel)
	if err != nil {
		t.Fatalf("reload agent: %v", err)
	}
	wf, err := enrollReload[config.WorkflowDef](files[0].data, files[0].rel)
	if err != nil {
		t.Fatalf("reload workflow: %v", err)
	}
	return ag, wf
}

func TestEnrollCarriesCleanedCappedCardDescription(t *testing.T) {
	raw := "Summarises\x1b[2J meetings\x00\n" + strings.Repeat("x", 500)
	ag, wf := enrollDescFixture(t, raw)
	for _, d := range []string{ag.Description, wf.Description} {
		if !strings.HasPrefix(d, "Summarises[2J meetings") {
			t.Fatalf("description not cleaned: %q", d)
		}
		for _, r := range d {
			if r < 0x20 || r == 0x7f {
				t.Fatalf("control character survived: %q", d)
			}
		}
		if n := len([]rune(d)); n != 200 {
			t.Fatalf("description is %d runes, want the 200-rune cap", n)
		}
	}
}

func TestEnrollWithoutCardDescriptionKeepsGenericText(t *testing.T) {
	ag, wf := enrollDescFixture(t, "")
	if want := "Enrolled third-party agent (card version 1.0.0); spawn-only"; ag.Description != want {
		t.Fatalf("agent description = %q, want %q", ag.Description, want)
	}
	if want := "Runs the enrolled agent scribe as a spawned child"; wf.Description != want {
		t.Fatalf("workflow description = %q, want %q", wf.Description, want)
	}
}

func TestPrintMenuShowsCleanedEnrolledDescription(t *testing.T) {
	_, wf := enrollDescFixture(t, "Takes notes\x1b[31m well")
	var b strings.Builder
	printMenu(&b, "r1", []menuEntry{{Role: "scribe", Workflow: wf.Name, Description: wf.Description}})
	if !strings.Contains(b.String(), "scribe/scribe: Takes notes[31m well\n") || strings.ContainsRune(b.String(), 0x1b) {
		t.Fatalf("menu = %q", b.String())
	}
}
