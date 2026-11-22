package control_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/ledger"
)

func goodEnrollMCP() *control.EnrollMCP {
	return &control.EnrollMCP{
		Resource:      "drive",
		Command:       []string{"npx", "-y", "drive-mcp"},
		EnvNames:      []string{"DRIVE_TOKEN"},
		ReadOnlyTools: []string{"search", "read"},
		Files:         []control.EnrollFile{{Path: "resources/drive.yaml", SHA256: enrollDigest}},
	}
}

func enrollMCPEvent(m *control.EnrollMCP) control.Event {
	return control.Event{Action: "enroll_mcp", Outcome: "success", EnrollMCP: m,
		Invoker: identity.Static("dana@example.com"), Witness: control.CaptureWitness()}
}

func TestAppendEnrollMCPRoundTripsAndRenders(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	if _, err := control.Append(p, enrollMCPEvent(goodEnrollMCP())); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(raw))
	d, err := control.Decode([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	m := d.EnrollMCP
	if m == nil || m.Resource != "drive" || len(m.Command) != 3 || len(m.EnvNames) != 1 ||
		len(m.ReadOnlyTools) != 2 || len(m.Files) != 1 || d.Enroll != nil {
		t.Fatalf("enroll_mcp payload did not round-trip: %+v", m)
	}
	out := control.Render([]ledger.Record{{Raw: []byte(line)}}, ledger.Head{Count: 1}, nil)
	if !strings.Contains(out, "resource drive enrolled") || strings.Contains(out, "agent  enrolled") {
		t.Fatalf("render must label the resource:\n%s", out)
	}
}

func TestEnrollMCPRefusalRendersOutcome(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	e := enrollMCPEvent(goodEnrollMCP())
	e.Outcome = "refused"
	e.Reason = &control.Reason{Code: control.CodeConsentDeclined, Message: "operator declined"}
	if _, err := control.Append(p, e); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	out := control.Render([]ledger.Record{{Raw: []byte(strings.TrimSpace(string(raw)))}}, ledger.Head{Count: 1}, nil)
	if !strings.Contains(out, "refused") || !strings.Contains(out, "drive") {
		t.Fatalf("declined enroll_mcp must render its decision:\n%s", out)
	}
}

func TestEnrollMCPSuccessRequiresPayload(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	if _, err := control.Append(p, enrollMCPEvent(nil)); err == nil {
		t.Fatal("a successful enroll_mcp with no payload must be rejected")
	}
}

func TestEnrollStillRequiresCardOnSuccess(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	if _, err := control.Append(p, enrollEvent(nil)); err == nil {
		t.Fatal("a successful enroll with no payload must still be rejected")
	}
	bad := goodEnroll()
	bad.CardSHA256 = ""
	if _, err := control.Append(p, enrollEvent(bad)); err == nil {
		t.Fatal("a successful enroll without card_sha256 must still be rejected")
	}
}

func TestEnrollMCPShapeRejects(t *testing.T) {
	long := strings.Repeat("x", 5000)
	manyArgs := make([]string, control.MaxEnrollCommand+1)
	for i := range manyArgs {
		manyArgs[i] = "a"
	}
	manyReq := make([]string, control.MaxEnrollRequested+1)
	for i := range manyReq {
		manyReq[i] = "a"
	}
	cases := map[string]func(*control.EnrollMCP){
		"empty resource":  func(m *control.EnrollMCP) { m.Resource = "" },
		"long resource":   func(m *control.EnrollMCP) { m.Resource = strings.Repeat("r", 65) },
		"no command":      func(m *control.EnrollMCP) { m.Command = nil },
		"too many args":   func(m *control.EnrollMCP) { m.Command = manyArgs },
		"empty arg":       func(m *control.EnrollMCP) { m.Command = []string{"npx", ""} },
		"long arg":        func(m *control.EnrollMCP) { m.Command = []string{long} },
		"too many envs":   func(m *control.EnrollMCP) { m.EnvNames = manyReq },
		"long env":        func(m *control.EnrollMCP) { m.EnvNames = []string{long} },
		"too many tools":  func(m *control.EnrollMCP) { m.ReadOnlyTools = manyReq },
		"long tool":       func(m *control.EnrollMCP) { m.ReadOnlyTools = []string{long} },
		"bad file sha":    func(m *control.EnrollMCP) { m.Files[0].SHA256 = "XYZ" },
		"empty file path": func(m *control.EnrollMCP) { m.Files[0].Path = "" },
		"too many files":  func(m *control.EnrollMCP) { m.Files = make([]control.EnrollFile, control.MaxEnrollFiles+1) },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			m := goodEnrollMCP()
			mut(m)
			p := filepath.Join(t.TempDir(), "control.jsonl")
			if _, err := control.Append(p, enrollMCPEvent(m)); err == nil {
				t.Fatalf("%s must be rejected", name)
			}
		})
	}
	t.Run("payload on another action", func(t *testing.T) {
		e := enrollEvent(goodEnroll())
		e.EnrollMCP = goodEnrollMCP()
		p := filepath.Join(t.TempDir(), "control.jsonl")
		if _, err := control.Append(p, e); err == nil {
			t.Fatal("enroll_mcp payload on an enroll record must be rejected")
		}
	})
	t.Run("config_hash", func(t *testing.T) {
		e := enrollMCPEvent(goodEnrollMCP())
		e.ConfigHash = enrollDigest
		p := filepath.Join(t.TempDir(), "control.jsonl")
		if _, err := control.Append(p, e); err == nil {
			t.Fatal("enroll_mcp must carry no config_hash")
		}
	})
}

func TestEnrollMCPChainVerifies(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	if _, err := control.Append(p, enrollMCPEvent(goodEnrollMCP())); err != nil {
		t.Fatal(err)
	}
	if _, err := control.Append(p, enrollEvent(goodEnroll())); err != nil {
		t.Fatal(err)
	}
	recs, head, err := ledger.ReadVerify(p, ledger.Locked)
	if err != nil || len(recs) != 2 || head.Count != 2 {
		t.Fatalf("chain with an enroll_mcp record must verify: recs=%d head=%+v err=%v", len(recs), head, err)
	}
}
