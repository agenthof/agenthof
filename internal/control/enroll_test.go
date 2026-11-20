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

const enrollDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func goodEnroll() *control.Enroll {
	return &control.Enroll{
		CardSHA256: enrollDigest,
		Artifact:   "ghcr.io/example/coder@sha256:" + enrollDigest,
		Requested:  []string{"tool:search", "fast"},
		SignerKID:  "kid-1",
		Files:      []control.EnrollFile{{Path: "agents/coder.yaml", SHA256: enrollDigest}},
	}
}

func enrollEvent(e *control.Enroll) control.Event {
	return control.Event{Action: "enroll", Agent: "coder", Outcome: "success", Enroll: e,
		Invoker: identity.Static("dana@example.com"), Witness: control.CaptureWitness()}
}

func TestAppendEnrollEvent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	if _, err := control.Append(p, enrollEvent(goodEnroll())); err != nil {
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
	if d.Enroll == nil || d.Enroll.CardSHA256 != enrollDigest || len(d.Enroll.Files) != 1 ||
		d.Enroll.Files[0].Path != "agents/coder.yaml" || d.Enroll.SignerKID != "kid-1" || len(d.Enroll.Requested) != 2 {
		t.Fatalf("enroll payload did not round-trip: %+v", d.Enroll)
	}
	out := control.Render([]ledger.Record{{Raw: []byte(line)}}, ledger.Head{Count: 1}, nil)
	if !strings.Contains(out, "coder") || !strings.Contains(out, enrollDigest) {
		t.Fatalf("render must name the agent and card digest:\n%s", out)
	}
}

func TestAppendEnrollDeclinedRendersDecision(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	e := enrollEvent(goodEnroll())
	e.Outcome = "refused"
	e.Reason = &control.Reason{Code: control.CodeConsentDeclined, Message: "operator declined"}
	if _, err := control.Append(p, e); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	out := control.Render([]ledger.Record{{Raw: []byte(strings.TrimSpace(string(raw)))}}, ledger.Head{Count: 1}, nil)
	if !strings.Contains(out, "refused") || !strings.Contains(out, "coder") {
		t.Fatalf("declined enroll must render its decision:\n%s", out)
	}
}

func TestEnrollShapeRejects(t *testing.T) {
	long := strings.Repeat("x", 5000)
	many := make([]string, control.MaxEnrollRequested+1)
	files := make([]control.EnrollFile, control.MaxEnrollFiles+1)
	mut := func(f func(*control.Enroll)) *control.Enroll { e := goodEnroll(); f(e); return e }
	withEvent := func(f func(*control.Event)) control.Event { e := enrollEvent(goodEnroll()); f(&e); return e }
	cases := map[string]control.Event{
		"missing payload":            enrollEvent(nil),
		"bad card digest":            enrollEvent(mut(func(e *control.Enroll) { e.CardSHA256 = "nothex" })),
		"empty artifact":             enrollEvent(mut(func(e *control.Enroll) { e.Artifact = "" })),
		"long artifact":              enrollEvent(mut(func(e *control.Enroll) { e.Artifact = long })),
		"long kid":                   enrollEvent(mut(func(e *control.Enroll) { e.SignerKID = long })),
		"too many requested":         enrollEvent(mut(func(e *control.Enroll) { e.Requested = many })),
		"long requested":             enrollEvent(mut(func(e *control.Enroll) { e.Requested = []string{long} })),
		"too many files":             enrollEvent(mut(func(e *control.Enroll) { e.Files = files })),
		"bad file digest":            enrollEvent(mut(func(e *control.Enroll) { e.Files[0].SHA256 = "zz" })),
		"empty file path":            enrollEvent(mut(func(e *control.Enroll) { e.Files[0].Path = "" })),
		"carries config_hash":        withEvent(func(e *control.Event) { e.ConfigHash = enrollDigest }),
		"payload on another action":  withEvent(func(e *control.Event) { e.Action = "apply" }),
		"non-success without reason": withEvent(func(e *control.Event) { e.Outcome = "refused" }),
	}
	for name, ev := range cases {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "control.jsonl")
			if _, err := control.Append(p, ev); err == nil {
				t.Fatal("Append must reject this enroll event")
			}
			if _, err := os.Stat(p); err == nil {
				t.Fatal("a rejected record must not create the ledger")
			}
		})
	}
}
