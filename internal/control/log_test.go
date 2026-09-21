package control_test

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/identity"
)

// readFirstJSON reads the first line of the JSONL file at p and decodes it
// as a generic JSON object.
func readFirstJSON(t *testing.T, p string) map[string]any {
	t.Helper()
	return readNthJSON(t, p, 0)
}

// readNthJSON reads the (0-based) nth line of the JSONL file at p and
// decodes it as a generic JSON object.
func readNthJSON(t *testing.T, p string, n int) map[string]any {
	t.Helper()
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	i := 0
	for sc.Scan() {
		if i == n {
			var m map[string]any
			if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
				t.Fatal(err)
			}
			return m
		}
		i++
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	t.Fatalf("line %d not found in %s", n, p)
	return nil
}

func TestControlAppendSeqAndGenesis(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	inv := identity.Static("dana@example.com")
	h1, err := control.Append(p, control.Event{Action: "apply", Outcome: "success", Invoker: inv, Witness: control.CaptureWitness()})
	if err != nil {
		t.Fatal(err)
	}
	if h1.Count != 1 {
		t.Fatalf("count=%d", h1.Count)
	}
	// genesis carries a non-empty log_id; seq==1
	first := readFirstJSON(t, p)
	if first["seq"].(float64) != 1 {
		t.Fatal("seq must start at 1")
	}
	if first["log_id"] == nil || first["log_id"] == "" {
		t.Fatal("genesis needs log_id")
	}
	h2, err := control.Append(p, control.Event{Action: "disable", Agent: "coder",
		Outcome: "success", Invoker: inv, Witness: control.CaptureWitness()})
	if err != nil {
		t.Fatal(err)
	}
	if h2.Count != 2 {
		t.Fatalf("count=%d", h2.Count)
	}
	// second record: seq==2, NO log_id
	second := readNthJSON(t, p, 1)
	if second["seq"].(float64) != 2 {
		t.Fatal("seq must be 2")
	}
	if _, ok := second["log_id"]; ok {
		t.Fatal("only genesis carries log_id")
	}
}

func TestControlSuccessOmitsReason(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	_, _ = control.Append(p, control.Event{Action: "apply", Outcome: "success",
		Invoker: identity.Static("d"), Witness: control.CaptureWitness()})
	if _, ok := readFirstJSON(t, p)["reason"]; ok {
		t.Fatal("success must omit reason")
	}
}

// TestAppendNonSuccessRequiresReason covers the centrally enforced
// condition: Append must enforce, in one place, that a non-"success"
// outcome always carries an explanation — never scattered across call
// sites that might forget it.
func TestAppendNonSuccessRequiresReason(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	_, err := control.Append(p, control.Event{Action: "disable", Outcome: "refused",
		Invoker: identity.Static("dana@example.com"), Witness: control.CaptureWitness()})
	if err == nil {
		t.Fatal("a non-success outcome with a nil Reason must be rejected")
	}
}

// TestAppendPopulatedReasonRoundTrips checks that a non-success Event
// WITH a populated Reason is accepted and that reason.code/reason.message
// actually reach the wire — not just that Append tolerates a non-nil
// pointer.
func TestAppendPopulatedReasonRoundTrips(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	_, err := control.Append(p, control.Event{
		Action:  "disable",
		Agent:   "coder",
		Outcome: "refused",
		Reason:  &control.Reason{Code: control.CodeAgentNotFound, Message: "agent coder not found"},
		Invoker: identity.Static("dana@example.com"), Witness: control.CaptureWitness(),
	})
	if err != nil {
		t.Fatalf("Append with a populated Reason must succeed: %v", err)
	}
	rec := readFirstJSON(t, p)
	reason, ok := rec["reason"].(map[string]any)
	if !ok {
		t.Fatalf("reason missing or not an object: %+v", rec["reason"])
	}
	if reason["code"] != control.CodeAgentNotFound {
		t.Fatalf("reason.code = %v, want %s", reason["code"], control.CodeAgentNotFound)
	}
	if reason["message"] != "agent coder not found" {
		t.Fatalf("reason.message = %v, want %q", reason["message"], "agent coder not found")
	}
}
