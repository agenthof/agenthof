package control_test

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/ledger"
	"github.com/agenthof/agenthof/internal/origin"
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

// TestAppendBootstrapRoundTrips: the additive bootstrap marker is written on
// the wire only when set, and reads back through Decode.
func TestAppendBootstrapRoundTrips(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.jsonl")
	inv := identity.Static("dana@example.com")
	if _, err := control.Append(p, control.Event{Action: "apply", Outcome: "success",
		Invoker: inv, Witness: control.CaptureWitness(), ConfigHash: "sha256:abc", Bootstrap: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := control.Append(p, control.Event{Action: "apply", Outcome: "success",
		Invoker: inv, Witness: control.CaptureWitness(), ConfigHash: "sha256:def"}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 records, got %d:\n%s", len(lines), raw)
	}
	if !strings.Contains(lines[0], `"bootstrap":true`) {
		t.Fatalf("first record must carry bootstrap:true: %s", lines[0])
	}
	if strings.Contains(lines[1], `"bootstrap"`) {
		t.Fatalf("an ordinary apply must omit the bootstrap field entirely: %s", lines[1])
	}
	recs, _, verr := ledger.ReadVerify(p, ledger.Locked)
	if verr != nil {
		t.Fatal(verr)
	}
	d0, err := control.Decode(recs[0].Raw)
	if err != nil {
		t.Fatal(err)
	}
	d1, err := control.Decode(recs[1].Raw)
	if err != nil {
		t.Fatal(err)
	}
	if !d0.Bootstrap || d1.Bootstrap {
		t.Fatalf("decoded bootstrap: first=%v second=%v, want true/false", d0.Bootstrap, d1.Bootstrap)
	}
}

// TestAppendOriginRoundTripsSanitizedAndOrdered: the additive origin lands
// on the wire after fragment_sha256 and before prev, sanitized the way the
// run ledger sanitizes it, and reads back through Decode.
func TestAppendOriginRoundTripsSanitizedAndOrdered(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.jsonl")
	inv := identity.Static("dana@example.com")
	via := &origin.Origin{Via: "api", RemoteAddr: "127.0.0.1:5", UserAgent: "x\x1b[31m", ServerHost: "127.0.0.1:8080"}
	if _, err := control.Append(p, control.Event{Action: "apply", Outcome: "success",
		Invoker: inv, Witness: control.CaptureWitness(), ConfigHash: "sha256:abc", Bootstrap: true, Origin: via}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	want := `"config_hash":"sha256:abc","bootstrap":true,"origin":{"via":"api","remote_addr":"127.0.0.1:5","user_agent":"x[31m","server_host":"127.0.0.1:8080"},"prev":""`
	if !strings.Contains(string(raw), want) {
		t.Fatalf("wire order/sanitizing wrong:\n%s\nwant substring %s", raw, want)
	}
	if via.UserAgent != "x\x1b[31m" {
		t.Fatal("Append must sanitize a copy, not the caller's value")
	}
	recs, _, verr := ledger.ReadVerify(p, ledger.Locked)
	if verr != nil {
		t.Fatal(verr)
	}
	d, err := control.Decode(recs[0].Raw)
	if err != nil {
		t.Fatal(err)
	}
	if d.Origin == nil || d.Origin.Via != "api" || d.Origin.UserAgent != "x[31m" {
		t.Fatalf("Decode origin = %+v", d.Origin)
	}
}

// TestAppendNilOriginIsByteAbsent: every CLI control record (no origin) is
// byte-identical to before the field existed.
func TestAppendNilOriginIsByteAbsent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.jsonl")
	if _, err := control.Append(p, control.Event{Action: "apply", Outcome: "success",
		Invoker: identity.Static("dana@example.com"), Witness: control.CaptureWitness(), ConfigHash: "sha256:abc"}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "origin") {
		t.Fatalf("a nil origin must not serialize: %s", raw)
	}
	recs, _, _ := ledger.ReadVerify(p, ledger.Locked)
	if d, _ := control.Decode(recs[0].Raw); d.Origin != nil {
		t.Fatalf("Decode must leave Origin nil: %+v", d.Origin)
	}
}
