package control_test

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
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

// TestAppendDetailRoundTripsSanitizedAndOrdered: detail is cleaned by Append
// (printable runes only, at most 200), sits after origin and before prev on
// the wire, and decodes back.
func TestAppendDetailRoundTripsSanitizedAndOrdered(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.jsonl")
	inv := identity.Static("dana@example.com")
	const line = "pruned 3 run(s) and 1 artifact(s) older than 180d"
	for _, e := range []control.Event{
		{Action: "prune", Outcome: "success", Invoker: inv, Witness: control.CaptureWitness(), Detail: line, Origin: &origin.Origin{Via: "api"}},
		{Action: "prune", Outcome: "success", Invoker: inv, Witness: control.CaptureWitness(), Detail: "a\x1b[31mb"},
		{Action: "prune", Outcome: "success", Invoker: inv, Witness: control.CaptureWitness(), Detail: strings.Repeat("x", 300)},
	} {
		if _, err := control.Append(p, e); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	want := `"origin":{"via":"api"},"detail":"` + line + `","prev":""`
	if !strings.Contains(string(raw), want) {
		t.Fatalf("wire order wrong:\n%s\nwant substring %s", raw, want)
	}
	recs, _, verr := ledger.ReadVerify(p, ledger.Locked)
	if verr != nil {
		t.Fatal(verr)
	}
	var got []string
	for _, r := range recs {
		d, err := control.Decode(r.Raw)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, d.Detail)
	}
	if got[0] != line || got[1] != "a[31mb" || got[2] != strings.Repeat("x", 200) {
		t.Fatalf("Decode detail = %q", got)
	}
}

// TestAppendEmptyDetailIsByteAbsent: every record written before the field
// existed, and every record that does not set it, carries no detail key at
// all — the wire shape of an existing ledger is unchanged.
func TestAppendEmptyDetailIsByteAbsent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.jsonl")
	if _, err := control.Append(p, control.Event{Action: "apply", Outcome: "success",
		Invoker: identity.Static("dana@example.com"), Witness: control.CaptureWitness(), ConfigHash: "sha256:abc"}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "detail") {
		t.Fatalf("an empty detail must not serialize: %s", raw)
	}
	recs, _, _ := ledger.ReadVerify(p, ledger.Locked)
	if d, _ := control.Decode(recs[0].Raw); d.Detail != "" {
		t.Fatalf("Decode must leave Detail empty: %q", d.Detail)
	}
	// A record written before the field existed decodes with it empty.
	old := []byte(`{"v":"control/1","seq":1,"time":"2026-09-21T10:01:00Z","action":"apply","outcome":"success","invoker":{"subject":"dana@example.com","issuer":"local","method":"asserted"},"witness":{"os_user":"dana","hostname":"host"},"prev":""}`)
	if d, err := control.Decode(old); err != nil || d.Detail != "" {
		t.Fatalf("existing record: err=%v detail=%q", err, d.Detail)
	}
}

// TestGenesisLogID: the one-field decode of the genesis record Append wrote
// yields the 32-hex log_id the raw line carries, for the ledger's whole life;
// an empty ledger, an undecodable genesis, and a genesis without a log_id or
// with a malformed one are refused.
func TestGenesisLogID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.jsonl")
	ev := control.Event{Action: "apply", Outcome: "success", ConfigHash: "sha256:" + strings.Repeat("a", 64),
		Invoker: identity.Invoker{Subject: "dana@example.com", Issuer: "local", Method: "asserted"}, Witness: control.CaptureWitness()}
	if _, err := control.Append(path, ev); err != nil {
		t.Fatal(err)
	}
	recs, _, err := ledger.ReadVerify(path, ledger.Locked)
	if err != nil {
		t.Fatal(err)
	}
	id, err := control.GenesisLogID(recs)
	if err != nil || !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(id) {
		t.Fatalf("GenesisLogID = %q, %v", id, err)
	}
	if !strings.Contains(string(recs[0].Raw), `"log_id":"`+id+`"`) {
		t.Fatalf("the id must be the genesis line's: %s", recs[0].Raw)
	}
	if _, err := control.Append(path, ev); err != nil {
		t.Fatal(err)
	}
	recs, _, _ = ledger.ReadVerify(path, ledger.Locked)
	if again, _ := control.GenesisLogID(recs); again != id {
		t.Fatalf("the id is the genesis record's for the ledger's life: %s vs %s", again, id)
	}
	if strings.Contains(string(recs[1].Raw), "log_id") {
		t.Fatal("only the genesis record carries log_id")
	}
	for name, bad := range map[string][]ledger.Record{
		"empty":     nil,
		"no log_id": {{Raw: []byte(`{"v":"control/1","seq":1,"prev":""}`)}},
		"not hex":   {{Raw: []byte(`{"v":"control/1","seq":1,"prev":"","log_id":"zz112233445566778899aabbccddeeff"}`)}},
		"short":     {{Raw: []byte(`{"log_id":"0011"}`)}},
		"uppercase": {{Raw: []byte(`{"log_id":"00112233445566778899AABBCCDDEEFF"}`)}},
		"not json":  {{Raw: []byte(`{"log_id":`)}},
	} {
		if _, err := control.GenesisLogID(bad); err == nil {
			t.Fatalf("%s must be refused", name)
		}
	}
}
