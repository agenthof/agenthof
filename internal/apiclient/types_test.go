package apiclient

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/engine"
)

func roundTrip[T any](t *testing.T, in T) T {
	t.Helper()
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out T
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round trip changed the value:\n in=%+v\nout=%+v\njson=%s", in, out, data)
	}
	return out
}

func TestWireTypesRoundTrip(t *testing.T) {
	fin := time.Date(2026, 10, 6, 12, 0, 1, 0, time.UTC)
	roundTrip(t, RunRequest{Role: "se", Workflow: "fix-bug", Input: "x"})
	roundTrip(t, RunAccepted{RunID: "r-0123456789abcdef", Status: StatusRefused, Reason: "why"})
	roundTrip(t, RunStatus{RunID: "r-0123456789abcdef", Status: "succeeded", Started: fin.Add(-time.Second), Finished: &fin, OutputSHA: "ab", OutputPreview: "p"})
	roundTrip(t, RunList{Runs: []RunSummary{{RunID: "r-1", Status: StatusRunning}}})
	roundTrip(t, RunEvents{Events: []engine.Event{{Type: "workflow_started", Time: fin}}, Head: Head{Hash: "h", Count: 1}, Integrity: IntegrityBroken, BrokenLine: 3})
	roundTrip(t, InvestigateQuery{Since: "2026-10-06T00:00:00Z", Run: "r-1"})
}

// TestWireKeysArePinned is the contract: a renamed key breaks every client.
func TestWireKeysArePinned(t *testing.T) {
	started := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	data, err := json.Marshal(RunStatus{RunID: "r-1", Status: StatusRunning, Started: started})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"run_id":"r-1","status":"running","started":"2026-10-06T12:00:00Z"}`
	if string(data) != want {
		t.Fatalf("RunStatus json = %s, want %s", data, want)
	}
	data, _ = json.Marshal(RunEvents{Events: []engine.Event{}, Head: Head{}, Integrity: IntegrityVerified})
	want = `{"events":[],"head":{"hash":"","count":0},"integrity":"verified"}`
	if string(data) != want {
		t.Fatalf("RunEvents json = %s, want %s", data, want)
	}
}

func TestInvestigateQueryValuesRoundTrip(t *testing.T) {
	q := InvestigateQuery{Since: "2026-10-06T00:00:00Z", Until: "2026-10-07T00:00:00Z", Invoker: "dana@example.com", Agent: "a", Outcome: "o", Run: "r-1", ConfigHash: "h"}
	got := InvestigateQueryFrom(q.Values())
	if got != q {
		t.Fatalf("got %+v, want %+v", got, q)
	}
	if v := (InvestigateQuery{}).Values(); len(v) != 0 {
		t.Fatalf("an empty query must encode no parameters, got %v", v)
	}
}

func TestApplyWireTypesRoundTripAndKeys(t *testing.T) {
	roundTrip(t, ApplyRequest{Files: map[string]string{"roles/ops.yaml": "name: ops\n"}})
	roundTrip(t, ApplyResult{Status: ApplyRejected, ConfigHash: "sha256:ab", Reason: "r", Errors: []string{"a", "b"}, Head: &Head{Hash: "h", Count: 2}})
	roundTrip(t, ApplyResult{Status: ApplyInstalled, ConfigHash: "sha256:ab", Bootstrap: true, Head: &Head{Hash: "h", Count: 1}, Agents: 1, Workflows: 2, Roles: 3})
	data, err := json.Marshal(ApplyResult{Status: ApplyBusy})
	if err != nil || string(data) != `{"status":"busy"}` {
		t.Fatalf("busy body = %s (err %v), want {\"status\":\"busy\"}", data, err)
	}
	data, _ = json.Marshal(ApplyResult{Status: ApplyPreconditionFailed, CurrentHash: "sha256:cd"})
	if string(data) != `{"status":"precondition_failed","current_hash":"sha256:cd"}` {
		t.Fatalf("412 body = %s", data)
	}
}

func TestConfigSnapshotRoundTripAndKeys(t *testing.T) {
	at := time.Date(2026, 10, 9, 2, 12, 1, 0, time.UTC)
	roundTrip(t, ConfigSnapshot{Hash: "sha256:ab", Version: 7, InstalledAt: at, Files: map[string]string{"roles/ops.yaml": "name: ops\n"}})
	data, err := json.Marshal(ConfigSnapshot{Hash: "sha256:ab", Version: 7, InstalledAt: at})
	if err != nil || string(data) != `{"hash":"sha256:ab","version":7,"installed_at":"2026-10-09T02:12:01Z"}` {
		t.Fatalf("hash-route body = %s (err %v)", data, err)
	}
	data, err = json.Marshal(ConfigSnapshot{Hash: "sha256:ab", Version: 7, InstalledAt: at, Files: map[string]string{"gateway.yaml": "models: {}\n"}})
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"hash":"sha256:ab","version":7,"installed_at":"2026-10-09T02:12:01Z","files":{"gateway.yaml":"models: {}\n"}}` {
		t.Fatalf("full body = %s", data)
	}
	// The document is ApplyRequest-compatible: apply --bundle ignores the
	// extra keys and reads files.
	var req ApplyRequest
	if err := json.Unmarshal(data, &req); err != nil || req.Files["gateway.yaml"] != "models: {}\n" {
		t.Fatalf("a pulled document must decode as an ApplyRequest: %v %+v", err, req)
	}
}

// TestApplyResultKeyIDIsAdditive: key_id travels on installed when the
// server signed, and is absent otherwise; the new status is a fixed string.
func TestApplyResultKeyIDIsAdditive(t *testing.T) {
	const id = "56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c"
	data, err := json.Marshal(ApplyResult{Status: ApplyInstalled, ConfigHash: "sha256:ab", KeyID: id})
	if err != nil || string(data) != `{"status":"installed","config_hash":"sha256:ab","key_id":"`+id+`"}` {
		t.Fatalf("%s %v", data, err)
	}
	data, _ = json.Marshal(ApplyResult{Status: ApplyInstalled, ConfigHash: "sha256:ab"})
	if strings.Contains(string(data), "key_id") {
		t.Fatalf("absent when unsigned: %s", data)
	}
	if ApplyInstalledNotSigned != "installed_not_signed" {
		t.Fatal("the status is a wire constant")
	}
}
