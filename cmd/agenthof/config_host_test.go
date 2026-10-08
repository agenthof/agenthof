package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/apiclient"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/obs"
)

var apiInvoker = identity.Invoker{Subject: "dana@example.com", Issuer: "https://idp.test", Method: "oidc", Groups: []string{"platform-eng"}}

func apiVia() *engine.Origin {
	return &engine.Origin{Via: "api", RemoteAddr: "127.0.0.1:5", ServerHost: "127.0.0.1:8080"}
}

func newConfigHost(t *testing.T, allowBootstrap bool) (*configHost, string, *bytes.Buffer) {
	t.Helper()
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	logs := &bytes.Buffer{}
	return &configHost{controlLog: ctl, allowBootstrap: allowBootstrap, logger: obs.New(logs, slog.LevelDebug, obs.FormatText)}, ctl, logs
}

func sampleBundle(t *testing.T) map[string][]byte {
	t.Helper()
	b, err := config.ReadBundle(writeSample(t))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestConfigHostBootstrapIsOptIn(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	off, ctl, _ := newConfigHost(t, false)
	res := off.Apply(apiInvoker, sampleBundle(t), apiclient.Precondition{ExpectNone: true}, apiVia())
	if res.Status != apiclient.ApplyRefused || res.Reason != msgBootstrapDisabled || res.Head == nil || res.Head.Count != 1 {
		t.Fatalf("%+v", res)
	}
	ev := controlEvents(t, ctl)
	if len(ev) != 1 || ev[0].Outcome != "refused" || ev[0].Origin == nil || ev[0].Origin.Via != "api" || ev[0].ConfigHash == "" {
		t.Fatalf("recorded refusal with origin and hash expected: %+v", ev)
	}
	on := &configHost{controlLog: ctl, allowBootstrap: true, logger: off.logger}
	res = on.Apply(apiInvoker, sampleBundle(t), apiclient.Precondition{ExpectNone: true}, apiVia())
	if res.Status != apiclient.ApplyInstalled || !res.Bootstrap || res.Agents != 2 || res.Workflows != 1 || res.Roles != 2 || res.Head.Count != 2 {
		t.Fatalf("%+v", res)
	}
	if readPointer(t, ctl) != res.ConfigHash {
		t.Fatal("the pointer must name the install")
	}
	if ev := controlEvents(t, ctl); !ev[1].Bootstrap || ev[1].Origin == nil || ev[1].Origin.Via != "api" || ev[1].AssertedAs != "" {
		t.Fatalf("%+v", ev[1])
	}
}

// TestApplyRejectedReasonCleanedOnlyOverAPI pins the Origin-scoped reason
// sanitization: a multi-line yaml error (whose text is "yaml: unmarshal
// errors:\n  line …") is recorded RAW by a CLI apply — the newline kept,
// byte-identical to what the local command recorded before the API path
// existed — and cleaned to one printable line by an API apply, where the
// proposer is any authorized token-holder. A single fixture exercises both so
// the two paths cannot drift.
func TestApplyRejectedReasonCleanedOnlyOverAPI(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	// model is a scalar string; a list is a yaml TypeError on unmarshal, whose
	// Error() is multi-line.
	badAgent := []byte("name: coder\nmodel: [a, b]\ninstruction: x\noutput: y\nendpoint: http://127.0.0.1:1\n")

	// CLI leg: a fresh root bootstraps the apply (permitted), then rejects on
	// the load error; the recorded reason keeps the newline.
	cliDir := writeSample(t)
	if err := os.WriteFile(filepath.Join(cliDir, "agents", "coder.yaml"), badAgent, 0o644); err != nil {
		t.Fatal(err)
	}
	cliCtl := filepath.Join(t.TempDir(), "control.jsonl")
	var out bytes.Buffer
	if code := cmdApply([]string{"--config", cliDir, "--control-log", cliCtl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 1 {
		t.Fatalf("a yaml type error must be rejected: exit %d\n%s", code, out.String())
	}
	cliReason := controlEvents(t, cliCtl)[0].Reason.Message
	if !strings.Contains(cliReason, "\n") {
		t.Fatalf("a CLI apply must record the raw multi-line reason (newline kept): %q", cliReason)
	}

	// API leg: the same files as a bundle; the recorded reason is cleaned to one
	// printable line, still naming the fault.
	h, apiCtl, _ := newConfigHost(t, true)
	bundle, err := config.ReadBundle(cliDir)
	if err != nil {
		t.Fatal(err)
	}
	res := h.Apply(apiInvoker, bundle, apiclient.Precondition{ExpectNone: true}, apiVia())
	if res.Status != apiclient.ApplyRejected {
		t.Fatalf("%+v", res)
	}
	apiReason := controlEvents(t, apiCtl)[0].Reason.Message
	if strings.ContainsAny(apiReason, "\x1b\n") {
		t.Fatalf("an API apply must record a cleaned one-line reason: %q", apiReason)
	}
	if !strings.Contains(apiReason, "cannot unmarshal") {
		t.Fatalf("the cleaned reason must still name the fault: %q", apiReason)
	}
}

func TestConfigHostMapsEveryOutcome(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	h, ctl, logs := newConfigHost(t, true)
	bundle := sampleBundle(t)
	first := h.Apply(apiInvoker, bundle, apiclient.Precondition{ExpectNone: true}, apiVia())
	if first.Status != apiclient.ApplyInstalled {
		t.Fatalf("%+v", first)
	}

	// 412: stale precondition, nothing recorded, current_hash set.
	stale := h.Apply(apiInvoker, bundle, apiclient.Precondition{ExpectNone: true}, apiVia())
	if stale.Status != apiclient.ApplyPreconditionFailed || stale.CurrentHash != first.ConfigHash || stale.Head != nil || stale.ConfigHash != "" {
		t.Fatalf("%+v", stale)
	}
	if len(controlEvents(t, ctl)) != 1 {
		t.Fatal("a failed precondition records nothing")
	}

	// 403: an invoker outside the apply grant.
	outsider := identity.Invoker{Subject: "mallory@example.com", Issuer: "https://idp.test", Method: "oidc", Groups: []string{"finance"}}
	refused := h.Apply(outsider, bundle, apiclient.Precondition{ExpectInstalled: first.ConfigHash}, apiVia())
	if refused.Status != apiclient.ApplyRefused || refused.Reason != "not authorized: no role grants apply to the invoker" || refused.ConfigHash == "" || refused.Head.Count != 2 {
		t.Fatalf("%+v", refused)
	}

	// 422: every load/validation line, cleaned; reason is the first.
	bad := sampleBundle(t)
	bad["roles/se.yaml"] = []byte("name: software-engineer\nworkflows: [nope]\nallowed_groups: [\"*\"]\n")
	// Two VALIDATION errors (both files still parse): an unknown workflow in
	// each role; the second role's name carries an escape (yaml's \e in a
	// double-quoted scalar) so the entity in its error line is attacker-shaped.
	bad["roles/ops.yaml"] = []byte("name: \"platform-admin\\e[2J\"\nallowed_groups: [platform-eng]\ncontrol: [apply]\nworkflows: [missing]\n")
	rejected := h.Apply(apiInvoker, bad, apiclient.Precondition{ExpectInstalled: first.ConfigHash}, apiVia())
	if rejected.Status != apiclient.ApplyRejected || len(rejected.Errors) < 2 || rejected.Reason != rejected.Errors[0] || rejected.ConfigHash == "" || rejected.Head.Count != 3 {
		t.Fatalf("%+v", rejected)
	}
	sawEscape := false
	for _, e := range rejected.Errors {
		if strings.ContainsAny(e, "\x1b\n") {
			t.Fatalf("422 lines must be cleaned: %q", e)
		}
		sawEscape = sawEscape || strings.Contains(e, "platform-admin[2J")
	}
	if !sawEscape {
		t.Fatalf("fixture must produce a line naming the escaped role (cleaned): %q", rejected.Errors)
	}
	if ev := controlEvents(t, ctl); strings.ContainsAny(ev[2].Reason.Message, "\x1b\n") {
		t.Fatalf("the recorded reason must be cleaned too: %q", ev[2].Reason.Message)
	}
	if readPointer(t, ctl) != first.ConfigHash {
		t.Fatal("a rejected proposal installs nothing")
	}

	// 500 error: the OS text is recorded and logged, never returned.
	store := installedStore(ctl)
	if err := os.Chmod(store, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(store, 0o700) })
	changed := sampleBundle(t)
	changed["agents/coder.yaml"] = []byte("name: coder\nmodel: fast\ninstruction: v2\noutput: patch\nendpoint: http://127.0.0.1:1\n")
	ioErr := h.Apply(apiInvoker, changed, apiclient.Precondition{ExpectInstalled: first.ConfigHash}, apiVia())
	if ioErr.Status != apiclient.ApplyError || ioErr.Reason != apiclient.ReasonStoreUnusable || ioErr.Head == nil || ioErr.Head.Count != 4 {
		t.Fatalf("%+v", ioErr)
	}
	if ev := controlEvents(t, ctl); ev[3].Outcome != "error" || !strings.Contains(ev[3].Reason.Message, "permission denied") {
		t.Fatalf("the recorded reason keeps the OS text: %+v", ev[3])
	}
	_ = os.Chmod(store, 0o700)

	// ledger damaged: nothing recorded, the hint is logged, not returned.
	if err := os.WriteFile(ctl, append(mustRead(t, ctl), []byte(`{"v":"control/1",`)...), 0o600); err != nil {
		t.Fatal(err)
	}
	damaged := h.Apply(apiInvoker, changed, apiclient.Precondition{ExpectInstalled: first.ConfigHash}, apiVia())
	if damaged.Status != apiclient.ApplyLedgerDamaged || damaged.Reason != apiclient.ReasonLedgerDamaged || damaged.Head != nil {
		t.Fatalf("%+v", damaged)
	}
	if !strings.Contains(logs.String(), "audit repair control --control-log "+ctl) {
		t.Fatalf("the repair hint must be logged:\n%s", logs.String())
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestConfigHostBusyMapsTo409Body: a CLI writer holding installed.lock
// makes the API apply busy — status busy, nothing else set, nothing
// recorded. Waits the real lockTimeout; t.Parallel.
func TestConfigHostBusyMapsTo409Body(t *testing.T) {
	t.Parallel()
	h, ctl, _ := newConfigHost(t, true)
	holdLock(t, "file", installedLock(ctl), 9000)
	res := h.Apply(apiInvoker, sampleBundle(t), apiclient.Precondition{ExpectNone: true}, apiVia())
	if res.Status != apiclient.ApplyBusy || res.Head != nil || res.Reason != "" || res.ConfigHash != "" {
		t.Fatalf("busy must carry status alone: %+v", res)
	}
	if _, err := os.Stat(ctl); err == nil {
		if len(controlEvents(t, ctl)) != 0 {
			t.Fatal("busy records nothing")
		}
	}
}
