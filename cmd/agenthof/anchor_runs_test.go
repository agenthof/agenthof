package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/anchor"
	"github.com/agenthof/agenthof/internal/anchor/anchortest"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/ledger"
	"github.com/agenthof/agenthof/internal/sidecar"
)

const testRunID = "r-0123456789abcdef"

// runsBackend is a Stub that counts its Submits and can be told to fail them,
// since the shared Stub's Fail gates only Verify.
type runsBackend struct {
	*anchortest.Stub
	mu        sync.Mutex
	submits   int
	submitErr error
	onSubmit  func()
}

func (b *runsBackend) Submit(ctx context.Context, h anchor.Head) (anchor.Receipt, error) {
	b.mu.Lock()
	b.submits++
	err, hook := b.submitErr, b.onSubmit
	b.mu.Unlock()
	if hook != nil {
		hook()
	}
	if err != nil {
		return anchor.Receipt{}, err
	}
	return b.Stub.Submit(ctx, h)
}

func (b *runsBackend) count() int { b.mu.Lock(); defer b.mu.Unlock(); return b.submits }

// useRunsBackend routes every backend construction to one runsBackend.
func useRunsBackend(t *testing.T) *runsBackend {
	t.Helper()
	b := &runsBackend{Stub: anchortest.NewStub([]byte("test-secret"))}
	prev := newAnchorBackend
	newAnchorBackend = func(backendSpec) (anchor.Backend, error) { return b, nil }
	t.Cleanup(func() { newAnchorBackend = prev })
	return b
}

// runsFixture is an applied root with run anchoring on and one finished run.
type runsFixture struct {
	ctl, logDir, id string
}

func newRunsFixture(t *testing.T) runsFixture {
	t.Helper()
	t.Setenv("AGENTHOF_TOKEN", "")
	t.Setenv("AGENTHOF_LOG_LEVEL", "")
	t.Setenv("AGENTHOF_LOG_FORMAT", "")
	ctl := applied(t, anchorSample(t))
	writeIntegrity(t, ctl, "anchor: tlog\nanchor_backend:\n  url: http://stub.invalid\nanchor_runs: on-demand\n")
	logDir := t.TempDir()
	writeRunLedger(t, logDir, testRunID,
		engine.Event{Type: "workflow_started"},
		engine.Event{Type: "step_started", Step: "a"},
		engine.Event{Type: "workflow_finished", Status: "succeeded"})
	return runsFixture{ctl: ctl, logDir: logDir, id: testRunID}
}

func (f runsFixture) args(extra ...string) []string {
	return append([]string{"--control-log", f.ctl, "--as", "dana@example.com", "--groups", "platform-eng", "--log-dir", f.logDir}, extra...)
}

// anchorCmd drives cmdAuditAnchor with separate stdout and stderr.
func anchorCmd(args []string) (code int, stdout, stderr string) {
	var out, errb bytes.Buffer
	code = cmdAuditAnchor(args, &out, &errb)
	return code, out.String(), errb.String()
}

func lastControl(t *testing.T, ctl string) control.DecodedEvent {
	t.Helper()
	recs := controlRecords(t, ctl)
	d, err := control.Decode(recs[len(recs)-1].Raw)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func noSidecar(t *testing.T, f runsFixture) {
	t.Helper()
	if _, err := os.Lstat(sidecar.Path(f.logDir, f.id)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a sidecar exists (or cannot be statted): %v", err)
	}
	if tmp, _ := filepath.Glob(filepath.Join(f.logDir, "*.tmp-*")); len(tmp) != 0 {
		t.Fatalf("temp files left behind: %v", tmp)
	}
}

// TestAuditAnchorRunShapeCheckedBeforeAnyPath: a --run value that is not a run
// id is refused right after flag parsing, before the posture is read, before
// any path is built and before the lock directory could be created: --log-dir
// names a path that does not exist and the answer is the id error, not ENOENT;
// the log directory is not created; nothing is recorded; no backend is built.
func TestAuditAnchorRunShapeCheckedBeforeAnyPath(t *testing.T) {
	f := newRunsFixture(t)
	b := useRunsBackend(t)
	missing := filepath.Join(t.TempDir(), "nope", "runs")
	before := len(controlRecords(t, f.ctl))
	for _, id := range []string{"../control", "../control.jsonl", "R-0123456789ABCDEF", "r-0123456789abcde", "r-0123456789abcdef0", "", "r-0123456789abcdef/../x"} {
		code, out, _ := anchorCmd([]string{"--control-log", f.ctl, "--as", "dana@example.com", "--groups", "platform-eng", "--log-dir", missing, "--run", id})
		if code != 1 || !strings.Contains(out, fmt.Sprintf("audit anchor: --run %q is not a run id (want r- followed by 16 lowercase hex)", id)) || strings.Contains(out, "no such file") {
			t.Fatalf("id %q: exit %d\n%s", id, code, out)
		}
		if strings.Contains(out, "control head:") {
			t.Fatalf("id %q: printed a control head\n%s", id, out)
		}
	}
	// Not even the posture is read: a control log that does not exist gives the
	// same answer.
	code, out, _ := anchorCmd([]string{"--control-log", filepath.Join(t.TempDir(), "absent", "control.jsonl"), "--log-dir", missing, "--run", "../control"})
	if code != 1 || !strings.Contains(out, "is not a run id") {
		t.Fatalf("absent control log: exit %d\n%s", code, out)
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the log directory was touched: %v", err)
	}
	if got := len(controlRecords(t, f.ctl)); got != before || b.count() != 0 {
		t.Fatalf("records %d -> %d, submits %d", before, got, b.count())
	}
}

// TestAuditAnchorRunWritesSidecarAndRunScopedRecord: one --run files the run's
// final head, writes <id>.anchor beside the ledger with the invoker's three
// identity keys and nothing more, records a run-scoped success carrying no
// proof, and prints the three lines then the control head.
func TestAuditAnchorRunWritesSidecarAndRunScopedRecord(t *testing.T) {
	f := newRunsFixture(t)
	b := useRunsBackend(t)
	runPath := filepath.Join(f.logDir, f.id+".jsonl")
	runBefore, err := os.ReadFile(runPath)
	if err != nil {
		t.Fatal(err)
	}
	_, runHead, err := ledger.ReadVerify(runPath, ledger.Unlocked)
	if err != nil {
		t.Fatal(err)
	}

	code, out, _ := anchorCmd(f.args("--run", f.id))
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if b.count() != 1 {
		t.Fatalf("submits = %d", b.count())
	}

	recs, found, err := sidecar.Read(sidecar.Path(f.logDir, f.id))
	if err != nil || !found || len(recs) != 1 {
		t.Fatalf("sidecar: %v %v %d", err, found, len(recs))
	}
	r := recs[0]
	if r.RunID != f.id || r.Seq != runHead.Count || r.Seq != 3 || r.Hash != runHead.Hash || r.Kind != "tlog" || r.Ref == "" || r.Proof == "" {
		t.Fatalf("sidecar record %+v (head %+v)", r, runHead)
	}
	if r.AnchoredBy.Subject != "dana@example.com" || r.AnchoredBy.Method != "asserted" {
		t.Fatalf("anchored_by %+v", r.AnchoredBy)
	}
	raw, err := os.ReadFile(sidecar.Path(f.logDir, f.id))
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(bytes.TrimSpace(raw), &generic); err != nil {
		t.Fatal(err)
	}
	var by map[string]json.RawMessage
	if err := json.Unmarshal(generic["anchored_by"], &by); err != nil || len(by) != 3 {
		t.Fatalf("anchored_by keys = %v (%v)", by, err)
	}
	for _, k := range []string{"subject", "issuer", "method"} {
		if _, ok := by[k]; !ok {
			t.Fatalf("anchored_by lacks %q: %s", k, generic["anchored_by"])
		}
	}
	for _, banned := range []string{`"groups"`, `"witness"`} {
		if bytes.Contains(raw, []byte(banned)) {
			t.Fatalf("sidecar carries %s: %s", banned, raw)
		}
	}

	d := lastControl(t, f.ctl)
	if d.Action != "anchor" || d.Outcome != "success" || d.Anchor == nil || d.Anchor.RunID != f.id || d.Anchor.Seq != 3 || d.Anchor.Hash != runHead.Hash || d.Anchor.Ref != r.Ref || d.Anchor.Proof != "" {
		t.Fatalf("control record %+v / %+v", d, d.Anchor)
	}
	all := controlRecords(t, f.ctl)
	if bytes.Contains(all[len(all)-1].Raw, []byte(`"proof"`)) {
		t.Fatalf("the run-scoped control record carries a proof: %s", all[len(all)-1].Raw)
	}

	head := ledgerHeadOf(t, f.ctl)
	want := fmt.Sprintf("anchored run %s: events=3 sha256=%s\n", f.id, runHead.Hash)
	if !strings.HasPrefix(out, want) ||
		!strings.Contains(out, fmt.Sprintf("\n  log: %s  entry: %s  log key: none (as served)\n", r.Backend, r.Ref)) ||
		!strings.Contains(out, "\n  index: -  integrated: ") || !strings.Contains(out, "  (as reported by the log)\n") ||
		!strings.HasSuffix(out, fmt.Sprintf("control head: seq=%d sha256=%s\n", head.Count, head.Hash)) {
		t.Fatalf("stdout:\n%s", out)
	}

	runAfter, err := os.ReadFile(runPath)
	if err != nil || !bytes.Equal(runAfter, runBefore) {
		t.Fatalf("the run's ledger changed: %v", err)
	}
}

func ledgerHeadOf(t *testing.T, ctl string) ledger.Head {
	t.Helper()
	_, head, err := ledger.ReadVerify(ctl, ledger.Locked)
	if err != nil {
		t.Fatal(err)
	}
	return head
}

// TestAuditAnchorRunRePins: anchoring the same head again is a re-pin — a
// second sidecar line and a second control record, never a refusal.
func TestAuditAnchorRunRePins(t *testing.T) {
	f := newRunsFixture(t)
	b := useRunsBackend(t)
	base := len(controlRecords(t, f.ctl))
	for i := 0; i < 2; i++ {
		if code, out, _ := anchorCmd(f.args("--run", f.id)); code != 0 {
			t.Fatalf("pin %d: exit %d\n%s", i, code, out)
		}
	}
	recs, _, err := sidecar.Read(sidecar.Path(f.logDir, f.id))
	if err != nil || len(recs) != 2 || b.count() != 2 {
		t.Fatalf("sidecar %d records (%v), submits %d", len(recs), err, b.count())
	}
	if got := len(controlRecords(t, f.ctl)); got != base+2 {
		t.Fatalf("control records %d, want %d", got, base+2)
	}
}

// TestAuditAnchorRunRefusedUnderNone: without anchor_runs: on-demand there is
// nothing to do — exit 1, unrecorded, and the backend is never reached.
func TestAuditAnchorRunRefusedUnderNone(t *testing.T) {
	f := newRunsFixture(t)
	b := useRunsBackend(t)
	tlogPostureFor(t, f.ctl, "http://stub.invalid")
	before := len(controlRecords(t, f.ctl))
	code, out, _ := anchorCmd(f.args("--run", f.id))
	if code != 1 || !strings.Contains(out, "run anchoring is not configured") || strings.Contains(out, "control head:") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if got := len(controlRecords(t, f.ctl)); got != before || b.count() != 0 {
		t.Fatalf("records %d -> %d, submits %d", before, got, b.count())
	}
	noSidecar(t, f)
}

// TestAuditAnchorRunNotAnchorable: a run that is missing, unterminated or torn
// is exit 1 with nothing recorded and nothing written.
func TestAuditAnchorRunNotAnchorable(t *testing.T) {
	f := newRunsFixture(t)
	b := useRunsBackend(t)
	unterminated := "r-00000000000000a1"
	writeRunLedger(t, f.logDir, unterminated, engine.Event{Type: "workflow_started"}, engine.Event{Type: "step_started", Step: "a"})
	torn := "r-00000000000000a2"
	writeRunLedger(t, f.logDir, torn, engine.Event{Type: "workflow_started"}, engine.Event{Type: "workflow_finished", Status: "succeeded"})
	tornPath := filepath.Join(f.logDir, torn+".jsonl")
	st, err := os.Stat(tornPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(tornPath, st.Size()-5); err != nil {
		t.Fatal(err)
	}
	before := len(controlRecords(t, f.ctl))
	for _, c := range []struct{ id, want string }{
		{"r-00000000000000a0", fmt.Sprintf("audit anchor: no run r-00000000000000a0 under %s", f.logDir)},
		{unterminated, "audit anchor: run " + unterminated + " has no final event; still running or tail lost — not anchorable"},
		{torn, "audit anchor: run " + torn + ": "},
	} {
		code, out, _ := anchorCmd(f.args("--run", c.id))
		if code != 1 || !strings.Contains(out, c.want) || strings.Contains(out, "control head:") {
			t.Fatalf("%s: exit %d\n%s", c.id, code, out)
		}
		if c.id == torn && !strings.Contains(out, "; a run ledger has no repair — not anchorable") {
			t.Fatalf("torn: %s", out)
		}
		if _, err := os.Lstat(sidecar.Path(f.logDir, c.id)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s: a sidecar was written: %v", c.id, err)
		}
	}
	if got := len(controlRecords(t, f.ctl)); got != before || b.count() != 0 {
		t.Fatalf("records %d -> %d, submits %d", before, got, b.count())
	}
}

// TestAuditAnchorRunSubmitFailureRecordsErrorWithRunID: a log that answers no
// is one recorded error naming the run and what was tried, exit 1, with no
// ref, no sidecar and no temp file.
func TestAuditAnchorRunSubmitFailureRecordsErrorWithRunID(t *testing.T) {
	f := newRunsFixture(t)
	b := useRunsBackend(t)
	b.submitErr = errors.New("status 429 from rekor.test")
	_, runHead, err := ledger.ReadVerify(filepath.Join(f.logDir, f.id+".jsonl"), ledger.Unlocked)
	if err != nil {
		t.Fatal(err)
	}
	code, out, _ := anchorCmd(f.args("--run", f.id))
	head := ledgerHeadOf(t, f.ctl)
	if code != 1 || !strings.Contains(out, "audit anchor: run "+f.id+": status 429 from rekor.test\n") || !strings.HasSuffix(out, fmt.Sprintf("control head: seq=%d sha256=%s\n", head.Count, head.Hash)) {
		t.Fatalf("exit %d\n%s", code, out)
	}
	d := lastControl(t, f.ctl)
	if d.Action != "anchor" || d.Outcome != "error" || d.Reason == nil || d.Reason.Code != control.CodeAnchorFailed || d.Anchor == nil ||
		d.Anchor.RunID != f.id || d.Anchor.Seq != 3 || d.Anchor.Hash != runHead.Hash || d.Anchor.Ref != "" || d.Anchor.Proof != "" || d.Anchor.Kind != "tlog" {
		t.Fatalf("record %+v / %+v", d, d.Anchor)
	}
	noSidecar(t, f)
}

// TestAuditAnchorRunProofNotWritten: the log took the head but the proof
// cannot be put beside the run — the operator is told, an error naming the run
// is recorded, and the command fails.
func TestAuditAnchorRunProofNotWritten(t *testing.T) {
	f := newRunsFixture(t)
	b := useRunsBackend(t)
	// A directory where the sidecar belongs makes sidecar.Append refuse.
	if err := os.Mkdir(sidecar.Path(f.logDir, f.id), 0o700); err != nil {
		t.Fatal(err)
	}
	code, out, _ := anchorCmd(f.args("--run", f.id))
	head := ledgerHeadOf(t, f.ctl)
	if code != 1 || b.count() != 1 ||
		!strings.Contains(out, "audit anchor: run "+f.id+": anchored at ") || !strings.Contains(out, " but the run's proof could NOT be written beside it: ") ||
		!strings.HasSuffix(out, fmt.Sprintf("control head: seq=%d sha256=%s\n", head.Count, head.Hash)) {
		t.Fatalf("exit %d submits %d\n%s", code, b.count(), out)
	}
	d := lastControl(t, f.ctl)
	if d.Outcome != "error" || d.Reason == nil || d.Reason.Code != control.CodeIOError || d.Anchor == nil || d.Anchor.RunID != f.id || d.Anchor.Seq != 3 {
		t.Fatalf("record %+v / %+v", d, d.Anchor)
	}
}

// TestAuditAnchorRunNotRecorded: the log took the head and the proof is beside
// the run, but the control ledger cannot take the record — said plainly, exit 1.
func TestAuditAnchorRunNotRecorded(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: file permissions are not enforced")
	}
	f := newRunsFixture(t)
	b := useRunsBackend(t)
	b.onSubmit = func() {
		if err := os.Chmod(f.ctl, 0o400); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { _ = os.Chmod(f.ctl, 0o600) })
	before := len(controlRecords(t, f.ctl))
	code, out, _ := anchorCmd(f.args("--run", f.id))
	if code != 1 || !strings.Contains(out, "audit anchor: anchored run "+f.id+" and its proof is beside the receipt, but the control ledger did NOT record it: ") || strings.Contains(out, "control head:") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if recs, found, err := sidecar.Read(sidecar.Path(f.logDir, f.id)); err != nil || !found || len(recs) != 1 {
		t.Fatalf("sidecar: %v %v %d", err, found, len(recs))
	}
	_ = os.Chmod(f.ctl, 0o600)
	if got := len(controlRecords(t, f.ctl)); got != before {
		t.Fatalf("control records %d -> %d", before, got)
	}
}

// TestAuditAnchorRunBusyWhenLockHeld: another holder of <log-dir>/.anchor.lock
// makes --run exit 1 with the busy text, unrecorded, before any network.
// It waits out the ledger's lock timeout (about 5 s) by design.
func TestAuditAnchorRunBusyWhenLockHeld(t *testing.T) {
	f := newRunsFixture(t)
	b := useRunsBackend(t)
	unlock, err := ledger.LockFile(sidecar.LockPath(f.logDir))
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	before := len(controlRecords(t, f.ctl))
	code, out, _ := anchorCmd(f.args("--run", f.id))
	want := fmt.Sprintf("audit anchor: another agenthof process is anchoring runs under %s; retry\n", f.logDir)
	if code != 1 || out != want {
		t.Fatalf("exit %d\n%q\nwant %q", code, out, want)
	}
	if got := len(controlRecords(t, f.ctl)); got != before || b.count() != 0 {
		t.Fatalf("records %d -> %d, submits %d", before, got, b.count())
	}
	noSidecar(t, f)
}

// TestAuditAnchorMutuallyExclusiveFlags: --run and --pending are two forms;
// asking for both is a usage error, and so is a non-positive --limit.
func TestAuditAnchorMutuallyExclusiveFlags(t *testing.T) {
	f := newRunsFixture(t)
	b := useRunsBackend(t)
	before := len(controlRecords(t, f.ctl))
	code, out, _ := anchorCmd(f.args("--run", "x", "--pending"))
	if code != 2 || !strings.Contains(out, "audit anchor: --run and --pending are mutually exclusive") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	for _, limit := range []string{"0", "-3"} {
		code, out, _ = anchorCmd(f.args("--run", f.id, "--limit", limit))
		if code != 2 || !strings.Contains(out, "audit anchor: --limit must be positive") {
			t.Fatalf("--limit %s: exit %d\n%s", limit, code, out)
		}
	}
	if got := len(controlRecords(t, f.ctl)); got != before || b.count() != 0 {
		t.Fatalf("records %d -> %d, submits %d", before, got, b.count())
	}
}

// TestAuditAnchorRunWarnsOnPublicLogAndNoPin: the two operational warnings
// reach stderr — never stdout — when the posture names the public log and no
// anchor.pub is pinned. (They are reachable only through cmdAuditAnchor, not
// through cmdAudit, which discards stderr.)
func TestAuditAnchorRunWarnsOnPublicLogAndNoPin(t *testing.T) {
	f := newRunsFixture(t)
	useRunsBackend(t)
	writeIntegrity(t, f.ctl, "anchor: tlog\nanchor_backend:\n  url: https://rekor.sigstore.dev\nanchor_runs: on-demand\n")
	code, out, errb := anchorCmd(f.args("--run", f.id))
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errb)
	}
	if !strings.Contains(errb, "anchor_backend names a public log") || !strings.Contains(errb, "no anchor.pub beside the control ledger") {
		t.Fatalf("stderr lacks the warnings:\n%s", errb)
	}
	if strings.Contains(out, "public log") || strings.Contains(out, "anchor.pub") || strings.Contains(strings.ToLower(out), "warn") {
		t.Fatalf("a warning reached stdout:\n%s", out)
	}
}

// TestAnchorRunClassifiesFaultsForTheSweep: anchorRun's outcome carries the
// distinction a sweep acts on. Only a log that ANSWERED and refused this head
// is per-entry (runSubmitFailed); a log that did not answer, a credential the
// broker could not resolve and a backend that could not be built are
// pass-fatal, because every later run would meet the same fault. Each is
// recorded as one error naming the run, and the real Rekor client and broker
// produce them — nothing here fakes the classification's input.
func TestAnchorRunClassifiesFaultsForTheSweep(t *testing.T) {
	const creds = "  credential:\n    grant_type: client_credentials\n    client_auth: client_secret_basic\n    token_endpoint: %s/token\n    client_id_env: ANCHOR_TEST_CLIENT_ID\n    client_secret_env: ANCHOR_TEST_CLIENT_SECRET\n"
	for _, c := range []struct {
		name     string
		posture  func(url string) string
		prepare  func(f *anchortest.RekorV1)
		build    func(backendSpec) (anchor.Backend, error) // overrides the real backend when set
		want     runAnchorOutcome
		wantReqs int
	}{
		{name: "log answered 429", want: runSubmitFailed, wantReqs: 1, prepare: func(f *anchortest.RekorV1) { f.Fail(429) }},
		{name: "log did not answer", want: runTransportFailed, wantReqs: 1, prepare: func(f *anchortest.RekorV1) { f.Drop() }},
		{name: "credential not resolvable", want: runBackendFailed, wantReqs: 0,
			posture: func(url string) string { return fmt.Sprintf(creds, url) }},
		{name: "backend not constructible", want: runBackendFailed, wantReqs: 0,
			build: func(backendSpec) (anchor.Backend, error) {
				return nil, errors.New("anchor backend kind \"x\" is not implemented")
			}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newRunsFixture(t)
			t.Setenv("ANCHOR_TEST_CLIENT_ID", "")
			t.Setenv("ANCHOR_TEST_CLIENT_SECRET", "")
			fake := anchortest.NewRekorV1()
			t.Cleanup(fake.Close)
			extra := ""
			if c.posture != nil {
				extra = c.posture(fake.URL)
			}
			writeIntegrity(t, f.ctl, "anchor: tlog\nanchor_backend:\n  url: "+fake.URL+"\n"+extra+"anchor_runs: on-demand\n")
			if c.prepare != nil {
				c.prepare(fake)
			}
			if c.build != nil {
				prev := newAnchorBackend
				newAnchorBackend = c.build
				t.Cleanup(func() { newAnchorBackend = prev })
			}
			var out bytes.Buffer
			s, code := openAnchorSession(anchorRuns, f.ctl, "dana@example.com", "platform-eng", "", 30*time.Second, &out, io.Discard)
			if s == nil {
				t.Fatalf("session: exit %d\n%s", code, out.String())
			}
			out.Reset()
			outcome, shipped, head := s.anchorRun(f.logDir, f.id)
			if outcome != c.want || shipped != nil || head.Count == 0 {
				t.Fatalf("outcome %d (want %d), shipped %v, head %+v\n%s", outcome, c.want, shipped, head, out.String())
			}
			if got := len(fake.Requests()); got != c.wantReqs {
				t.Fatalf("log saw %d requests, want %d", got, c.wantReqs)
			}
			d := lastControl(t, f.ctl)
			if d.Outcome != "error" || d.Reason == nil || d.Reason.Code != control.CodeAnchorFailed || d.Anchor == nil || d.Anchor.RunID != f.id || d.Anchor.Ref != "" {
				t.Fatalf("record %+v / %+v", d, d.Anchor)
			}
			if !strings.HasPrefix(out.String(), "audit anchor: run "+f.id+": ") {
				t.Fatalf("stdout %q", out.String())
			}
			noSidecar(t, f)
		})
	}
}
