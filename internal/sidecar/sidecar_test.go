package sidecar_test

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/anchor"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/ledger"
	"github.com/agenthof/agenthof/internal/sidecar"
)

const testRun = "r-0123456789abcdef"

// writeRun writes events as a real run ledger <dir>/<id>.jsonl and returns
// its verified chain.
func writeRun(t *testing.T, dir, id string, events ...engine.Event) []ledger.Record {
	t.Helper()
	log, err := engine.OpenLog(dir, id)
	if err != nil {
		t.Fatal(err)
	}
	b := engine.Binding{Invoker: identity.Static("dana@example.com"), Role: "r", Workflow: "w", RunID: id}
	for i, e := range events {
		e.Time, e.Binding = time.Unix(int64(i), 0).UTC(), b
		if err := log.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	recs, _, err := ledger.ReadVerify(filepath.Join(dir, id+".jsonl"), ledger.Unlocked)
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

func rec(seq int) sidecar.Record {
	return sidecar.Record{
		Time: time.Date(2026, 10, 27, 1, 2, 3, 0, time.UTC), RunID: testRun, Seq: seq,
		Hash: strings.Repeat("ab", 32), Kind: "tlog", BackendKind: "transparency-log",
		Backend: "https://rekor.example", Ref: "42", Proof: "AQID", BackendKeyID: strings.Repeat("cd", 32),
		AnchoredBy: sidecar.Actor{Subject: "dana@example.com", Issuer: "https://idp.test", Method: "oidc"},
	}
}

func TestAppendThenReadRoundTripsEveryField(t *testing.T) {
	dir := t.TempDir()
	p := sidecar.Path(dir, testRun)
	want := rec(3)
	if err := sidecar.Append(p, testRun, want); err != nil {
		t.Fatal(err)
	}
	got, found, err := sidecar.Read(p)
	if err != nil || !found || len(got) != 1 || got[0] != want {
		t.Fatalf("Read = %+v found=%v err=%v, want %+v", got, found, err, want)
	}
	st, err := os.Stat(p)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("stat %v mode %v", err, st)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 || ents[0].Name() != testRun+".anchor" {
		t.Fatalf("dir holds %v, want only the sidecar", ents)
	}
}

func TestAppendIsARePinAppend(t *testing.T) {
	p := sidecar.Path(t.TempDir(), testRun)
	a, b := rec(3), rec(3)
	b.Ref = "43"
	for _, r := range []sidecar.Record{a, b} {
		if err := sidecar.Append(p, testRun, r); err != nil {
			t.Fatal(err)
		}
	}
	got, found, err := sidecar.Read(p)
	if err != nil || !found || len(got) != 2 || got[0] != a || got[1] != b {
		t.Fatalf("Read = %+v found=%v err=%v", got, found, err)
	}
}

func TestReadAbsentIsNotFound(t *testing.T) {
	recs, found, err := sidecar.Read(sidecar.Path(t.TempDir(), testRun))
	if recs != nil || found || err != nil {
		t.Fatalf("= %v %v %v", recs, found, err)
	}
}

func writeRaw(t *testing.T, content string) string {
	t.Helper()
	p := sidecar.Path(t.TempDir(), testRun)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func line(t *testing.T, r sidecar.Record) string {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b) + "\n"
}

func TestReadRefusesEmptyOverCapAndUndecodable(t *testing.T) {
	if _, _, err := sidecar.Read(writeRaw(t, "")); err == nil {
		t.Fatal("an empty sidecar must be an error")
	}
	if _, _, err := sidecar.Read(writeRaw(t, strings.Repeat(line(t, rec(3)), sidecar.MaxRecords))); err != nil {
		t.Fatalf("exactly MaxRecords must read: %v", err)
	}
	_, _, err := sidecar.Read(writeRaw(t, strings.Repeat(line(t, rec(3)), sidecar.MaxRecords+1)))
	if err == nil || !strings.Contains(err.Error(), fmt.Sprint(sidecar.MaxRecords)) {
		t.Fatalf("33 lines: %v", err)
	}
	_, _, err = sidecar.Read(writeRaw(t, "not json\n"))
	if err == nil || !strings.Contains(err.Error(), "line 1") {
		t.Fatalf("undecodable: %v", err)
	}
	_, _, err = sidecar.Read(writeRaw(t, line(t, rec(3))+"{\n"))
	if err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("second line undecodable: %v", err)
	}
}

func TestReadBoundsEveryField(t *testing.T) {
	over := func(mut func(*sidecar.Record), want string) {
		t.Helper()
		r := rec(3)
		mut(&r)
		_, _, err := sidecar.Read(writeRaw(t, line(t, r)))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("want error containing %q, got %v", want, err)
		}
	}
	over(func(r *sidecar.Record) { r.Proof = strings.Repeat("A", anchor.MaxProofLen+1) }, "sidecar line 1: proof is 8193 bytes; the cap is 8192")
	over(func(r *sidecar.Record) { r.Ref = strings.Repeat("a", control.MaxAnchorRefLen+1) }, "ref is 257 bytes; the cap is 256")
	over(func(r *sidecar.Record) { r.Backend = strings.Repeat("a", control.MaxAnchorBackendLen+1) }, "backend is 2049 bytes; the cap is 2048")
	over(func(r *sidecar.Record) { r.BackendKind = strings.Repeat("a", control.MaxAnchorBackendKindLen+1) }, "backend_kind is 65 bytes; the cap is 64")
	over(func(r *sidecar.Record) { r.BackendKeyID = strings.Repeat("a", control.MaxAnchorBackendKeyIDLen+1) }, "backend_key_id is 129 bytes; the cap is 128")

	// at the caps exactly: fine
	r := rec(3)
	r.Proof = strings.Repeat("A", anchor.MaxProofLen)
	r.Ref = strings.Repeat("a", control.MaxAnchorRefLen)
	r.Backend = strings.Repeat("a", control.MaxAnchorBackendLen)
	r.BackendKind = strings.Repeat("a", control.MaxAnchorBackendKindLen)
	r.BackendKeyID = strings.Repeat("a", control.MaxAnchorBackendKeyIDLen)
	if _, _, err := sidecar.Read(writeRaw(t, line(t, r))); err != nil {
		t.Fatalf("a record at every cap must read: %v", err)
	}

	// a single line longer than the scanner's buffer: an error, not a hang
	// or a partial read.
	huge := strings.Repeat("x", sidecar.MaxLineLen+10) + "\n"
	if _, _, err := sidecar.Read(writeRaw(t, huge)); err == nil {
		t.Fatal("a line over MaxLineLen must be an error")
	}
	if _, _, err := sidecar.Read(writeRaw(t, line(t, rec(3))+huge)); err == nil {
		t.Fatal("a later line over MaxLineLen must be an error")
	}

	// the same, but valid JSON that decodes to a good record (the extra key
	// is ignored): only the scanner's own bound can refuse it.
	padded := func(n int) string {
		b, err := json.Marshal(rec(3))
		if err != nil {
			t.Fatal(err)
		}
		return `{"pad":"` + strings.Repeat("x", n) + `",` + string(b[1:]) + "\n"
	}
	if _, _, err := sidecar.Read(writeRaw(t, padded(sidecar.MaxLineLen))); !errors.Is(err, bufio.ErrTooLong) {
		t.Fatalf("a valid-JSON line over MaxLineLen: err = %v, want bufio.ErrTooLong", err)
	}
	if _, _, err := sidecar.Read(writeRaw(t, padded(sidecar.MaxLineLen/2))); err != nil {
		t.Fatalf("a valid line under MaxLineLen must read: %v", err)
	}
}

func TestReadIgnoresStrayTemp(t *testing.T) {
	dir := t.TempDir()
	p := sidecar.Path(dir, testRun)
	if err := sidecar.Append(p, testRun, rec(3)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, testRun+".anchor.tmp-x"), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, found, err := sidecar.Read(p)
	if err != nil || !found || len(got) != 1 {
		t.Fatalf("%v %v %v", got, found, err)
	}
}

func TestAnchoredByCarriesSubjectIssuerMethodOnly(t *testing.T) {
	b, err := json.Marshal(rec(3))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	var by map[string]any
	if err := json.Unmarshal(m["anchored_by"], &by); err != nil {
		t.Fatal(err)
	}
	if len(by) != 3 || by["subject"] == nil || by["issuer"] == nil || by["method"] == nil {
		t.Fatalf("anchored_by = %v", by)
	}
}

func TestTwoWritersLeaveOneWholeSidecar(t *testing.T) {
	p := sidecar.Path(t.TempDir(), testRun)
	var wg sync.WaitGroup
	for w := 0; w < 2; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				// Concurrent appends without a lock may lose a record to the
				// other writer's read-modify-write; the file must stay whole.
				if err := sidecar.Append(p, testRun, rec(3)); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	got, found, err := sidecar.Read(p)
	if err != nil || !found || len(got) == 0 {
		t.Fatalf("sidecar not whole: %d records found=%v err=%v", len(got), found, err)
	}
	ents, _ := os.ReadDir(filepath.Dir(p))
	if len(ents) != 1 {
		t.Fatalf("temp left behind: %v", ents)
	}
}

func TestFinalEvent(t *testing.T) {
	dir := t.TempDir()
	chain := func(id string, types ...string) []ledger.Record {
		var evs []engine.Event
		for _, ty := range types {
			evs = append(evs, engine.Event{Type: ty})
		}
		return writeRun(t, dir, id, evs...)
	}
	cases := []struct {
		id    string
		types []string
		want  bool
	}{
		{"r-00000000000000a1", []string{"workflow_started", "step_started", "workflow_finished"}, true},
		{"r-00000000000000a2", []string{"run_refused"}, true},
		{"r-00000000000000a3", []string{"run_refused", "step_started"}, false},
		{"r-00000000000000a4", []string{"workflow_started", "run_refused"}, false},
		{"r-00000000000000a5", []string{"workflow_started", "step_started"}, false},
	}
	for _, c := range cases {
		if got := sidecar.FinalEvent(chain(c.id, c.types...)); got != c.want {
			t.Errorf("FinalEvent(%v) = %v, want %v", c.types, got, c.want)
		}
	}
	if sidecar.FinalEvent(nil) {
		t.Error("FinalEvent(empty) = true")
	}
}
