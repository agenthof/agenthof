package control_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/ledger"
)

// fiveRecords appends five apply records to a fresh control log and returns
// its path (the shape every seam test starts from).
func fiveRecords(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "control.jsonl")
	inv, w := identity.Static("dana@example.com"), control.CaptureWitness()
	for i := 0; i < 5; i++ {
		if _, err := control.Append(p, control.Event{Action: "apply", Outcome: "success", Invoker: inv, Witness: w, ConfigHash: "sha256:abc"}); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

// TestReadSingleFileIsReadVerify: on a never-sealed root, Read returns
// exactly ReadVerify's records and head, no sealed segments, state open,
// FirstSeq 1, and creates no file; a torn or broken file yields a *SetError
// whose text is today's ledger text and which unwraps to the ledger error.
func TestReadSingleFileIsReadVerify(t *testing.T) {
	p := fiveRecords(t)
	want, wantHead, _ := ledger.ReadVerify(p, ledger.Locked)
	v, err := control.Read(p, ledger.Locked)
	if err != nil || v.Head != wantHead || len(v.Records) != len(want) || v.Sealed != nil || v.State != control.StateOpen || v.FirstSeq != 1 || v.LogID != "" {
		t.Fatalf("Read: %v %+v", err, v)
	}
	for i := range want {
		if string(want[i].Raw) != string(v.Records[i].Raw) {
			t.Fatalf("record %d differs", i)
		}
	}
	if v.Active.N != 0 || v.Active.FirstSeq != 1 || v.Active.HeadSeq != 5 || v.Active.HeadHash != wantHead.Hash || v.Active.Records != 5 {
		t.Fatalf("active: %+v", v.Active)
	}
	entries, _ := os.ReadDir(filepath.Dir(p))
	if len(entries) != 1 {
		t.Fatalf("Read must create nothing: %v", entries)
	}
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	_, _ = f.WriteString(`{"v":"control/1","seq":6,"prev":""`)
	_ = f.Close()
	_, _, lerr := ledger.ReadVerify(p, ledger.Locked)
	_, err = control.Read(p, ledger.Locked)
	var se *control.SetError
	var torn *ledger.TornError
	if !errors.As(err, &se) || se.Fault != control.FaultTorn || se.Segment != 0 || se.Seq != 6 || err.Error() != lerr.Error() || !errors.As(err, &torn) {
		t.Fatalf("torn active: %v (ledger: %v)", err, lerr)
	}
}

// TestReadNoRootIsRawNotExist: no active, no manifest, no siblings → the raw
// *fs.PathError, so os.IsNotExist and errors.Is(fs.ErrNotExist) hold.
func TestReadNoRootIsRawNotExist(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	_, err := control.Read(p, ledger.Locked)
	var pe *fs.PathError
	if !errors.As(err, &pe) || !os.IsNotExist(err) || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("no root: %T %v", err, err)
	}
	if _, serr := os.Lstat(p); !errors.Is(serr, fs.ErrNotExist) {
		t.Fatal("Read must not create the active")
	}
}

// TestSetErrorUnwrapIsActiveTornBrokenOnly: the Unwrap matrix — only a torn
// or broken ACTIVE exposes its ledger error; every other (Fault, Segment)
// pair unwraps to nothing, so errors.As(&torn/&broken) and
// errors.Is(fs.ErrNotExist) are false for it even when Err is set.
func TestSetErrorUnwrapIsActiveTornBrokenOnly(t *testing.T) {
	torn := &ledger.TornError{Offset: 3}
	broken := &ledger.ChainBrokenError{Line: 2}
	notExist := &fs.PathError{Op: "open", Path: "x", Err: fs.ErrNotExist}
	for _, f := range []control.Fault{control.FaultTorn, control.FaultBroken, control.FaultBoundary, control.FaultMissingSegment, control.FaultActiveMissing, control.FaultUnexpectedSegment, control.FaultManifest, control.FaultSealNotLast} {
		for _, seg := range []int{0, 1, 2} {
			for _, inner := range []error{torn, broken, notExist} {
				err := error(&control.SetError{Fault: f, Segment: seg, Path: "/r/control.jsonl", Seq: 1, Err: inner})
				var gotTorn *ledger.TornError
				var gotBroken *ledger.ChainBrokenError
				exposes := seg == 0 && (f == control.FaultTorn || f == control.FaultBroken)
				if errors.As(err, &gotTorn) != (exposes && inner == torn) || errors.As(err, &gotBroken) != (exposes && inner == broken) || errors.Is(err, fs.ErrNotExist) != (exposes && inner == notExist) {
					t.Fatalf("fault %d segment %d inner %T: unwrap exposure wrong", f, seg, inner)
				}
			}
		}
	}
}

// TestSiblingsFoundUnderAMetacharacterPath: a root whose directory and base
// name carry glob metacharacters still finds its siblings and its history —
// an unexpected segment is loud, a missing active beside a segment is
// FaultActiveMissing and is not recreated. (A glob over the path would read
// "[1]" as pattern syntax, list nothing and go silent.)
func TestSiblingsFoundUnderAMetacharacterPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a[1]*?")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "c[1].jsonl")
	if _, err := control.Append(p, control.Event{Action: "apply", Outcome: "success", Invoker: identity.Static("dana@example.com"), Witness: control.CaptureWitness(), ConfigHash: "sha256:abc"}); err != nil {
		t.Fatal(err)
	}
	if v, err := control.Read(p, ledger.Locked); err != nil || v.Head.Count != 1 {
		t.Fatalf("clean root: %v %+v", err, v.Head)
	}
	seg := control.SegmentPath(p, 2)
	if err := os.WriteFile(seg, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var se *control.SetError
	if _, err := control.Read(p, ledger.Locked); !errors.As(err, &se) || se.Fault != control.FaultUnexpectedSegment || !strings.Contains(err.Error(), "c[1].jsonl.seg-000002") {
		t.Fatalf("sibling under a metacharacter path: %v", err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if _, err := control.Read(p, ledger.Locked); !errors.As(err, &se) || se.Fault != control.FaultActiveMissing {
		t.Fatalf("history under a metacharacter path: %v", err)
	}
	if err := control.Writable(p); !errors.As(err, &se) || se.Fault != control.FaultActiveMissing {
		t.Fatalf("Writable: %v", err)
	}
	if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("a missing active beside history must not be recreated")
	}
}

// TestWritableCreatesThroughADanglingSymlink: a --control-log that is a
// symlink to a not-yet-existing target is the pre-provisioned shape; the
// first writer creates the target through the link, as ledger.Open did, and
// both names then read the same set.
func TestWritableCreatesThroughADanglingSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real", "control.jsonl")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "control.jsonl")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := control.Writable(link); err != nil {
		t.Fatalf("first writer through a dangling link: %v", err)
	}
	fi, err := os.Lstat(target)
	if err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("the target must now exist as a regular file: %v", err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the link must still be a link")
	}
	if _, err := control.Append(link, control.Event{Action: "apply", Outcome: "success", Invoker: identity.Static("dana@example.com"), Witness: control.CaptureWitness(), ConfigHash: "sha256:abc"}); err != nil {
		t.Fatal(err)
	}
	a, aerr := control.Read(link, ledger.Locked)
	b, berr := control.Read(target, ledger.Locked)
	if aerr != nil || berr != nil || a.Head != b.Head || a.Head.Count != 1 {
		t.Fatalf("both names must read one set: %v %v %+v %+v", aerr, berr, a.Head, b.Head)
	}
}

// TestDanglingSymlinkBesideHistoryIsActiveMissing: a link whose target was
// deleted beside a manifest is a root with history and no active — the
// history is sought beside the TARGET, so neither the reader nor the writer
// treats the dangling name as "nothing recorded", and nothing is created.
func TestDanglingSymlinkBesideHistoryIsActiveMissing(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real", "control.jsonl")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	m := `{"v":"segments/1","log_id":"` + strings.Repeat("ab", 16) + `","segments":[]}`
	if err := os.WriteFile(control.ManifestPath(target), []byte(m), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "control.jsonl")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	var se *control.SetError
	if err := control.Writable(link); !errors.As(err, &se) || se.Fault != control.FaultActiveMissing {
		t.Fatalf("Writable through a dangling link beside history: %v", err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("the writer must not create the target beside history")
	}
	_, err := control.Read(link, ledger.Locked)
	if !errors.As(err, &se) || se.Fault != control.FaultActiveMissing || os.IsNotExist(err) {
		t.Fatalf("Read through a dangling link beside history: %v", err)
	}
}

// TestAppendRefusesSealRecords: until the seal writer exists, an Event that
// says "seal" or carries a seal payload is refused before the ledger is
// opened — nothing is dropped silently and no file is created.
func TestAppendRefusesSealRecords(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	inv, w := identity.Static("dana@example.com"), control.CaptureWitness()
	for _, e := range []control.Event{
		{Action: "seal", Outcome: "success", Invoker: inv, Witness: w},
		{Action: "apply", Outcome: "success", Invoker: inv, Witness: w, ConfigHash: "sha256:abc", Seal: &control.Seal{Segment: 1}},
	} {
		if _, err := control.Append(p, e); err == nil || !strings.Contains(err.Error(), "written only by audit seal") {
			t.Fatalf("%s: %v", e.Action, err)
		}
	}
	if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("a refused seal must create nothing")
	}
}

// TestSiblingGlobMatchesSegmentsOnly: beside the ledger, the manifest, a
// manifest temp, a swap temp and a torn fragment are never siblings; only
// `.seg-` + six digits is a segment, and any other `.seg-*` spelling is an
// unexpected segment (never silently ignored).
func TestSiblingGlobMatchesSegmentsOnly(t *testing.T) {
	p := fiveRecords(t)
	dir := filepath.Dir(p)
	for _, name := range []string{"control.jsonl.segments-abc123", ".control.jsonl.next-xyz", "control.jsonl.torn-1700000000"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := control.Read(p, ledger.Locked); err != nil {
		t.Fatalf("temps and fragments are not siblings: %v", err)
	}
	for _, bad := range []string{"control.jsonl.seg-1", "control.jsonl.seg-0000001"} {
		path := filepath.Join(dir, bad)
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := control.Read(p, ledger.Locked)
		var se *control.SetError
		if !errors.As(err, &se) || se.Fault != control.FaultUnexpectedSegment || !strings.Contains(err.Error(), bad) {
			t.Fatalf("%s: %v", bad, err)
		}
		_ = os.Remove(path)
	}
	// A conforming segment file with no manifest is loud too — even over an
	// empty active (the deleted-manifest case).
	seg := control.SegmentPath(p, 2)
	if err := os.WriteFile(seg, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := control.Read(p, ledger.Locked)
	var se *control.SetError
	if !errors.As(err, &se) || se.Fault != control.FaultUnexpectedSegment || !strings.Contains(err.Error(), "but no manifest control.jsonl.segments") {
		t.Fatalf("segments without a manifest: %v", err)
	}
	if err := os.Truncate(p, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := control.Read(p, ledger.Locked); !errors.As(err, &se) || se.Fault != control.FaultUnexpectedSegment {
		t.Fatalf("over an empty active the fault must still be loud: %v", err)
	}
}
