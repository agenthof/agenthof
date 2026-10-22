package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/ledger"
)

const (
	testHash  = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testLogID = "0123456789abcdef0123456789abcdef"
)

// goodSink is a valid sink block whose retain_until is after sealByHand's
// fixed seal time (2026-10-15).
func goodSink() SealSink {
	return SealSink{Kind: "s3-object-lock", URL: "https://s3.eu-central-1.amazonaws.com/acme/agenthof", Key: "agenthof/" + testLogID + "/seg-000001", Mode: "compliance", RetainUntil: time.Date(2033, 10, 20, 9, 12, 0, 0, time.UTC)}
}

// earlySink is a block whose retain_until is NOT after the seal's time.
func earlySink() SealSink {
	s := goodSink()
	s.RetainUntil = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	return s
}

const earlyRetainText = "sink.retain_until 2020-01-01T00:00:00Z recorded, not after the seal's time 2026-10-15T09:00:00Z"

// TestSealSinkWireShape: a seal with a Sink block marshals the block as the
// LAST key of "seal" in the order kind, url, key, mode, retain_until; a Seal
// without one marshals exactly as before (no "sink" key) — the worm line is
// the floor line with the block spliced in before the closing brace.
func TestSealSinkWireShape(t *testing.T) {
	block := goodSink()
	worm, err := json.Marshal(Seal{Segment: 1, FirstSeq: 1, HeadSeq: 2, HeadHash: testHash, ContentSHA256: testHash, Sink: &block})
	if err != nil {
		t.Fatal(err)
	}
	floor, err := json.Marshal(Seal{Segment: 1, FirstSeq: 1, HeadSeq: 2, HeadHash: testHash, ContentSHA256: testHash})
	if err != nil {
		t.Fatal(err)
	}
	suffix := `,"sink":{"kind":"s3-object-lock","url":"https://s3.eu-central-1.amazonaws.com/acme/agenthof","key":"agenthof/` + testLogID + `/seg-000001","mode":"compliance","retain_until":"2033-10-20T09:12:00Z"}}`
	if !strings.HasSuffix(string(worm), suffix) {
		t.Fatalf("worm seal: %s", worm)
	}
	if strings.Contains(string(floor), "sink") {
		t.Fatalf("floor seal carries a sink key: %s", floor)
	}
	if string(worm) != strings.TrimSuffix(string(floor), "}")+suffix {
		t.Fatalf("the worm line is not the floor line plus the block:\n%s\n%s", worm, floor)
	}
	var back Seal
	if err := json.Unmarshal(worm, &back); err != nil || back.Sink == nil || *back.Sink != block {
		t.Fatalf("round trip: %v %+v", err, back)
	}
}

// TestCheckSealShapeSinkRules: the shape permit's sink rules, one case per
// rule, exact texts; a refused seal with a payload still fails the shipped
// rule first.
func TestCheckSealShapeSinkRules(t *testing.T) {
	good := func(mut func(*SealSink)) Event {
		e := sealEvent()
		b := goodSink()
		if mut != nil {
			mut(&b)
		}
		e.Seal = &Seal{Segment: 1, FirstSeq: 1, HeadSeq: 5, HeadHash: testHash, ContentSHA256: testHash, Sink: &b}
		return e
	}
	if err := checkSealShape(good(nil)); err != nil {
		t.Fatalf("a valid block must pass: %v", err)
	}
	if err := checkSealSink(nil); err != nil {
		t.Fatalf("no block is the floor: %v", err)
	}
	urlText := func(u string) string {
		return "control: seal sink url " + strconv.Quote(u) + " is not an absolute http(s) URL with a bucket path"
	}
	keyText := func(k string) string {
		return "control: seal sink key " + strconv.Quote(k) + " must be relative with no .. segment"
	}
	longURL := "https://h/" + strings.Repeat("a", MaxAnchorBackendLen)
	longKey := strings.Repeat("k", MaxSinkKeyLen+1)
	cases := []struct {
		name string
		mut  func(*SealSink)
		want string
	}{
		{"kind empty", func(s *SealSink) { s.Kind = "" }, "control: seal sink kind is empty"},
		{"url without a bucket path", func(s *SealSink) { s.URL = "https://host" }, urlText("https://host")},
		{"url root only", func(s *SealSink) { s.URL = "https://host/" }, urlText("https://host/")},
		{"url ftp", func(s *SealSink) { s.URL = "ftp://x/b" }, urlText("ftp://x/b")},
		{"url userinfo", func(s *SealSink) { s.URL = "https://u:p@h/b" }, urlText("https://u:p@h/b")},
		{"url query", func(s *SealSink) { s.URL = "https://h/b?x" }, urlText("https://h/b?x")},
		{"url bare query", func(s *SealSink) { s.URL = "https://h/b?" }, urlText("https://h/b?")},
		{"url fragment", func(s *SealSink) { s.URL = "https://h/b#f" }, urlText("https://h/b#f")},
		{"url empty", func(s *SealSink) { s.URL = "" }, urlText("")},
		{"url over the cap", func(s *SealSink) { s.URL = longURL }, urlText(longURL)},
		{"key empty", func(s *SealSink) { s.Key = "" }, keyText("")},
		{"key absolute", func(s *SealSink) { s.Key = "/a/b" }, keyText("/a/b")},
		{"key dot-dot", func(s *SealSink) { s.Key = "a/../b" }, keyText("a/../b")},
		{"key over the cap", func(s *SealSink) { s.Key = longKey }, keyText(longKey)},
		{"mode governance", func(s *SealSink) { s.Mode = "governance" }, `control: seal sink mode "governance" is not compliance`},
		{"mode empty", func(s *SealSink) { s.Mode = "" }, `control: seal sink mode "" is not compliance`},
		{"retain_until unset", func(s *SealSink) { s.RetainUntil = time.Time{} }, "control: seal sink retain_until is unset"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkSealShape(good(tc.mut))
			if err == nil || err.Error() != tc.want {
				t.Fatalf("got %v\nwant %s", err, tc.want)
			}
		})
	}
	refused := good(nil)
	refused.Outcome = "refused"
	refused.Reason = &Reason{Code: CodeNotAuthorized, Message: "no"}
	if err := checkSealShape(refused); err == nil || err.Error() != "control: a refused seal closed nothing and carries no payload" {
		t.Fatalf("refused with payload: %v", err)
	}
}

// TestSealChainFieldsAgree: nil → false; equal five fields with different
// Sink pointers (nil vs set, two different blocks) → true; any one chain
// field differing → false.
func TestSealChainFieldsAgree(t *testing.T) {
	want := Seal{Segment: 1, FirstSeq: 1, HeadSeq: 5, HeadHash: testHash, ContentSHA256: testHash}
	if sealChainFieldsAgree(nil, want) {
		t.Fatal("nil must not agree")
	}
	b1, b2 := goodSink(), goodSink()
	b2.Key = "other/" + testLogID + "/seg-000009"
	for i, got := range []*Seal{
		{Segment: 1, FirstSeq: 1, HeadSeq: 5, HeadHash: testHash, ContentSHA256: testHash},
		{Segment: 1, FirstSeq: 1, HeadSeq: 5, HeadHash: testHash, ContentSHA256: testHash, Sink: &b1},
		{Segment: 1, FirstSeq: 1, HeadSeq: 5, HeadHash: testHash, ContentSHA256: testHash, Sink: &b2},
	} {
		if !sealChainFieldsAgree(got, want) {
			t.Fatalf("case %d: the chain fields agree regardless of Sink", i)
		}
	}
	wantWithSink := want
	wantWithSink.Sink = &b1
	if !sealChainFieldsAgree(&Seal{Segment: 1, FirstSeq: 1, HeadSeq: 5, HeadHash: testHash, ContentSHA256: testHash}, wantWithSink) {
		t.Fatal("want's own Sink is ignored too")
	}
	other := strings.Repeat("f", 64)
	for name, got := range map[string]Seal{
		"segment":        {Segment: 2, FirstSeq: 1, HeadSeq: 5, HeadHash: testHash, ContentSHA256: testHash},
		"first_seq":      {Segment: 1, FirstSeq: 2, HeadSeq: 5, HeadHash: testHash, ContentSHA256: testHash},
		"head_seq":       {Segment: 1, FirstSeq: 1, HeadSeq: 6, HeadHash: testHash, ContentSHA256: testHash},
		"head_hash":      {Segment: 1, FirstSeq: 1, HeadSeq: 5, HeadHash: other, ContentSHA256: testHash},
		"content_sha256": {Segment: 1, FirstSeq: 1, HeadSeq: 5, HeadHash: testHash, ContentSHA256: other},
	} {
		g := got
		g.Sink = &b1
		if sealChainFieldsAgree(&g, want) {
			t.Fatalf("%s differs; must not agree", name)
		}
	}
}

// TestVerifySealedCarriesTheSinkBlock: a seal line with a Sink block reads
// clean and the block rides on the Segment; a block whose retain_until is
// not after the seal's time is FaultManifest{1} with the fixed text — through
// verifySealed (a sealed root) and through finishActive (state B).
func TestVerifySealedCarriesTheSinkBlock(t *testing.T) {
	block, early := goodSink(), earlySink()
	root := func(t *testing.T, stopAt string, s *SealSink) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "control.jsonl")
		appendN(t, p, 5)
		sealByHand(t, p, stopAt, s)
		return p
	}
	requireEarlyFault := func(t *testing.T, err error, path string, seq int) {
		t.Helper()
		var se *SetError
		if !errors.As(err, &se) || se.Fault != FaultManifest || se.Segment != 1 || se.Path != path || se.Seq != seq || se.Err == nil || se.Err.Error() != earlyRetainText {
			t.Fatalf("got %v (%+v)", err, se)
		}
	}
	t.Run("sealed", func(t *testing.T) {
		p := root(t, "", &block)
		v, err := Read(p, ledger.Locked)
		if err != nil {
			t.Fatal(err)
		}
		if len(v.Sealed) != 1 || v.Sealed[0].Sink == nil || *v.Sealed[0].Sink != block || v.Active.Sink != nil {
			t.Fatalf("%+v", v.Sealed)
		}
		if !strings.Contains(RenderView(v, nil), "verified (6 events, 1 sealed segments)") {
			t.Fatal("renders as verified")
		}
	})
	t.Run("sealed, retain_until not after the seal", func(t *testing.T) {
		p := root(t, "", &early)
		resolved, _ := filepath.EvalSymlinks(p)
		v, err := Read(p, ledger.Locked)
		requireEarlyFault(t, err, SegmentPath(resolved, 1), 0)
		if len(v.Sealed) != 0 {
			t.Fatalf("the faulted segment is not in the view: %+v", v.Sealed)
		}
	})
	t.Run("state B", func(t *testing.T) {
		p := root(t, "B", &block)
		v, err := Read(p, ledger.Locked)
		if err != nil || v.State != StateSealedNotRotated || v.Active.Sink != nil {
			t.Fatalf("%v %+v", err, v.Active)
		}
	})
	t.Run("state B, retain_until not after the seal", func(t *testing.T) {
		p := root(t, "B", &early)
		resolved, _ := filepath.EvalSymlinks(p)
		v, err := Read(p, ledger.Locked)
		requireEarlyFault(t, err, resolved, 6)
		if v.State != StateOpen {
			t.Fatalf("a planted seal marks no state: %v", v.State)
		}
	})
}

// TestOlderShapedRecordVerifies: a seal line with no "sink" key (today's
// shape) still reads clean and the Segment carries no block.
func TestOlderShapedRecordVerifies(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	appendN(t, p, 5)
	line := sealByHand(t, p, "")
	if bytes.Contains(line, []byte(`"sink"`)) {
		t.Fatalf("a floor seal line carries no sink key: %s", line)
	}
	v, err := Read(p, ledger.Locked)
	if err != nil || len(v.Sealed) != 1 || v.Sealed[0].Sink != nil || v.Active.Sink != nil {
		t.Fatalf("%v %+v", err, v.Sealed)
	}
}

// TestSegmentBytesAreTheFile: on a sealed root, segmentBytes over the
// segment's records equals the file byte for byte, and its sha256 is
// segmentDigests' whole — the manifest's sha256.
func TestSegmentBytesAreTheFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	appendN(t, p, 5)
	sealByHand(t, p, "")
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	v, err := Read(p, ledger.Locked)
	if err != nil {
		t.Fatal(err)
	}
	recs := v.Records[:v.Sealed[0].Records]
	file, err := os.ReadFile(SegmentPath(resolved, 1))
	if err != nil {
		t.Fatal(err)
	}
	data := segmentBytes(recs)
	if !bytes.Equal(data, file) {
		t.Fatalf("segmentBytes is not the file:\n%s\n%s", data, file)
	}
	sum := sha256.Sum256(data)
	whole, size := segmentDigests(recs)
	if hex.EncodeToString(sum[:]) != whole || whole != v.Sealed[0].SHA256 || size != int64(len(file)) {
		t.Fatalf("%s %s %s %d %d", hex.EncodeToString(sum[:]), whole, v.Sealed[0].SHA256, size, len(file))
	}
	if segmentBytes(nil) != nil {
		t.Fatal("no records, no bytes")
	}
}
