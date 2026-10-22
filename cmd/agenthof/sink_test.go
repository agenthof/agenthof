package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/broker"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/ledger"
	"github.com/agenthof/agenthof/internal/sink"
	"github.com/agenthof/agenthof/internal/sink/sinktest"
)

// TestSinkForDispatch: the floor is a nil interface (never a typed nil);
// s3-object-lock builds an *sink.S3 with the posture's retention; any other
// kind is "not implemented"; a URL without a bucket is the sink's own
// refusal.
func TestSinkForDispatch(t *testing.T) {
	be, err := sinkFor(config.Integrity{}, time.Minute)
	if err != nil || be != nil {
		t.Fatalf("floor: %v %#v", err, be)
	}
	cred := config.BackendCredential{CredentialSource: "static_env", ClientAuth: "sigv4", ClientIDEnv: "ID", ClientSecretEnv: "SECRET"}
	in := config.Integrity{Sink: "worm", SinkBackend: config.IntegrityBackend{Kind: "s3-object-lock", URL: "https://s3.eu-central-1.amazonaws.com/worm/agenthof/", Mode: "compliance", Retention: "7y", Credential: cred}}
	be, err = sinkFor(in, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	s3, ok := be.(*sink.S3)
	if !ok || s3.URL() != "https://s3.eu-central-1.amazonaws.com/worm/agenthof" || s3.Region() != "eu-central-1" {
		t.Fatalf("%T %v", be, be)
	}
	loc := s3.Locator("abc", 2, time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC))
	if loc.Key != "agenthof/abc/seg-000002" || loc.RetainUntil != time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC).Add(7*config.RetentionYear) {
		t.Fatalf("%+v", loc)
	}
	if _, err := sinkBackendFor(sinkSpec{Backend: config.IntegrityBackend{Kind: "gcs-bucket-lock", URL: "https://x.example/b", Retention: "1d"}}); err == nil || err.Error() != `sink backend kind "gcs-bucket-lock" is not implemented` {
		t.Fatalf("kind: %v", err)
	}
	if _, err := sinkBackendFor(sinkSpec{Backend: config.IntegrityBackend{Kind: "s3-object-lock", URL: "https://x.example", Retention: "1d", Credential: cred}}); err == nil || !strings.Contains(err.Error(), "names no bucket") {
		t.Fatalf("bucket: %v", err)
	}
	if _, err := sinkBackendFor(sinkSpec{Backend: config.IntegrityBackend{Kind: "s3-object-lock", URL: "https://x.example/b", Retention: "0d", Credential: cred}}); err == nil {
		t.Fatal("retention is parsed by the one grammar")
	}
}

// TestSinkCredentialRefAndKeys: the posture's credential maps onto the
// broker reference for the sink resource, and the resolver reads the env
// NAMES at call time — an unset name is an error naming it, never a value.
func TestSinkCredentialRefAndKeys(t *testing.T) {
	c := config.BackendCredential{CredentialSource: "static_env", ClientAuth: "sigv4", ClientIDEnv: "WORM_ID", ClientSecretEnv: "WORM_SECRET", TokenEnv: "WORM_SESSION"}
	want := broker.CredentialRef{ResourceID: "integrity/sink_backend", Source: "static_env", ClientAuth: "sigv4", ClientIDEnv: "WORM_ID", ClientSecretEnv: "WORM_SECRET", TokenEnv: "WORM_SESSION"}
	if got := sinkCredentialRef(c); got != want {
		t.Fatalf("%+v", got)
	}
	keys := sinkKeys(c)
	t.Setenv("WORM_ID", "AKID")
	t.Setenv("WORM_SECRET", "s3cr3t")
	t.Setenv("WORM_SESSION", "")
	_, err := keys(context.Background())
	if err == nil || !strings.Contains(err.Error(), "WORM_SESSION") || strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("unset session: %v", err)
	}
	t.Setenv("WORM_SESSION", "tok")
	kp, err := keys(context.Background())
	if err != nil || kp != (broker.KeyPair{ID: "AKID", Secret: "s3cr3t", Session: "tok"}) {
		t.Fatalf("%v %+v", err, kp)
	}
}

// TestProtectedLine pins the one line the seal prints for the copy.
func TestProtectedLine(t *testing.T) {
	until := time.Date(2033, 10, 20, 9, 0, 0, 0, time.UTC)
	res := control.SealResult{Sink: &control.SealSink{Kind: "s3-object-lock", URL: "https://s3.example/worm/agenthof", Key: "agenthof/abc/seg-000001", Mode: "compliance", RetainUntil: until.Add(-time.Hour)}, VersionID: "v-9", RetainUntil: until}
	if got := protectedLine(res); got != "protected: s3-object-lock https://s3.example/worm/agenthof key=agenthof/abc/seg-000001 version=v-9 compliance until 2033-10-20T09:00:00Z" {
		t.Fatal(got)
	}
	res.Existed = true
	if got := protectedLine(res); !strings.HasSuffix(got, " until 2033-10-20T09:00:00Z (already confirmed)") {
		t.Fatal(got)
	}
}

// --- audit verify control: the sink pass ---

// Pinned texts of the sink pass, in the order they print.
const (
	notIndependent = " (sink address taken from the root being verified — not independent; pass --integrity)"
	missingLine    = "      MISSING — no version exists at the key (never written, or the lock is not what the posture claims)\n"
	noneLine       = "protected copies: none (if this root is meant to keep protected copies — integrity.yaml sink: worm — run audit seal)\n"
	offlineLine    = "protected copies: not checked (--offline)\n"
)

// verifiedSummary is the summary for one copy verified and accounted for,
// with the not-independent suffix.
const verifiedSummary = "protected copies: 1 (1 verified, 0 missing, 0 mismatch, 0 under-locked, 0 unverifiable); sink holds 1 objects for this ledger, 1 accounted for" + notIndependent + "\n"

// reforge rewrites every record of the chain file at path from seq on (seq
// counted from s.Base+1), re-marshalled with prev recomputed, so the chain
// stays valid while every hash from seq on differs — rewriteTail for a file
// that begins at s. It returns the file's new whole-file digest, head hash
// and size.
func reforge(t *testing.T, path string, s ledger.Start, from int, mutate func(seq int, m map[string]any)) (whole, head string, size int64) {
	t.Helper()
	recs, _, err := ledger.ReadVerifyFrom(path, ledger.Unlocked, s)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	prev := s.Prev
	for i, r := range recs {
		raw := r.Raw
		seq := int(s.Base) + i + 1
		if seq >= from {
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatal(err)
			}
			m["prev"] = prev
			mutate(seq, m)
			if raw, err = json.Marshal(m); err != nil {
				t.Fatal(err)
			}
		}
		out.Write(raw)
		out.WriteByte('\n')
		sum := sha256.Sum256(raw)
		prev = hex.EncodeToString(sum[:])
	}
	if err := os.WriteFile(path, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(out.Bytes())
	return hex.EncodeToString(sum[:]), prev, int64(out.Len())
}

// readManifest / writeManifest edit the manifest beside ctl.
func readManifest(t *testing.T, ctl string) control.Manifest {
	t.Helper()
	data, err := os.ReadFile(control.ManifestPath(ctl))
	if err != nil {
		t.Fatal(err)
	}
	m, err := control.ParseManifest(data, ctl)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func writeManifest(t *testing.T, ctl string, m control.Manifest) {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(control.ManifestPath(ctl), append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

// dropSinkBlock re-forges sealed segment 1 of ctl without its seal record's
// sink block — the record is still a seal, the chain still verifies — and
// rewrites the manifest's digest and head for it. The active must be empty
// (nothing chains onto the old head).
func dropSinkBlock(t *testing.T, ctl string) {
	t.Helper()
	seg := control.SegmentPath(ctl, 1)
	sealSeq := sealedView(t, ctl).Sealed[0].HeadSeq // the seal record is the segment's last; the records before it keep their bytes
	whole, head, size := reforge(t, seg, ledger.Start{}, sealSeq, func(_ int, m map[string]any) {
		if seal, ok := m["seal"].(map[string]any); ok {
			delete(seal, "sink")
		}
	})
	m := readManifest(t, ctl)
	m.Segments[0].SHA256, m.Segments[0].HeadHash, m.Segments[0].Bytes = whole, head, size
	writeManifest(t, ctl, m)
}

func sealedView(t *testing.T, ctl string) control.View {
	t.Helper()
	v, err := control.Read(ctl, ledger.Locked)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func segmentBytes(t *testing.T, ctl string, n int) []byte {
	t.Helper()
	data, err := os.ReadFile(control.SegmentPath(ctl, n))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// after returns out from the first occurrence of marker on, or fails.
func after(t *testing.T, out, marker string) string {
	t.Helper()
	i := strings.Index(out, marker)
	if i < 0 {
		t.Fatalf("missing %q in:\n%s", marker, out)
	}
	return out[i:]
}

// TestVerifyControlWormVerified: the happy path prints the segment line, the
// protected copy line, the verified verdict and the summary with the
// not-independent suffix; --integrity naming a copy of the same posture
// drops the suffix; --integrity naming a file that does not exist makes the
// copy unverifiable (exit 10 — never the floor, never 2).
func TestVerifyControlWormVerified(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, f := wormSealedRoot(t)
	key := segmentKey(t, ctl, 1)
	code, out := verifyControl(t, "--control-log", ctl)
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	rest := after(t, out, "segment 1: seq 1–3 sealed")
	rest = after(t, rest, "  protected copy: s3-object-lock "+f.URL()+"/agenthof key="+key+"\n")
	rest = after(t, rest, "      verified — oldest version v-1 compliance until ")
	if !regexp.MustCompile(`^      verified — oldest version v-1 compliance until 20\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ \(bytes match\)\n`).MatchString(rest) {
		t.Fatalf("verdict line:\n%s", rest)
	}
	if !strings.Contains(rest, "\n"+verifiedSummary) {
		t.Fatalf("summary:\n%s", out)
	}
	if !strings.Contains(out, "installed config: ") || strings.Index(out, "protected copies:") > strings.Index(out, "installed config: ") {
		t.Fatalf("the sink block prints before the pointer line:\n%s", out)
	}

	// The same posture held off the box: independent.
	copyPath := filepath.Join(t.TempDir(), "integrity.yaml")
	posture, err := os.ReadFile(integrityPath(ctl))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copyPath, posture, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out = verifyControl(t, "--control-log", ctl, "--integrity", copyPath)
	if code != 0 || strings.Contains(out, notIndependent) || !strings.Contains(out, strings.TrimSuffix(verifiedSummary, notIndependent+"\n")+"\n") {
		t.Fatalf("--integrity: exit %d\n%s", code, out)
	}

	// --integrity naming nothing: the flag is the pin; absent fails closed.
	nope := filepath.Join(t.TempDir(), "nope.yaml")
	code, out = verifyControl(t, "--control-log", ctl, "--integrity", nope)
	if code != exitSinkUnverifiable || !strings.Contains(out, "      unverifiable — integrity "+nope+": no such file or directory\n") || !strings.Contains(out, "0 under-locked, 1 unverifiable); sink not listed — integrity "+nope+": ") || strings.Contains(out, notIndependent) {
		t.Fatalf("missing --integrity: exit %d\n%s", code, out)
	}
}

// TestVerifyControlOldestVersionRule: the local file is never edited (the
// chain would refuse first); the sink's versions are what move. A newer
// differing version is information; once the oldest is not the local
// segment the verdict is LOCAL MISMATCH, and a later matching version does
// not rescue it.
func TestVerifyControlOldestVersionRule(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	far := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl, f := wormSealedRoot(t)
	key := segmentKey(t, ctl, 1)
	local := segmentBytes(t, ctl, 1)

	f.Plant(key, append(append([]byte{}, local...), []byte("x\n")...), "COMPLIANCE", far)
	code, out := verifyControl(t, "--control-log", ctl)
	if code != 0 || !regexp.MustCompile(`(?m)^      verified — oldest version v-1 compliance until [0-9T:Z-]+ \(bytes match; 1 later versions differ: written over, the protected copy stands\)\n`).MatchString(out) || !strings.Contains(out, verifiedSummary) {
		t.Fatalf("newer differing version: exit %d\n%s", code, out)
	}

	f.RemoveVersion(key, "v-1")
	f.Plant(key, []byte("other\n"), "COMPLIANCE", far)
	const mismatch = "      LOCAL MISMATCH — the oldest version v-2 at the key does not hold the local segment's bytes: the local file was altered (the seal wrote the oldest; a later matching version is not the copy); run: agenthof audit restore control --segment 1\n"
	code, out = verifyControl(t, "--control-log", ctl)
	if code != exitSinkMismatch || !strings.Contains(out, mismatch) || !strings.Contains(out, "protected copies: 1 (0 verified, 0 missing, 1 mismatch, 0 under-locked, 0 unverifiable); sink holds 1 objects for this ledger, 0 accounted for"+notIndependent+"\n") {
		t.Fatalf("oldest replaced: exit %d\n%s", code, out)
	}

	f.Plant(key, local, "COMPLIANCE", far) // a matching NEWER version is not the copy
	code, out = verifyControl(t, "--control-log", ctl)
	if code != exitSinkMismatch || !strings.Contains(out, mismatch) || strings.Contains(out, "      verified — oldest") {
		t.Fatalf("later match: exit %d\n%s", code, out)
	}
}

// TestVerifyControlMissingAndUnderLocked: no version at the key is MISSING
// (and nothing is held, so no bucket-first line); a version holding the
// bytes under a GOVERNANCE lock, a shorter COMPLIANCE lock or no lock is
// UNDER-LOCKED with the cause spelled.
func TestVerifyControlMissingAndUnderLocked(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	far := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl, f := wormSealedRoot(t)
	key := segmentKey(t, ctl, 1)
	local := segmentBytes(t, ctl, 1)
	recorded := sealedView(t, ctl).Sealed[0].Sink.RetainUntil

	f.RemoveVersions(key)
	code, out := verifyControl(t, "--control-log", ctl)
	if code != exitSinkMismatch || !strings.Contains(out, missingLine) || strings.Contains(out, "  sink: key") || !strings.Contains(out, "protected copies: 1 (0 verified, 1 missing, 0 mismatch, 0 under-locked, 0 unverifiable); sink holds 0 objects for this ledger, 0 accounted for"+notIndependent+"\n") {
		t.Fatalf("missing: exit %d\n%s", code, out)
	}

	for _, tc := range []struct {
		mode, want string
		until      time.Time
	}{
		{"GOVERNANCE", "is GOVERNANCE until 2030-01-01T00:00:00Z\n", far},
		{"COMPLIANCE", "is locked only until " + recorded.Add(-time.Hour).UTC().Format(time.RFC3339) + ", before the recorded " + recorded.UTC().Format(time.RFC3339) + "\n", recorded.Add(-time.Hour)},
		{"", "is unlocked\n", time.Time{}},
	} {
		f.RemoveVersions(key)
		id := f.Plant(key, local, tc.mode, tc.until)
		code, out := verifyControl(t, "--control-log", ctl)
		if code != exitSinkMismatch || !strings.Contains(out, "      UNDER-LOCKED — version "+id+" holds the bytes but "+tc.want) || !strings.Contains(out, "0 mismatch, 1 under-locked, 0 unverifiable); sink holds 1 objects for this ledger, 1 accounted for") {
			t.Fatalf("%q: exit %d\n%s", tc.mode, code, out)
		}
	}
}

// TestVerifyControlSeesThroughDeleteMarker: a delete marker on the key is
// information; the locked version beneath it still verifies and is
// accounted for.
func TestVerifyControlSeesThroughDeleteMarker(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, f := wormSealedRoot(t)
	f.AddDeleteMarker(segmentKey(t, ctl, 1))
	code, out := verifyControl(t, "--control-log", ctl)
	if code != 0 || !regexp.MustCompile(`(?m)^      verified — oldest version v-1 compliance until [0-9T:Z-]+ \(bytes match\)\n      key has a delete marker; the locked versions stand\n`).MatchString(out) || !strings.Contains(out, verifiedSummary) {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

// twiceSealedWormRoot seals a worm root twice: segment 1 (seq 1–3) and
// segment 2 (seq 4–5), both with protected copies; the active is empty.
func twiceSealedWormRoot(t *testing.T) (string, string, *sinktest.Fake) {
	t.Helper()
	root, ctl, f := wormRoot(t)
	if code, out := auditSeal(t, ctl); code != 0 {
		t.Fatalf("seal 1: %d\n%s", code, out)
	}
	var buf bytes.Buffer
	if code := cmdRegistry([]string{"enable", "coder", "--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &buf); code != 0 {
		t.Fatalf("enable: %d\n%s", code, buf.String())
	}
	if code, out := auditSeal(t, ctl); code != 0 {
		t.Fatalf("seal 2: %d\n%s", code, out)
	}
	return root, ctl, f
}

// tidy drops segment 2 locally, lists only segment 1 in the manifest and
// empties the active: a consistent local set that no longer accounts for
// what the sink holds. The chain verifies (its head is segment 1's seal).
func tidy(t *testing.T, ctl string) {
	t.Helper()
	if err := os.Remove(control.SegmentPath(ctl, 2)); err != nil {
		t.Fatal(err)
	}
	m := readManifest(t, ctl)
	m.Segments = m.Segments[:1]
	writeManifest(t, ctl, m)
	if err := os.WriteFile(ctl, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// The pointer named the install segment 2 recorded; the tidied set's
	// last install is segment 1's, so the same hand aims the pointer there —
	// what the sink catches is not the pointer verdict.
	last, err := control.Decode(sealedView(t, ctl).Records[1].Raw)
	if err != nil || last.ConfigHash == "" {
		t.Fatalf("%v %+v", err, last)
	}
	repointTo(t, ctl, last.ConfigHash)
}

// TestVerifyControlBucketFirst (the direction that sees a consistent local
// rewrite): the tidied set verifies as a chain and is caught by the key the
// sink still holds for segment 2; re-forged without sink blocks under a
// local posture it exits 0 on the box, and 9 against the off-box posture,
// both keys unaccounted for.
func TestVerifyControlBucketFirst(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	_, ctl, _ := twiceSealedWormRoot(t)
	id := sealedView(t, ctl).LogID
	tidy(t, ctl)
	v := sealedView(t, ctl)
	if len(v.Sealed) != 1 || v.Head.Count != 3 {
		t.Fatalf("the tidied set must verify as a one-segment chain: %+v", v.Head)
	}
	code, out := verifyControl(t, "--control-log", ctl)
	if code != exitSinkMismatch || !strings.Contains(out, "  sink: key agenthof/"+id+"/seg-000002 is not accounted for by this ledger's local segments — segment 2 missing or replaced locally; run: agenthof audit restore control --segment 2\n") || !strings.Contains(out, "protected copies: 1 (1 verified, 0 missing, 0 mismatch, 0 under-locked, 0 unverifiable); sink holds 2 objects for this ledger, 1 accounted for"+notIndependent+"\n") {
		t.Fatalf("tidied: exit %d\n%s", code, out)
	}

	// Re-forged without sink blocks, the posture flipped to local.
	dropSinkBlock(t, ctl)
	offBox := filepath.Join(t.TempDir(), "integrity.yaml")
	posture, err := os.ReadFile(integrityPath(ctl))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(offBox, posture, 0o600); err != nil {
		t.Fatal(err)
	}
	writeIntegrity(t, ctl, "sink: local\n")
	if v := sealedView(t, ctl); len(v.Sealed) != 1 || v.Sealed[0].Sink != nil {
		t.Fatalf("the re-forged set must verify without a block: %+v", v.Sealed)
	}
	code, out = verifyControl(t, "--control-log", ctl)
	if code != 0 || !strings.Contains(out, noneLine) || strings.Contains(out, "protected copy:") {
		t.Fatalf("on the box: exit %d\n%s", code, out)
	}
	code, out = verifyControl(t, "--control-log", ctl, "--integrity", offBox)
	if code != exitSinkMismatch || !strings.Contains(out, "  protected copy: none (sealed before sink: worm)\n") ||
		!strings.Contains(out, "  sink: key agenthof/"+id+"/seg-000001 is not accounted for by this ledger's local segments — segment 1 missing or replaced locally; run: agenthof audit restore control --segment 1\n") ||
		!strings.Contains(out, "  sink: key agenthof/"+id+"/seg-000002 is not accounted for by this ledger's local segments — segment 2 missing or replaced locally; run: agenthof audit restore control --segment 2\n") ||
		!strings.Contains(out, "protected copies: 0 (0 verified, 0 missing, 0 mismatch, 0 under-locked, 0 unverifiable); sink holds 2 objects for this ledger, 0 accounted for\n") {
		t.Fatalf("off-box posture: exit %d\n%s", code, out)
	}
}

// TestVerifyControlSinkUnverifiable: every cause that is no verdict — a
// refused listing, a failed read, a posture that does not parse (never exit
// 2), a local posture with blocks on record, a posture naming another sink —
// is unverifiable, exit 10, never 9.
func TestVerifyControlSinkUnverifiable(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, f := wormSealedRoot(t)
	host := fakeHost(f)

	f.Deny = map[string]bool{"ListObjectVersions": true}
	code, out := verifyControl(t, "--control-log", ctl)
	if code != exitSinkUnverifiable || !strings.Contains(out, "      unverifiable — status 403 AccessDenied from "+host+" (ListObjectVersions)\n") || !strings.Contains(out, "protected copies: 1 (0 verified, 0 missing, 0 mismatch, 0 under-locked, 1 unverifiable); sink not listed — status 403 AccessDenied from "+host+" (ListObjectVersions)"+notIndependent+"\n") || strings.Contains(out, sinktest.Sentinel) {
		t.Fatalf("listing denied: exit %d\n%s", code, out)
	}
	f.Deny = nil

	f.Status = map[string]int{"GetObject": 500}
	code, out = verifyControl(t, "--control-log", ctl)
	if code != exitSinkUnverifiable || !strings.Contains(out, "      unverifiable — status 500 from "+host+" (GetObject)\n") || !strings.Contains(out, "0 under-locked, 1 unverifiable); sink holds 1 objects for this ledger, 1 accounted for") || strings.Contains(out, sinktest.Sentinel) {
		t.Fatalf("read failed: exit %d\n%s", code, out)
	}
	f.Status = nil

	p := writeIntegrity(t, ctl, "sink: worm\nsink_backend: [\n")
	code, out = verifyControl(t, "--control-log", ctl)
	if code != exitSinkUnverifiable || !strings.Contains(out, "      unverifiable — integrity "+p+": ") || !strings.Contains(out, "1 unverifiable); sink not listed — integrity "+p+": ") || strings.Contains(out, notIndependent) || !strings.Contains(out, "control head: seq=3 ") {
		t.Fatalf("unparsable posture: exit %d\n%s", code, out)
	}

	writeIntegrity(t, ctl, "sink: local\n")
	code, out = verifyControl(t, "--control-log", ctl)
	if code != exitSinkUnverifiable || !strings.Contains(out, "      unverifiable — no sink credential configured\n") || !strings.Contains(out, "1 unverifiable); sink not listed — no sink credential configured\n") {
		t.Fatalf("local posture with a block on record: exit %d\n%s", code, out)
	}

	wormPostureFor(t, ctl, f, "/other", "1d")
	code, out = verifyControl(t, "--control-log", ctl)
	if code != exitSinkUnverifiable || !strings.Contains(out, "      unverifiable — the record names s3-object-lock "+f.URL()+"/agenthof but the posture names "+f.URL()+"/other; pass the posture that names it\n") || !strings.Contains(out, "1 unverifiable); sink holds 0 objects for this ledger, 0 accounted for") {
		t.Fatalf("another sink: exit %d\n%s", code, out)
	}
}

// wormAnchoredRoot is a worm root whose operator may also anchor, under a
// layered posture (sink: worm + anchor: tlog through the stub), sealed once
// (segment 1 = seq 1–3) and then anchored (seq 4, in the active).
func wormAnchoredRoot(t *testing.T) (string, string, *sinktest.Fake) {
	t.Helper()
	root := writeSample(t)
	role := "name: platform-admin\nallowed_groups: [platform-eng]\ncontrol: [apply, enable, disable, repair, provision, prune, anchor, seal]\n"
	if err := os.WriteFile(filepath.Join(root, "roles", "ops.yaml"), []byte(role), 0o644); err != nil {
		t.Fatal(err)
	}
	ctl := applied(t, root)
	var out bytes.Buffer
	if code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("disable: %d\n%s", code, out.String())
	}
	f := sinktest.NewFake(t)
	wormPostureFor(t, ctl, f, "/agenthof", "1d")
	posture, err := os.ReadFile(integrityPath(ctl))
	if err != nil {
		t.Fatal(err)
	}
	writeIntegrity(t, ctl, string(posture)+"anchor: tlog\nanchor_backend:\n  url: http://stub.invalid\n")
	if code, out := auditSeal(t, ctl); code != 0 {
		t.Fatalf("seal: %d\n%s", code, out)
	}
	out.Reset()
	if code := cmdAudit([]string{"anchor", "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("anchor: %d\n%s", code, out.String())
	}
	return root, ctl, f
}

// TestVerifyControlSinkPrecedence: 1, 6, 9, 3, 4, 5, 7, 10, 8 — 9 outranks
// 3, 4 and 5; 6 outranks 9; 7 outranks 10; 3 outranks 10; 10 outranks 8.
func TestVerifyControlSinkPrecedence(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	zeros := strings.Repeat("0", 64)

	// 9 outranks 3: a tainted worm root whose copy is missing.
	root, ctl, f := wormRoot(t)
	if code, out := auditSeal(t, ctl); code != 0 {
		t.Fatalf("seal: %d\n%s", code, out)
	}
	var buf bytes.Buffer
	if code := cmdRegistry([]string{"enable", "coder", "--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &buf); code != 0 {
		t.Fatalf("enable: %d\n%s", code, buf.String())
	}
	tearTail(t, ctl)
	buf.Reset()
	if code := cmdAuditRepairControl([]string{"control", "--control-log", ctl, "--config", root, "--as", "dana@example.com", "--groups", "platform-eng"}, &buf); code != 0 {
		t.Fatalf("repair: %d\n%s", code, buf.String())
	}
	if code, out := verifyControl(t, "--control-log", ctl); code != 3 || !strings.Contains(out, "TAINTED") {
		t.Fatalf("tainted, copy intact: exit %d\n%s", code, out)
	}
	f.RemoveVersions(segmentKey(t, ctl, 1))
	if code, out := verifyControl(t, "--control-log", ctl); code != exitSinkMismatch || !strings.Contains(out, "TAINTED") || !strings.Contains(out, missingLine) {
		t.Fatalf("9 outranks 3: exit %d\n%s", code, out)
	}
	// 3 outranks 10.
	f.Deny = map[string]bool{"ListObjectVersions": true}
	if code, out := verifyControl(t, "--control-log", ctl); code != 3 || !strings.Contains(out, "unverifiable — status 403") {
		t.Fatalf("3 outranks 10: exit %d\n%s", code, out)
	}
	f.Deny = nil

	// 9 outranks 4 and 5.
	ctl2, f2 := wormSealedRoot(t)
	f2.RemoveVersions(segmentKey(t, ctl2, 1))
	if code, out := verifyControl(t, "--control-log", ctl2, "--expect-head", zeros); code != exitSinkMismatch || !strings.Contains(out, "expect-head mismatch") {
		t.Fatalf("9 outranks 4: exit %d\n%s", code, out)
	}
	repointTo(t, ctl2, "sha256:"+strings.Repeat("ab", 32))
	if code, out := verifyControl(t, "--control-log", ctl2); code != exitSinkMismatch || !strings.Contains(out, "does NOT match the last recorded install") {
		t.Fatalf("9 outranks 5: exit %d\n%s", code, out)
	}

	// 6 outranks 9; 7 outranks 10.
	stub := useStub(t)
	_, ctl3, f3 := wormAnchoredRoot(t)
	if code, out := verifyControl(t, "--control-log", ctl3); code != 0 || !strings.Contains(out, "anchors: 1 (1 verified, 0 mismatch, 0 unverifiable)") || !strings.Contains(out, verifiedSummary) {
		t.Fatalf("anchored worm root: exit %d\n%s", code, out)
	}
	v := sealedView(t, ctl3)
	reforge(t, ctl3, ledger.Start{Prev: v.Sealed[0].HeadHash, Base: uint64(v.Sealed[0].HeadSeq)}, 4, func(seq int, m map[string]any) {
		if seq == 4 {
			m["anchor"].(map[string]any)["hash"] = strings.Repeat("ff", 32)
		}
	})
	f3.RemoveVersions(segmentKey(t, ctl3, 1))
	if code, out := verifyControl(t, "--control-log", ctl3); code != exitAnchorMismatch || !strings.Contains(out, "MISMATCH — the chain does not reproduce") || !strings.Contains(out, missingLine) {
		t.Fatalf("6 outranks 9: exit %d\n%s", code, out)
	}
	_, ctl4, f4 := wormAnchoredRoot(t)
	stub.Fail()
	f4.Deny = map[string]bool{"ListObjectVersions": true}
	if code, out := verifyControl(t, "--control-log", ctl4); code != exitAnchorUnverifiable || !strings.Contains(out, "unverifiable — stub: unavailable") || !strings.Contains(out, "unverifiable — status 403") {
		t.Fatalf("7 outranks 10: exit %d\n%s", code, out)
	}

	// 10 outranks 8: state B (the copy owed) against a sink that refuses to list.
	_, ctl5, f5 := wormRoot(t)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "after_seal_before_sink")
	auditSeal(t, ctl5)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "")
	if code, out := verifyControl(t, "--control-log", ctl5); code != exitRotationIncomplete || !strings.Contains(out, "protected copies: 0 (0 verified, 0 missing, 0 mismatch, 0 under-locked, 0 unverifiable); sink holds 0 objects for this ledger, 0 accounted for") {
		t.Fatalf("state B, listable: exit %d\n%s", code, out)
	}
	f5.Deny = map[string]bool{"ListObjectVersions": true}
	if code, out := verifyControl(t, "--control-log", ctl5); code != exitSinkUnverifiable || !strings.Contains(out, "rotation not completed") || !strings.Contains(out, "sink not listed — status 403") {
		t.Fatalf("10 outranks 8: exit %d\n%s", code, out)
	}
}

// TestVerifyControlStateBCopyIsPending: a state-B root whose copy landed
// before the manifest write is not "unaccounted for" — the key is the
// rotating segment's, owed to audit seal — so verify exits 8, never 9.
func TestVerifyControlStateBCopyIsPending(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	_, ctl, f := wormRoot(t)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "after_sink_before_manifest")
	auditSeal(t, ctl)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "")
	key := segmentKey(t, ctl, 1)
	if vs := f.Versions(key); len(vs) != 1 {
		t.Fatalf("the copy landed: %+v", vs)
	}
	code, out := verifyControl(t, "--control-log", ctl)
	if code != exitRotationIncomplete || !strings.Contains(out, "  sink: key "+key+" is segment 1, whose rotation did not complete; run: agenthof audit seal\n") || strings.Contains(out, "not accounted for") || !strings.Contains(out, "sink holds 0 objects for this ledger, 0 accounted for") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

// TestVerifyControlOffline: --offline skips the sink pass — no request, the
// not-checked line, and the exit unaffected on a root that is otherwise 9.
func TestVerifyControlOffline(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, f := wormSealedRoot(t)
	f.RemoveVersions(segmentKey(t, ctl, 1))
	before := len(f.Requests())
	code, out := verifyControl(t, "--control-log", ctl, "--offline")
	if code != 0 || !strings.Contains(out, offlineLine) || strings.Contains(out, "protected copy:") || len(f.Requests()) != before {
		t.Fatalf("exit %d (%d requests)\n%s", code, len(f.Requests())-before, out)
	}
}

// TestVerifyControlExpiring: a retention ending within 30 days adds the
// expiring line under the verdict; with the clock past the recorded date the
// copy is "unlocked — verified"; a lock that ended while the recorded date
// has not is UNDER-LOCKED.
func TestVerifyControlExpiring(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, f := wormSealedRoot(t) // retention 1d
	code, out := verifyControl(t, "--control-log", ctl)
	if code != 0 || !regexp.MustCompile(`(?m)^      verified — oldest version v-1 compliance until [0-9T:Z-]+ \(bytes match\)\n      expiring — verified; retention ends in 1 days\n`).MatchString(out) {
		t.Fatalf("exit %d\n%s", code, out)
	}

	// The verdict function with an injected clock past the recorded date.
	in, err := loadIntegrity(ctl)
	if err != nil {
		t.Fatal(err)
	}
	be, err := sinkFor(in, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	v := sealedView(t, ctl)
	seg := v.Sealed[0]
	ended := seg.Sink.RetainUntil
	c := verifyCopy(context.Background(), be, seg, ended.Add(time.Hour))
	if c.state != copyVerified || c.info != "unlocked — verified; the retention period ended "+ended.UTC().Format(time.RFC3339) {
		t.Fatalf("%+v", c)
	}
	// The lock ended, the recorded date has not: UNDER-LOCKED.
	key := segmentKey(t, ctl, 1)
	f.RemoveVersions(key)
	id := f.Plant(key, segmentBytes(t, ctl, 1), "COMPLIANCE", ended.Add(-time.Hour))
	c = verifyCopy(context.Background(), be, seg, ended.Add(-30*time.Minute))
	if c.state != copyUnderLocked || c.verdict != "UNDER-LOCKED — version "+id+" holds the bytes but is locked only until "+ended.Add(-time.Hour).UTC().Format(time.RFC3339)+", before the recorded "+ended.UTC().Format(time.RFC3339) {
		t.Fatalf("%+v", c)
	}
}

// TestVerifyControlFloorPrintsNone: a sealed floor root prints the none
// line; a segment sealed before the posture, with the posture then added,
// prints its "none (sealed before sink: worm)" line and a summary of zero
// copies.
func TestVerifyControlFloorPrintsNone(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := sealedRoot(t)
	code, out := verifyControl(t, "--control-log", ctl)
	if code != 0 || !strings.Contains(out, noneLine) || strings.Contains(out, "protected copy:") {
		t.Fatalf("floor: exit %d\n%s", code, out)
	}
	f := sinktest.NewFake(t)
	wormPostureFor(t, ctl, f, "/agenthof", "1d")
	code, out = verifyControl(t, "--control-log", ctl)
	if code != 0 || !strings.Contains(out, "  protected copy: none (sealed before sink: worm)\n") || !strings.Contains(out, "protected copies: 0 (0 verified, 0 missing, 0 mismatch, 0 under-locked, 0 unverifiable); sink holds 0 objects for this ledger, 0 accounted for"+notIndependent+"\n") {
		t.Fatalf("posture added later: exit %d\n%s", code, out)
	}
	// A never-sealed root prints no sink line and reads nothing.
	plain := applied(t, writeSample(t))
	if code, out := verifyControl(t, "--control-log", plain); code != 0 || strings.Contains(out, "protected cop") {
		t.Fatalf("never sealed: exit %d\n%s", code, out)
	}
}

// TestInvestigateAndServeStayPostureBlind: investigate, locally and over
// serve, never touches the sink — a worm root whose sink refuses everything
// yields exit 0 and no request after the seal.
func TestInvestigateAndServeStayPostureBlind(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	t.Setenv("AGENTHOF_SERVER", "")
	ctl, f := wormSealedRoot(t)
	f.Deny = map[string]bool{"ListObjectVersions": true, "GetObject": true, "GetObjectRetention": true, "GetObjectLockConfiguration": true}
	before := len(f.Requests())
	var out bytes.Buffer
	if code := cmdInvestigate([]string{"--log-dir", t.TempDir(), "--control-log", ctl, "--json"}, &out); code != 0 || len(f.Requests()) != before {
		t.Fatalf("investigate: exit %d (%d requests)\n%s", code, len(f.Requests())-before, out.String())
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	oidc := cmdTestOIDCServer(t, key)
	token := cmdMintToken(t, key, map[string]any{"iss": oidc.URL, "aud": "agenthof", "exp": time.Now().Add(time.Hour).Unix(), "sub": "u-1", "email": "dana@example.com"})
	t.Chdir(t.TempDir())
	t.Setenv("AGENTHOF_OIDC_ISSUER", oidc.URL)
	t.Setenv("AGENTHOF_OIDC_CLIENT_ID", "agenthof")
	addrFile := filepath.Join(t.TempDir(), "addr")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan int, 1)
	var serveOut bytes.Buffer
	go func() {
		done <- cmdServe(ctx, []string{"--addr", "127.0.0.1:0", "--addr-file", addrFile, "--control-log", ctl, "--log-dir", t.TempDir()}, &serveOut, io.Discard)
	}()
	var addr string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if b, err := os.ReadFile(addrFile); err == nil && strings.TrimSpace(string(b)) != "" {
			addr = strings.TrimSpace(string(b))
			break
		}
	}
	if addr == "" {
		t.Fatalf("serve did not start\n%s", serveOut.String())
	}
	out.Reset()
	if code := cmdInvestigate([]string{"--server", "http://" + addr, "--token", token, "--json"}, &out); code != 0 || !strings.Contains(out.String(), `"investigate/1"`) || len(f.Requests()) != before {
		t.Fatalf("over serve: exit %d (%d requests)\n%s", code, len(f.Requests())-before, out.String())
	}
	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("serve exited %d\n%s", code, serveOut.String())
	}
}

// TestVerifyControlLocalMismatchByDigest: an oldest version of exactly the
// local segment's length with one byte flipped is LOCAL MISMATCH by digest —
// the one path to that verdict is the bytes in hand, never a listing figure.
func TestVerifyControlLocalMismatchByDigest(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	far := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl, f := wormSealedRoot(t)
	key := segmentKey(t, ctl, 1)
	flipped := segmentBytes(t, ctl, 1)
	flipped[len(flipped)/2] ^= 0x01
	f.RemoveVersions(key)
	id := f.Plant(key, flipped, "COMPLIANCE", far)
	code, out := verifyControl(t, "--control-log", ctl)
	if code != exitSinkMismatch || !strings.Contains(out, "      LOCAL MISMATCH — the oldest version "+id+" at the key does not hold the local segment's bytes") || !strings.Contains(out, "1 mismatch, 0 under-locked, 0 unverifiable); sink holds 1 objects for this ledger, 0 accounted for") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

// TestVerifySinkStaleViewIsNotTamper: a seal that lands while a verification
// is in its network phase puts an object past the view the verifier read;
// judged against the view re-read under the ledger's lock it is in flight —
// no "not accounted for", never definitive, undecided so the operator
// re-runs.
func TestVerifySinkStaleViewIsNotTamper(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root, ctl, _ := wormRoot(t)
	if code, out := auditSeal(t, ctl); code != 0 {
		t.Fatalf("seal 1: %d\n%s", code, out)
	}
	var buf bytes.Buffer
	if code := cmdRegistry([]string{"enable", "coder", "--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &buf); code != 0 {
		t.Fatalf("enable: %d\n%s", code, buf.String())
	}
	stale := sealedView(t, ctl)                    // one sealed segment; the active holds the enable
	if code, out := auditSeal(t, ctl); code != 0 { // segment 2 lands in the sink after the view was read
		t.Fatalf("seal 2: %d\n%s", code, out)
	}
	var out bytes.Buffer
	s := verifySink(ctl, "", stale, false, time.Minute, &out)
	if s.definitive() || !s.undecided() || s.inFlight != 1 || strings.Contains(out.String(), "not accounted for") || !strings.Contains(out.String(), "  sink: key "+segmentKey(t, ctl, 2)+" is segment 2, sealed during this verification; re-run\n") || !strings.Contains(out.String(), "sink holds 1 objects for this ledger, 1 accounted for, 1 sealed during this verification — re-run") {
		t.Fatalf("%+v\n%s", s, out.String())
	}
	// Through the command the fresh view accounts for both: exit 0.
	if code, text := verifyControl(t, "--control-log", ctl); code != 0 || !strings.Contains(text, "sink holds 2 objects for this ledger, 2 accounted for") {
		t.Fatalf("re-run: exit %d\n%s", code, text)
	}
}

// readerOverride is a SinkReader over the fake with one or two answers
// replaced — the shapes a store could answer that the fake does not.
type readerOverride struct {
	control.SinkReader
	listVersions func(control.KeyVersions) control.KeyVersions
	retention    func() control.SinkRetention
}

func (r readerOverride) ListVersions(ctx context.Context, key string) (control.KeyVersions, error) {
	kv, err := r.SinkReader.ListVersions(ctx, key)
	if err == nil && r.listVersions != nil {
		kv = r.listVersions(kv)
	}
	return kv, err
}

func (r readerOverride) GetRetention(ctx context.Context, key, id string) (control.SinkRetention, error) {
	if r.retention != nil {
		return r.retention(), nil
	}
	return r.SinkReader.GetRetention(ctx, key, id)
}

// TestVerifyCopyIncompleteAnswersAreUnverifiable: a listing whose Size is
// not the object's length, a listing with no Size at all, a retention
// document with a date but no mode, and one naming a mode this verifier
// does not know are each unverifiable — never MISSING, MISMATCH or
// UNDER-LOCKED.
func TestVerifyCopyIncompleteAnswersAreUnverifiable(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, _ := wormSealedRoot(t)
	in, err := loadIntegrity(ctl)
	if err != nil {
		t.Fatal(err)
	}
	be, err := sinkFor(in, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	seg := sealedView(t, ctl).Sealed[0]
	resize := func(delta int64) func(control.KeyVersions) control.KeyVersions {
		return func(kv control.KeyVersions) control.KeyVersions {
			kv.Versions[0].Size += delta
			return kv
		}
	}
	for name, tc := range map[string]struct {
		r    readerOverride
		want string
	}{
		"size larger":   {readerOverride{SinkReader: be, listVersions: resize(1)}, "unverifiable — the listing and the object disagree on the size of version v-1"},
		"size smaller":  {readerOverride{SinkReader: be, listVersions: resize(-1)}, "unverifiable — the listing and the object disagree on the size of version v-1"},
		"size absent":   {readerOverride{SinkReader: be, listVersions: resize(-seg.Bytes)}, "unverifiable — the listing and the object disagree on the size of version v-1 (0 listed, "},
		"date, no mode": {readerOverride{SinkReader: be, retention: func() control.SinkRetention { return control.SinkRetention{RetainUntil: seg.Sink.RetainUntil} }}, "unverifiable — the retention document for version v-1 carries a date but no mode"},
		"unknown mode": {readerOverride{SinkReader: be, retention: func() control.SinkRetention {
			return control.SinkRetention{Mode: "LEGAL_HOLD", RetainUntil: seg.Sink.RetainUntil}
		}}, "unverifiable — the retention document for version v-1 names a mode this verifier does not know: LEGAL_HOLD"},
	} {
		c := verifyCopy(context.Background(), tc.r, seg, time.Now())
		if c.state != copyUnverifiable || !strings.HasPrefix(c.verdict, tc.want) {
			t.Fatalf("%s: %+v", name, c)
		}
	}
	// The fake's own answers still verify: the override is the only change.
	if c := verifyCopy(context.Background(), be, seg, time.Now()); c.state != copyVerified {
		t.Fatalf("baseline: %+v", c)
	}
}
