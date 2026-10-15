package control

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/ledger"
)

func goodWritableManifest() Manifest {
	return Manifest{V: ManifestVersion, LogID: strings.Repeat("ab", 16), Segments: []ManifestEntry{
		{N: 1, File: "control.jsonl.seg-000001", FirstSeq: 1, HeadSeq: 3, HeadHash: strings.Repeat("1", 64), SHA256: strings.Repeat("2", 64), Bytes: 10, SealedAt: time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)},
	}}
}

func noTempsBeside(t *testing.T, p string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Dir(p))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".segments-") || strings.Contains(e.Name(), ".next-") {
			t.Fatalf("temp left behind: %s", e.Name())
		}
	}
}

// TestWriteManifestRoundTripsAtomically: written whole, 0600, no temp left
// behind, and the bytes ParseManifest reads back are the manifest written;
// a second write replaces it.
func TestWriteManifestRoundTripsAtomically(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	appendN(t, p, 2)
	m := goodWritableManifest()
	if err := writeManifest(p, m); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(ManifestPath(p))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", err, info.Mode())
	}
	got, err := loadManifest(p)
	if err != nil || got == nil || !reflect.DeepEqual(*got, m) {
		t.Fatalf("round trip: %v got %+v want %+v", err, got, m)
	}
	m.Segments[0].HeadSeq = 4
	if err := writeManifest(p, m); err != nil {
		t.Fatal(err)
	}
	got, err = loadManifest(p)
	if err != nil || got.Segments[0].HeadSeq != 4 {
		t.Fatalf("rename must replace: %v %+v", err, got)
	}
	noTempsBeside(t, p)
}

// TestWriteManifestRefusesWhatTheReaderRefuses: the writer holds itself to the
// reader's rules, so no writer can leave a manifest the next read faults on.
// An empty segments list — a shape no seal produces — is the case that
// matters most: nothing is written and no temp is left.
func TestWriteManifestRefusesWhatTheReaderRefuses(t *testing.T) {
	for name, mutate := range map[string]func(*Manifest){
		"no segments": func(m *Manifest) { m.Segments = nil },
		"empty list":  func(m *Manifest) { m.Segments = []ManifestEntry{} },
		"wrong file":  func(m *Manifest) { m.Segments[0].File = "other.seg-000001" },
		"bad log_id":  func(m *Manifest) { m.LogID = "short" },
	} {
		p := filepath.Join(t.TempDir(), "control.jsonl")
		m := goodWritableManifest()
		mutate(&m)
		if err := writeManifest(p, m); err == nil {
			t.Fatalf("%s: written", name)
		}
		if _, err := os.Lstat(ManifestPath(p)); err == nil {
			t.Fatalf("%s: a manifest exists after a refused write", name)
		}
		noTempsBeside(t, p)
	}
}

// TestParseManifestRefusesNoSegments: a manifest naming no sealed segment is
// not a state any writer produces; it is refused, not read as "sealed zero
// times".
func TestParseManifestRefusesNoSegments(t *testing.T) {
	for _, body := range []string{
		`{"v":"segments/1","log_id":"` + strings.Repeat("ab", 16) + `","segments":[]}`,
		`{"v":"segments/1","log_id":"` + strings.Repeat("ab", 16) + `","segments":null}`,
		`{"v":"segments/1","log_id":"` + strings.Repeat("ab", 16) + `"}`,
	} {
		if _, err := ParseManifest([]byte(body), "/root/control.jsonl"); err == nil || !strings.Contains(err.Error(), "segments") {
			t.Fatalf("%s: err %v, want it to name segments", body, err)
		}
	}
}

// TestSweepTempsRemovesOnlyTemps: stale manifest and swap temps go; the
// ledger, a segment, the manifest and a torn fragment stay — and a directory
// whose name holds glob syntax is swept like any other.
func TestSweepTempsRemovesOnlyTemps(t *testing.T) {
	for _, dirName := range []string{"plain", "a[1]"} {
		dir := filepath.Join(t.TempDir(), dirName)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, "control.jsonl")
		appendN(t, p, 1)
		keep := []string{"control.jsonl.seg-000001", "control.jsonl.segments", "control.jsonl.torn-1700000000"}
		gone := []string{"control.jsonl.segments-abc123", ".control.jsonl.next-xyz"}
		for _, n := range append(keep, gone...) {
			if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		sweepTemps(p)
		for _, n := range keep {
			if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
				t.Fatalf("%s: %s must stay", dirName, n)
			}
		}
		for _, n := range gone {
			if _, err := os.Stat(filepath.Join(dir, n)); err == nil {
				t.Fatalf("%s: %s must go", dirName, n)
			}
		}
	}
}

// TestSwapActiveLeavesAnEmptyActive: the old inode survives under a hard
// link, the name refers to a new empty 0600 file, no temp remains.
func TestSwapActiveLeavesAnEmptyActive(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	appendN(t, p, 2)
	before, _ := os.Stat(p)
	if err := os.Link(p, SegmentPath(p, 1)); err != nil {
		t.Fatal(err)
	}
	if err := swapActive(p); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(p)
	seg, _ := os.Stat(SegmentPath(p, 1))
	if after.Size() != 0 || after.Mode().Perm() != 0o600 || os.SameFile(before, after) || !os.SameFile(before, seg) {
		t.Fatalf("swap: active %d bytes same=%v; segment same=%v", after.Size(), os.SameFile(before, after), os.SameFile(before, seg))
	}
	entries, _ := os.ReadDir(filepath.Dir(p))
	if len(entries) != 2 {
		t.Fatalf("%v", entries)
	}
}

// TestIncrementalHashMatchesFile: segmentDigests' whole digest over a file's
// records equals sha256(file bytes) with size the file size, and
// sealContentDigest over all but the last record equals sha256 of the file up
// to the last line — the recipe a sealing writer and a verifying reader share.
func TestIncrementalHashMatchesFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	appendN(t, p, 4)
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	recs, _, err := ledger.ReadVerify(p, ledger.Unlocked)
	if err != nil {
		t.Fatal(err)
	}
	whole, size := segmentDigests(recs)
	sum := sha256.Sum256(data)
	lastStart := strings.LastIndex(strings.TrimSuffix(string(data), "\n"), "\n") + 1
	prefix := sha256.Sum256(data[:lastStart])
	if whole != hex.EncodeToString(sum[:]) || size != int64(len(data)) {
		t.Fatalf("whole digest or size differs from the file's bytes")
	}
	if got := sealContentDigest(recs[:len(recs)-1]); got != hex.EncodeToString(prefix[:]) {
		t.Fatalf("content digest %s differs from sha256 of the bytes before the last line", got)
	}
}
