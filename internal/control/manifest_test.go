package control_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/control"
)

func goodManifest() control.Manifest {
	return control.Manifest{V: control.ManifestVersion, LogID: strings.Repeat("ab", 16), Segments: []control.ManifestEntry{
		{N: 1, File: "control.jsonl.seg-000001", FirstSeq: 1, HeadSeq: 57, HeadHash: strings.Repeat("1", 64), SHA256: strings.Repeat("2", 64), Bytes: 18233, SealedAt: time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)},
		{N: 2, File: "control.jsonl.seg-000002", FirstSeq: 58, HeadSeq: 120, HeadHash: strings.Repeat("3", 64), SHA256: strings.Repeat("4", 64), Bytes: 20000, SealedAt: time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)},
	}}
}

// TestParseManifestRoundTripAndRefusals: a well-formed manifest round-trips;
// an unknown v, an unknown key at either level, the reserved removed_at and
// object keys, n out of order, a file name that is not Base(SegmentPath(n)),
// a first_seq that does not continue, and a hash that is not 64 hex are each
// refused naming the field.
func TestParseManifestRoundTripAndRefusals(t *testing.T) {
	data, _ := json.Marshal(goodManifest())
	m, err := control.ParseManifest(data, "/root/control.jsonl")
	if err != nil || len(m.Segments) != 2 || m.Segments[1].HeadSeq != 120 {
		t.Fatalf("round trip: %v %+v", err, m)
	}
	mutate := func(f func(map[string]any)) []byte {
		var raw map[string]any
		_ = json.Unmarshal(data, &raw)
		f(raw)
		b, _ := json.Marshal(raw)
		return b
	}
	seg := func(raw map[string]any, i int) map[string]any { return raw["segments"].([]any)[i].(map[string]any) }
	for name, c := range map[string]struct {
		data []byte
		want string
	}{
		"version":      {mutate(func(r map[string]any) { r["v"] = "segments/2" }), "v"},
		"unknown top":  {mutate(func(r map[string]any) { r["active"] = 1 }), "unknown field"},
		"removed_at":   {mutate(func(r map[string]any) { seg(r, 0)["removed_at"] = "2026-10-15T00:00:00Z" }), "unknown field"},
		"object":       {mutate(func(r map[string]any) { seg(r, 0)["object"] = map[string]any{} }), "unknown field"},
		"n order":      {mutate(func(r map[string]any) { seg(r, 1)["n"] = 3 }), "n"},
		"file name":    {mutate(func(r map[string]any) { seg(r, 0)["file"] = "../control.jsonl.seg-000001" }), "file"},
		"file abs":     {mutate(func(r map[string]any) { seg(r, 1)["file"] = "/root/control.jsonl.seg-000002" }), "file"},
		"first_seq":    {mutate(func(r map[string]any) { seg(r, 1)["first_seq"] = 59 }), "first_seq"},
		"head_hash":    {mutate(func(r map[string]any) { seg(r, 0)["head_hash"] = "zz" }), "head_hash"},
		"sha256 upper": {mutate(func(r map[string]any) { seg(r, 0)["sha256"] = strings.Repeat("A", 64) }), "sha256"},
		"log_id":       {mutate(func(r map[string]any) { r["log_id"] = "short" }), "log_id"},
	} {
		if _, err := control.ParseManifest(c.data, "/root/control.jsonl"); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: err %v, want it to name %q", name, err, c.want)
		}
	}
}

// TestSegmentNamesNeverEndInJSONL: the retention guard — runs prune deletes
// aged *.jsonl under --log-dir — never sees a segment or the manifest.
func TestSegmentNamesNeverEndInJSONL(t *testing.T) {
	for _, log := range []string{"/r/control.jsonl", "/r/x.jsonl", "ledger"} {
		for _, p := range []string{control.SegmentPath(log, 1), control.SegmentPath(log, 999999), control.ManifestPath(log)} {
			if strings.HasSuffix(p, ".jsonl") || !strings.HasPrefix(p, log+".") {
				t.Fatalf("%s: %s must be a sibling of the log and never end in .jsonl", log, p)
			}
		}
	}
	if control.SegmentPath("/r/control.jsonl", 7) != "/r/control.jsonl.seg-000007" || control.ManifestPath("/r/control.jsonl") != "/r/control.jsonl.segments" {
		t.Fatal("path grammar")
	}
}
