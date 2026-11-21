package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const (
	helperFileEnv   = "MEMSTORE_TEST_HELPER_FILE"
	helperPrefixEnv = "MEMSTORE_TEST_HELPER_PREFIX"
	helperPerProc   = 25
)

// TestMain doubles as the helper process for the two-process test: when the
// helper env is set it upserts helperPerProc records and exits.
func TestMain(m *testing.M) {
	if file := os.Getenv(helperFileEnv); file != "" {
		prefix := os.Getenv(helperPrefixEnv)
		be := newEmbeddedBackend(file, embeddedMaxEntries)
		for i := 0; i < helperPerProc; i++ {
			id := fmt.Sprintf("%s-%02d", prefix, i)
			if err := be.Upsert(context.Background(), "m", id, "", []float32{1, 0}, id, nil); err != nil {
				fmt.Fprintln(os.Stderr, "helper upsert:", err)
				os.Exit(2)
			}
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func newTestBackend(t *testing.T, max int) (*embeddedBackend, string) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "store.json")
	return newEmbeddedBackend(file, max), file
}

var bg = context.Background()

func TestEmbeddedUpsertSearchTopK(t *testing.T) {
	be, _ := newTestBackend(t, 100)
	for id, v := range map[string][]float32{
		"a": {1, 0},
		"b": {1, 1},
		"c": {0, 1},
	} {
		if err := be.Upsert(bg, "m", id, "", v, "t-"+id, nil); err != nil {
			t.Fatal(err)
		}
	}
	hits, err := be.Search(bg, "m", []float32{1, 0.1}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 2 || hits[0].ID != "a" || hits[1].ID != "b" {
		t.Fatalf("want [a b], got %+v", hits)
	}
	if !(hits[0].Score > hits[1].Score) || hits[0].Text != "t-a" {
		t.Fatalf("scores not descending / text wrong: %+v", hits)
	}
	all, _ := be.Search(bg, "m", []float32{1, 0.1}, 10)
	if len(all) != 3 || all[2].ID != "c" || !(all[1].Score > all[2].Score) {
		t.Fatalf("bad full ordering: %+v", all)
	}
}

func TestEmbeddedPersistReload(t *testing.T) {
	be, file := newTestBackend(t, 100)
	if err := be.Upsert(bg, "m", "a", "", []float32{1, 2}, "hello", nil); err != nil {
		t.Fatal(err)
	}
	hits, err := newEmbeddedBackend(file, 100).Search(bg, "m", []float32{1, 2}, 1)
	if err != nil || len(hits) != 1 || hits[0].ID != "a" || hits[0].Text != "hello" {
		t.Fatalf("reload failed: %+v %v", hits, err)
	}
}

func TestEmbeddedUnknownCollectionEmpty(t *testing.T) {
	be, _ := newTestBackend(t, 100)
	hits, err := be.Search(bg, "never", []float32{1}, 3)
	if err != nil || hits != nil {
		t.Fatalf("want nil,nil got %v %v", hits, err)
	}
}

func TestEmbeddedDimensionMismatch(t *testing.T) {
	be, _ := newTestBackend(t, 100)
	if err := be.Upsert(bg, "m", "a", "", []float32{1, 0}, "x", nil); err != nil {
		t.Fatal(err)
	}
	if err := be.Upsert(bg, "m", "b", "", []float32{1, 0, 0}, "x", nil); !errors.Is(err, ErrDimensionMismatch) {
		t.Fatalf("upsert: want ErrDimensionMismatch, got %v", err)
	}
	if _, err := be.Search(bg, "m", []float32{1, 0, 0}, 1); !errors.Is(err, ErrDimensionMismatch) {
		t.Fatalf("search: want ErrDimensionMismatch, got %v", err)
	}
}

func TestEmbeddedDeterministicIDOverwrites(t *testing.T) {
	be, _ := newTestBackend(t, 100)
	if err := be.Upsert(bg, "m", "same", "", []float32{1, 0}, "old", nil); err != nil {
		t.Fatal(err)
	}
	if err := be.Upsert(bg, "m", "same", "", []float32{1, 0}, "new", nil); err != nil {
		t.Fatal(err)
	}
	hits, _ := be.Search(bg, "m", []float32{1, 0}, 10)
	if len(hits) != 1 || hits[0].Text != "new" {
		t.Fatalf("want one record with newest text, got %+v", hits)
	}
}

func TestEmbeddedCorruptFileRefused(t *testing.T) {
	be, file := newTestBackend(t, 100)
	garbage := []byte("}{garbage")
	if err := os.WriteFile(file, garbage, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := be.Search(bg, "m", []float32{1}, 1); !errors.Is(err, ErrStoreCorrupt) {
		t.Fatalf("search: want ErrStoreCorrupt, got %v", err)
	}
	if err := be.Upsert(bg, "m", "a", "", []float32{1}, "x", nil); !errors.Is(err, ErrStoreCorrupt) {
		t.Fatalf("upsert: want ErrStoreCorrupt, got %v", err)
	}
	got, _ := os.ReadFile(file)
	if !bytes.Equal(got, garbage) {
		t.Fatalf("corrupt file was modified: %q", got)
	}
}

func TestEmbeddedZeroLengthRefused(t *testing.T) {
	be, file := newTestBackend(t, 100)
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := be.Upsert(bg, "m", "a", "", []float32{1}, "x", nil); !errors.Is(err, ErrStoreCorrupt) {
		t.Fatalf("want ErrStoreCorrupt, got %v", err)
	}
	if fi, _ := os.Stat(file); fi.Size() != 0 {
		t.Fatal("zero-length file was overwritten")
	}
}

func TestEmbeddedEntryCap(t *testing.T) {
	be, _ := newTestBackend(t, 3)
	for i := 0; i < 3; i++ {
		if err := be.Upsert(bg, "m", fmt.Sprint("id", i), "", []float32{1}, "x", nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := be.Upsert(bg, "m", "extra", "", []float32{1}, "x", nil); !errors.Is(err, ErrEntryCap) {
		t.Fatalf("want ErrEntryCap, got %v", err)
	}
	// Overwriting an existing id at the cap is not a new entry.
	if err := be.Upsert(bg, "m", "id0", "", []float32{1}, "y", nil); err != nil {
		t.Fatalf("overwrite at cap must succeed: %v", err)
	}
}

func TestEmbeddedMetadataByteForByteAndCallerIDDistinct(t *testing.T) {
	be, file := newTestBackend(t, 100)
	meta := json.RawMessage(`{"k": "v",  "n":[1, 2]}`)
	if err := be.Upsert(bg, "m", "uuid-1", "caller-7", []float32{1, 0}, "x", meta); err != nil {
		t.Fatal(err)
	}
	hits, err := be.Search(bg, "m", []float32{1, 0}, 1)
	if err != nil || len(hits) != 1 {
		t.Fatalf("%v %+v", err, hits)
	}
	if !bytes.Equal(hits[0].Metadata, meta) {
		t.Fatalf("metadata changed: %q", hits[0].Metadata)
	}
	if bytes.Contains(hits[0].Metadata, []byte("caller-7")) {
		t.Fatal("callerID leaked into metadata")
	}
	raw, _ := os.ReadFile(file)
	var s storeFile
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	rec := s.Collections["m"].Records[0]
	if rec.CallerID != "caller-7" || rec.ID != "uuid-1" || rec.Meta != string(meta) {
		t.Fatalf("record fields wrong: %+v", rec)
	}
}

func TestEmbeddedScoresFiniteForLargeComponents(t *testing.T) {
	be, _ := newTestBackend(t, 100)
	big := float32(math.MaxFloat32)
	if err := be.Upsert(bg, "m", "a", "", []float32{big, big}, "x", nil); err != nil {
		t.Fatal(err)
	}
	hits, err := be.Search(bg, "m", []float32{big, big}, 1)
	if err != nil || len(hits) != 1 {
		t.Fatalf("%v %+v", err, hits)
	}
	if s := float64(hits[0].Score); math.IsInf(s, 0) || math.IsNaN(s) || math.Abs(s-1) > 1e-4 {
		t.Fatalf("score not finite/~1: %v", hits[0].Score)
	}
}

func TestEmbeddedTieBreakByID(t *testing.T) {
	be, _ := newTestBackend(t, 100)
	for _, id := range []string{"c", "a", "b"} {
		if err := be.Upsert(bg, "m", id, "", []float32{1, 0}, "x", nil); err != nil {
			t.Fatal(err)
		}
	}
	hits, _ := be.Search(bg, "m", []float32{1, 0}, 3)
	if len(hits) != 3 || hits[0].ID != "a" || hits[1].ID != "b" || hits[2].ID != "c" {
		t.Fatalf("ties must order by id ascending: %+v", hits)
	}
}

func TestEmbeddedSweepsStaleTemps(t *testing.T) {
	be, file := newTestBackend(t, 100)
	stale := file + ".tmp.99999.deadbeef"
	if err := os.WriteFile(stale, []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := be.Upsert(bg, "m", "a", "", []float32{1}, "x", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("stale temp not swept")
	}
}

func TestEmbeddedTwoProcessConcurrentUpsert(t *testing.T) {
	file := filepath.Join(t.TempDir(), "store.json")
	var cmds []*exec.Cmd
	var outs []*bytes.Buffer
	for _, prefix := range []string{"p1", "p2"} {
		cmd := exec.Command(os.Args[0])
		cmd.Env = append(os.Environ(), helperFileEnv+"="+file, helperPrefixEnv+"="+prefix)
		out := &bytes.Buffer{}
		cmd.Stdout, cmd.Stderr = out, out
		cmds, outs = append(cmds, cmd), append(outs, out)
	}
	for _, c := range cmds {
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
	}
	for i, c := range cmds {
		if err := c.Wait(); err != nil {
			t.Fatalf("helper %d failed: %v: %s", i, err, outs[i])
		}
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var s storeFile
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("store does not parse: %v", err)
	}
	if n := len(s.Collections["m"].Records); n != 2*helperPerProc {
		t.Fatalf("lost updates: want %d records, got %d", 2*helperPerProc, n)
	}
}
