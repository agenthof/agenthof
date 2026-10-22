package sink

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/control"
)

// The sink logic over the in-memory store: the oldest-version rule, the
// read-back, prefix and key, the reader's shapes — pure, no network.

const logID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

var (
	segData = []byte("{\"seq\":1}\n{\"seq\":2}\n")
	segHash = hexSHA256(segData)
)

func newLogic(store objectStore) *S3 {
	return newS3("https://s3.eu-central-1.amazonaws.com/worm/agenthof", "worm", "agenthof", store, 7*365*24*time.Hour, time.Minute)
}

func locatorFor(s *S3) control.SealSink { return s.Locator(logID, 1, fixedNow) }

func TestLogicLocatorAndPrefix(t *testing.T) {
	s := newLogic(newMemStore())
	if s.Kind() != KindS3ObjectLock || s.URL() != "https://s3.eu-central-1.amazonaws.com/worm/agenthof" {
		t.Errorf("kind/url: %q %q", s.Kind(), s.URL())
	}
	if got := s.Prefix(logID); got != "agenthof/"+logID+"/" {
		t.Errorf("Prefix = %q", got)
	}
	loc := s.Locator(logID, 3, fixedNow)
	want := control.SealSink{Kind: "s3-object-lock", URL: s.URL(), Key: "agenthof/" + logID + "/seg-000003", Mode: "compliance", RetainUntil: fixedUntil}
	if loc != want {
		t.Errorf("Locator\n got %+v\nwant %+v", loc, want)
	}
	if loc.RetainUntil.Nanosecond() != 0 || loc.RetainUntil.Location() != time.UTC {
		t.Error("retain_until is not whole seconds UTC")
	}
	// No prefix: the key starts at the log id.
	bare := newS3("https://h/worm", "worm", "", newMemStore(), time.Hour, time.Minute)
	if got := bare.Locator(logID, 3, fixedNow).Key; got != logID+"/seg-000003" {
		t.Errorf("bare key = %q", got)
	}
	if got := bare.Prefix(logID); got != logID+"/" {
		t.Errorf("bare prefix = %q", got)
	}
}

func TestLogicPrepare(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()
	s := newLogic(m)
	loc := locatorFor(s)
	if err := s.Prepare(ctx, loc); err != nil {
		t.Errorf("empty key, lock enabled: %v", err)
	}
	if m.count("lock") != 1 || m.count("list") != 1 || !strings.HasSuffix(m.ops[1], " "+loc.Key) {
		t.Errorf("preflight ops: %v", m.ops)
	}

	m.lockOff = true
	err := s.Prepare(ctx, loc)
	if err == nil || err.Error() != "bucket worm does not have Object Lock enabled; enable it on the bucket (versioning is required) before sink: worm" {
		t.Errorf("lock off: %v", err)
	}
	m.lockOff = false

	// A marker alone does not occupy the key; any version does — Prepare
	// runs before the seal has bytes, so a fresh seal's key must be empty.
	m.marker(loc.Key)
	if err := s.Prepare(ctx, loc); err != nil {
		t.Errorf("marker only: %v", err)
	}
	m.plant(loc.Key, []byte("foreign\n"), "COMPLIANCE", fixedUntil)
	err = s.Prepare(ctx, loc)
	if err == nil || err.Error() != "key "+loc.Key+" is occupied by a version that is not this segment; the sink cannot take this seal — choose a fresh prefix or remove the foreign object" {
		t.Errorf("occupied: %v", err)
	}

	// The store's refusals pass through unchanged.
	m.fail = map[string]error{"list": &StatusError{Op: "ListObjectVersions", Status: 403, Host: "h", Code: "AccessDenied"}}
	var se *StatusError
	if err := s.Prepare(ctx, loc); !errors.As(err, &se) || se.Status != 403 {
		t.Errorf("list denied: %v", err)
	}
	m.fail = map[string]error{"lock": &StatusError{Op: "GetObjectLockConfiguration", Status: 500, Host: "h"}}
	if err := s.Prepare(ctx, loc); !errors.As(err, &se) || se.Status != 500 {
		t.Errorf("lock config failed: %v", err)
	}
}

func TestLogicPutWritesAndConfirms(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()
	s := newLogic(m)
	loc := locatorFor(s)
	rcpt, err := s.Put(ctx, loc, segData, segHash)
	if err != nil {
		t.Fatal(err)
	}
	if rcpt.VersionID != "v-1" || !rcpt.RetainUntil.Equal(fixedUntil) || rcpt.Existed {
		t.Errorf("receipt: %+v", rcpt)
	}
	v := m.objects[loc.Key][0]
	if string(v.data) != string(segData) || v.lock.Mode != "COMPLIANCE" || !v.lock.RetainUntil.Equal(fixedUntil) {
		t.Errorf("stored: %+v", v)
	}
	// list → put → retention read-back: confirmed means read.
	if want := []string{"list " + loc.Key, "put " + loc.Key, "retention " + loc.Key}; strings.Join(m.ops, ",") != strings.Join(want, ",") {
		t.Errorf("ops %v, want %v", m.ops, want)
	}

	// A second Put with the same bytes: the oldest version is the segment
	// and locked — confirmed without a PUT.
	m.ops = nil
	rcpt, err = s.Put(ctx, loc, segData, segHash)
	if err != nil {
		t.Fatal(err)
	}
	if rcpt.VersionID != "v-1" || !rcpt.Existed || !rcpt.RetainUntil.Equal(fixedUntil) {
		t.Errorf("idempotent receipt: %+v", rcpt)
	}
	if m.count("put") != 0 || m.count("get") != 1 || m.count("retention") != 1 {
		t.Errorf("idempotent ops: %v", m.ops)
	}
	// A longer lock than the locator's is fine (retention can only grow).
	m.objects[loc.Key][0].lock.RetainUntil = fixedUntil.Add(24 * time.Hour)
	if rcpt, err := s.Put(ctx, loc, segData, segHash); err != nil || !rcpt.Existed || !rcpt.RetainUntil.Equal(fixedUntil.Add(24*time.Hour)) {
		t.Errorf("longer lock: %+v %v", rcpt, err)
	}
}

func TestLogicPutRefusesOccupiedKey(t *testing.T) {
	ctx := context.Background()
	occupied := "key %s is occupied by a version that is not this segment; the sink cannot take this seal — choose a fresh prefix or remove the foreign object"
	t.Run("foreign version", func(t *testing.T) {
		m := newMemStore()
		s := newLogic(m)
		loc := locatorFor(s)
		m.plant(loc.Key, []byte("foreign\n"), "COMPLIANCE", fixedUntil)
		_, err := s.Put(ctx, loc, segData, segHash)
		if err == nil || err.Error() != strings.Replace(occupied, "%s", loc.Key, 1) {
			t.Errorf("err = %v", err)
		}
		if m.count("put") != 0 {
			t.Error("wrote on top of a foreign version")
		}
	})
	t.Run("own copy under a newer foreign version", func(t *testing.T) {
		// ANY non-matching version refuses — a forgery written over the
		// seal's copy is not confirmed just because the oldest matches.
		m := newMemStore()
		s := newLogic(m)
		loc := locatorFor(s)
		m.plant(loc.Key, segData, "COMPLIANCE", fixedUntil)
		m.plant(loc.Key, []byte("forgery, same length\n"), "COMPLIANCE", fixedUntil)
		_, err := s.Put(ctx, loc, segData, segHash)
		if err == nil || !strings.HasPrefix(err.Error(), "key "+loc.Key+" is occupied") {
			t.Errorf("err = %v", err)
		}
		if m.count("put") != 0 {
			t.Error("wrote on top")
		}
	})
	t.Run("size differs: refused without a download", func(t *testing.T) {
		m := newMemStore()
		s := newLogic(m)
		loc := locatorFor(s)
		m.plant(loc.Key, []byte("x"), "COMPLIANCE", fixedUntil)
		_, err := s.Put(ctx, loc, segData, segHash)
		if err == nil || !strings.HasPrefix(err.Error(), "key "+loc.Key+" is occupied") {
			t.Errorf("err = %v", err)
		}
		if m.count("get") != 0 || m.count("put") != 0 {
			t.Errorf("ops %v", m.ops)
		}
	})
	t.Run("exact key only", func(t *testing.T) {
		m := newMemStore()
		s := newLogic(m)
		loc := locatorFor(s)
		m.plant(loc.Key+"x", []byte("sibling\n"), "COMPLIANCE", fixedUntil)
		m.plant(loc.Key+"/child", []byte("child\n"), "COMPLIANCE", fixedUntil)
		rcpt, err := s.Put(ctx, loc, segData, segHash)
		if err != nil || rcpt.Existed || rcpt.VersionID != "v-3" {
			t.Errorf("sibling keys occupied the exact key: %+v %v", rcpt, err)
		}
	})
	t.Run("delete marker alone", func(t *testing.T) {
		m := newMemStore()
		s := newLogic(m)
		loc := locatorFor(s)
		m.marker(loc.Key)
		rcpt, err := s.Put(ctx, loc, segData, segHash)
		if err != nil || rcpt.Existed {
			t.Errorf("a marker occupied the key: %+v %v", rcpt, err)
		}
	})
}

func TestLogicPutUnconfirmed(t *testing.T) {
	ctx := context.Background()
	t.Run("no version id", func(t *testing.T) {
		m := newMemStore()
		m.versionOff = true
		s := newLogic(m)
		_, err := s.Put(ctx, locatorFor(s), segData, segHash)
		if err == nil || err.Error() != "sink answered without a version id; versioning is not enabled, so no lock was applied — nothing confirmed" {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("retention denied after the PUT", func(t *testing.T) {
		m := newMemStore()
		m.fail = map[string]error{"retention": &StatusError{Op: "GetObjectRetention", Status: 403, Host: "127.0.0.1:1", Code: "AccessDenied"}}
		s := newLogic(m)
		loc := locatorFor(s)
		_, err := s.Put(ctx, loc, segData, segHash)
		want := "protected copy written but NOT confirmed: the credential cannot read the object's retention; grant s3:GetObjectRetention, s3:GetObject and s3:ListBucketVersions, then re-run (status 403 from 127.0.0.1:1 (GetObjectRetention))"
		if err == nil || err.Error() != want {
			t.Errorf("err = %v", err)
		}
		var se *StatusError
		if !errors.As(err, &se) || se.Op != "GetObjectRetention" {
			t.Errorf("the StatusError is not wrapped: %v", err)
		}
		if len(m.objects[loc.Key]) != 1 {
			t.Error("the PUT did not land")
		}
	})
	t.Run("retention failed otherwise", func(t *testing.T) {
		m := newMemStore()
		m.fail = map[string]error{"retention": errors.New("h: connection reset")}
		s := newLogic(m)
		_, err := s.Put(ctx, locatorFor(s), segData, segHash)
		if err == nil || err.Error() != "protected copy written but NOT confirmed: h: connection reset" {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("governance", func(t *testing.T) {
		m := newMemStore()
		s := newLogic(m)
		loc := locatorFor(s)
		m.plant(loc.Key, segData, "GOVERNANCE", fixedUntil)
		_, err := s.Put(ctx, loc, segData, segHash)
		want := "oldest version v-1 at the key holds the segment but is locked GOVERNANCE until 2033-10-18T09:12:00Z, not COMPLIANCE until 2033-10-18T09:12:00Z; the sink is not what the posture claims"
		if err == nil || err.Error() != want {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("short date", func(t *testing.T) {
		m := newMemStore()
		s := newLogic(m)
		loc := locatorFor(s)
		m.plant(loc.Key, segData, "COMPLIANCE", fixedUntil.Add(-time.Second))
		_, err := s.Put(ctx, loc, segData, segHash)
		want := "oldest version v-1 at the key holds the segment but is locked COMPLIANCE until 2033-10-18T09:11:59Z, not COMPLIANCE until 2033-10-18T09:12:00Z; the sink is not what the posture claims"
		if err == nil || err.Error() != want {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("unlocked", func(t *testing.T) {
		m := newMemStore()
		s := newLogic(m)
		loc := locatorFor(s)
		m.plant(loc.Key, segData, "", time.Time{})
		_, err := s.Put(ctx, loc, segData, segHash)
		want := "oldest version v-1 at the key holds the segment but is not locked, not COMPLIANCE until 2033-10-18T09:12:00Z; the sink is not what the posture claims"
		if err == nil || err.Error() != want {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("weaker lock on the fresh write", func(t *testing.T) {
		// The store wrote, versioned, but applied a lesser lock than asked:
		// the same under-locked verdict, on the version just written.
		m := newMemStore()
		s := newLogic(&downgradingStore{memStore: m})
		loc := locatorFor(s)
		_, err := s.Put(ctx, loc, segData, segHash)
		if err == nil || !strings.HasPrefix(err.Error(), "oldest version v-1 at the key holds the segment but is locked GOVERNANCE until ") || !strings.Contains(err.Error(), ", not COMPLIANCE until ") {
			t.Errorf("err = %v", err)
		}
		if m.count("put") != 1 || m.count("retention") != 1 {
			t.Errorf("ops %v", m.ops)
		}
	})
	t.Run("digest mismatch is a caller fault", func(t *testing.T) {
		m := newMemStore()
		s := newLogic(m)
		_, err := s.Put(ctx, locatorFor(s), segData, strings.Repeat("0", 64))
		if err == nil || !strings.Contains(err.Error(), "does not match") || m.count("put") != 0 {
			t.Errorf("err = %v, ops %v", err, m.ops)
		}
	})
	t.Run("mode other than compliance is never written", func(t *testing.T) {
		m := newMemStore()
		s := newLogic(m)
		loc := locatorFor(s)
		loc.Mode = "governance"
		_, err := s.Put(ctx, loc, segData, segHash)
		if err == nil || !strings.Contains(err.Error(), "compliance") || m.count("put") != 0 {
			t.Errorf("err = %v, ops %v", err, m.ops)
		}
	})
}

// downgradingStore applies GOVERNANCE whatever mode is asked.
type downgradingStore struct{ *memStore }

func (d *downgradingStore) putLocked(ctx context.Context, key string, body []byte, _ string, until time.Time) (string, error) {
	return d.memStore.putLocked(ctx, key, body, "GOVERNANCE", until)
}

func TestLogicReader(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()
	s := newLogic(m)
	p := s.Prefix(logID)
	k1, k2 := p+"seg-000001", p+"seg-000002"
	m.plant(k1, []byte("a1"), "COMPLIANCE", fixedUntil)
	m.plant(k1, []byte("a2x"), "COMPLIANCE", fixedUntil)
	m.marker(k1)
	m.plant(k2, []byte("b1"), "", time.Time{})
	m.plant(p+"seg-000001x", []byte("sib"), "COMPLIANCE", fixedUntil)

	kv, err := s.ListVersions(ctx, k1)
	if err != nil {
		t.Fatal(err)
	}
	if kv.Key != k1 || !kv.DeleteMarker || len(kv.Versions) != 2 || kv.Versions[0].ID != "v-1" || kv.Versions[1].ID != "v-2" {
		t.Errorf("ListVersions = %+v (want oldest first, marker seen, sibling excluded)", kv)
	}
	if v := kv.Versions[1]; v.Size != 3 || v.IsLatest || v.LastModified.IsZero() {
		t.Errorf("version fields: %+v", v)
	}
	if kv.Versions[0].IsLatest {
		t.Error("the oldest is not the latest")
	}

	all, err := s.ListPrefix(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 || all[0].Key != k1 || !all[0].DeleteMarker || all[0].Versions[0].ID != "v-1" || all[1].Key != k1+"x" || all[2].Key != k2 || all[2].DeleteMarker {
		t.Errorf("ListPrefix = %+v", all)
	}
	if empty, err := s.ListPrefix(ctx, "nothing/"); err != nil || len(empty) != 0 {
		t.Errorf("empty prefix: %+v %v", empty, err)
	}

	r, err := s.GetRetention(ctx, k1, "v-1")
	if err != nil || r != (control.SinkRetention{Mode: "COMPLIANCE", RetainUntil: fixedUntil}) {
		t.Errorf("GetRetention = %+v %v", r, err)
	}
	if r, err := s.GetRetention(ctx, k2, "v-4"); err != nil || r != (control.SinkRetention{}) {
		t.Errorf("unlocked GetRetention = %+v %v", r, err)
	}

	if b, err := s.Get(ctx, k1, "v-2", 3); err != nil || string(b) != "a2x" {
		t.Errorf("Get = %q %v", b, err)
	}
	_, err = s.Get(ctx, k1, "v-2", 2)
	if err == nil || err.Error() != "object "+k1+" version v-2 exceeds the 2-byte bound" {
		t.Errorf("bounded Get: %v", err)
	}
	var se *StatusError
	if _, err := s.Get(ctx, k1, "v-99", 10); !errors.As(err, &se) || se.Status != 404 {
		t.Errorf("missing version: %v", err)
	}
}

func TestLogicTimeoutPerCall(t *testing.T) {
	b := &blockingStore{}
	s := newS3("https://h/worm", "worm", "", b, time.Hour, 20*time.Millisecond)
	start := time.Now()
	err := s.Prepare(context.Background(), s.Locator(logID, 1, fixedNow))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Error("the timeout did not bound the call")
	}
}
