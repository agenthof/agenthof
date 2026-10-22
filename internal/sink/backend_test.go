package sink_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/sink"
	"github.com/agenthof/agenthof/internal/sink/sinktest"
)

// The public backend end to end: NewS3 over the httptest fake — the
// composition every later consumer uses (the seal, verify, restore).

const logID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

var (
	fixedNow   = time.Date(2026, 10, 20, 9, 12, 0, 789_000_000, time.UTC)
	fixedUntil = time.Date(2033, 10, 18, 9, 12, 0, 0, time.UTC)
	segData    = []byte("{\"seq\":1}\n{\"seq\":2}\n")
	segHash    = hexSHA256(segData)
	ctx        = context.Background()
)

func hexSHA256(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func newS3(t *testing.T, f *sinktest.Fake, prefix string) *sink.S3 {
	t.Helper()
	s, err := sink.NewS3(f.URL()+prefix, sink.S3Options{Keys: f.Keys, Retention: 7 * config.RetentionYear, Now: func() time.Time { return fixedNow }})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func hostOf(f *sinktest.Fake) string {
	u, _ := url.Parse(f.URL())
	return u.Host
}

var _ sink.Backend = (*sink.S3)(nil)

func TestLocatorAndPrefix(t *testing.T) {
	f := sinktest.NewFake(t)
	s := newS3(t, f, "/agenthof/")
	if s.URL() != f.URL()+"/agenthof" {
		t.Errorf("URL = %q", s.URL())
	}
	if got := s.Prefix(logID); got != "agenthof/"+logID+"/" {
		t.Errorf("Prefix = %q", got)
	}
	want := control.SealSink{Kind: "s3-object-lock", URL: f.URL() + "/agenthof", Key: "agenthof/" + logID + "/seg-000003", Mode: "compliance", RetainUntil: fixedUntil}
	if got := s.Locator(logID, 3, fixedNow); got != want {
		t.Errorf("Locator\n got %+v\nwant %+v", got, want)
	}
	if got := newS3(t, f, "").Locator(logID, 3, fixedNow).Key; got != logID+"/seg-000003" {
		t.Errorf("no-prefix key = %q", got)
	}

	for _, c := range []struct{ url, want string }{
		{"https://h", "names no bucket"},
		{"https://h/", "names no bucket"},
		{"https://u:p@h/b", "not an absolute http(s) URL without credentials"},
		{"ftp://h/b", "not an absolute http(s) URL without credentials"},
		{"https://h/b?x=1", "not an absolute http(s) URL without credentials"},
	} {
		_, err := sink.NewS3(c.url, sink.S3Options{Keys: f.Keys, Retention: time.Hour})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("NewS3(%q) = %v, want %q", c.url, err, c.want)
		}
	}
	if _, err := sink.NewS3(f.URL(), sink.S3Options{Retention: time.Hour}); err == nil {
		t.Error("NewS3 without Keys")
	}
	if _, err := sink.NewS3(f.URL(), sink.S3Options{Keys: f.Keys}); err == nil {
		t.Error("NewS3 without Retention")
	}
}

func TestRegionDerivation(t *testing.T) {
	cases := []struct {
		url, region, want string
	}{
		{"https://s3.eu-central-1.amazonaws.com/b", "", "eu-central-1"},
		{"https://s3-ap-southeast-2.amazonaws.com/b", "", "ap-southeast-2"},
		{"https://s3.cn-north-1.amazonaws.com.cn/b", "", "cn-north-1"},
		{"https://s3.us-gov-west-1.amazonaws.com/b", "", "us-gov-west-1"},
		{"https://s3.us-iso-east-1.amazonaws.com/b", "", "us-iso-east-1"},
		{"https://s3.us-isob-east-1.amazonaws.com/b", "", "us-isob-east-1"},
		{"https://s3.amazonaws.com/b", "", "us-east-1"},
		{"https://s3.eu-central-1.amazonaws.com/b", "x-y", "x-y"},
		{"https://minio.internal:9000/b", "", "us-east-1"},
		{"http://127.0.0.1:9000/b", "", "us-east-1"},
	}
	f := sinktest.NewFake(t)
	for _, c := range cases {
		s, err := sink.NewS3(c.url, sink.S3Options{Keys: f.Keys, Retention: time.Hour, Region: c.region})
		if err != nil {
			t.Errorf("NewS3(%q): %v", c.url, err)
			continue
		}
		if got := s.Region(); got != c.want {
			t.Errorf("NewS3(%q, %q) region = %q, want %q", c.url, c.region, got, c.want)
		}
	}
	// An AWS host the rule cannot read is refused, never signed for a
	// guessed region.
	for _, u := range []string{
		"https://s3-fips.us-east-1.amazonaws.com/b",
		"https://s3.dualstack.eu-west-1.amazonaws.com/b",
		"https://bucket.s3.eu-west-1.amazonaws.com/b",
		"https://s3-external-1.amazonaws.com/b", // the legacy us-east-1 alias is not a region
		"https://s3-accelerate.amazonaws.com/b", // nor is the accelerate endpoint
	} {
		_, err := sink.NewS3(u, sink.S3Options{Keys: f.Keys, Retention: time.Hour})
		if err == nil || !strings.Contains(err.Error(), "cannot derive the signing region") {
			t.Errorf("NewS3(%q) = %v", u, err)
		}
	}
	// The fake's URL derives us-east-1, and the scope says so.
	s := newS3(t, f, "")
	if err := s.Prepare(ctx, s.Locator(logID, 1, fixedNow)); err != nil {
		t.Fatal(err)
	}
	if authz := f.Requests()[0].Header.Get("Authorization"); !strings.Contains(authz, "/20261020/us-east-1/s3/aws4_request,") {
		t.Errorf("scope in %q", authz)
	}
}

func TestPrepare(t *testing.T) {
	f := sinktest.NewFake(t)
	s := newS3(t, f, "/agenthof")
	loc := s.Locator(logID, 1, fixedNow)
	if err := s.Prepare(ctx, loc); err != nil {
		t.Errorf("Prepare: %v", err)
	}
	ops := []string{}
	for _, r := range f.Requests() {
		ops = append(ops, r.Op)
	}
	if strings.Join(ops, ",") != "GetObjectLockConfiguration,ListObjectVersions" {
		t.Errorf("preflight ops: %v", ops)
	}
	f.LockDisabled = true
	if err := s.Prepare(ctx, loc); err == nil || err.Error() != "bucket worm does not have Object Lock enabled; enable it on the bucket (versioning is required) before sink: worm" {
		t.Errorf("lock disabled: %v", err)
	}
	f.LockDisabled = false
	var se *sink.StatusError
	f.Deny = map[string]bool{"ListObjectVersions": true}
	if err := s.Prepare(ctx, loc); !errors.As(err, &se) || se.Op != "ListObjectVersions" || se.Status != 403 {
		t.Errorf("list denied: %v", err)
	}
	f.Deny = map[string]bool{"GetObjectLockConfiguration": true}
	if err := s.Prepare(ctx, loc); !errors.As(err, &se) || se.Op != "GetObjectLockConfiguration" || se.Status != 403 {
		t.Errorf("lock config denied: %v", err)
	}
	f.Deny = nil
	f.Plant(loc.Key, []byte("foreign\n"), "COMPLIANCE", fixedUntil)
	if err := s.Prepare(ctx, loc); err == nil || !strings.HasPrefix(err.Error(), "key "+loc.Key+" is occupied by a version that is not this segment") {
		t.Errorf("occupied: %v", err)
	}
}

func TestPutConfirms(t *testing.T) {
	f := sinktest.NewFake(t)
	s := newS3(t, f, "/agenthof")
	loc := s.Locator(logID, 1, fixedNow)
	rcpt, err := s.Put(ctx, loc, segData, segHash)
	if err != nil {
		t.Fatal(err)
	}
	if rcpt.VersionID != "v-1" || !rcpt.RetainUntil.Equal(loc.RetainUntil) || rcpt.Existed {
		t.Errorf("receipt: %+v", rcpt)
	}
	var put *sinktest.Request
	ops := []string{}
	for i := range f.Requests() {
		r := f.Requests()[i]
		ops = append(ops, r.Op)
		if r.Op == "PutObject" {
			put = &r
		}
	}
	if strings.Join(ops, ",") != "ListObjectVersions,PutObject,ListObjectVersions,GetObjectRetention" {
		t.Errorf("ops: %v", ops)
	}
	if put == nil {
		t.Fatal("no PUT")
	}
	m := sha256.Sum256(segData)
	want := map[string]string{
		"X-Amz-Object-Lock-Mode":              "COMPLIANCE",
		"X-Amz-Object-Lock-Retain-Until-Date": "2033-10-18T09:12:00Z",
		"X-Amz-Checksum-Sha256":               base64.StdEncoding.EncodeToString(m[:]),
		"X-Amz-Content-Sha256":                segHash,
		"Content-Type":                        "application/x-ndjson",
	}
	for k, v := range want {
		if got := put.Header.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if md := put.Header.Get("Content-Md5"); len(md) != 24 {
		t.Errorf("Content-MD5 = %q is not base64 of a raw 16-byte digest", md)
	}
	if put.RequestURI != "/worm/agenthof/"+logID+"/seg-000001" {
		t.Errorf("PUT path = %q", put.RequestURI)
	}

	// Idempotent on its own copy: no second PUT.
	rcpt, err = s.Put(ctx, loc, segData, segHash)
	if err != nil || !rcpt.Existed || rcpt.VersionID != "v-1" {
		t.Errorf("second Put: %+v %v", rcpt, err)
	}
	puts := 0
	for _, r := range f.Requests() {
		if r.Op == "PutObject" {
			puts++
		}
	}
	if puts != 1 {
		t.Errorf("%d PUTs, want 1", puts)
	}
}

func TestPutRefusesOccupiedKey(t *testing.T) {
	f := sinktest.NewFake(t)
	s := newS3(t, f, "/agenthof")
	loc := s.Locator(logID, 1, fixedNow)
	f.Plant(loc.Key, []byte("foreign\n"), "COMPLIANCE", fixedUntil)
	_, err := s.Put(ctx, loc, segData, segHash)
	if err == nil || err.Error() != "key "+loc.Key+" is occupied by a version that is not this segment; the sink cannot take this seal — choose a fresh prefix or remove the foreign object" {
		t.Errorf("err = %v", err)
	}
	// The own copy present AND a newer foreign version on top: still refused.
	f.RemoveVersions(loc.Key)
	f.Plant(loc.Key, segData, "COMPLIANCE", fixedUntil)
	f.Plant(loc.Key, bytes.ToUpper(segData), "COMPLIANCE", fixedUntil)
	if _, err := s.Put(ctx, loc, segData, segHash); err == nil || !strings.HasPrefix(err.Error(), "key "+loc.Key+" is occupied") {
		t.Errorf("own under foreign: %v", err)
	}
	for _, r := range f.Requests() {
		if r.Op == "PutObject" {
			t.Fatal("a PUT was sent to an occupied key")
		}
	}
	// A sibling key does not occupy the exact key.
	f.RemoveVersions(loc.Key)
	f.Plant(loc.Key+"x", []byte("sibling\n"), "COMPLIANCE", fixedUntil)
	if rcpt, err := s.Put(ctx, loc, segData, segHash); err != nil || rcpt.Existed {
		t.Errorf("sibling: %+v %v", rcpt, err)
	}
}

func TestPutUnconfirmed(t *testing.T) {
	t.Run("no versioning", func(t *testing.T) {
		f := sinktest.NewFake(t)
		f.NoVersioning = true
		s := newS3(t, f, "/agenthof")
		_, err := s.Put(ctx, s.Locator(logID, 1, fixedNow), segData, segHash)
		if err == nil || err.Error() != "sink answered without a version id; versioning is not enabled, so no lock was applied — nothing confirmed" {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("retention denied", func(t *testing.T) {
		f := sinktest.NewFake(t)
		f.Deny = map[string]bool{"GetObjectRetention": true}
		s := newS3(t, f, "/agenthof")
		loc := s.Locator(logID, 1, fixedNow)
		_, err := s.Put(ctx, loc, segData, segHash)
		want := "protected copy written but NOT confirmed: the credential cannot read the object's retention; grant s3:GetObjectRetention, s3:GetObject and s3:ListBucketVersions, then re-run (status 403 AccessDenied from " + hostOf(f) + " (GetObjectRetention))"
		if err == nil || err.Error() != want {
			t.Errorf("err = %v", err)
		}
		var se *sink.StatusError
		if !errors.As(err, &se) || se.Op != "GetObjectRetention" {
			t.Errorf("not wrapped: %v", err)
		}
		if vs := f.Versions(loc.Key); len(vs) != 1 || vs[0].ID != "v-1" {
			t.Errorf("the PUT did not land: %+v", vs)
		}
	})
	t.Run("governance and short date", func(t *testing.T) {
		f := sinktest.NewFake(t)
		s := newS3(t, f, "/agenthof")
		loc := s.Locator(logID, 1, fixedNow)
		f.Plant(loc.Key, segData, "GOVERNANCE", fixedUntil)
		_, err := s.Put(ctx, loc, segData, segHash)
		if err == nil || err.Error() != "oldest version v-1 at the key holds the segment but is locked GOVERNANCE until 2033-10-18T09:12:00Z, not COMPLIANCE until 2033-10-18T09:12:00Z; the sink is not what the posture claims" {
			t.Errorf("governance: %v", err)
		}
		f.RemoveVersions(loc.Key)
		f.Plant(loc.Key, segData, "COMPLIANCE", fixedUntil.Add(-time.Hour))
		_, err = s.Put(ctx, loc, segData, segHash)
		if err == nil || err.Error() != "oldest version v-2 at the key holds the segment but is locked COMPLIANCE until 2033-10-18T08:12:00Z, not COMPLIANCE until 2033-10-18T09:12:00Z; the sink is not what the posture claims" {
			t.Errorf("short date: %v", err)
		}
	})
}

func TestListVersionsSeesThroughDeleteMarker(t *testing.T) {
	f := sinktest.NewFake(t)
	s := newS3(t, f, "/agenthof")
	key := s.Prefix(logID) + "seg-000001"
	f.Plant(key, segData, "COMPLIANCE", fixedUntil)
	f.AddDeleteMarker(key)
	kv, err := s.ListVersions(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if kv.Key != key || !kv.DeleteMarker || len(kv.Versions) != 1 || kv.Versions[0].ID != "v-1" || kv.Versions[0].Size != int64(len(segData)) {
		t.Errorf("ListVersions = %+v", kv)
	}
	all, err := s.ListPrefix(ctx, s.Prefix(logID))
	if err != nil || len(all) != 1 || !all[0].DeleteMarker || all[0].Versions[0].ID != "v-1" {
		t.Errorf("ListPrefix = %+v %v", all, err)
	}
}

// TestListVersionsRoundTripsEscapedKey: a key with a space and a "+" goes
// out encoded once on the prefix, comes back through the listing's <Key>
// XML escape/unescape, and is filtered to the exact key — the sibling with
// the same prefix is not it.
func TestListVersionsRoundTripsEscapedKey(t *testing.T) {
	f := sinktest.NewFake(t)
	s := newS3(t, f, "/my prefix")
	key := "my prefix/a+b/seg-000001"
	f.Plant(key, []byte("one"), "COMPLIANCE", fixedUntil)
	f.Plant(key+"x", []byte("sibling"), "COMPLIANCE", fixedUntil)
	kv, err := s.ListVersions(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if kv.Key != key || len(kv.Versions) != 1 || kv.Versions[0].ID != "v-1" || kv.Versions[0].Size != 3 {
		t.Errorf("ListVersions = %+v", kv)
	}
	if uri := f.Requests()[0].RequestURI; !strings.Contains(uri, "prefix=my%20prefix%2Fa%2Bb%2Fseg-000001") {
		t.Errorf("listing prefix on the wire: %s", uri)
	}
	all, err := s.ListPrefix(ctx, "my prefix/a+b/")
	if err != nil || len(all) != 2 || all[0].Key != key || all[1].Key != key+"x" {
		t.Errorf("ListPrefix = %+v %v", all, err)
	}
}

func TestListPaging(t *testing.T) {
	f := sinktest.NewFake(t)
	f.PageSize = 2
	s := newS3(t, f, "/agenthof")
	p := s.Prefix(logID)
	for i := 0; i < 5; i++ {
		f.Plant(p+"seg-000001", []byte{byte(i)}, "COMPLIANCE", fixedUntil)
	}
	f.Plant(p+"seg-000002", []byte("two"), "COMPLIANCE", fixedUntil)
	all, err := s.ListPrefix(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || len(all[0].Versions) != 5 || all[0].Versions[0].ID != "v-1" || all[0].Versions[4].ID != "v-5" || all[1].Versions[0].ID != "v-6" {
		t.Errorf("ListPrefix = %+v", all)
	}
	reqs := f.Requests()
	if len(reqs) != 3 {
		t.Fatalf("%d requests, want 3 pages", len(reqs))
	}
	for _, r := range reqs[1:] {
		if !strings.Contains(r.RequestURI, "key-marker=") || !strings.Contains(r.RequestURI, "version-id-marker=") {
			t.Errorf("continuation without both markers: %s", r.RequestURI)
		}
	}
	f.NeverTerminate = true
	if _, err := s.ListPrefix(ctx, p); err == nil || !strings.Contains(err.Error(), "listing exceeded 1000 pages") {
		t.Errorf("unterminated: %v", err)
	}
}

func TestGetBounded(t *testing.T) {
	f := sinktest.NewFake(t)
	s := newS3(t, f, "/agenthof")
	key := s.Prefix(logID) + "seg-000001"
	data := []byte("hello")
	f.Plant(key, data, "COMPLIANCE", fixedUntil)
	if got, err := s.Get(ctx, key, "v-1", int64(len(data))); err != nil || !bytes.Equal(got, data) {
		t.Errorf("Get = %q %v", got, err)
	}
	if _, err := s.Get(ctx, key, "v-1", int64(len(data))-1); err == nil || err.Error() != "object "+key+" version v-1 exceeds the 4-byte bound" {
		t.Errorf("bounded: %v", err)
	}
	if r, err := s.GetRetention(ctx, key, "v-1"); err != nil || r.Mode != "COMPLIANCE" || !r.RetainUntil.Equal(fixedUntil) {
		t.Errorf("GetRetention = %+v %v", r, err)
	}
}

func TestFaultsByKnobAndNoSignedURLInErrors(t *testing.T) {
	f := sinktest.NewFake(t)
	s := newS3(t, f, "/agenthof")
	loc := s.Locator(logID, 1, fixedNow)
	var texts []string
	collect := func(err error) error {
		if err != nil {
			texts = append(texts, err.Error())
		}
		return err
	}

	f.Redirect = true
	if err := collect(s.Prepare(ctx, loc)); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Errorf("redirect: %v", err)
	}
	f.Redirect = false
	f.Oversize = true
	if _, err := s.ListPrefix(ctx, s.Prefix(logID)); collect(err) == nil || err.Error() != "response body from "+hostOf(f)+" exceeds 1 MiB" {
		t.Errorf("oversize: %v", err)
	}
	f.Oversize = false
	f.Status = map[string]int{"GetObjectLockConfiguration": 500}
	var se *sink.StatusError
	if err := collect(s.Prepare(ctx, loc)); !errors.As(err, &se) || se.Status != 500 {
		t.Errorf("500: %v", err)
	}
	f.Status = nil
	f.Skew = true
	err := collect(s.Prepare(ctx, loc))
	if !errors.Is(err, sink.ErrClockSkew) || strings.Contains(strings.ToLower(err.Error()), "credential") || strings.Contains(err.Error(), "AccessDenied") {
		t.Errorf("skew: %v", err)
	}
	f.Skew = false

	slow := sinktest.NewFake(t)
	slow.Slow = 300 * time.Millisecond
	st, err := sink.NewS3(slow.URL(), sink.S3Options{Keys: slow.Keys, Retention: time.Hour, Timeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if err := collect(st.Prepare(ctx, loc)); !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), hostOf(slow)) {
		t.Errorf("timeout: %v", err)
	}

	for _, text := range texts {
		for _, banned := range []string{"X-Amz-Signature", "Authorization", f.Secret, sinktest.Sentinel} {
			if strings.Contains(text, banned) {
				t.Errorf("error %q carries %q", text, banned)
			}
		}
	}
}
