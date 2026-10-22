package sink

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/broker"
	"github.com/agenthof/agenthof/internal/sink/sinktest"
)

// The transport (sigv4Store) against the faithful httptest fake: wire
// details — headers, encoding, paging, XML, faults — and nothing of the
// write-once rule, which the logic tests cover over an in-memory store.

var (
	fixedNow   = time.Date(2026, 10, 20, 9, 12, 0, 789_000_000, time.UTC)
	fixedUntil = time.Date(2033, 10, 18, 9, 12, 0, 0, time.UTC)
	ctx        = context.Background()
)

func newStore(t *testing.T, f *sinktest.Fake, region string) *sigv4Store {
	t.Helper()
	u, err := url.Parse(f.URL())
	if err != nil {
		t.Fatal(err)
	}
	return newSigV4Store(u.Scheme+"://"+u.Host, u.Host, f.Bucket, region, nil, f.Keys, func() time.Time { return fixedNow })
}

func hexSHA256(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestStorePutHeadersAndPath(t *testing.T) {
	f := sinktest.NewFake(t)
	s := newStore(t, f, "us-east-1")
	data := []byte("one\ntwo\n")
	id, err := s.putLocked(ctx, "my prefix/a+b/seg-000001", data, "COMPLIANCE", fixedUntil)
	if err != nil || id != "v-1" {
		t.Fatalf("putLocked: %q %v", id, err)
	}
	reqs := f.Requests()
	if len(reqs) != 1 || reqs[0].Op != "PutObject" {
		t.Fatalf("requests: %+v", reqs)
	}
	r := reqs[0]
	// The wire path is the key encoded once — and the fake's independent
	// verifier accepted the signature over it.
	if r.RequestURI != "/worm/my%20prefix/a%2Bb/seg-000001" {
		t.Errorf("request URI = %q", r.RequestURI)
	}
	want := map[string]string{
		"X-Amz-Object-Lock-Mode":              "COMPLIANCE",
		"X-Amz-Object-Lock-Retain-Until-Date": "2033-10-18T09:12:00Z",
		"Content-Md5":                         contentMD5(data),
		"X-Amz-Checksum-Sha256":               checksumSHA256(data),
		"X-Amz-Content-Sha256":                hexSHA256(data),
		"Content-Type":                        "application/x-ndjson",
		"X-Amz-Date":                          "20261020T091200Z",
	}
	for k, v := range want {
		if got := r.Header.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if len(contentMD5(data)) != 24 || len(checksumSHA256(data)) != 44 {
		t.Error("digest headers are not base64 of the raw digests")
	}
	if r.BodySHA256 != hexSHA256(data) {
		t.Error("the body sent is not the data")
	}
	if vs := f.Versions("my prefix/a+b/seg-000001"); len(vs) != 1 || vs[0].Mode != "COMPLIANCE" || !vs[0].Until.Equal(fixedUntil) {
		t.Errorf("stored: %+v", vs)
	}
}

func TestStorePutWithoutVersioning(t *testing.T) {
	f := sinktest.NewFake(t)
	f.NoVersioning = true
	id, err := newStore(t, f, "us-east-1").putLocked(ctx, "k", []byte("x"), "COMPLIANCE", fixedUntil)
	if err != nil || id != "" {
		t.Errorf("putLocked = %q, %v; want an empty id and no error", id, err)
	}
}

func TestStoreRegionScopeAndSessionToken(t *testing.T) {
	f := sinktest.NewFake(t)
	f.Region = "eu-central-1"
	s := newStore(t, f, "eu-central-1")
	s.keys = func(context.Context) (broker.KeyPair, error) {
		return broker.KeyPair{ID: f.KeyID, Secret: f.Secret, Session: "sess/tok+en=="}, nil
	}
	ok, err := s.lockEnabled(ctx)
	if err != nil || !ok {
		t.Fatalf("lockEnabled: %v %v", ok, err)
	}
	r := f.Requests()[0]
	authz := r.Header.Get("Authorization")
	if !strings.Contains(authz, "/20261020/eu-central-1/s3/aws4_request,") {
		t.Errorf("scope in %q", authz)
	}
	if !strings.Contains(authz, "x-amz-security-token") || r.Header.Get("X-Amz-Security-Token") != "sess/tok+en==" {
		t.Errorf("session token not sent and signed: %q", authz)
	}
	// A region the fake does not expect is a signature failure, reported as
	// the store's refusal — never as a credential value.
	f.Region = "us-east-1"
	_, err = s.lockEnabled(ctx)
	var se *StatusError
	if !errors.As(err, &se) || se.Status != 403 || se.Code != "SignatureDoesNotMatch" {
		t.Errorf("wrong region: %v", err)
	}
}

func TestStoreListPaging(t *testing.T) {
	f := sinktest.NewFake(t)
	f.PageSize = 2
	for i := 0; i < 5; i++ {
		f.Plant("p/a", []byte{byte(i)}, "COMPLIANCE", fixedUntil)
	}
	f.Plant("p/b", []byte("bb"), "COMPLIANCE", fixedUntil)
	f.AddDeleteMarker("p/b")
	f.Plant("q/c", []byte("c"), "COMPLIANCE", fixedUntil) // outside the prefix
	s := newStore(t, f, "us-east-1")
	got, err := s.listVersions(ctx, "p/")
	if err != nil {
		t.Fatal(err)
	}
	var seen []string
	for _, v := range got {
		kind := "V"
		if v.DeleteMarker {
			kind = "M"
		}
		seen = append(seen, kind+":"+v.Key+":"+v.ID)
	}
	want := "V:p/a:v-5 V:p/a:v-4 V:p/a:v-3 V:p/a:v-2 V:p/a:v-1 M:p/b:v-7 V:p/b:v-6"
	if strings.Join(seen, " ") != want {
		t.Errorf("entries\n got %v\nwant %v", seen, want)
	}
	if !got[0].IsLatest || got[1].IsLatest || got[5].IsLatest != true || got[6].Size != 2 || got[6].LastModified.IsZero() {
		t.Errorf("entry fields: %+v", got)
	}
	reqs := f.Requests()
	if len(reqs) != 4 {
		t.Fatalf("%d requests, want 4 pages", len(reqs))
	}
	if !strings.Contains(reqs[0].RequestURI, "prefix=p%2F") || strings.Contains(reqs[0].RequestURI, "marker") {
		t.Errorf("first page: %s", reqs[0].RequestURI)
	}
	for _, r := range reqs[1:] {
		if !strings.Contains(r.RequestURI, "key-marker=p%2F") || !strings.Contains(r.RequestURI, "version-id-marker=v-") {
			t.Errorf("continuation lacks a marker: %s", r.RequestURI)
		}
	}
	if !strings.Contains(reqs[1].RequestURI, "version-id-marker=v-4") {
		t.Errorf("second page continues after v-4: %s", reqs[1].RequestURI)
	}

	f.NeverTerminate = true
	_, err = s.listVersions(ctx, "p/")
	if err == nil || !strings.Contains(err.Error(), "listing exceeded 1000 pages") {
		t.Errorf("unterminated listing: %v", err)
	}
}

func TestStoreRetentionAndLockConfig(t *testing.T) {
	f := sinktest.NewFake(t)
	s := newStore(t, f, "us-east-1")
	id := f.Plant("k", []byte("x"), "COMPLIANCE", fixedUntil)
	l, err := s.retention(ctx, "k", id)
	if err != nil || l.Mode != "COMPLIANCE" || !l.RetainUntil.Equal(fixedUntil) {
		t.Errorf("retention: %+v %v", l, err)
	}
	if r := f.Requests()[0]; !strings.Contains(r.RequestURI, "/worm/k?retention&versionId=v-1") && !strings.Contains(r.RequestURI, "/worm/k?versionId=v-1&retention") {
		t.Errorf("retention request: %s", r.RequestURI)
	}
	plain := f.Plant("u", []byte("x"), "", time.Time{})
	if l, err := s.retention(ctx, "u", plain); err != nil || l != (lock{}) {
		t.Errorf("unlocked version: %+v %v", l, err)
	}
	_, err = s.retention(ctx, "k", "v-9")
	var se *StatusError
	if !errors.As(err, &se) || se.Status != 404 || se.Code != "NoSuchVersion" || se.Op != "GetObjectRetention" {
		t.Errorf("missing version: %v", err)
	}

	if ok, err := s.lockEnabled(ctx); err != nil || !ok {
		t.Errorf("lockEnabled: %v %v", ok, err)
	}
	f.LockDisabled = true
	if ok, err := s.lockEnabled(ctx); err != nil || ok {
		t.Errorf("lock disabled: %v %v", ok, err)
	}
	f.Deny = map[string]bool{"GetObjectLockConfiguration": true}
	_, err = s.lockEnabled(ctx)
	if !errors.As(err, &se) || se.Status != 403 || se.Code != "AccessDenied" || se.Op != "GetObjectLockConfiguration" {
		t.Errorf("denied: %v", err)
	}
}

func TestStoreGetBounded(t *testing.T) {
	f := sinktest.NewFake(t)
	s := newStore(t, f, "us-east-1")
	data := []byte("hello")
	id := f.Plant("k", data, "COMPLIANCE", fixedUntil)
	got, err := s.get(ctx, "k", id, int64(len(data)))
	if err != nil || !bytes.Equal(got, data) {
		t.Errorf("get: %q %v", got, err)
	}
	if !strings.Contains(f.Requests()[0].RequestURI, "/worm/k?versionId=v-1") {
		t.Errorf("get request: %s", f.Requests()[0].RequestURI)
	}
	if _, err := s.get(ctx, "k", id, int64(len(data))-1); !errors.Is(err, errObjectTooLarge) {
		t.Errorf("over the bound: %v", err)
	}
	if _, err := s.get(ctx, "k", id, int64(len(data))+100); err != nil {
		t.Errorf("under the bound: %v", err)
	}
}

func TestStoreFaults(t *testing.T) {
	f := sinktest.NewFake(t)
	host := strings.TrimPrefix(strings.TrimSuffix(f.URL(), "/"+f.Bucket), "http://")
	s := newStore(t, f, "us-east-1")
	var texts []string

	f.Redirect = true
	_, err := s.lockEnabled(ctx)
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Errorf("redirect: %v", err)
	}
	texts = append(texts, err.Error())
	if n := len(f.Requests()); n != 1 {
		t.Errorf("%d requests after a redirect, want 1 (never followed)", n)
	}
	f.Redirect = false

	f.Oversize = true
	_, err = s.listVersions(ctx, "")
	if err == nil || err.Error() != "response body from "+host+" exceeds 1 MiB" {
		t.Errorf("oversize: %v", err)
	}
	texts = append(texts, err.Error())
	f.Oversize = false

	// The timeout gets a fake of its own: the handler is still in flight
	// when the client gives up, so no knob on it may change afterwards.
	slow := sinktest.NewFake(t)
	slow.Slow = 300 * time.Millisecond
	tctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	_, err = newStore(t, slow, "us-east-1").lockEnabled(tctx)
	cancel()
	if err == nil || !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), strings.TrimPrefix(strings.TrimSuffix(slow.URL(), "/"+slow.Bucket), "http://")) {
		t.Errorf("slow: %v", err)
	}
	texts = append(texts, err.Error())

	f.Status = map[string]int{"GetObjectLockConfiguration": 500}
	_, err = s.lockEnabled(ctx)
	var se *StatusError
	if !errors.As(err, &se) || se.Status != 500 || se.Host != host || err.Error() != "status 500 from "+host+" (GetObjectLockConfiguration)" {
		t.Errorf("500: %v", err)
	}
	texts = append(texts, err.Error())
	f.Status = nil

	f.Skew = true
	_, err = s.lockEnabled(ctx)
	if !errors.Is(err, ErrClockSkew) || strings.Contains(strings.ToLower(err.Error()), "credential") || strings.Contains(err.Error(), "AccessDenied") {
		t.Errorf("skew: %v", err)
	}
	texts = append(texts, err.Error())
	f.Skew = false

	f.Deny = map[string]bool{"PutObject": true}
	_, err = s.putLocked(ctx, "k", []byte("x"), "COMPLIANCE", fixedUntil)
	if !errors.As(err, &se) || se.Status != 403 || se.Code != "AccessDenied" || se.Op != "PutObject" {
		t.Errorf("denied PUT: %v", err)
	}
	texts = append(texts, err.Error())
	f.Deny = nil

	// A key-pair resolver's failure is returned as is (it names a variable,
	// never a value) and nothing is sent.
	before := len(f.Requests())
	s.keys = func(context.Context) (broker.KeyPair, error) {
		return broker.KeyPair{}, errors.New("broker: environment variable WORM_KEY is not set")
	}
	_, err = s.lockEnabled(ctx)
	if err == nil || err.Error() != "broker: environment variable WORM_KEY is not set" || len(f.Requests()) != before {
		t.Errorf("keys error: %v (%d requests)", err, len(f.Requests())-before)
	}
	texts = append(texts, err.Error())

	for _, text := range texts {
		for _, banned := range []string{f.Secret, "Signature", "Authorization", "X-Amz", sinktest.Sentinel, "/worm"} {
			if strings.Contains(text, banned) {
				t.Errorf("error text %q carries %q", text, banned)
			}
		}
	}
}

func TestStoreNoAcceptEncodingSurprises(t *testing.T) {
	// The listing is read whole and decoded as XML whatever transport
	// encoding the client negotiated: a stock http.Client is enough.
	f := sinktest.NewFake(t)
	f.Plant("k", []byte("x"), "COMPLIANCE", fixedUntil)
	s := newSigV4Store(strings.TrimSuffix(f.URL(), "/"+f.Bucket), strings.TrimPrefix(strings.TrimSuffix(f.URL(), "/"+f.Bucket), "http://"), f.Bucket, "us-east-1", &http.Client{}, f.Keys, func() time.Time { return fixedNow })
	got, err := s.listVersions(ctx, "k")
	if err != nil || len(got) != 1 || got[0].ID != "v-1" {
		t.Errorf("list: %+v %v", got, err)
	}
}
