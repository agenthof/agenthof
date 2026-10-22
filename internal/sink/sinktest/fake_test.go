package sinktest_test

import (
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // the transport header S3 requires on a lock PUT
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/sink/sinktest"
)

var until = time.Date(2033, 10, 18, 9, 12, 0, 0, time.UTC)

// do sends one request to the fake, signed by its own helper unless unsigned,
// and returns the status, the headers and the body.
func do(t *testing.T, f *sinktest.Fake, method, target string, body []byte, hdr map[string]string, unsigned bool) (int, http.Header, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, f.URL()+target, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if !unsigned {
		f.Sign(req, body)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, resp.Header, raw
}

// lockPut is a PUT with every header the real client sends.
func lockPut(t *testing.T, f *sinktest.Fake, key string, data []byte, tweak func(map[string]string)) (int, http.Header, []byte) {
	t.Helper()
	m := md5.Sum(data) //nolint:gosec // see the import
	s := sha256.Sum256(data)
	hdr := map[string]string{
		"X-Amz-Object-Lock-Mode":              "COMPLIANCE",
		"X-Amz-Object-Lock-Retain-Until-Date": until.Format(time.RFC3339),
		"Content-MD5":                         base64.StdEncoding.EncodeToString(m[:]),
		"X-Amz-Checksum-Sha256":               base64.StdEncoding.EncodeToString(s[:]),
		"Content-Type":                        "application/x-ndjson",
	}
	if tweak != nil {
		tweak(hdr)
	}
	return do(t, f, http.MethodPut, "/"+key, data, hdr, false)
}

func code(t *testing.T, body []byte) string {
	t.Helper()
	var e struct {
		Code string `xml:"Code"`
	}
	if err := xml.Unmarshal(body, &e); err != nil {
		t.Fatalf("error body %q: %v", body, err)
	}
	return e.Code
}

func TestFakeVersioningAndLock(t *testing.T) {
	f := sinktest.NewFake(t)
	key := "p/seg-000001"
	data := []byte("one\n")

	st, h, body := lockPut(t, f, key, data, nil)
	if st != 200 || h.Get("x-amz-version-id") != "v-1" {
		t.Fatalf("first PUT: %d %q %s", st, h.Get("x-amz-version-id"), body)
	}
	if st, h, _ := lockPut(t, f, key, data, nil); st != 200 || h.Get("x-amz-version-id") != "v-2" {
		t.Fatalf("second PUT: %d %q", st, h.Get("x-amz-version-id"))
	}
	st, _, body = do(t, f, http.MethodGet, "?versions&prefix=p/", nil, nil, false)
	if st != 200 {
		t.Fatalf("list: %d %s", st, body)
	}
	if !strings.Contains(string(body), `xmlns="http://s3.amazonaws.com/doc/2006-03-01/"`) {
		t.Errorf("listing lacks the 2006-03-01 namespace: %s", body)
	}
	if i2, i1 := strings.Index(string(body), "<VersionId>v-2</VersionId>"), strings.Index(string(body), "<VersionId>v-1</VersionId>"); i2 < 0 || i1 < 0 || i2 > i1 {
		t.Errorf("listing is not newest first: %s", body)
	}
	if !strings.Contains(string(body), "<IsLatest>true</IsLatest>") {
		t.Errorf("no IsLatest: %s", body)
	}

	// A plain DELETE on a locked key adds a marker; nothing is removed.
	if st, h, _ := do(t, f, http.MethodDelete, "/"+key, nil, nil, false); st != 204 || h.Get("x-amz-delete-marker") != "true" {
		t.Fatalf("delete: %d", st)
	}
	vs := f.Versions(key)
	if len(vs) != 3 || !vs[0].Marker || vs[1].ID != "v-2" || vs[2].ID != "v-1" {
		t.Fatalf("versions after marker: %+v", vs)
	}
	_, _, body = do(t, f, http.MethodGet, "?versions&prefix="+key, nil, nil, false)
	if !strings.Contains(string(body), "<DeleteMarker>") || !strings.Contains(string(body), "<VersionId>v-1</VersionId>") {
		t.Errorf("listing hides the marker or a version: %s", body)
	}
	// A plain GET sees the marker (404); a versioned GET sees through it.
	if st, _, body := do(t, f, http.MethodGet, "/"+key, nil, nil, false); st != 404 || code(t, body) != "NoSuchKey" {
		t.Errorf("plain GET under a marker: %d %s", st, body)
	}
	if st, _, body := do(t, f, http.MethodGet, "/"+key+"?versionId=v-1", nil, nil, false); st != 200 || !bytes.Equal(body, data) {
		t.Errorf("versioned GET: %d %q", st, body)
	}

	// A COMPLIANCE version refuses a versioned delete.
	if st, _, body := do(t, f, http.MethodDelete, "/"+key+"?versionId=v-1", nil, nil, false); st != 403 || code(t, body) != "AccessDenied" {
		t.Errorf("delete of a locked version: %d %s", st, body)
	}
	if len(f.Versions(key)) != 3 {
		t.Error("a locked version was removed")
	}

	// Retention reads back as written, in AWS's millisecond form.
	st, _, body = do(t, f, http.MethodGet, "/"+key+"?retention&versionId=v-1", nil, nil, false)
	if st != 200 || !strings.Contains(string(body), "<Mode>COMPLIANCE</Mode>") || !strings.Contains(string(body), "<RetainUntilDate>2033-10-18T09:12:00.000Z</RetainUntilDate>") {
		t.Errorf("retention: %d %s", st, body)
	}
	// An unlocked version has no retention configuration.
	id := f.Plant("p/plain", []byte("x"), "", time.Time{})
	if st, _, body := do(t, f, http.MethodGet, "/p/plain?retention&versionId="+id, nil, nil, false); st != 404 || code(t, body) != "NoSuchObjectLockConfiguration" {
		t.Errorf("retention of an unlocked version: %d %s", st, body)
	}

	// Object Lock is enabled on the bucket.
	if st, _, body := do(t, f, http.MethodGet, "?object-lock", nil, nil, false); st != 200 || !strings.Contains(string(body), "<ObjectLockEnabled>Enabled</ObjectLockEnabled>") {
		t.Errorf("lock config: %d %s", st, body)
	}
}

func TestFakeRefusals(t *testing.T) {
	t.Run("lock disabled", func(t *testing.T) {
		f := sinktest.NewFake(t)
		f.LockDisabled = true
		if st, _, body := lockPut(t, f, "k", []byte("x"), nil); st != 400 || code(t, body) != "InvalidRequest" {
			t.Errorf("PUT with lock headers: %d %s", st, body)
		}
		if st, _, body := do(t, f, http.MethodGet, "?object-lock", nil, nil, false); st != 404 || code(t, body) != "ObjectLockConfigurationNotFoundError" {
			t.Errorf("lock config: %d %s", st, body)
		}
	})
	t.Run("no versioning", func(t *testing.T) {
		f := sinktest.NewFake(t)
		f.NoVersioning = true
		st, h, _ := lockPut(t, f, "k", []byte("x"), nil)
		if st != 200 || h.Get("x-amz-version-id") != "" {
			t.Errorf("PUT: %d %q", st, h.Get("x-amz-version-id"))
		}
		if vs := f.Versions("k"); len(vs) != 1 || vs[0].Mode != "" {
			t.Errorf("a lock was applied without versioning: %+v", vs)
		}
	})
	t.Run("bad digests", func(t *testing.T) {
		f := sinktest.NewFake(t)
		if st, _, body := lockPut(t, f, "k", []byte("x"), func(h map[string]string) { h["Content-MD5"] = "AAAAAAAAAAAAAAAAAAAAAA==" }); st != 400 || code(t, body) != "BadDigest" {
			t.Errorf("bad Content-MD5: %d %s", st, body)
		}
		if st, _, body := lockPut(t, f, "k", []byte("x"), func(h map[string]string) { h["X-Amz-Checksum-Sha256"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" }); st != 400 || code(t, body) != "InvalidRequest" {
			t.Errorf("bad checksum: %d %s", st, body)
		}
		if st, _, body := lockPut(t, f, "k", []byte("x"), func(h map[string]string) { delete(h, "Content-MD5") }); st != 400 || code(t, body) != "InvalidRequest" {
			t.Errorf("lock PUT without Content-MD5: %d %s", st, body)
		}
		if len(f.Versions("k")) != 0 {
			t.Error("a refused PUT stored a version")
		}
	})
	t.Run("signature", func(t *testing.T) {
		f := sinktest.NewFake(t)
		if st, _, body := do(t, f, http.MethodGet, "?object-lock", nil, nil, true); st != 403 || code(t, body) != "SignatureDoesNotMatch" {
			t.Errorf("unsigned: %d %s", st, body)
		}
		// Signed, then tampered: a path the signature does not cover.
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, f.URL()+"/a", nil)
		f.Sign(req, nil)
		req.URL.Path = "/" + f.Bucket + "/b"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 403 || code(t, raw) != "SignatureDoesNotMatch" {
			t.Errorf("tampered: %d %s", resp.StatusCode, raw)
		}
		// A payload hash that is not the body's (signed as such, so the
		// signature itself is fine — the hash check must catch it).
		req, _ = http.NewRequestWithContext(context.Background(), http.MethodPut, f.URL()+"/k", bytes.NewReader([]byte("x")))
		req.Header.Set("X-Amz-Content-Sha256", hex.EncodeToString(make([]byte, 32)))
		f.Sign(req, nil)
		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 403 || code(t, raw) != "SignatureDoesNotMatch" {
			t.Errorf("wrong payload hash: %d %s", resp.StatusCode, raw)
		}
	})
	t.Run("knobs", func(t *testing.T) {
		f := sinktest.NewFake(t)
		f.Deny = map[string]bool{"GetObjectLockConfiguration": true}
		if st, _, body := do(t, f, http.MethodGet, "?object-lock", nil, nil, false); st != 403 || code(t, body) != "AccessDenied" {
			t.Errorf("denied: %d %s", st, body)
		}
		f.Deny = nil
		f.Status = map[string]int{"GetObjectLockConfiguration": 500}
		if st, _, _ := do(t, f, http.MethodGet, "?object-lock", nil, nil, false); st != 500 {
			t.Errorf("forced status: %d", st)
		}
		f.Status = nil
		f.Skew = true
		if st, _, body := do(t, f, http.MethodGet, "?object-lock", nil, nil, false); st != 403 || code(t, body) != "RequestTimeTooSkewed" {
			t.Errorf("skew: %d %s", st, body)
		}
		f.Skew = false
		f.Oversize = true
		if _, _, body := do(t, f, http.MethodGet, "?versions", nil, nil, false); len(body) <= 1<<20 {
			t.Errorf("oversize listing is %d bytes", len(body))
		}
		f.Oversize = false
		f.Redirect = true
		c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, f.URL()+"?object-lock", nil)
		f.Sign(req, nil)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 302 || !strings.Contains(resp.Header.Get("Location"), sinktest.Sentinel) {
			t.Errorf("redirect: %d %q", resp.StatusCode, resp.Header.Get("Location"))
		}
		f.Redirect = false
		if got := f.Requests(); len(got) == 0 || got[0].Op != "GetObjectLockConfiguration" || got[0].Method != http.MethodGet {
			t.Errorf("requests: %+v", got)
		}
	})
}

var markerRE = regexp.MustCompile(`<(Version|DeleteMarker)><Key>([^<]*)</Key><VersionId>([^<]*)</VersionId>`)

func TestFakePaging(t *testing.T) {
	f := sinktest.NewFake(t)
	f.PageSize = 2
	for i := 0; i < 5; i++ {
		f.Plant("p/a", []byte{byte(i)}, "COMPLIANCE", until)
	}
	f.Plant("p/b", []byte("b"), "COMPLIANCE", until)
	f.AddDeleteMarker("p/b")

	type page struct {
		IsTruncated         bool   `xml:"IsTruncated"`
		NextKeyMarker       string `xml:"NextKeyMarker"`
		NextVersionIDMarker string `xml:"NextVersionIdMarker"`
	}
	var seen []string
	km, vm := "", ""
	for n := 0; ; n++ {
		target := "?versions&prefix=p/"
		if km != "" {
			target += "&key-marker=" + km + "&version-id-marker=" + vm
		}
		st, _, body := do(t, f, http.MethodGet, target, nil, nil, false)
		if st != 200 {
			t.Fatalf("page %d: %d %s", n, st, body)
		}
		for _, m := range markerRE.FindAllStringSubmatch(string(body), -1) {
			seen = append(seen, m[1]+":"+m[2]+":"+m[3])
		}
		var p page
		if err := xml.Unmarshal(body, &p); err != nil {
			t.Fatal(err)
		}
		if !p.IsTruncated {
			if n != 3 {
				t.Errorf("walked %d pages, want 4", n+1)
			}
			break
		}
		km, vm = p.NextKeyMarker, p.NextVersionIDMarker
		if n > 10 {
			t.Fatal("paging never terminates")
		}
	}
	want := []string{"Version:p/a:v-5", "Version:p/a:v-4", "Version:p/a:v-3", "Version:p/a:v-2", "Version:p/a:v-1", "DeleteMarker:p/b:v-7", "Version:p/b:v-6"}
	if strings.Join(seen, " ") != strings.Join(want, " ") {
		t.Errorf("entries\n got %v\nwant %v", seen, want)
	}
	reqs := f.Requests()
	if len(reqs) != 4 || !strings.Contains(reqs[1].RequestURI, "key-marker=p/a") || !strings.Contains(reqs[1].RequestURI, "version-id-marker=v-4") {
		t.Errorf("second page request: %+v", reqs)
	}

	f.NeverTerminate = true
	_, _, body := do(t, f, http.MethodGet, "?versions&prefix=p/&key-marker=p%2Fb&version-id-marker=v-6", nil, nil, false)
	if !strings.Contains(string(body), "<IsTruncated>true</IsTruncated>") {
		t.Errorf("NeverTerminate did not force truncation: %s", body)
	}
}

func TestFakePlantAndRemove(t *testing.T) {
	f := sinktest.NewFake(t)
	id := f.Plant("k", []byte("x"), "GOVERNANCE", until)
	if id != "v-1" || f.Versions("k")[0].Mode != "GOVERNANCE" {
		t.Fatalf("plant: %q %+v", id, f.Versions("k"))
	}
	f.RemoveVersion("k", id)
	if len(f.Versions("k")) != 0 {
		t.Error("RemoveVersion kept the version")
	}
	f.Plant("k", []byte("y"), "COMPLIANCE", until)
	f.Plant("k", []byte("z"), "COMPLIANCE", until)
	f.RemoveVersions("k")
	if len(f.Versions("k")) != 0 {
		t.Error("RemoveVersions kept a version")
	}
	// The credential the fake expects.
	kp, err := f.Keys(context.Background())
	if err != nil || kp.ID != f.KeyID || kp.Secret != f.Secret {
		t.Errorf("Keys: %v", err)
	}
}
