// Package sinktest holds Fake, an httptest fake of the five S3 operations
// the worm sink uses, faithful in the ways a hand-rolled client is wrong:
// it verifies SigV4 signatures with its own canonicalization of the request
// AS RECEIVED, checks Content-MD5, x-amz-checksum-sha256 and the payload
// hash against the body, refuses a lock whose retain-until date is not in
// the future, keeps versions newest first with delete markers, pages
// ListObjectVersions with both markers, and answers each endpoint's XML in
// the 2006-03-01 namespace. Imported only by tests, so it never
// compiles into the binary (the anchortest precedent).
package sinktest

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // the transport header S3 requires on a lock PUT
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/broker"
)

// Sentinel is placed in every failure body and Location header the fake
// emits, so a test can assert a client never echoes response text.
const Sentinel = "SENTINEL-NEVER-ON-A-RECORD"

// s3NS is the namespace of every S3 response document.
const s3NS = "http://s3.amazonaws.com/doc/2006-03-01/"

// Planted is one version at a key as the fake holds it.
type Planted struct {
	ID           string
	Data         []byte
	Mode         string // "COMPLIANCE", "GOVERNANCE" or ""
	Until        time.Time
	Marker       bool
	LastModified time.Time
}

// Request is one request the fake received, by S3 operation name.
type Request struct {
	Op         string
	Method     string
	RequestURI string
	Header     http.Header
	BodySHA256 string
}

// Fake is the S3 Object Lock fake. The knobs are plain fields, set before
// the request they should shape; the handler reads them under the fake's
// lock, so a test sets them between requests, never during one (a request
// the client timed out on is still in flight: give a timeout its own fake).
type Fake struct {
	Bucket        string // "worm"
	KeyID, Secret string // "AKIDFAKE", "fake-secret" — what Keys presents and the scope must name
	Region        string // "us-east-1" — what the credential scope must name
	LockDisabled  bool   // the bucket has no Object Lock configuration
	NoVersioning  bool   // a PUT answers without a version id and applies no lock
	// Deny answers 403 AccessDenied for an operation: "PutObject",
	// "GetObject", "GetObjectRetention", "ListObjectVersions",
	// "GetObjectLockConfiguration", "DeleteObject". Status forces a status
	// (500 …) for one.
	Deny   map[string]bool
	Status map[string]int
	// Redirect answers one 302 to another host; Oversize pads the listing
	// past 1 MiB; Skew answers 403 RequestTimeTooSkewed; NeverTerminate
	// makes every listing page claim IsTruncated.
	Redirect, Oversize, Skew, NeverTerminate bool
	Slow                                     time.Duration // delay before every response
	PageSize                                 int           // ListObjectVersions max-keys (default 1000)

	srv *httptest.Server

	mu       sync.Mutex
	next     int
	objects  map[string][]Planted // newest first
	requests []Request
}

// NewFake starts the fake; t.Cleanup stops it.
func NewFake(t testing.TB) *Fake {
	t.Helper()
	f := &Fake{Bucket: "worm", KeyID: "AKIDFAKE", Secret: "fake-secret", Region: "us-east-1", objects: map[string][]Planted{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

// URL is the server's URL plus the bucket: a sink_backend.url for tests
// (append "/<prefix>" freely).
func (f *Fake) URL() string { return f.srv.URL + "/" + f.Bucket }

// Keys is the key-pair resolver a client under test uses.
func (f *Fake) Keys(context.Context) (broker.KeyPair, error) {
	return broker.KeyPair{ID: f.KeyID, Secret: f.Secret}, nil
}

// Plant writes a version outside any seal — a foreign object, an earlier
// copy, a wrong lock — and returns its id.
func (f *Fake) Plant(key string, data []byte, mode string, until time.Time) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.add(key, Planted{Data: bytes.Clone(data), Mode: mode, Until: until})
}

// AddDeleteMarker puts a delete marker on key, as a plain DeleteObject does.
func (f *Fake) AddDeleteMarker(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.add(key, Planted{Marker: true})
}

// Versions lists key's versions newest first, markers included.
func (f *Fake) Versions(key string) []Planted {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Planted, len(f.objects[key]))
	copy(out, f.objects[key])
	return out
}

// RemoveVersion simulates loss of one version (the fake is not S3; a
// compliance lock refuses this over the wire). RemoveVersions removes all.
func (f *Fake) RemoveVersion(key, id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	vs := f.objects[key]
	for i, v := range vs {
		if v.ID == id {
			f.objects[key] = append(vs[:i:i], vs[i+1:]...)
			return
		}
	}
}

// RemoveVersions removes every version and marker at key.
func (f *Fake) RemoveVersions(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.objects, key)
}

// Requests returns every request received so far, in order.
func (f *Fake) Requests() []Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Request, len(f.requests))
	copy(out, f.requests)
	return out
}

// add mints the next version id and prepends p at key. Caller holds mu.
func (f *Fake) add(key string, p Planted) string {
	f.next++
	p.ID = "v-" + strconv.Itoa(f.next)
	p.LastModified = time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC).Add(time.Duration(f.next) * time.Second)
	f.objects[key] = append([]Planted{p}, f.objects[key]...)
	return p.ID
}

// Sign signs req the way the fake verifies: SigV4 over every header on the
// request plus host, under the fake's key and region, with the payload hash
// of body. For tests that talk to the fake directly.
func (f *Fake) Sign(req *http.Request, body []byte) {
	sum := sha256.Sum256(body)
	payload := hex.EncodeToString(sum[:])
	req.Header.Set("X-Amz-Content-Sha256", payload)
	now := time.Now().UTC()
	req.Header.Set("X-Amz-Date", now.Format("20060102T150405Z"))
	names := []string{"host"}
	for n := range req.Header {
		names = append(names, strings.ToLower(n))
	}
	sort.Strings(names)
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	creq := canonical(req.Method, req.URL.Path, req.URL.RawQuery, host, req.Header, names, payload)
	scope := now.Format("20060102") + "/" + f.Region + "/s3/aws4_request"
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+f.KeyID+"/"+scope+", SignedHeaders="+strings.Join(names, ";")+", Signature="+signature(f.Secret, now.Format("20060102"), f.Region, now.Format("20060102T150405Z"), scope, creq))
}

// serve is the handler: record, delay, the global knobs, the signature, then
// the operation.
func (f *Fake) serve(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, Sentinel, http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	slow := f.Slow
	f.mu.Unlock()
	if slow > 0 {
		// A client that gives up leaves this handler in flight until the
		// delay passes or its connection closes; a test that drives a
		// timeout uses a fake of its own and sets no knob afterwards.
		select {
		case <-time.After(slow):
		case <-r.Context().Done():
			return
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	op, key, bucketOK := f.classify(r)
	sum := sha256.Sum256(body)
	f.requests = append(f.requests, Request{Op: op, Method: r.Method, RequestURI: r.RequestURI, Header: r.Header.Clone(), BodySHA256: hex.EncodeToString(sum[:])})
	if f.Redirect {
		w.Header().Set("Location", "http://other.invalid/"+Sentinel)
		w.WriteHeader(http.StatusFound)
		return
	}
	if f.Skew {
		f.fail(w, http.StatusForbidden, "RequestTimeTooSkewed")
		return
	}
	if code := f.verifySignature(r, body); code != "" {
		f.fail(w, http.StatusForbidden, code)
		return
	}
	if st := f.Status[op]; st != 0 {
		w.WriteHeader(st)
		_, _ = io.WriteString(w, Sentinel)
		return
	}
	if f.Deny[op] {
		f.fail(w, http.StatusForbidden, "AccessDenied")
		return
	}
	if !bucketOK {
		f.fail(w, http.StatusNotFound, "NoSuchBucket")
		return
	}
	switch op {
	case "GetObjectLockConfiguration":
		f.lockConfig(w)
	case "ListObjectVersions":
		f.list(w, r.URL.Query())
	case "PutObject":
		f.put(w, r, key, body)
	case "GetObject":
		f.get(w, key, r.URL.Query().Get("versionId"))
	case "GetObjectRetention":
		f.retention(w, key, r.URL.Query().Get("versionId"))
	case "DeleteObject":
		f.del(w, r, key, r.URL.Query().Get("versionId"))
	default:
		f.fail(w, http.StatusMethodNotAllowed, "MethodNotAllowed")
	}
}

// classify names the S3 operation a request is, the key it names, and
// whether the path's first segment is this fake's bucket.
func (f *Fake) classify(r *http.Request) (op, key string, bucketOK bool) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	bucket, rest, _ := strings.Cut(path, "/")
	bucketOK = bucket == f.Bucket
	q := r.URL.Query()
	switch {
	case rest == "" && r.Method == http.MethodGet && q.Has("object-lock"):
		op = "GetObjectLockConfiguration"
	case rest == "" && r.Method == http.MethodGet && q.Has("versions"):
		op = "ListObjectVersions"
	case rest != "" && r.Method == http.MethodGet && q.Has("retention"):
		op = "GetObjectRetention"
	case rest != "" && r.Method == http.MethodGet:
		op = "GetObject"
	case rest != "" && r.Method == http.MethodPut:
		op = "PutObject"
	case rest != "" && r.Method == http.MethodDelete:
		op = "DeleteObject"
	default:
		op = "Unknown"
	}
	return op, rest, bucketOK
}

// fail writes an S3 error document with the given code and the sentinel in
// its message.
func (f *Fake) fail(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>%s</Message><Resource>/</Resource><RequestId>%s</RequestId></Error>`, code, Sentinel, Sentinel)
}

func (f *Fake) lockConfig(w http.ResponseWriter) {
	if f.LockDisabled {
		f.fail(w, http.StatusNotFound, "ObjectLockConfigurationNotFoundError")
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><ObjectLockConfiguration xmlns="%s"><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>`, s3NS)
}

// entry is one listing line: a version or a marker, in S3's order (keys
// ascending, newest first within a key).
type entry struct {
	key string
	p   Planted
}

func (f *Fake) list(w http.ResponseWriter, q url.Values) {
	prefix, keyMarker, verMarker := q.Get("prefix"), q.Get("key-marker"), q.Get("version-id-marker")
	keys := make([]string, 0, len(f.objects))
	for k := range f.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var all []entry
	for _, k := range keys {
		for _, p := range f.objects[k] {
			all = append(all, entry{k, p})
		}
	}
	// Continue after the marker pair: everything up to and including the
	// named (key, version) is skipped; a key-marker alone skips the key.
	if keyMarker != "" {
		start := len(all)
		for i, e := range all {
			if e.key > keyMarker {
				start = i
				break
			}
			if e.key == keyMarker && verMarker != "" && e.p.ID == verMarker {
				start = i + 1
				break
			}
		}
		all = all[start:]
	}
	size := f.PageSize
	if size <= 0 {
		size = 1000
	}
	truncated := len(all) > size || f.NeverTerminate
	if len(all) > size {
		all = all[:size]
	}
	var b strings.Builder
	fmt.Fprintf(&b, `<?xml version="1.0" encoding="UTF-8"?><ListVersionsResult xmlns="%s"><Name>%s</Name><Prefix>%s</Prefix><KeyMarker>%s</KeyMarker><VersionIdMarker>%s</VersionIdMarker><MaxKeys>%d</MaxKeys><IsTruncated>%t</IsTruncated>`,
		s3NS, f.Bucket, xmlEscape(prefix), xmlEscape(keyMarker), xmlEscape(verMarker), size, truncated)
	if truncated {
		nextKey, nextVer := keyMarker, verMarker // NeverTerminate past the end: the same markers again
		if len(all) > 0 {
			nextKey, nextVer = all[len(all)-1].key, all[len(all)-1].p.ID
		}
		fmt.Fprintf(&b, "<NextKeyMarker>%s</NextKeyMarker><NextVersionIdMarker>%s</NextVersionIdMarker>", xmlEscape(nextKey), nextVer)
	}
	for _, e := range all {
		latest := f.objects[e.key][0].ID == e.p.ID
		if e.p.Marker {
			fmt.Fprintf(&b, "<DeleteMarker><Key>%s</Key><VersionId>%s</VersionId><IsLatest>%t</IsLatest><LastModified>%s</LastModified><Owner><ID>fake</ID></Owner></DeleteMarker>",
				xmlEscape(e.key), e.p.ID, latest, e.p.LastModified.Format("2006-01-02T15:04:05.000Z"))
			continue
		}
		fmt.Fprintf(&b, `<Version><Key>%s</Key><VersionId>%s</VersionId><IsLatest>%t</IsLatest><LastModified>%s</LastModified><ETag>"%x"</ETag><Size>%d</Size><Owner><ID>fake</ID></Owner><StorageClass>STANDARD</StorageClass></Version>`,
			xmlEscape(e.key), e.p.ID, latest, e.p.LastModified.Format("2006-01-02T15:04:05.000Z"), md5.Sum(e.p.Data), len(e.p.Data)) //nolint:gosec // the ETag S3 shows
	}
	if f.Oversize {
		b.WriteString("<!--")
		b.WriteString(strings.Repeat(" ", 1<<20))
		b.WriteString("-->")
	}
	b.WriteString("</ListVersionsResult>")
	w.Header().Set("Content-Type", "application/xml")
	_, _ = io.WriteString(w, b.String())
}

func (f *Fake) put(w http.ResponseWriter, r *http.Request, key string, body []byte) {
	mode, untilRaw := r.Header.Get("x-amz-object-lock-mode"), r.Header.Get("x-amz-object-lock-retain-until-date")
	locking := mode != "" || untilRaw != ""
	if md := r.Header.Get("Content-MD5"); md != "" {
		sum := md5.Sum(body) //nolint:gosec // the header's own digest
		if md != base64.StdEncoding.EncodeToString(sum[:]) {
			f.fail(w, http.StatusBadRequest, "BadDigest")
			return
		}
	} else if locking {
		// S3: "Content-MD5 HTTP header is required for Put Object requests
		// with Object Lock parameters".
		f.fail(w, http.StatusBadRequest, "InvalidRequest")
		return
	}
	if ck := r.Header.Get("x-amz-checksum-sha256"); ck != "" {
		// A malformed value is InvalidRequest; a well-formed one that is
		// not the body's digest is BadDigest, as S3 answers.
		if raw, err := base64.StdEncoding.DecodeString(ck); err != nil || len(raw) != sha256.Size {
			f.fail(w, http.StatusBadRequest, "InvalidRequest")
			return
		}
		sum := sha256.Sum256(body)
		if ck != base64.StdEncoding.EncodeToString(sum[:]) {
			f.fail(w, http.StatusBadRequest, "BadDigest")
			return
		}
	}
	var until time.Time
	if locking {
		if f.LockDisabled {
			f.fail(w, http.StatusBadRequest, "InvalidRequest")
			return
		}
		if mode != "COMPLIANCE" && mode != "GOVERNANCE" {
			f.fail(w, http.StatusBadRequest, "InvalidArgument")
			return
		}
		var err error
		if until, err = time.Parse(time.RFC3339Nano, untilRaw); err != nil {
			f.fail(w, http.StatusBadRequest, "InvalidArgument")
			return
		}
		// S3: "The retain until date must be in the future".
		if !until.After(time.Now()) {
			f.fail(w, http.StatusBadRequest, "InvalidArgument")
			return
		}
	}
	if f.NoVersioning {
		f.objects[key] = []Planted{{ID: "null", Data: bytes.Clone(body), LastModified: time.Now().UTC()}}
		w.Header().Set("ETag", fmt.Sprintf(`"%x"`, md5.Sum(body))) //nolint:gosec // the ETag S3 shows
		w.WriteHeader(http.StatusOK)
		return
	}
	id := f.add(key, Planted{Data: bytes.Clone(body), Mode: mode, Until: until})
	w.Header().Set("x-amz-version-id", id)
	w.Header().Set("ETag", fmt.Sprintf(`"%x"`, md5.Sum(body))) //nolint:gosec // the ETag S3 shows
	w.WriteHeader(http.StatusOK)
}

// find returns the version at key named by id ("" = the newest).
func (f *Fake) find(key, id string) (Planted, bool) {
	vs := f.objects[key]
	if len(vs) == 0 {
		return Planted{}, false
	}
	if id == "" {
		return vs[0], true
	}
	for _, v := range vs {
		if v.ID == id {
			return v, true
		}
	}
	return Planted{}, false
}

func (f *Fake) get(w http.ResponseWriter, key, id string) {
	v, ok := f.find(key, id)
	switch {
	case !ok && id != "":
		f.fail(w, http.StatusNotFound, "NoSuchVersion")
	case !ok, v.Marker && id == "":
		f.fail(w, http.StatusNotFound, "NoSuchKey")
	case v.Marker:
		f.fail(w, http.StatusMethodNotAllowed, "MethodNotAllowed")
	default:
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Length", strconv.Itoa(len(v.Data)))
		w.Header().Set("x-amz-version-id", v.ID)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(v.Data)
	}
}

func (f *Fake) retention(w http.ResponseWriter, key, id string) {
	v, ok := f.find(key, id)
	switch {
	case !ok:
		f.fail(w, http.StatusNotFound, "NoSuchVersion")
	case v.Marker:
		f.fail(w, http.StatusMethodNotAllowed, "MethodNotAllowed")
	case v.Mode == "":
		f.fail(w, http.StatusNotFound, "NoSuchObjectLockConfiguration")
	default:
		w.Header().Set("Content-Type", "application/xml")
		_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Retention xmlns="%s"><Mode>%s</Mode><RetainUntilDate>%s</RetainUntilDate></Retention>`, s3NS, v.Mode, v.Until.UTC().Format("2006-01-02T15:04:05.000Z"))
	}
}

func (f *Fake) del(w http.ResponseWriter, r *http.Request, key, id string) {
	if id == "" {
		mid := f.add(key, Planted{Marker: true})
		w.Header().Set("x-amz-delete-marker", "true")
		w.Header().Set("x-amz-version-id", mid)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	v, ok := f.find(key, id)
	if !ok {
		f.fail(w, http.StatusNotFound, "NoSuchVersion")
		return
	}
	locked := !v.Marker && v.Mode != "" && time.Now().Before(v.Until)
	if locked && (v.Mode == "COMPLIANCE" || r.Header.Get("x-amz-bypass-governance-retention") != "true") {
		f.fail(w, http.StatusForbidden, "AccessDenied")
		return
	}
	vs := f.objects[key]
	for i := range vs {
		if vs[i].ID == id {
			f.objects[key] = append(vs[:i:i], vs[i+1:]...)
			break
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// verifySignature checks the request's SigV4 signature independently: the
// Authorization shape, the credential scope (this fake's key id, the
// x-amz-date day, its region, s3), the payload hash against the body, and
// the signature over the fake's own canonicalization of the request as
// received. It returns the S3 error code to answer, or "".
func (f *Fake) verifySignature(r *http.Request, body []byte) string {
	authz := r.Header.Get("Authorization")
	if !strings.HasPrefix(authz, "AWS4-HMAC-SHA256 ") {
		return "SignatureDoesNotMatch"
	}
	fields := map[string]string{}
	for _, part := range strings.Split(strings.TrimPrefix(authz, "AWS4-HMAC-SHA256 "), ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return "SignatureDoesNotMatch"
		}
		fields[k] = v
	}
	date := r.Header.Get("X-Amz-Date")
	if _, err := time.Parse("20060102T150405Z", date); err != nil {
		return "SignatureDoesNotMatch"
	}
	scope := date[:8] + "/" + f.Region + "/s3/aws4_request"
	if cred := fields["Credential"]; cred != f.KeyID+"/"+scope {
		if strings.HasPrefix(cred, f.KeyID+"/") {
			return "SignatureDoesNotMatch"
		}
		return "InvalidAccessKeyId"
	}
	sum := sha256.Sum256(body)
	payload := hex.EncodeToString(sum[:])
	if r.Header.Get("X-Amz-Content-Sha256") != payload {
		return "SignatureDoesNotMatch"
	}
	names := strings.Split(fields["SignedHeaders"], ";")
	required := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	if r.Header.Get("X-Amz-Security-Token") != "" {
		required = append(required, "x-amz-security-token")
	}
	for _, want := range required {
		found := false
		for _, n := range names {
			found = found || n == want
		}
		if !found {
			return "SignatureDoesNotMatch"
		}
	}
	creq := canonical(r.Method, r.URL.Path, r.URL.RawQuery, r.Host, r.Header, names, payload)
	want := signature(f.Secret, date[:8], f.Region, date, scope, creq)
	if !hmac.Equal([]byte(fields["Signature"]), []byte(want)) {
		return "SignatureDoesNotMatch"
	}
	return ""
}

// canonical is the fake's own canonical request from a request as received:
// the decoded path re-encoded once per segment, the query re-encoded and
// sorted, the named headers.
func canonical(method, path, rawQuery, host string, h http.Header, names []string, payload string) string {
	segs := strings.Split(path, "/")
	for i, s := range segs {
		segs[i] = encode(s)
	}
	// Pairs sort by encoded name, then value (SigV4's rule) — not by the
	// joined "name=value" string.
	var pairs [][2]string
	for _, p := range strings.Split(rawQuery, "&") {
		if p == "" {
			continue
		}
		k, v, _ := strings.Cut(p, "=")
		ku, _ := url.PathUnescape(k)
		vu, _ := url.PathUnescape(v)
		pairs = append(pairs, [2]string{encode(ku), encode(vu)})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i][0] != pairs[j][0] {
			return pairs[i][0] < pairs[j][0]
		}
		return pairs[i][1] < pairs[j][1]
	})
	query := make([]string, len(pairs))
	for i, p := range pairs {
		query[i] = p[0] + "=" + p[1]
	}
	var b strings.Builder
	b.WriteString(method + "\n" + strings.Join(segs, "/") + "\n" + strings.Join(query, "&") + "\n")
	for _, n := range names {
		v := strings.Join(h.Values(n), ",")
		if n == "host" {
			v = host
		}
		b.WriteString(n + ":" + strings.Join(strings.Fields(v), " ") + "\n")
	}
	b.WriteString("\n" + strings.Join(names, ";") + "\n" + payload)
	return b.String()
}

// encode is RFC 3986 unreserved-or-%XX, the SigV4 component encoding.
func encode(s string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			b.WriteByte('%')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&15])
		}
	}
	return b.String()
}

// signature derives the SigV4 signature of a canonical request.
func signature(secret, day, region, date, scope, creq string) string {
	h := func(key []byte, data string) []byte {
		m := hmac.New(sha256.New, key)
		m.Write([]byte(data))
		return m.Sum(nil)
	}
	k := h([]byte("AWS4"+secret), day)
	k = h(k, region)
	k = h(k, "s3")
	k = h(k, "aws4_request")
	sum := sha256.Sum256([]byte(creq))
	sts := "AWS4-HMAC-SHA256\n" + date + "\n" + scope + "\n" + hex.EncodeToString(sum[:])
	return hex.EncodeToString(h(k, sts))
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
