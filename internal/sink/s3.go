package sink

import (
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // a transport integrity header the lock PUT requires, not a security function
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/agenthof/agenthof/internal/broker"
)

// sigv4Store is the hand-rolled objectStore: the five S3 REST operations,
// path-style, SigV4-signed, over net/http and encoding/xml. It knows the
// wire and nothing of the write-once rule.
type sigv4Store struct {
	base   string // scheme://host
	host   string // for error texts: never a path, never a body
	bucket string
	region string
	client *http.Client
	keys   func(context.Context) (broker.KeyPair, error)
	now    func() time.Time
}

const (
	// maxListBody bounds every response body but an object's own: a
	// listing page, a retention document, an error. A page of 1000
	// versions is well under 1 MiB.
	maxListBody = 1 << 20
	// maxListPages caps a listing walk; past it the store is not answering
	// a question this client asked.
	maxListPages = 1000
	// MaxRestoreBody bounds an object read when no manifest figure bounds
	// it (a rebuild from the bucket).
	MaxRestoreBody = 256 << 20

	contentTypeNDJSON = "application/x-ndjson"
	sigV4Service      = "s3"
)

// errBodyTooLarge is do's answer for a body over the bound it was given.
var errBodyTooLarge = errors.New("response body exceeds the bound")

// newSigV4Store builds the transport for bucket at base (scheme://host).
// client nil is a fresh http.Client; whatever is given is copied and the
// copy never follows a redirect. now nil is time.Now.
func newSigV4Store(base, host, bucket, region string, client *http.Client, keys func(context.Context) (broker.KeyPair, error), now func() time.Time) *sigv4Store {
	var c http.Client
	if client != nil {
		c = *client
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if now == nil {
		now = time.Now
	}
	return &sigv4Store{base: base, host: host, bucket: bucket, region: region, client: &c, keys: keys, now: now}
}

var _ objectStore = (*sigv4Store)(nil)

// objectURL is "<base>/<bucket>/<key encoded once>" — the wire path and the
// signed path are the same bytes. query is already encoded.
func (s *sigv4Store) objectURL(key, query string) string {
	u := s.base + "/" + uriEncode(s.bucket)
	if key != "" {
		u += "/" + uriEncodePath(key)
	}
	if query != "" {
		u += "?" + query
	}
	return u
}

// queryString encodes name/value pairs once, in the order given; a pair
// with an empty value is a bare subresource ("versions").
func queryString(pairs ...[2]string) string {
	parts := make([]string, 0, len(pairs))
	for _, p := range pairs {
		if p[1] == "" {
			parts = append(parts, uriEncode(p[0]))
			continue
		}
		parts = append(parts, uriEncode(p[0])+"="+uriEncode(p[1]))
	}
	return strings.Join(parts, "&")
}

// do performs one signed request and returns the status, headers and body
// (at most maxBody bytes, else errBodyTooLarge; an error body is bounded by
// maxListBody instead). A transport error is "<host>: <cause>" — never the
// URL. The caller classifies the status.
func (s *sigv4Store) do(ctx context.Context, method, rawURL string, body []byte, hdr http.Header, maxBody int64) (int, http.Header, []byte, error) {
	kp, err := s.keys(ctx)
	if err != nil {
		return 0, nil, nil, err // names an env var, never a value
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	for k, vs := range hdr {
		req.Header[k] = vs
	}
	sum := sha256.Sum256(body)
	payloadHash := hex.EncodeToString(sum[:])
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	signV4(req, kp, s.region, sigV4Service, s.now(), payloadHash)

	resp, err := s.client.Do(req)
	if err != nil {
		// A *url.Error repeats the full URL; keep its cause only.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return 0, nil, nil, fmt.Errorf("%s: %w", s.host, err)
	}
	defer func() { _ = resp.Body.Close() }()
	bound := maxBody
	if resp.StatusCode/100 != 2 {
		bound = maxListBody
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, bound+1))
	if err != nil {
		return 0, nil, nil, fmt.Errorf("%s: %w", s.host, err)
	}
	if int64(len(raw)) > bound {
		return resp.StatusCode, resp.Header, nil, errBodyTooLarge
	}
	return resp.StatusCode, resp.Header, raw, nil
}

// refusal classifies a non-2xx answer: a redirect is never followed; a
// RequestTimeTooSkewed is the clock, not the credential; anything else is
// a *StatusError with the body's code when it carried one.
func (s *sigv4Store) refusal(op string, status int, raw []byte) error {
	if status/100 == 3 {
		return fmt.Errorf("%s answered a redirect (status %d); not followed", s.host, status)
	}
	var e errorResult
	_ = xml.Unmarshal(raw, &e) // no code is fine; the status still speaks
	if e.Code == "RequestTimeTooSkewed" {
		return fmt.Errorf("%w (%s)", ErrClockSkew, s.host)
	}
	return &StatusError{Op: op, Status: status, Host: s.host, Code: e.Code}
}

// tooLarge is the text for a body over maxListBody.
func (s *sigv4Store) tooLarge() error {
	return fmt.Errorf("response body from %s exceeds 1 MiB", s.host)
}

func (s *sigv4Store) putLocked(ctx context.Context, key string, body []byte, mode string, until time.Time) (string, error) {
	hdr := http.Header{}
	hdr.Set("Content-Type", contentTypeNDJSON)
	hdr.Set("Content-MD5", contentMD5(body))
	hdr.Set("X-Amz-Checksum-Sha256", checksumSHA256(body))
	hdr.Set("X-Amz-Object-Lock-Mode", mode)
	hdr.Set("X-Amz-Object-Lock-Retain-Until-Date", until.UTC().Format(time.RFC3339))
	status, h, raw, err := s.do(ctx, http.MethodPut, s.objectURL(key, ""), body, hdr, maxListBody)
	switch {
	case errors.Is(err, errBodyTooLarge):
		return "", s.tooLarge()
	case err != nil:
		return "", err
	case status/100 != 2:
		return "", s.refusal("PutObject", status, raw)
	}
	return h.Get("x-amz-version-id"), nil
}

func (s *sigv4Store) get(ctx context.Context, key, versionID string, max int64) ([]byte, error) {
	status, _, raw, err := s.do(ctx, http.MethodGet, s.objectURL(key, queryString([2]string{"versionId", versionID})), nil, nil, max)
	switch {
	case errors.Is(err, errBodyTooLarge):
		if status/100 == 2 {
			return nil, errObjectTooLarge
		}
		return nil, s.tooLarge()
	case err != nil:
		return nil, err
	case status/100 != 2:
		return nil, s.refusal("GetObject", status, raw)
	}
	return raw, nil
}

func (s *sigv4Store) retention(ctx context.Context, key, versionID string) (lock, error) {
	status, _, raw, err := s.do(ctx, http.MethodGet, s.objectURL(key, queryString([2]string{"retention", ""}, [2]string{"versionId", versionID})), nil, nil, maxListBody)
	switch {
	case errors.Is(err, errBodyTooLarge):
		return lock{}, s.tooLarge()
	case err != nil:
		return lock{}, err
	case status/100 != 2:
		err := s.refusal("GetObjectRetention", status, raw)
		var se *StatusError
		if errors.As(err, &se) && se.Status == http.StatusNotFound && se.Code == "NoSuchObjectLockConfiguration" {
			return lock{}, nil // the version exists and carries no lock
		}
		return lock{}, err
	}
	var r retentionResult
	if err := xml.Unmarshal(raw, &r); err != nil {
		return lock{}, fmt.Errorf("response from %s is not a Retention document", s.host)
	}
	until, err := time.Parse(time.RFC3339Nano, r.RetainUntilDate)
	if err != nil {
		return lock{}, fmt.Errorf("response from %s carries an unreadable RetainUntilDate", s.host)
	}
	return lock{Mode: r.Mode, RetainUntil: until.UTC()}, nil
}

func (s *sigv4Store) lockEnabled(ctx context.Context) (bool, error) {
	status, _, raw, err := s.do(ctx, http.MethodGet, s.objectURL("", queryString([2]string{"object-lock", ""})), nil, nil, maxListBody)
	switch {
	case errors.Is(err, errBodyTooLarge):
		return false, s.tooLarge()
	case err != nil:
		return false, err
	case status/100 != 2:
		err := s.refusal("GetObjectLockConfiguration", status, raw)
		var se *StatusError
		if errors.As(err, &se) && se.Status == http.StatusNotFound && se.Code == "ObjectLockConfigurationNotFoundError" {
			return false, nil // the bucket answers; it has no lock configuration
		}
		return false, err
	}
	var c objectLockConfiguration
	if err := xml.Unmarshal(raw, &c); err != nil {
		return false, fmt.Errorf("response from %s is not an ObjectLockConfiguration document", s.host)
	}
	return c.ObjectLockEnabled == "Enabled", nil
}

// listVersions walks ListObjectVersions under prefix: every page continues
// with BOTH markers (key-marker and version-id-marker) until IsTruncated is
// false, at most maxListPages pages.
func (s *sigv4Store) listVersions(ctx context.Context, prefix string) ([]objectVersion, error) {
	var out []objectVersion
	keyMarker, verMarker := "", ""
	for page := 0; ; page++ {
		if page == maxListPages {
			return nil, fmt.Errorf("listing exceeded %d pages", maxListPages)
		}
		pairs := [][2]string{{"versions", ""}}
		if prefix != "" {
			pairs = append(pairs, [2]string{"prefix", prefix})
		}
		if keyMarker != "" {
			pairs = append(pairs, [2]string{"key-marker", keyMarker}, [2]string{"version-id-marker", verMarker})
		}
		status, _, raw, err := s.do(ctx, http.MethodGet, s.objectURL("", queryString(pairs...)), nil, nil, maxListBody)
		switch {
		case errors.Is(err, errBodyTooLarge):
			return nil, s.tooLarge()
		case err != nil:
			return nil, err
		case status/100 != 2:
			return nil, s.refusal("ListObjectVersions", status, raw)
		}
		var r listVersionsResult
		if err := xml.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("response from %s is not a ListVersionsResult document", s.host)
		}
		for _, e := range r.Entries {
			if e.XMLName.Local != "Version" && e.XMLName.Local != "DeleteMarker" {
				continue
			}
			var modified time.Time
			if e.LastModified != "" {
				if modified, err = time.Parse(time.RFC3339Nano, e.LastModified); err != nil {
					return nil, fmt.Errorf("response from %s carries an unreadable LastModified", s.host)
				}
			}
			out = append(out, objectVersion{Key: e.Key, ID: e.VersionID, IsLatest: e.IsLatest, DeleteMarker: e.XMLName.Local == "DeleteMarker", Size: e.Size, LastModified: modified.UTC()})
		}
		if !r.IsTruncated {
			return out, nil
		}
		if r.NextKeyMarker == "" {
			return nil, fmt.Errorf("response from %s is truncated without a continuation marker", s.host)
		}
		keyMarker, verMarker = r.NextKeyMarker, r.NextVersionIDMarker
	}
}

// contentMD5 is the Content-MD5 header value: base64 of the raw 16-byte digest.
func contentMD5(data []byte) string {
	sum := md5.Sum(data) //nolint:gosec // see the import
	return base64.StdEncoding.EncodeToString(sum[:])
}

// checksumSHA256 is the x-amz-checksum-sha256 header value: base64 of the raw
// 32-byte digest — never the hex form.
func checksumSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return base64.StdEncoding.EncodeToString(sum[:])
}
