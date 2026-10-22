package sink

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/agenthof/agenthof/internal/broker"
	"github.com/agenthof/agenthof/internal/control"
)

// KindS3ObjectLock is the IntegrityBackend.Kind vocabulary for this sink.
const KindS3ObjectLock = "s3-object-lock"

// Backend is what the seal, verify and restore hold: both sides of the sink
// seam in one value.
type Backend interface {
	control.SinkWriter
	control.SinkReader
}

// S3Options configures an S3.
type S3Options struct {
	Region    string                                        // "" → read from an S3 regional amazonaws.com host; another AWS host is refused; a non-AWS host signs for us-east-1
	Client    *http.Client                                  // nil → fresh; always copied, redirects disabled on the copy
	Keys      func(context.Context) (broker.KeyPair, error) // resolved per request; required
	Retention time.Duration                                 // Locator: retain_until = sealedAt + Retention; required
	Timeout   time.Duration                                 // per store call; 0 → 60s
	Now       func() time.Time                              // nil → time.Now; x-amz-date and the scope
}

// defaultTimeout bounds each store call when S3Options.Timeout is unset.
const defaultTimeout = 60 * time.Second

// S3 is the sink logic over an objectStore: control.SinkWriter and
// control.SinkReader for one bucket and prefix. It decides — the
// oldest-version rule, the read-back, the bounds — and never sees a
// request; NewS3 pairs it with the hand-rolled SigV4 transport.
type S3 struct {
	url       string // as configured, one trailing slash trimmed: the record's url
	bucket    string
	prefix    string // the path beyond the bucket, no slash at either end; may be empty
	region    string
	retention time.Duration
	timeout   time.Duration
	store     objectStore
}

var _ Backend = (*S3)(nil)

// NewS3 builds the backend for rawURL = endpoint + /bucket[/prefix].
func NewS3(rawURL string, o S3Options) (*S3, error) {
	u, err := parseBackendURL(rawURL)
	if err != nil {
		return nil, err
	}
	parsed, err := url.Parse(u)
	if err != nil {
		return nil, err
	}
	bucket, prefix, _ := strings.Cut(strings.Trim(parsed.Path, "/"), "/")
	if bucket == "" {
		return nil, fmt.Errorf("%q names no bucket", rawURL)
	}
	if o.Keys == nil {
		return nil, errors.New("sink: S3Options.Keys is required")
	}
	if o.Retention <= 0 {
		return nil, errors.New("sink: S3Options.Retention must be positive")
	}
	region, err := regionFor(parsed.Hostname(), o.Region)
	if err != nil {
		return nil, err
	}
	store := newSigV4Store(parsed.Scheme+"://"+parsed.Host, parsed.Host, bucket, region, o.Client, o.Keys, o.Now)
	s := newS3(u, bucket, strings.Trim(prefix, "/"), store, o.Retention, o.Timeout)
	s.region = region
	return s, nil
}

// newS3 is the logic over any store; the tests hand in an in-memory one.
func newS3(u, bucket, prefix string, store objectStore, retention, timeout time.Duration) *S3 {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &S3{url: u, bucket: bucket, prefix: prefix, retention: retention, timeout: timeout, store: store}
}

// parseBackendURL admits an absolute http or https URL with a host and no
// userinfo, query or fragment, and trims one trailing slash (the anchor
// backend's rule).
func parseBackendURL(s string) (string, error) {
	s = strings.TrimSuffix(s, "/")
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", fmt.Errorf("%q is not an absolute http(s) URL without credentials", s)
	}
	return u.String(), nil
}

// awsRegionHostRE reads the region out of an S3 regional endpoint:
// s3.<region>.amazonaws.com, s3-<region>.amazonaws.com, and the .com.cn
// partition. The capture is a region's shape (us-east-1, eu-central-1,
// us-gov-west-1, us-iso-east-1, cn-north-1), so the legacy and special
// endpoints (s3-external-1, s3-accelerate, …) do not read as regions.
var awsRegionHostRE = regexp.MustCompile(`^s3[.-]([a-z]{2}(?:-gov|-iso[a-z]?)?-[a-z]+-\d+)\.amazonaws\.com(\.cn)?$`)

// regionFor is the signing region: the configured one when set; else read
// from an AWS regional endpoint; the legacy global endpoint is us-east-1;
// any other amazonaws.com host (FIPS, dual-stack, virtual-hosted) is
// refused rather than signed for a guessed region; a non-AWS host (MinIO,
// a private store) signs for us-east-1, which such stores accept.
func regionFor(host, configured string) (string, error) {
	if configured != "" {
		return configured, nil
	}
	host = strings.ToLower(host)
	if m := awsRegionHostRE.FindStringSubmatch(host); m != nil {
		return m[1], nil
	}
	if host == "s3.amazonaws.com" {
		return "us-east-1", nil
	}
	if strings.HasSuffix(host, ".amazonaws.com") || strings.HasSuffix(host, ".amazonaws.com.cn") {
		return "", fmt.Errorf("cannot derive the signing region from host %s; set region in sink_backend", host)
	}
	return "us-east-1", nil
}

// Kind is KindS3ObjectLock.
func (s *S3) Kind() string { return KindS3ObjectLock }

// URL is the backend URL as configured, one trailing slash trimmed.
func (s *S3) URL() string { return s.url }

// Region is the signing region in use.
func (s *S3) Region() string { return s.region }

// Prefix is "<prefix>/<log_id>/" — the ledger's keys live under it.
func (s *S3) Prefix(logID string) string {
	if s.prefix == "" {
		return logID + "/"
	}
	return s.prefix + "/" + logID + "/"
}

// Locator is pure: the sink block for segment n of logID sealed at
// sealedAt — retain_until is sealedAt + retention, whole seconds, UTC.
func (s *S3) Locator(logID string, n int, sealedAt time.Time) control.SealSink {
	return control.SealSink{
		Kind:        KindS3ObjectLock,
		URL:         s.url,
		Key:         s.Prefix(logID) + fmt.Sprintf("seg-%06d", n),
		Mode:        "compliance",
		RetainUntil: sealedAt.UTC().Truncate(time.Second).Add(s.retention),
	}
}

// bounded applies the per-call timeout.
func (s *S3) bounded(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, s.timeout)
}

// keyVersions lists the exact key: its non-marker versions oldest first
// and whether a delete marker sits on it. The store answers the prefix
// (which also matches "seg-000001x"), so the key is filtered here.
func (s *S3) keyVersions(ctx context.Context, key string) (control.KeyVersions, error) {
	cctx, cancel := s.bounded(ctx)
	defer cancel()
	entries, err := s.store.listVersions(cctx, key)
	if err != nil {
		return control.KeyVersions{}, err
	}
	kv := control.KeyVersions{Key: key}
	for _, e := range entries {
		if e.Key != key {
			continue
		}
		if e.DeleteMarker {
			kv.DeleteMarker = true
			continue
		}
		// Served newest first; oldest first here.
		kv.Versions = append([]control.SinkVersion{{ID: e.ID, IsLatest: e.IsLatest, Size: e.Size, LastModified: e.LastModified}}, kv.Versions...)
	}
	return kv, nil
}

// occupiedErr is the refusal for a key holding a version that is not the
// segment: the seal never writes on top.
func occupiedErr(key string) error {
	return fmt.Errorf("key %s is occupied by a version that is not this segment; the sink cannot take this seal — choose a fresh prefix or remove the foreign object", key)
}

// Prepare is the preflight before anything is linked or recorded: the
// credential resolves, the bucket answers with Object Lock enabled, and
// the seal's key can be listed and holds no version. A fresh seal's key
// has nothing of its own yet (a re-run completes through Put, which can
// compare bytes), so any version there is foreign; a delete marker alone
// is not.
func (s *S3) Prepare(ctx context.Context, loc control.SealSink) error {
	cctx, cancel := s.bounded(ctx)
	enabled, err := s.store.lockEnabled(cctx)
	cancel()
	if err != nil {
		return err
	}
	if !enabled {
		return fmt.Errorf("bucket %s does not have Object Lock enabled; enable it on the bucket (versioning is required) before sink: worm", s.bucket)
	}
	kv, err := s.keyVersions(ctx, loc.Key)
	if err != nil {
		return err
	}
	if len(kv.Versions) > 0 {
		return occupiedErr(loc.Key)
	}
	return nil
}

// Put writes data under loc, locked as loc says, and confirms it by reading
// the lock back. The order: list the exact key; every non-marker version
// there must hash to data (any that does not refuses the seal — no PUT);
// if one does, the OLDEST is the seal's own: its lock is read back and the
// receipt says Existed. An empty key is written with the lock headers; the
// version the store minted must then list as the key's OLDEST and has its
// lock read back. A write with no version id, one that is not the oldest,
// a refused read-back, or a lesser lock is unconfirmed.
func (s *S3) Put(ctx context.Context, loc control.SealSink, data []byte, sha256hex string) (control.PutReceipt, error) {
	if loc.Mode != "compliance" {
		return control.PutReceipt{}, fmt.Errorf("sink: mode %q is not compliance; this sink writes compliance locks only", loc.Mode)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != sha256hex {
		return control.PutReceipt{}, fmt.Errorf("sink: segment digest %s does not match the bytes (%s)", sha256hex, got)
	}
	kv, err := s.keyVersions(ctx, loc.Key)
	if err != nil {
		return control.PutReceipt{}, err
	}
	for _, v := range kv.Versions {
		if v.Size != int64(len(data)) {
			return control.PutReceipt{}, occupiedErr(loc.Key)
		}
		body, err := s.get(ctx, loc.Key, v.ID, int64(len(data)))
		if errors.Is(err, errObjectTooLarge) {
			return control.PutReceipt{}, occupiedErr(loc.Key)
		}
		if err != nil {
			return control.PutReceipt{}, err
		}
		if !bytes.Equal(body, data) {
			return control.PutReceipt{}, occupiedErr(loc.Key)
		}
	}
	if len(kv.Versions) > 0 {
		oldest := kv.Versions[0]
		l, err := s.retentionOf(ctx, loc.Key, oldest.ID)
		if err != nil {
			return control.PutReceipt{}, err
		}
		if err := underLocked(oldest.ID, l, loc); err != nil {
			return control.PutReceipt{}, err
		}
		return control.PutReceipt{VersionID: oldest.ID, RetainUntil: l.RetainUntil, Existed: true}, nil
	}

	cctx, cancel := s.bounded(ctx)
	id, err := s.store.putLocked(cctx, loc.Key, data, "COMPLIANCE", loc.RetainUntil)
	cancel()
	if err != nil {
		return control.PutReceipt{}, err
	}
	if id == "" {
		return control.PutReceipt{}, errors.New("sink answered without a version id; versioning is not enabled, so no lock was applied — nothing confirmed")
	}
	// The write is the seal's own only if it is the OLDEST at the key —
	// the version verify judges. Another writer can land a version between
	// the empty listing and the PUT; then this one sits on top of a foreign
	// object and is not confirmed (a re-run meets the occupied refusal).
	after, err := s.keyVersions(ctx, loc.Key)
	if err != nil {
		return control.PutReceipt{}, fmt.Errorf("protected copy written but NOT confirmed: %w", err)
	}
	if len(after.Versions) == 0 || after.Versions[0].ID != id {
		return control.PutReceipt{}, fmt.Errorf("protected copy written but NOT confirmed: version %s is not the oldest at the key — the key was written concurrently", id)
	}
	l, err := s.retentionOf(ctx, loc.Key, id)
	if err != nil {
		var se *StatusError
		if errors.As(err, &se) && se.Status == http.StatusForbidden {
			return control.PutReceipt{}, fmt.Errorf("protected copy written but NOT confirmed: the credential cannot read the object's retention; grant s3:GetObjectRetention, s3:GetObject and s3:ListBucketVersions, then re-run (%w)", err)
		}
		return control.PutReceipt{}, fmt.Errorf("protected copy written but NOT confirmed: %w", err)
	}
	if err := underLocked(id, l, loc); err != nil {
		return control.PutReceipt{}, err
	}
	return control.PutReceipt{VersionID: id, RetainUntil: l.RetainUntil}, nil
}

// underLocked is the verdict on a read-back: the version must be locked in
// loc's mode (upper-cased on the wire) to at least loc's date. A longer
// retention is fine — it can only be extended.
func underLocked(versionID string, l lock, loc control.SealSink) error {
	want := strings.ToUpper(loc.Mode)
	if l.Mode == want && !l.RetainUntil.Before(loc.RetainUntil) {
		return nil
	}
	have := "not locked"
	if l.Mode != "" {
		have = "locked " + l.Mode + " until " + l.RetainUntil.UTC().Format(time.RFC3339)
	}
	return fmt.Errorf("oldest version %s at the key holds the segment but is %s, not %s until %s; the sink is not what the posture claims", versionID, have, want, loc.RetainUntil.UTC().Format(time.RFC3339))
}

func (s *S3) retentionOf(ctx context.Context, key, versionID string) (lock, error) {
	cctx, cancel := s.bounded(ctx)
	defer cancel()
	return s.store.retention(cctx, key, versionID)
}

func (s *S3) get(ctx context.Context, key, versionID string, max int64) ([]byte, error) {
	cctx, cancel := s.bounded(ctx)
	defer cancel()
	return s.store.get(cctx, key, versionID, max)
}

// ListVersions lists one key: non-marker versions oldest first, and
// whether a delete marker sits on it.
func (s *S3) ListVersions(ctx context.Context, key string) (control.KeyVersions, error) {
	return s.keyVersions(ctx, key)
}

// ListPrefix lists every key under prefix, each with its versions oldest
// first and its marker, in the order the store first names the keys.
func (s *S3) ListPrefix(ctx context.Context, prefix string) ([]control.KeyVersions, error) {
	cctx, cancel := s.bounded(ctx)
	defer cancel()
	entries, err := s.store.listVersions(cctx, prefix)
	if err != nil {
		return nil, err
	}
	var out []control.KeyVersions
	index := map[string]int{}
	for _, e := range entries {
		i, ok := index[e.Key]
		if !ok {
			i = len(out)
			index[e.Key] = i
			out = append(out, control.KeyVersions{Key: e.Key})
		}
		if e.DeleteMarker {
			out[i].DeleteMarker = true
			continue
		}
		out[i].Versions = append([]control.SinkVersion{{ID: e.ID, IsLatest: e.IsLatest, Size: e.Size, LastModified: e.LastModified}}, out[i].Versions...)
	}
	return out, nil
}

// GetRetention reads a version's lock back.
func (s *S3) GetRetention(ctx context.Context, key, versionID string) (control.SinkRetention, error) {
	l, err := s.retentionOf(ctx, key, versionID)
	if err != nil {
		return control.SinkRetention{}, err
	}
	return control.SinkRetention{Mode: l.Mode, RetainUntil: l.RetainUntil}, nil
}

// Get reads one version whole, refusing a body over max bytes.
func (s *S3) Get(ctx context.Context, key, versionID string, max int64) ([]byte, error) {
	body, err := s.get(ctx, key, versionID, max)
	if errors.Is(err, errObjectTooLarge) {
		return nil, fmt.Errorf("object %s version %s exceeds the %d-byte bound", key, versionID, max)
	}
	return body, err
}
