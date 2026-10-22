package control

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"
)

// The sink seam: what a seal needs from a write-once sink (SinkWriter), and
// what verify, restore and rebuild need to read back from it (SinkReader).
// Both are declared here and implemented elsewhere — the seal calls the sink
// between its two commits, and this package must not import a storage
// client. A nil SinkWriter is the floor: the shipped seal, no copy.

// SealSink is the additive sink block of a seal payload: where the protected
// copy of the segment goes, locked how, and until when. Everything in it is
// known before the seal line is appended (Locator is pure); nothing about
// the upload's outcome is on the chain — that is the sink's own state, read
// back by verify. Never a credential, a signed URL or an ETag.
type SealSink struct {
	Kind        string    `json:"kind"`         // "s3-object-lock"
	URL         string    `json:"url"`          // sink_backend.url as configured, one trailing slash trimmed
	Key         string    `json:"key"`          // "<prefix>/<log_id>/seg-NNNNNN"
	Mode        string    `json:"mode"`         // "compliance"
	RetainUntil time.Time `json:"retain_until"` // UTC, whole seconds
}

// MaxSinkKeyLen caps a seal's sink key, judged at Append beside the URL cap
// (MaxAnchorBackendLen): an object key's own limit, far above anything
// Locator produces.
const MaxSinkKeyLen = 1024

// PutReceipt is what a sink reports back from a Put.
type PutReceipt struct {
	VersionID   string
	RetainUntil time.Time // as the sink reports it (not before the locator's)
	Existed     bool      // confirmed without writing: the key's oldest version already was this segment
}

// SinkWriter is what the seal calls for a root whose posture is sink: worm.
// Kind and URL are what the record names.
type SinkWriter interface {
	Kind() string
	URL() string
	// Prepare is the preflight before anything is linked or recorded: the
	// credential resolves, the bucket answers, Object Lock is enabled on it,
	// and the seal's own key (s) can be listed.
	Prepare(ctx context.Context, s SealSink) error
	// Locator is pure: the sink block the seal record will carry.
	Locator(logID string, n int, sealedAt time.Time) SealSink
	// Put writes data under s, locked as s says, and confirms it by reading
	// the lock back on the version it wrote. It lists the key first: an
	// empty key is written; a key whose oldest version hashes to data (and
	// is locked as s says) is confirmed without a new PUT; a key occupied by
	// any version that does NOT hash to data is refused — never written on
	// top — so the oldest version at a key is always the seal's own. sha256
	// is data's hex digest, which the sink must have stored.
	Put(ctx context.Context, s SealSink, data []byte, sha256 string) (PutReceipt, error)
}

// SinkVersion is one object version at a key, as the sink lists it.
type SinkVersion struct {
	ID           string
	IsLatest     bool
	Size         int64
	LastModified time.Time
}

// SinkRetention is a version's lock as the sink reports it. Mode is
// "COMPLIANCE", "GOVERNANCE" or "" (no lock).
type SinkRetention struct {
	Mode        string
	RetainUntil time.Time
}

// KeyVersions is a key's non-marker versions, oldest first, and whether a
// delete marker sits on the key.
type KeyVersions struct {
	Key          string
	Versions     []SinkVersion
	DeleteMarker bool
}

// SinkReader is what verify, restore and rebuild call: the sink's side of
// the story, read back. It lives here, beside its readers, rather than
// beside the backend that implements it.
type SinkReader interface {
	// Prefix is "<prefix>/<log_id>/" — the ledger's keys live under it.
	Prefix(logID string) string
	ListVersions(ctx context.Context, key string) (KeyVersions, error)
	ListPrefix(ctx context.Context, prefix string) ([]KeyVersions, error)
	GetRetention(ctx context.Context, key, versionID string) (SinkRetention, error)
	// Get reads one version whole, refusing a body over max bytes.
	Get(ctx context.Context, key, versionID string, max int64) ([]byte, error)
}

// sealChainFieldsAgree is the one seal comparison both readers use: got is
// present and its five chain fields — the ones a reader recomputes — equal
// want's. The sink block is ignored on both sides: the chain cannot
// recompute a bucket, so a block is carried as recorded, never compared.
func sealChainFieldsAgree(got *Seal, want Seal) bool {
	return got != nil &&
		got.Segment == want.Segment &&
		got.FirstSeq == want.FirstSeq &&
		got.HeadSeq == want.HeadSeq &&
		got.HeadHash == want.HeadHash &&
		got.ContentSHA256 == want.ContentSHA256
}

// checkSealSink is the shape permit for a seal's sink block, in fixed order,
// first fault only: nil is the floor; kind non-empty; url an absolute http(s)
// URL with a bucket path, under the cap; key relative, no .. segment, under
// the cap; mode exactly compliance; retain_until set. Shape only — whether
// the sink exists is not the chain's question, and whether retain_until is
// after the seal's time is the reader's (the record's time is stamped after
// this permit runs).
func checkSealSink(s *SealSink) error {
	if s == nil {
		return nil
	}
	switch {
	case s.Kind == "":
		return errors.New("control: seal sink kind is empty")
	case !sinkURLOK(s.URL) || len(s.URL) > MaxAnchorBackendLen:
		return fmt.Errorf("control: seal sink url %q is not an absolute http(s) URL with a bucket path", s.URL)
	case s.Key == "" || strings.HasPrefix(s.Key, "/") || len(s.Key) > MaxSinkKeyLen || slices.Contains(strings.Split(s.Key, "/"), ".."):
		return fmt.Errorf("control: seal sink key %q must be relative with no .. segment", s.Key)
	case s.Mode != "compliance":
		return fmt.Errorf("control: seal sink mode %q is not compliance", s.Mode)
	case s.RetainUntil.IsZero():
		return errors.New("control: seal sink retain_until is unset")
	}
	return nil
}

// sinkURLOK is the backend-URL rule the integrity posture admits (an
// absolute http(s) URL with a host and no userinfo, query or fragment) plus
// what a sink needs of it: a path with at least one non-empty segment, the
// bucket.
func sinkURLOK(s string) bool {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return false
	}
	return strings.Trim(u.Path, "/") != ""
}

// sinkRetainErr is the reader's one disagreement over a sink block: its
// retain_until is not after the seal record's own time. Both readers wrap it
// in a FaultManifest directly, so the text is the same byte for byte.
func sinkRetainErr(s *SealSink, sealTime time.Time) error {
	return fmt.Errorf("sink.retain_until %s recorded, not after the seal's time %s", s.RetainUntil.UTC().Format(time.RFC3339), sealTime.UTC().Format(time.RFC3339))
}
