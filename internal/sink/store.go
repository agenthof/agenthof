package sink

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// objectStore is the transport line: the five storage operations the sink
// logic needs, in storage-neutral terms. Nothing of HTTP, XML or SigV4
// crosses it, and no write-once rule lives below it — an implementation
// stores and reports, the logic above decides. sigv4Store is the shipped
// implementation; a vendor client (minio-go: PutObject with a retention
// mode, GetObject, GetObjectRetention, GetBucketObjectLockConfig,
// ListObjects with versions) is the intended second, and the in-memory
// store the logic tests use is the proof the line is neutral.
type objectStore interface {
	// putLocked writes body at key under the given retention mode and date
	// and returns the version id the store minted — "" when the store did
	// not version the write (versioning off), which the logic treats as
	// unconfirmed. Integrity headers are the implementation's own concern.
	putLocked(ctx context.Context, key string, body []byte, mode string, until time.Time) (versionID string, err error)
	// get reads one version whole; a body over max bytes is errObjectTooLarge.
	get(ctx context.Context, key, versionID string, max int64) ([]byte, error)
	// retention reports a version's lock; a version with no lock is the zero
	// lock and no error.
	retention(ctx context.Context, key, versionID string) (lock, error)
	// lockEnabled reports whether the bucket has Object Lock enabled; a
	// bucket with no lock configuration is false and no error.
	lockEnabled(ctx context.Context) (bool, error)
	// listVersions returns every version and delete marker under prefix, as
	// the store lists them: grouped by key, and within a key newest first.
	// A key's versions may be split across the store's pages; the
	// implementation joins them.
	listVersions(ctx context.Context, prefix string) ([]objectVersion, error)
}

// lock is a version's retention as the store reports it. Mode is
// "COMPLIANCE", "GOVERNANCE" or "" (no lock).
type lock struct {
	Mode        string
	RetainUntil time.Time
}

// objectVersion is one listing entry: a version or a delete marker.
type objectVersion struct {
	Key          string
	ID           string
	IsLatest     bool
	DeleteMarker bool
	Size         int64
	LastModified time.Time
}

// errObjectTooLarge is get's answer for a body over its bound.
var errObjectTooLarge = errors.New("object exceeds the read bound")

// StatusError is a store's refusal of one operation: the status it answered,
// the host, and the error code when the body carried one. Op is the S3
// operation name ("GetObjectRetention" …); it is the same vocabulary for
// any implementation.
type StatusError struct {
	Op     string
	Status int
	Host   string
	Code   string
}

// Error is "status 403 AccessDenied from <host> (<op>)", the code omitted
// when the body carried none.
func (e *StatusError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("status %d from %s (%s)", e.Status, e.Host, e.Op)
	}
	return fmt.Sprintf("status %d %s from %s (%s)", e.Status, e.Code, e.Host, e.Op)
}

// ErrClockSkew is the cause when the store answered RequestTimeTooSkewed:
// the signature was fine, this machine's clock is not. Never reported as a
// credential failure.
var ErrClockSkew = errors.New("clock skew: the sink answered RequestTimeTooSkewed — this machine's clock is more than 15 minutes off")
