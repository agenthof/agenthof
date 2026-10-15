package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/agenthof/agenthof/internal/ledger"
)

// ManifestVersion is the manifest's shape version (Article VI: the control/1,
// files/v1, investigate/1 convention). Unknown values are refused.
const ManifestVersion = "segments/1"

// Manifest is <controlLog>.segments: the ordered list of sealed segments with
// their Starts, heads and content hashes. It is an advisory index and the
// list a future worm sink ships; every value in it is recomputed from the
// files on every read and any disagreement refuses the read. It is never
// edited in place: written whole by temp+fsync+rename.
type Manifest struct {
	V        string          `json:"v"`
	LogID    string          `json:"log_id"`
	Segments []ManifestEntry `json:"segments"`
}

// ManifestEntry describes one sealed segment. File is the base name, pinned
// to filepath.Base(SegmentPath(resolved, n)) — descriptive, never a
// redirection. SHA256 is the whole file including the seal line: the unit's
// identity. SealedAt is the seal record's time (informational; the record is
// the authority). The reserved keys removed_at (retention pruning) and object
// (a remote locator) are refused when present, like every unknown key.
type ManifestEntry struct {
	N        int       `json:"n"`
	File     string    `json:"file"`
	FirstSeq int       `json:"first_seq"`
	HeadSeq  int       `json:"head_seq"`
	HeadHash string    `json:"head_hash"`
	SHA256   string    `json:"sha256"`
	Bytes    int64     `json:"bytes"`
	SealedAt time.Time `json:"sealed_at"`
}

// ParseManifest decodes and validates a manifest for the ledger whose
// RESOLVED active path is resolved. Unknown keys at any level, an unknown v,
// a log_id that is not 32 lowercase hex, an n that is not its position+1, a
// file that is not exactly Base(SegmentPath(resolved, n)), a first_seq that
// does not continue the previous head_seq (1 for the first), a head_seq
// below first_seq, a hash that is not 64 lowercase hex, or non-positive
// bytes each fail naming the field. Cross-checks against the files are
// Read's, not this function's.
func ParseManifest(data []byte, resolved string) (Manifest, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("manifest: %w", err)
	}
	if dec.More() {
		return Manifest{}, errors.New("manifest: trailing data after the object")
	}
	if m.V != ManifestVersion {
		return Manifest{}, fmt.Errorf("manifest: v %q is not %s", m.V, ManifestVersion)
	}
	if !genesisLogIDRE.MatchString(m.LogID) {
		return Manifest{}, errors.New("manifest: log_id is not 32 lowercase hex")
	}
	prevHead := 0
	for i, e := range m.Segments {
		n := i + 1
		switch {
		case e.N != n:
			return Manifest{}, fmt.Errorf("manifest: segments[%d] n %d is not %d", i, e.N, n)
		case e.File != filepath.Base(SegmentPath(resolved, n)):
			return Manifest{}, fmt.Errorf("manifest: segment %d file %q is not %s", n, e.File, filepath.Base(SegmentPath(resolved, n)))
		case e.FirstSeq != prevHead+1:
			return Manifest{}, fmt.Errorf("manifest: segment %d first_seq %d does not continue from %d", n, e.FirstSeq, prevHead)
		case e.HeadSeq < e.FirstSeq:
			return Manifest{}, fmt.Errorf("manifest: segment %d head_seq %d is below first_seq %d", n, e.HeadSeq, e.FirstSeq)
		case !anchorHashRE.MatchString(e.HeadHash):
			return Manifest{}, fmt.Errorf("manifest: segment %d head_hash is not a lowercase hex sha256", n)
		case !anchorHashRE.MatchString(e.SHA256):
			return Manifest{}, fmt.Errorf("manifest: segment %d sha256 is not a lowercase hex sha256", n)
		case e.Bytes <= 0:
			return Manifest{}, fmt.Errorf("manifest: segment %d bytes %d", n, e.Bytes)
		}
		prevHead = e.HeadSeq
	}
	return m, nil
}

// loadManifest reads the manifest beside resolved: (nil, nil) when absent;
// a *SetError{FaultManifest, Segment 0} when present and unusable.
func loadManifest(resolved string) (*Manifest, error) {
	path := ManifestPath(resolved)
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, &SetError{Fault: FaultManifest, Path: path, Err: err}
	}
	m, err := ParseManifest(data, resolved)
	if err != nil {
		return nil, &SetError{Fault: FaultManifest, Path: path, Err: err}
	}
	return &m, nil
}

// segmentDigests is the per-line hasher the reader and the writer share: for
// a chain that verified, the file's bytes are exactly each record's Raw plus
// '\n', so whole is sha256 over every line given (over a sealed segment's
// records, seal line included, it is the manifest's sha256) and size is their
// length. A second SHA-256 pass over bytes already in memory — one read of
// the file, stated plainly.
func segmentDigests(records []ledger.Record) (whole string, size int64) {
	h := sha256.New()
	for _, r := range records {
		_, _ = h.Write(r.Raw)
		_, _ = h.Write([]byte{'\n'})
		size += int64(len(r.Raw)) + 1
	}
	return hex.EncodeToString(h.Sum(nil)), size
}

// sealContentDigest is the seal payload's content_sha256: sha256 of every
// byte of the segment BEFORE the seal line, newlines included — which is
// segmentDigests' whole digest over the records the seal closes, the seal
// record itself excluded. The recipe for a writer about to seal an active
// with records R: content_sha256 = sealContentDigest(R); the manifest's
// sha256 is then segmentDigests(append(R, sealLine)). A reader hands it the
// segment's records with the seal line sliced off; both sides call this one
// function, so neither can hash one line too few or too many.
func sealContentDigest(preSeal []ledger.Record) string {
	whole, _ := segmentDigests(preSeal)
	return whole
}
