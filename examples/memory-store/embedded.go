package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
)

// embeddedMaxEntries is the hard cap on records across all collections.
const embeddedMaxEntries = 10000

// storeFile is the on-disk shape. The collection is a map key, never a path.
type storeFile struct {
	Collections map[string]*storeCollection `json:"collections"`
}

type storeCollection struct {
	Dim     int           `json:"dim"`
	Records []storeRecord `json:"records"`
}

// storeRecord keeps the caller's id and the caller's metadata as separate
// fields. Meta is held as a string so the caller's bytes survive untouched.
type storeRecord struct {
	ID       string    `json:"id"`
	CallerID string    `json:"caller_id,omitempty"`
	Vec      []float32 `json:"vec"`
	Text     string    `json:"text"`
	Meta     string    `json:"meta,omitempty"`
}

// embeddedBackend is a brute-force cosine store over a single file. Every
// operation takes an exclusive flock on the never-renamed sidecar
// "<store>.lock", reloads the file under it, and rewrites it atomically.
type embeddedBackend struct {
	path       string
	maxEntries int
	mu         sync.Mutex // queues this process's operations instead of having each block a thread inside flock; the per-operation flock is what excludes other holders
}

func newEmbeddedBackend(storeFile string, maxEntries int) *embeddedBackend {
	return &embeddedBackend{path: storeFile, maxEntries: maxEntries}
}

// lock takes the process mutex and the cross-process flock. The returned
// func releases both. The flock wait does not honor ctx cancellation: a hung
// peer holding the lock blocks the caller, and a cancelled ctx surfaces as
// ErrBackendUnavailable only before the wait. Acceptable for a reference store.
func (b *embeddedBackend) lock() (func(), error) {
	b.mu.Lock()
	if err := os.MkdirAll(filepath.Dir(b.path), 0o700); err != nil {
		b.mu.Unlock()
		return nil, ErrBackendUnavailable
	}
	f, err := os.OpenFile(b.path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		b.mu.Unlock()
		return nil, ErrBackendUnavailable
	}
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if !errors.Is(err, syscall.EINTR) {
			break
		}
	}
	if err != nil {
		_ = f.Close()
		b.mu.Unlock()
		return nil, ErrBackendUnavailable
	}
	return func() {
		// Closing the descriptor releases the flock.
		_ = f.Close()
		b.mu.Unlock()
	}, nil
}

// load reads the store. A missing file is an empty store; an empty or
// unparseable file is ErrStoreCorrupt so it is never overwritten.
func (b *embeddedBackend) load() (*storeFile, error) {
	data, err := os.ReadFile(b.path)
	if errors.Is(err, os.ErrNotExist) {
		return &storeFile{Collections: map[string]*storeCollection{}}, nil
	}
	if err != nil {
		return nil, ErrBackendUnavailable
	}
	var s storeFile
	if len(data) == 0 || json.Unmarshal(data, &s) != nil || s.Collections == nil {
		return nil, ErrStoreCorrupt
	}
	for _, c := range s.Collections {
		if c == nil {
			return nil, ErrStoreCorrupt
		}
		for _, r := range c.Records {
			if len(r.Vec) != c.Dim {
				return nil, ErrStoreCorrupt
			}
		}
	}
	return &s, nil
}

// save writes the store through a per-process-unique temp: fsync the file,
// rename it over the store, fsync the directory. The caller holds the lock.
func (b *embeddedBackend) save(s *storeFile) error {
	data, err := json.Marshal(s)
	if err != nil {
		return ErrBackendUnavailable
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return ErrBackendUnavailable
	}
	tmp := fmt.Sprintf("%s.tmp.%d.%s", b.path, os.Getpid(), hex.EncodeToString(nonce[:]))
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return ErrBackendUnavailable
	}
	_, werr := f.Write(data)
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil || serr != nil || cerr != nil {
		_ = os.Remove(tmp)
		return ErrBackendUnavailable
	}
	if err := os.Rename(tmp, b.path); err != nil {
		_ = os.Remove(tmp)
		return ErrBackendUnavailable
	}
	d, err := os.Open(filepath.Dir(b.path))
	if err != nil {
		return ErrBackendUnavailable
	}
	serr = d.Sync()
	cerr = d.Close()
	if serr != nil || cerr != nil {
		return ErrBackendUnavailable
	}
	return nil
}

// sweepTemps removes temps left by a crashed writer. Only call it while
// holding the exclusive lock: every writer holds that lock for the life of its
// temp, so any temp seen here is stale.
func (b *embeddedBackend) sweepTemps() {
	// A literal prefix match, never a glob: the store path may itself contain
	// glob metacharacters.
	dir, prefix := filepath.Dir(b.path), filepath.Base(b.path)+".tmp."
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

func (b *embeddedBackend) Upsert(ctx context.Context, collection, id, callerID string, vec []float32, text string, meta json.RawMessage) error {
	if err := ctx.Err(); err != nil {
		return ErrBackendUnavailable
	}
	unlock, err := b.lock()
	if err != nil {
		return err
	}
	defer unlock()
	b.sweepTemps()

	s, err := b.load()
	if err != nil {
		return err
	}
	c := s.Collections[collection]
	if c == nil {
		c = &storeCollection{Dim: len(vec)}
		s.Collections[collection] = c
	} else if c.Dim != len(vec) {
		return ErrDimensionMismatch
	}
	rec := storeRecord{ID: id, CallerID: callerID, Vec: append([]float32(nil), vec...), Text: text, Meta: string(meta)}
	replaced := false
	for i := range c.Records {
		if c.Records[i].ID == id {
			c.Records[i] = rec
			replaced = true
			break
		}
	}
	if !replaced {
		total := 0
		for _, cc := range s.Collections {
			total += len(cc.Records)
		}
		if total >= b.maxEntries {
			return ErrEntryCap
		}
		c.Records = append(c.Records, rec)
	}
	return b.save(s)
}

func (b *embeddedBackend) Search(ctx context.Context, collection string, vec []float32, k int) ([]Hit, error) {
	if err := ctx.Err(); err != nil {
		return nil, ErrBackendUnavailable
	}
	unlock, err := b.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()

	s, err := b.load()
	if err != nil {
		return nil, err
	}
	c := s.Collections[collection]
	if c == nil {
		return nil, nil
	}
	if c.Dim != len(vec) {
		return nil, ErrDimensionMismatch
	}
	hits := make([]Hit, 0, len(c.Records))
	for _, r := range c.Records {
		h := Hit{ID: r.ID, Score: cosine(vec, r.Vec), Text: r.Text}
		if r.Meta != "" {
			h.Metadata = json.RawMessage(r.Meta)
		}
		hits = append(hits, h)
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Score != hits[j].Score {
			return hits[i].Score > hits[j].Score
		}
		return hits[i].ID < hits[j].ID
	})
	if k >= 0 && len(hits) > k {
		hits = hits[:k]
	}
	return hits, nil
}

// cosine is computed entirely in float64 so large finite float32 components
// cannot overflow the dot product; a zero-norm vector scores 0.
func cosine(a, b []float32) float32 {
	var dot, na, nb float64
	for i := range a {
		x, y := float64(a[i]), float64(b[i])
		dot += x * y
		na += x * x
		nb += y * y
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return float32(dot / (math.Sqrt(na) * math.Sqrt(nb)))
}
