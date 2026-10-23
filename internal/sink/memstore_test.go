package sink

import (
	"bytes"
	"context"
	"strconv"
	"strings"
	"time"
)

// memStore is an in-memory objectStore: the second implementation of the
// transport line, and the proof that nothing of HTTP crosses it. The logic
// tests run over it with no network. Versions are kept newest first, as a
// store lists them; delete markers are versions with Marker set.
type memStore struct {
	lockOff    bool             // the bucket has no Object Lock configuration
	versionOff bool             // a put answers with no version id and applies no lock
	fail       map[string]error // op → error ("put", "get", "retention", "lock", "list")
	next       int
	objects    map[string][]memVersion
	ops        []string // "<op> <key>" in call order
}

type memVersion struct {
	id     string
	data   []byte
	lock   lock
	marker bool
	at     time.Time
}

func newMemStore() *memStore { return &memStore{objects: map[string][]memVersion{}} }

var _ objectStore = (*memStore)(nil)

// plant adds a version outside any seal and returns its id.
func (m *memStore) plant(key string, data []byte, mode string, until time.Time) string {
	return m.add(key, memVersion{data: bytes.Clone(data), lock: lock{Mode: mode, RetainUntil: until}})
}

func (m *memStore) marker(key string) { m.add(key, memVersion{marker: true}) }

func (m *memStore) add(key string, v memVersion) string {
	m.next++
	v.id = "v-" + strconv.Itoa(m.next)
	v.at = time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC).Add(time.Duration(m.next) * time.Second)
	m.objects[key] = append([]memVersion{v}, m.objects[key]...)
	return v.id
}

func (m *memStore) record(op, key string) error {
	m.ops = append(m.ops, strings.TrimSpace(op+" "+key))
	return m.fail[op]
}

func (m *memStore) count(op string) int {
	n := 0
	for _, o := range m.ops {
		if strings.HasPrefix(o, op+" ") || o == op {
			n++
		}
	}
	return n
}

func (m *memStore) putLocked(_ context.Context, key string, body []byte, mode string, until time.Time) (string, error) {
	if err := m.record("put", key); err != nil {
		return "", err
	}
	if m.versionOff {
		m.objects[key] = []memVersion{{id: "null", data: bytes.Clone(body)}}
		return "", nil
	}
	return m.add(key, memVersion{data: bytes.Clone(body), lock: lock{Mode: mode, RetainUntil: until}}), nil
}

func (m *memStore) find(key, id string) (memVersion, bool) {
	for _, v := range m.objects[key] {
		if v.id == id {
			return v, true
		}
	}
	return memVersion{}, false
}

func (m *memStore) get(_ context.Context, key, versionID string, max int64) ([]byte, error) {
	if err := m.record("get", key); err != nil {
		return nil, err
	}
	v, ok := m.find(key, versionID)
	if !ok || v.marker {
		return nil, &StatusError{Op: "GetObject", Status: 404, Host: "mem", Code: "NoSuchVersion"}
	}
	if int64(len(v.data)) > max {
		return nil, errObjectTooLarge
	}
	return bytes.Clone(v.data), nil
}

func (m *memStore) retention(_ context.Context, key, versionID string) (lock, error) {
	if err := m.record("retention", key); err != nil {
		return lock{}, err
	}
	v, ok := m.find(key, versionID)
	if !ok || v.marker {
		return lock{}, &StatusError{Op: "GetObjectRetention", Status: 404, Host: "mem", Code: "NoSuchVersion"}
	}
	return v.lock, nil
}

func (m *memStore) lockEnabled(context.Context) (bool, error) {
	if err := m.record("lock", ""); err != nil {
		return false, err
	}
	return !m.lockOff, nil
}

func (m *memStore) listVersions(_ context.Context, prefix string) ([]objectVersion, error) {
	if err := m.record("list", prefix); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(m.objects))
	for k := range m.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	// Key order, newest first within a key: the order S3 serves.
	for i := range keys {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	var out []objectVersion
	for _, k := range keys {
		for i, v := range m.objects[k] {
			out = append(out, objectVersion{Key: k, ID: v.id, IsLatest: i == 0, DeleteMarker: v.marker, Size: int64(len(v.data)), LastModified: v.at})
		}
	}
	return out, nil
}

// blockingStore is an objectStore whose every call waits for the context:
// the per-call timeout's test.
type blockingStore struct{ memStore }

func (b *blockingStore) lockEnabled(ctx context.Context) (bool, error) {
	<-ctx.Done()
	return false, ctx.Err()
}
