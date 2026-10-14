package anchortest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/agenthof/agenthof/internal/anchor"
	"github.com/transparency-dev/merkle"
	"github.com/transparency-dev/merkle/rfc6962"
)

// Sentinel is placed in every failure body and Location header the fake
// emits, so a test can assert a client never echoes response text.
const Sentinel = "SENTINEL-NEVER-ON-A-RECORD"

// RekorV1 is an httptest fake of the Rekor v1 API: POST /api/v1/log/entries
// (hashedrekord 0.0.1 only), GET /api/v1/log/entries/{entryUUID}, GET
// /api/v1/log/publicKey. It keeps an in-memory RFC 6962 tree, signs real
// checkpoints with its own ECDSA P-256 key in the exact sumdb note format
// Rekor uses, and exposes switches that drive every failure the client must
// classify. One fake per test or per script: the switches are global to it.
type RekorV1 struct {
	URL    string
	server *httptest.Server
	treeID uint64

	mu          sync.Mutex
	priv        *ecdsa.PrivateKey
	hostname    string
	leaves      [][]byte         // entry bodies in log order
	index       map[string]int   // entryID → leaf index
	integrated  map[string]int64 // entryID → integratedTime (unix seconds)
	corrupt     map[string]bool
	forgotten   map[string]bool
	requests    []string
	lastPosted  []byte
	failNext    int
	corruptNext bool
	garbageNext bool
	dropping    bool // Drop/Stop: close every connection until Start
	delay       time.Duration
	cosign      bool
	pad         int
}

// NewRekorV1 starts a fake with a fresh key, tree id 1193050959916656506 and
// hostname "rekor.test".
func NewRekorV1() *RekorV1 {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err) // test-only; crypto/rand failing is not a case to model
	}
	f := &RekorV1{treeID: 1193050959916656506, priv: priv, hostname: "rekor.test",
		index: map[string]int{}, integrated: map[string]int64{}, corrupt: map[string]bool{}, forgotten: map[string]bool{}}
	f.server = httptest.NewServer(http.HandlerFunc(f.handle))
	f.URL = f.server.URL
	return f
}

// Close shuts the fake's server down.
func (f *RekorV1) Close() { f.server.Close() }

// Switches. Each takes the lock; the handler reads them once per request.

// Fail makes the NEXT request answer status, with Sentinel in the body and Location.
func (f *RekorV1) Fail(status int) { f.mu.Lock(); f.failNext = status; f.mu.Unlock() }

// CorruptNext makes the next 201 serve a body whose hash differs from its entry id.
func (f *RekorV1) CorruptNext() { f.mu.Lock(); f.corruptNext = true; f.mu.Unlock() }

// GarbageNext makes the NEXT request answer 200 with Sentinel as a non-JSON body.
func (f *RekorV1) GarbageNext() { f.mu.Lock(); f.garbageNext = true; f.mu.Unlock() }

// Drop closes every connection without a response until Start. It is sticky
// because Go's transport retries an idempotent request whose reused
// connection closed.
func (f *RekorV1) Drop() { f.mu.Lock(); f.dropping = true; f.mu.Unlock() }

// Stop is Drop's synonym, for scripts that read "the log is down".
func (f *RekorV1) Stop() { f.Drop() }

// Start undoes Drop and Stop.
func (f *RekorV1) Start() { f.mu.Lock(); f.dropping = false; f.mu.Unlock() }

// Delay holds every request for d before answering.
func (f *RekorV1) Delay(d time.Duration) { f.mu.Lock(); f.delay = d; f.mu.Unlock() }

// Corrupt makes GET of entryID serve a body whose leaf hash differs.
func (f *RekorV1) Corrupt(entryID string) { f.mu.Lock(); f.corrupt[entryID] = true; f.mu.Unlock() }

// Forget makes GET of entryID answer 404.
func (f *RekorV1) Forget(entryID string) { f.mu.Lock(); f.forgotten[entryID] = true; f.mu.Unlock() }

// Cosign adds a second signature line, under an unrelated key, to every checkpoint.
func (f *RekorV1) Cosign() { f.mu.Lock(); f.cosign = true; f.mu.Unlock() }

// SetHostname changes the checkpoint origin's hostname.
func (f *RekorV1) SetHostname(s string) { f.mu.Lock(); f.hostname = s; f.mu.Unlock() }

// PadProof appends n extra 64-hex hashes to every proof, to exceed MaxProofLen.
func (f *RekorV1) PadProof(n int) { f.mu.Lock(); f.pad = n; f.mu.Unlock() }

// RotateKey replaces the log's signing key; later checkpoints and the served
// public key use the new one.
func (f *RekorV1) RotateKey() {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	f.mu.Lock()
	f.priv = priv
	f.mu.Unlock()
}

// Reset clears every switch and the request log; the tree and key stay.
func (f *RekorV1) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failNext, f.corruptNext, f.garbageNext, f.dropping, f.delay, f.cosign, f.pad = 0, false, false, false, 0, false, 0
	f.corrupt, f.forgotten, f.requests = map[string]bool{}, map[string]bool{}, nil
}

// Requests returns the request log, one "METHOD /path" per request.
func (f *RekorV1) Requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...)
}

// LastProposed returns the raw body of the last POST.
func (f *RekorV1) LastProposed() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]byte(nil), f.lastPosted...)
}

// Entries returns the number of entries in the tree.
func (f *RekorV1) Entries() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.leaves) }

// TreeID returns the log's tree id.
func (f *RekorV1) TreeID() uint64 { return f.treeID }

// PublicKey returns the key the log currently signs with.
func (f *RekorV1) PublicKey() *ecdsa.PublicKey {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &f.priv.PublicKey
}

// PrivateKey returns the key the log currently signs with, so a test can
// forge an honestly signed checkpoint.
func (f *RekorV1) PrivateKey() *ecdsa.PrivateKey {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.priv
}

// PublicKeyPEM returns the current key as a PEM "PUBLIC KEY" block.
func (f *RekorV1) PublicKeyPEM() []byte {
	der, err := x509.MarshalPKIXPublicKey(f.PublicKey())
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// SignNote signs text as Rekor signs a checkpoint: "— <name> " +
// base64(keyhash ‖ ASN.1 ECDSA signature over sha256(text)), appended after a
// blank line. Exported so a test can forge a checkpoint under a key of its
// choosing.
func SignNote(priv *ecdsa.PrivateKey, name, text string) ([]byte, error) {
	h, err := anchor.KeyHash(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	d := sha256.Sum256([]byte(text))
	sig, err := ecdsa.SignASN1(rand.Reader, priv, d[:])
	if err != nil {
		return nil, err
	}
	var hb [4]byte
	binary.BigEndian.PutUint32(hb[:], h)
	return []byte("— " + name + " " + base64.StdEncoding.EncodeToString(append(hb[:], sig...)) + "\n"), nil
}

// FlipSignature flips the final byte of the decoded signature on the note's
// last signature line — past the 4-byte key hash — and re-encodes it, so the
// key hash still matches and only the signature is wrong. (Flipping a base64
// character instead can yield an invalid character and a malformed note.)
func FlipSignature(msg []byte) ([]byte, error) {
	i := bytes.LastIndex(msg, []byte("\n— "))
	if i < 0 || !bytes.HasSuffix(msg, []byte("\n")) {
		return nil, errors.New("no signature line")
	}
	name, b64, ok := strings.Cut(strings.TrimPrefix(string(msg[i+1:len(msg)-1]), "— "), " ")
	if !ok {
		return nil, errors.New("malformed signature line")
	}
	sig, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	if len(sig) <= 4 {
		return nil, errors.New("signature is too short to flip")
	}
	sig[len(sig)-1] ^= 0x01
	return append(msg[:i+1:i+1], []byte("— "+name+" "+base64.StdEncoding.EncodeToString(sig)+"\n")...), nil
}

// --- RFC 6962 tree math (RFC 6962 §2.1), recursive, fine for test sizes ---

func largestPowerOfTwoBelow(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

func mth(h merkle.LogHasher, leaves [][]byte) []byte {
	switch len(leaves) {
	case 0:
		return h.EmptyRoot()
	case 1:
		return h.HashLeaf(leaves[0])
	}
	k := largestPowerOfTwoBelow(len(leaves))
	return h.HashChildren(mth(h, leaves[:k]), mth(h, leaves[k:]))
}

// inclusionPath is PATH(m, D[n]): the sibling hashes from leaf m to the root.
func inclusionPath(h merkle.LogHasher, leaves [][]byte, m int) [][]byte {
	n := len(leaves)
	if n <= 1 {
		return nil
	}
	k := largestPowerOfTwoBelow(n)
	if m < k {
		return append(inclusionPath(h, leaves[:k], m), mth(h, leaves[k:]))
	}
	return append(inclusionPath(h, leaves[k:], m-k), mth(h, leaves[:k]))
}

// --- wire shapes (Rekor v1 openapi.yaml) ---

type proposedEntry struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       struct {
		Data struct {
			Hash struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"value"`
			} `json:"hash"`
		} `json:"data"`
		Signature struct {
			Content   string `json:"content"`
			PublicKey struct {
				Content string `json:"content"`
			} `json:"publicKey"`
		} `json:"signature"`
	} `json:"spec"`
}

type inclusionProof struct {
	Checkpoint string   `json:"checkpoint"`
	Hashes     []string `json:"hashes"`
	LogIndex   int64    `json:"logIndex"`
	RootHash   string   `json:"rootHash"`
	TreeSize   int64    `json:"treeSize"`
}

type logEntryAnon struct {
	Body           string `json:"body"`
	IntegratedTime int64  `json:"integratedTime"`
	LogID          string `json:"logID"`
	LogIndex       int64  `json:"logIndex"`
	Verification   struct {
		InclusionProof       inclusionProof `json:"inclusionProof"`
		SignedEntryTimestamp string         `json:"signedEntryTimestamp"`
	} `json:"verification"`
}

func (f *RekorV1) entryID(leaf []byte) string {
	return fmt.Sprintf("%016x", f.treeID) + hex.EncodeToString(leaf)
}

// checkpoint signs the current tree head: "<hostname> - <treeID>\n<size>\n<b64 root>\n",
// a blank line, the log's signature line and, when Cosign is set, a witness
// line under an unrelated key. Caller holds the lock.
func (f *RekorV1) checkpoint(root []byte) (string, error) {
	text := fmt.Sprintf("%s - %d\n%d\n%s\n", f.hostname, f.treeID, len(f.leaves), base64.StdEncoding.EncodeToString(root))
	line, err := SignNote(f.priv, f.hostname, text)
	if err != nil {
		return "", err
	}
	out := text + "\n" + string(line)
	if f.cosign {
		witness, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return "", err
		}
		wl, err := SignNote(witness, "witness.test", text)
		if err != nil {
			return "", err
		}
		out += string(wl)
	}
	return out, nil
}

// entry renders the LogEntryAnon for leaf i with a fresh proof over the
// current tree. Caller holds the lock.
func (f *RekorV1) entry(i int) (logEntryAnon, error) {
	h := rfc6962.DefaultHasher
	body := f.leaves[i]
	root := mth(h, f.leaves)
	var hashes []string
	for _, p := range inclusionPath(h, f.leaves, i) {
		hashes = append(hashes, hex.EncodeToString(p))
	}
	for k := 0; k < f.pad; k++ {
		hashes = append(hashes, strings.Repeat("00", 32))
	}
	cp, err := f.checkpoint(root)
	if err != nil {
		return logEntryAnon{}, err
	}
	keyID, err := anchor.KeyID(&f.priv.PublicKey)
	if err != nil {
		return logEntryAnon{}, err
	}
	id := f.entryID(h.HashLeaf(body))
	e := logEntryAnon{Body: base64.StdEncoding.EncodeToString(body), IntegratedTime: f.integrated[id], LogID: keyID, LogIndex: int64(i)}
	e.Verification.InclusionProof = inclusionProof{Checkpoint: cp, Hashes: hashes, LogIndex: int64(i), RootHash: hex.EncodeToString(root), TreeSize: int64(len(f.leaves))}
	e.Verification.SignedEntryTimestamp = base64.StdEncoding.EncodeToString([]byte("not-verified-by-this-build"))
	return e, nil
}

func (f *RekorV1) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	drop, fail, delay, garbage := f.dropping, f.failNext, f.delay, f.garbageNext
	f.failNext, f.garbageNext = 0, false
	f.mu.Unlock()

	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
	}
	if drop {
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				_ = conn.Close()
				return
			}
		}
		panic(http.ErrAbortHandler)
	}
	if fail != 0 {
		w.Header().Set("Location", Sentinel)
		w.WriteHeader(fail)
		_, _ = io.WriteString(w, Sentinel)
		return
	}
	if garbage {
		_, _ = io.WriteString(w, Sentinel)
		return
	}

	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/log/entries":
		if !acceptsJSON(r) {
			notAcceptable(w)
			return
		}
		f.create(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/log/entries/"):
		if !acceptsJSON(r) {
			notAcceptable(w)
			return
		}
		f.get(w, strings.TrimPrefix(r.URL.Path, "/api/v1/log/entries/"))
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/log/publicKey":
		// The publicKey endpoint produces application/x-pem-file only.
		// go-swagger content negotiation answers an Accept: application/json
		// request by JSON-encoding the PEM as a string (which a PEM parser
		// rejects) — faithfully reproduced so a client that asks for the
		// wrong media type is caught by the hermetic suite, not only against
		// the live log.
		if r.Header.Get("Accept") == "application/json" {
			w.Header().Set("Content-Type", "application/json")
			enc, _ := json.Marshal(string(f.PublicKeyPEM()))
			_, _ = w.Write(enc)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(f.PublicKeyPEM())
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/log":
		f.mu.Lock()
		root := mth(rfc6962.DefaultHasher, f.leaves)
		n := len(f.leaves)
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"rootHash": hex.EncodeToString(root), "treeSize": n, "treeID": fmt.Sprint(f.treeID)})
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, Sentinel)
	}
}

// acceptsJSON reports whether the request's Accept header allows the JSON the
// entries endpoints produce. An absent Accept and */* both pass, matching
// go-swagger's default negotiation; any other concrete type is refused 406.
func acceptsJSON(r *http.Request) bool {
	switch r.Header.Get("Accept") {
	case "", "application/json", "*/*":
		return true
	default:
		return false
	}
}

func notAcceptable(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotAcceptable)
	_, _ = io.WriteString(w, `{"code":406,"message":"not acceptable"}`)
}

// create validates the hashedrekord (kind, version, sha256 hex, a PEM PKIX
// ECDSA key, an ASN.1 signature over the digest), canonicalizes the body by
// re-marshalling the decoded struct, appends the leaf and answers 201 with
// ETag, Location and the single-key LogEntry map — the inclusion proof
// included, as Rekor's createLogEntry attaches it.
func (f *RekorV1) create(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, Sentinel, http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.lastPosted = raw
	f.mu.Unlock()

	var pe proposedEntry
	if err := json.Unmarshal(raw, &pe); err != nil || pe.Kind != "hashedrekord" || pe.APIVersion != "0.0.1" || pe.Spec.Data.Hash.Algorithm != "sha256" {
		http.Error(w, Sentinel, http.StatusBadRequest)
		return
	}
	digest, err := hex.DecodeString(pe.Spec.Data.Hash.Value)
	if err != nil || len(digest) != 32 {
		http.Error(w, Sentinel, http.StatusBadRequest)
		return
	}
	sig, err := base64.StdEncoding.DecodeString(pe.Spec.Signature.Content)
	if err != nil {
		http.Error(w, Sentinel, http.StatusBadRequest)
		return
	}
	pemBytes, err := base64.StdEncoding.DecodeString(pe.Spec.Signature.PublicKey.Content)
	if err != nil {
		http.Error(w, Sentinel, http.StatusBadRequest)
		return
	}
	pub, err := anchor.ParseLogKey(pemBytes) // the same PKIX P-256 shape; the fake accepts only what the client is meant to send
	if err != nil || !ecdsa.VerifyASN1(pub, digest, sig) {
		http.Error(w, Sentinel, http.StatusBadRequest)
		return
	}
	body, err := json.Marshal(pe) // the fake's canonical form; the client never re-canonicalizes
	if err != nil {
		http.Error(w, Sentinel, http.StatusInternalServerError)
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	id := f.entryID(rfc6962.DefaultHasher.HashLeaf(body))
	f.leaves = append(f.leaves, body)
	f.index[id] = len(f.leaves) - 1
	f.integrated[id] = time.Now().Unix()
	e, err := f.entry(len(f.leaves) - 1)
	if err != nil {
		http.Error(w, Sentinel, http.StatusInternalServerError)
		return
	}
	if f.corruptNext {
		f.corruptNext = false
		e.Body = base64.StdEncoding.EncodeToString(corruptBody(body))
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", id[16:])
	w.Header().Set("Location", "/api/v1/log/entries/"+id)
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]logEntryAnon{id: e})
}

// corruptBody flips one byte inside the hash value so the body still parses
// but hashes to another leaf.
func corruptBody(body []byte) []byte {
	out := append([]byte(nil), body...)
	i := strings.Index(string(out), `"value":"`) + len(`"value":"`)
	if out[i] == '0' {
		out[i] = '1'
	} else {
		out[i] = '0'
	}
	return out
}

func (f *RekorV1) get(w http.ResponseWriter, id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	i, ok := f.index[id]
	if !ok || f.forgotten[id] {
		// Rekor v1 answers a genuinely absent entry with a bodyless 404
		// (getLogEntryByUUID's 404 carries no schema). The client treats any
		// 404 as unverifiable, not as tampering.
		w.WriteHeader(http.StatusNotFound)
		return
	}
	e, err := f.entry(i)
	if err != nil {
		http.Error(w, Sentinel, http.StatusInternalServerError)
		return
	}
	if f.corrupt[id] {
		e.Body = base64.StdEncoding.EncodeToString(corruptBody(f.leaves[i]))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]logEntryAnon{id: e})
}
