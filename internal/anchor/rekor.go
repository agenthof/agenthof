package anchor

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/note"
)

// Rekor is the transparency-log Backend over the Rekor v1 REST API: it
// submits a hashedrekord for the head's hash under an ephemeral ECDSA P-256
// key, verifies the inclusion proof the log returns, and keeps that proof and
// the signed checkpoint in the Receipt so every anchor verifies offline under
// a key the verifier trusts.
type Rekor struct {
	url     string // absolute, one trailing slash trimmed; Receipt.Backend
	host    string // for error texts: never a path, never a body
	client  *http.Client
	key     *ecdsa.PublicKey // pinned log key; nil = as served
	bearer  func(context.Context) (string, error)
	offline bool
}

// RekorOptions configures a Rekor. Client nil uses a fresh http.Client over
// the default transport; whatever client is given is copied and never follows
// a redirect. Key nil means "as served": the key the log presents for the
// entry's tree is fetched and its id recorded. Bearer nil means anonymous
// (the public-good log). Offline makes Verify fetch nothing — no served key,
// no presence check — so an unpinned Rekor can verify nothing offline.
type RekorOptions struct {
	Client  *http.Client
	Key     *ecdsa.PublicKey
	Bearer  func(ctx context.Context) (string, error)
	Offline bool
}

// maxBody bounds any response body this client reads: 1 MiB. A Rekor entry
// with its proof is a few KB; anything larger is not a Rekor answer.
const maxBody = 1 << 20

// parseBackendURL admits an absolute http or https URL with a host and no
// userinfo, query or fragment, and trims one trailing slash. The URL on a
// record comes from a possibly hostile ledger, so Verify re-checks it too.
func parseBackendURL(s string) (string, error) {
	s = strings.TrimSuffix(s, "/")
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", fmt.Errorf("%q is not an absolute http(s) URL without credentials", s)
	}
	return u.String(), nil
}

// NewRekor builds the backend for the log at rawURL.
func NewRekor(rawURL string, o RekorOptions) (*Rekor, error) {
	u, err := parseBackendURL(rawURL)
	if err != nil {
		return nil, err
	}
	parsed, err := url.Parse(u)
	if err != nil {
		return nil, err
	}
	var c http.Client
	if o.Client != nil {
		c = *o.Client
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Rekor{url: u, host: parsed.Host, client: &c, key: o.Key, bearer: o.Bearer, offline: o.Offline}, nil
}

var _ Backend = (*Rekor)(nil)

// Kind is the IntegrityBackend.Kind vocabulary for a transparency log.
func (r *Rekor) Kind() string { return "transparency-log" }

// do performs one request. It sends Accept: application/json, a JSON body on
// POST, and the bearer only when auth is set; it reads at most maxBody bytes
// and reports an oversized body as an error. A transport error is a
// *Transport ("<host>: <err>"); a status is returned for the caller to
// classify.
func (r *Rekor) do(ctx context.Context, method, path, accept string, body []byte, auth bool) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, r.url+path, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", accept)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth && r.bearer != nil {
		tok, err := r.bearer(ctx)
		if err != nil {
			return 0, nil, err // the broker's error names env NAMES only
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		// client.Do returns a *url.Error that repeats the full request URL
		// (path included); keep only its cause so the recorded message is
		// fixed phrases plus the host, never a path.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return 0, nil, &Transport{Host: r.host, Err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return 0, nil, &Transport{Host: r.host, Err: err}
	}
	if len(raw) > maxBody {
		return 0, nil, fmt.Errorf("response body from %s exceeds 1 MiB", r.host)
	}
	return resp.StatusCode, raw, nil
}

// --- wire shapes (Rekor v1 openapi.yaml) ---

type hashedRekord struct {
	APIVersion string           `json:"apiVersion"`
	Kind       string           `json:"kind"`
	Spec       hashedRekordSpec `json:"spec"`
}

type hashedRekordSpec struct {
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
}

type logEntryAnon struct {
	Body           json.RawMessage `json:"body"` // a base64 string in practice; typed loosely by the schema
	IntegratedTime int64           `json:"integratedTime"`
	LogID          string          `json:"logID"`
	LogIndex       int64           `json:"logIndex"`
	Verification   struct {
		InclusionProof *struct {
			Checkpoint string   `json:"checkpoint"`
			Hashes     []string `json:"hashes"`
			LogIndex   int64    `json:"logIndex"` // the per-tree leaf index
			RootHash   string   `json:"rootHash"`
			TreeSize   int64    `json:"treeSize"`
		} `json:"inclusionProof"`
	} `json:"verification"`
}

// rekorProofV1 names the proof envelope format. A change is a new string,
// never an edit (the agenthof-config-signature/v1 precedent).
const rekorProofV1 = "rekor-v1-proof/1"

// rekorProof is Receipt.Proof for a Rekor v1 entry, before base64: everything
// Verify needs offline — the entry body as served (to recompute the leaf hash
// and read data.hash.value), the inclusion path, and the signed checkpoint.
type rekorProof struct {
	V          string   `json:"v"`
	Body       string   `json:"body"`
	LogIndex   int64    `json:"log_index"`
	TreeSize   int64    `json:"tree_size"`
	RootHash   string   `json:"root_hash"`
	Hashes     []string `json:"hashes"`
	Checkpoint string   `json:"checkpoint"`
}

var (
	hexSHA256RE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	entryIDRE   = regexp.MustCompile(`^[0-9a-f]{80}$`)
)

// Fixed phrases shared by Submit and Verify.
const (
	msgKeyDiffersPinned   = "log key differs from the pinned key — update anchor.pub, or pass --anchor-key, to decide"
	msgKeyDiffersRecorded = "log key differs from the key recorded at anchor time — pin a key to decide"
	msgKeyDiffersServed   = "log key differs from the key the log serves for this tree"
)

// servedKey fetches the key the log serves for treeID and returns it with
// its id. Used at Submit when no key is pinned (recording the id) and at
// Verify when unpinned and online (comparing the id to the record's).
func (r *Rekor) servedKey(ctx context.Context, treeID uint64, auth bool) (*ecdsa.PublicKey, string, error) {
	status, raw, err := r.do(ctx, http.MethodGet, "/api/v1/log/publicKey?treeID="+strconv.FormatUint(treeID, 10), "application/x-pem-file", nil, auth)
	if err != nil {
		return nil, "", err
	}
	if status != http.StatusOK {
		return nil, "", fmt.Errorf("status %d from %s", status, r.host)
	}
	pub, err := ParseLogKey(raw)
	if err != nil {
		return nil, "", fmt.Errorf("log key served by %s: %w", r.host, err)
	}
	id, err := KeyID(pub)
	if err != nil {
		return nil, "", err
	}
	return pub, id, nil
}

// treeIDOf parses the shard tree id from an 80-hex entry id (its first 16
// hex, base 16) — Rekor's sharding.TreeID.
func treeIDOf(ref string) (uint64, error) {
	return strconv.ParseUint(ref[:16], 16, 64)
}

// verifyProofOffline is the one offline check Submit and Verify share, under
// key: the envelope version; the body hashes to the ref's leaf and names the
// head; the checkpoint opens under key (another key hash → *Unavailable with
// keyDiffers; a bad signature under the right hash → *Mismatch); the
// checkpoint names the ref's tree and the proof's root and size; the RFC 6962
// inclusion proof verifies. Any disagreement after the key verified is a
// *Mismatch; the only *Unavailable verdicts are an envelope format this build
// does not read and a key it does not hold.
func (r *Rekor) verifyProofOffline(head Head, ref string, env rekorProof, key *ecdsa.PublicKey, keyDiffers string) error {
	if env.V != rekorProofV1 {
		return &Unavailable{Cause: fmt.Sprintf("a proof format this build does not read (%q)", env.V)}
	}
	body, err := base64.StdEncoding.DecodeString(env.Body)
	if err != nil {
		return &Mismatch{Cause: "proof body is not base64"}
	}
	leaf := leafHash(body)
	if hex.EncodeToString(leaf) != ref[16:] {
		return &Mismatch{Cause: "log entry leaf hash differs from the recorded ref"}
	}
	var entry hashedRekord
	if err := json.Unmarshal(body, &entry); err != nil || entry.Kind != "hashedrekord" {
		return &Mismatch{Cause: "log entry body is not a hashedrekord"}
	}
	if strings.ToLower(entry.Spec.Data.Hash.Value) != head.Hash {
		return &Mismatch{Cause: "log entry hash differs from the recorded head"}
	}

	verifiers, err := NewLogKeyVerifiers(key)
	if err != nil {
		return &Unavailable{Cause: err.Error()}
	}
	n, err := note.Open([]byte(env.Checkpoint), verifiers)
	var unverified *note.UnverifiedNoteError
	var invalid *note.InvalidSignatureError
	switch {
	case errors.As(err, &unverified):
		return &Unavailable{Cause: keyDiffers}
	case errors.As(err, &invalid):
		return &Mismatch{Cause: "checkpoint signature under the trusted key is invalid"}
	case err != nil:
		return &Mismatch{Cause: "checkpoint is malformed"}
	}

	// The checkpoint body: "<origin>\n<size>\n<base64 root>\n"; origin is
	// "<hostname> - <treeID decimal>". The hostname is informational — a
	// server flag, not the URL — and is never judged.
	lines := strings.Split(strings.TrimSuffix(n.Text, "\n"), "\n")
	if len(lines) < 3 {
		return &Mismatch{Cause: "checkpoint is malformed"}
	}
	_, treeDec, ok := strings.Cut(lines[0], " - ")
	cpTree, perr := strconv.ParseUint(strings.TrimSpace(treeDec), 10, 64)
	refTree, rerr := treeIDOf(ref)
	if !ok || perr != nil || rerr != nil {
		return &Mismatch{Cause: "checkpoint origin does not name a tree"}
	}
	if cpTree != refTree {
		return &Mismatch{Cause: fmt.Sprintf("checkpoint names tree %d; the ref names tree %d", cpTree, refTree)}
	}
	size, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil || size != env.TreeSize {
		return &Mismatch{Cause: "proof tree size differs from the checkpoint"}
	}
	root, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || hex.EncodeToString(root) != strings.ToLower(env.RootHash) {
		return &Mismatch{Cause: "proof root differs from the checkpoint"}
	}
	hashes := make([][]byte, 0, len(env.Hashes))
	for _, h := range env.Hashes {
		b, err := hex.DecodeString(h)
		if err != nil {
			return &Mismatch{Cause: "inclusion proof is not hex"}
		}
		hashes = append(hashes, b)
	}
	if env.LogIndex < 0 || env.TreeSize < 0 {
		return &Mismatch{Cause: "inclusion proof does not verify"}
	}
	if err := proof.VerifyInclusion(rfc6962.DefaultHasher, uint64(env.LogIndex), uint64(size), leaf, hashes, root); err != nil {
		return &Mismatch{Cause: "inclusion proof does not verify"}
	}
	return nil
}

// Submit generates an ephemeral ECDSA P-256 key, signs the head's digest,
// POSTs a hashedrekord, and — before returning anything — verifies the
// inline inclusion proof and checkpoint under the pinned key, or under the
// key the log serves for the entry's tree (recording its id). Every failure
// is a plain error of fixed phrases and identifiers; the caller records it.
// The ephemeral key lives in this frame and nowhere else.
func (r *Rekor) Submit(ctx context.Context, head Head) (Receipt, error) {
	if !hexSHA256RE.MatchString(head.Hash) {
		return Receipt{}, fmt.Errorf("head hash %q is not a lowercase hex sha256", head.Hash)
	}
	digest, err := hex.DecodeString(head.Hash)
	if err != nil {
		return Receipt{}, err
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Receipt{}, fmt.Errorf("generate entry key: %w", err)
	}
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest)
	if err != nil {
		return Receipt{}, fmt.Errorf("sign: %w", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return Receipt{}, err
	}
	var entry hashedRekord
	entry.APIVersion, entry.Kind = "0.0.1", "hashedrekord"
	entry.Spec.Data.Hash.Algorithm, entry.Spec.Data.Hash.Value = "sha256", head.Hash
	entry.Spec.Signature.Content = base64.StdEncoding.EncodeToString(sig)
	entry.Spec.Signature.PublicKey.Content = base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	body, err := json.Marshal(entry)
	if err != nil {
		return Receipt{}, err
	}

	status, raw, err := r.do(ctx, http.MethodPost, "/api/v1/log/entries", "application/json", body, true)
	if err != nil {
		return Receipt{}, err
	}
	if status != http.StatusCreated {
		return Receipt{}, fmt.Errorf("status %d from %s", status, r.host)
	}
	ref, e, err := decodeSingleEntry(raw)
	if err != nil {
		return Receipt{}, fmt.Errorf("response from %s %w", r.host, err)
	}
	if e.Verification.InclusionProof == nil {
		return Receipt{}, fmt.Errorf("response from %s carries no inclusion proof", r.host)
	}
	ip := e.Verification.InclusionProof
	env := rekorProof{V: rekorProofV1, Body: e.bodyString(), LogIndex: ip.LogIndex, TreeSize: ip.TreeSize, RootHash: strings.ToLower(ip.RootHash), Hashes: ip.Hashes, Checkpoint: ip.Checkpoint}

	key, keyID, keyDiffers := r.key, "", msgKeyDiffersPinned
	if key == nil {
		keyDiffers = msgKeyDiffersServed
		treeID, err := treeIDOf(ref)
		if err != nil {
			return Receipt{}, fmt.Errorf("entry id %q is not an 80-hex entry id", ref)
		}
		key, keyID, err = r.servedKey(ctx, treeID, true)
		if err != nil {
			return Receipt{}, err
		}
	} else if keyID, err = KeyID(key); err != nil {
		return Receipt{}, err
	}
	// The size cap is judged before the proof is verified: a record can never
	// hold an oversized proof, so verifying one would be wasted work.
	envJSON, err := json.Marshal(env)
	if err != nil {
		return Receipt{}, err
	}
	proofB64 := base64.StdEncoding.EncodeToString(envJSON)
	if len(proofB64) > MaxProofLen {
		return Receipt{}, fmt.Errorf("proof is %d bytes; the cap is %d", len(proofB64), MaxProofLen)
	}
	if err := r.verifyProofOffline(head, ref, env, key, keyDiffers); err != nil {
		var u *Unavailable
		var m *Mismatch
		switch {
		case errors.As(err, &u):
			return Receipt{}, errors.New(u.Cause)
		case errors.As(err, &m):
			return Receipt{}, fmt.Errorf("entry does not verify: %s", m.Cause)
		}
		return Receipt{}, err
	}
	var integrated time.Time
	if e.IntegratedTime > 0 {
		integrated = time.Unix(e.IntegratedTime, 0).UTC()
	}
	return Receipt{Ref: ref, Proof: proofB64, Backend: r.url, BackendKeyID: keyID, IntegratedTime: integrated, LogIndex: e.LogIndex}, nil
}

// Verify checks the recorded anchor OFFLINE first — the stored proof under
// the trusted key — and only then, unless Offline, asks the log whether the
// entry is still there (a courtesy to the operator, never the verdict about
// the chain). Verdict ladder (the CLI prints Cause verbatim):
//
//   - the ref is not an 80-hex entry id, or the proof does not decode → *Mismatch
//   - the key: pinned → used; unpinned and Offline → *Unavailable "no key to
//     verify under"; unpinned → fetched for the ref's tree, and its id must
//     equal the recorded BackendKeyID, else *Unavailable "… recorded at
//     anchor time …"; a fetch failure → *Unavailable
//   - verifyProofOffline's verdict, if any
//   - Offline → nil; else the presence check: 200 with the stored body → nil;
//     200 with another body → *Mismatch; any non-200 (404 included) →
//     *Unavailable whose cause says the proof verified offline.
func (r *Rekor) Verify(ctx context.Context, head Head, rcpt Receipt) error {
	// The ref comes from a possibly hostile ledger: it is judged before
	// anything slices it or puts it on a URL.
	ref := strings.ToLower(rcpt.Ref)
	if !entryIDRE.MatchString(ref) {
		return &Mismatch{Cause: fmt.Sprintf("ref %q is not an 80-hex entry id", rcpt.Ref)}
	}
	raw, err := base64.StdEncoding.DecodeString(rcpt.Proof)
	if err != nil {
		return &Mismatch{Cause: "proof does not decode"}
	}
	var env rekorProof
	if err := json.Unmarshal(raw, &env); err != nil {
		return &Mismatch{Cause: "proof does not decode"}
	}
	treeID, err := treeIDOf(ref)
	if err != nil {
		return &Mismatch{Cause: fmt.Sprintf("ref %q is not an 80-hex entry id", rcpt.Ref)}
	}

	key, keyDiffers := r.key, msgKeyDiffersPinned
	if key == nil {
		if r.offline {
			return &Unavailable{Cause: "no key to verify under (unpinned, offline)"}
		}
		served, id, err := r.servedKey(ctx, treeID, false)
		if err != nil {
			return &Unavailable{Cause: err.Error()}
		}
		if id != rcpt.BackendKeyID {
			return &Unavailable{Cause: msgKeyDiffersRecorded}
		}
		key, keyDiffers = served, msgKeyDiffersRecorded
	}
	if err := r.verifyProofOffline(head, ref, env, key, keyDiffers); err != nil {
		return err
	}
	if r.offline {
		return nil
	}
	return r.presence(ctx, ref, env.Body)
}

// presence is the non-load-bearing "still there" check (GET by entry id).
func (r *Rekor) presence(ctx context.Context, ref, storedBody string) error {
	unavailable := func(cause string) error {
		return &Unavailable{Cause: cause + " (proof verified offline; presence not checked)"}
	}
	status, raw, err := r.do(ctx, http.MethodGet, "/api/v1/log/entries/"+ref, "application/json", nil, false)
	if err != nil {
		return unavailable(err.Error())
	}
	switch status {
	case http.StatusOK:
		id, e, err := decodeSingleEntry(raw)
		if err != nil || id != ref {
			return unavailable(fmt.Sprintf("malformed answer from %s", r.host))
		}
		if e.bodyString() != storedBody {
			return &Mismatch{Cause: "log serves a different body for the recorded entry"}
		}
		return nil
	default:
		// Every non-200, 404 included, is "could not check", never "tampered".
		// Rekor v1 gives no reliable way to tell a genuinely absent entry from
		// a vanished route: a real absent entry answers 404 with no body, while
		// a re-homed/proxied URL or the eventual v1 read-route removal answers
		// 404 with go-swagger's generic {"code":404} — the opposite of a tamper
		// signal. The presence check is non-load-bearing by design; the stored
		// proof, verified offline under the pinned key, is the verdict.
		return unavailable(fmt.Sprintf("status %d from %s", status, r.host))
	}
}

// ServedKey fetches, anonymously, the key the log serves for the tree an entry
// id names, with its id — what an operator pins (anchor.pub / --anchor-key)
// to verify offline. ref must be an 80-hex entry id; nothing is requested
// otherwise.
func (r *Rekor) ServedKey(ctx context.Context, ref string) (*ecdsa.PublicKey, string, error) {
	ref = strings.ToLower(ref)
	if !entryIDRE.MatchString(ref) {
		return nil, "", fmt.Errorf("ref %q is not an 80-hex entry id", ref)
	}
	treeID, err := treeIDOf(ref)
	if err != nil {
		return nil, "", fmt.Errorf("ref %q is not an 80-hex entry id", ref)
	}
	return r.servedKey(ctx, treeID, false)
}

// decodeSingleEntry parses a LogEntry — a JSON object with exactly one key,
// the entry id — and lowercases the id.
func decodeSingleEntry(raw []byte) (string, logEntryAnon, error) {
	var m map[string]logEntryAnon
	if err := json.Unmarshal(raw, &m); err != nil || len(m) != 1 {
		return "", logEntryAnon{}, errors.New("is not a single log entry")
	}
	for id, e := range m {
		id = strings.ToLower(id)
		if !entryIDRE.MatchString(id) {
			return "", logEntryAnon{}, errors.New("names an entry id that is not 80 hex")
		}
		return id, e, nil
	}
	return "", logEntryAnon{}, errors.New("is not a single log entry")
}

// bodyString returns the entry body when the log typed it as a string (as
// Rekor does) and "" otherwise; the leaf-hash check then fails honestly.
func (e logEntryAnon) bodyString() string {
	var s string
	if err := json.Unmarshal(e.Body, &s); err != nil {
		return ""
	}
	return s
}
