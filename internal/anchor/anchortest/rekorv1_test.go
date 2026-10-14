package anchortest_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/anchor"
	"github.com/agenthof/agenthof/internal/anchor/anchortest"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/note"
)

// propose builds a valid hashedrekord 0.0.1 for hash under a fresh P-256 key.
func propose(t *testing.T, hash string) []byte {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	digest, _ := hex.DecodeString(hash)
	sig, _ := ecdsa.SignASN1(rand.Reader, priv, digest)
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	body, _ := json.Marshal(map[string]any{
		"apiVersion": "0.0.1", "kind": "hashedrekord",
		"spec": map[string]any{
			"data":      map[string]any{"hash": map[string]any{"algorithm": "sha256", "value": hash}},
			"signature": map[string]any{"content": base64.StdEncoding.EncodeToString(sig), "publicKey": map[string]any{"content": base64.StdEncoding.EncodeToString(pub)}},
		},
	})
	return body
}

type entryAnon struct {
	Body           string `json:"body"`
	IntegratedTime int64  `json:"integratedTime"`
	LogID          string `json:"logID"`
	LogIndex       int64  `json:"logIndex"`
	Verification   struct {
		InclusionProof struct {
			Checkpoint string   `json:"checkpoint"`
			Hashes     []string `json:"hashes"`
			LogIndex   int64    `json:"logIndex"`
			RootHash   string   `json:"rootHash"`
			TreeSize   int64    `json:"treeSize"`
		} `json:"inclusionProof"`
	} `json:"verification"`
}

func post(t *testing.T, url string, body []byte) (int, string, entryAnon) {
	t.Helper()
	resp, err := http.Post(url+"/api/v1/log/entries", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 201 {
		return resp.StatusCode, string(raw), entryAnon{}
	}
	var m map[string]entryAnon
	if err := json.Unmarshal(raw, &m); err != nil || len(m) != 1 {
		t.Fatalf("201 body: %s (%v)", raw, err)
	}
	for id, e := range m {
		return 201, id, e
	}
	return 0, "", entryAnon{}
}

// TestRekorV1ProofsVerifyUnderTheRealLibraries: after three uploads, every
// entry's inclusion proof verifies with proof.VerifyInclusion against the
// root in a checkpoint note.Open accepts under the fake's key, the entry id is
// treeID(16 hex) ‖ HashLeaf(body), logID is the fake's key id, and the
// checkpoint origin names the tree id.
func TestRekorV1ProofsVerifyUnderTheRealLibraries(t *testing.T) {
	f := anchortest.NewRekorV1()
	t.Cleanup(f.Close)
	vs, err := anchor.NewLogKeyVerifiers(f.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	wantID, _ := anchor.KeyID(f.PublicKey())
	for i := 0; i < 3; i++ {
		hash := strings.Repeat(strconv.Itoa(i), 64)
		status, id, e := post(t, f.URL, propose(t, hash))
		if status != 201 {
			t.Fatalf("status %d", status)
		}
		body, err := base64.StdEncoding.DecodeString(e.Body)
		if err != nil {
			t.Fatal(err)
		}
		leaf := rfc6962.DefaultHasher.HashLeaf(body)
		if len(id) != 80 || id[:16] != fmt0(f.TreeID()) || id[16:] != hex.EncodeToString(leaf) {
			t.Fatalf("entry id %q is not treeID ‖ HashLeaf(body)", id)
		}
		if e.LogID != wantID || e.IntegratedTime == 0 || e.LogIndex != int64(i) {
			t.Fatalf("entry %+v", e)
		}
		n, err := note.Open([]byte(e.Verification.InclusionProof.Checkpoint), vs)
		if err != nil {
			t.Fatalf("checkpoint: %v", err)
		}
		lines := strings.Split(n.Text, "\n")
		if !strings.HasSuffix(lines[0], " - "+strconv.FormatUint(f.TreeID(), 10)) || lines[1] != strconv.Itoa(i+1) {
			t.Fatalf("checkpoint text %q", n.Text)
		}
		root, _ := base64.StdEncoding.DecodeString(lines[2])
		if hex.EncodeToString(root) != e.Verification.InclusionProof.RootHash {
			t.Fatal("rootHash must equal the checkpoint's root")
		}
		var hashes [][]byte
		for _, h := range e.Verification.InclusionProof.Hashes {
			b, _ := hex.DecodeString(h)
			hashes = append(hashes, b)
		}
		if err := proof.VerifyInclusion(rfc6962.DefaultHasher, uint64(e.Verification.InclusionProof.LogIndex), uint64(e.Verification.InclusionProof.TreeSize), leaf, hashes, root); err != nil {
			t.Fatalf("inclusion: %v", err)
		}
	}
	if got := f.Requests(); len(got) != 3 || got[0] != "POST /api/v1/log/entries" {
		t.Fatalf("requests %v", got)
	}
}

func fmt0(id uint64) string { return fmt.Sprintf("%016x", id) }

// TestRekorV1Switches: Fail answers the status with the sentinel in body and
// Location; Forget → 404; Corrupt → a body whose leaf hash differs; RotateKey
// changes the served key and signs later checkpoints with it; Cosign adds a
// second signature line; SetHostname changes the origin; PadProof lengthens
// hashes; Drop (and its synonym Stop) closes every connection until Start —
// sticky, because Go's transport retries an idempotent request whose reused
// connection closed, so a one-shot drop would be swallowed; Reset clears the
// log.
func TestRekorV1Switches(t *testing.T) {
	f := anchortest.NewRekorV1()
	t.Cleanup(f.Close)
	hash := strings.Repeat("ab", 32)
	_, id, e := post(t, f.URL, propose(t, hash))

	f.Fail(501)
	resp, err := http.Get(f.URL + "/api/v1/log/entries/" + id)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 501 || !strings.Contains(string(raw), anchortest.Sentinel) || resp.Header.Get("Location") != anchortest.Sentinel {
		t.Fatalf("Fail: %d %s", resp.StatusCode, raw)
	}

	f.Forget(id)
	resp, _ = http.Get(f.URL + "/api/v1/log/entries/" + id)
	_ = resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("Forget: %d", resp.StatusCode)
	}
	f.Reset()

	f.Corrupt(id)
	resp, _ = http.Get(f.URL + "/api/v1/log/entries/" + id)
	raw, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var m map[string]entryAnon
	_ = json.Unmarshal(raw, &m)
	if resp.StatusCode != 200 || m[id].Body == e.Body {
		t.Fatalf("Corrupt must serve another body: %d %s", resp.StatusCode, raw)
	}
	f.Reset()

	before := f.PublicKeyPEM()
	f.RotateKey()
	resp, _ = http.Get(f.URL + "/api/v1/log/publicKey?treeID=" + strconv.FormatUint(f.TreeID(), 10))
	raw, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if bytes.Equal(raw, before) || !bytes.Equal(raw, f.PublicKeyPEM()) || resp.Header.Get("Content-Type") != "application/x-pem-file" {
		t.Fatal("RotateKey must change the served key")
	}
	vs, _ := anchor.NewLogKeyVerifiers(f.PublicKey())
	f.Cosign()
	f.SetHostname("elsewhere")
	f.PadProof(3)
	_, _, e2 := post(t, f.URL, propose(t, strings.Repeat("cd", 32)))
	n, err := note.Open([]byte(e2.Verification.InclusionProof.Checkpoint), vs)
	if err != nil || len(n.UnverifiedSigs) != 1 || !strings.HasPrefix(n.Text, "elsewhere - ") {
		t.Fatalf("cosigned/renamed checkpoint: %+v %v", n, err)
	}
	if len(e2.Verification.InclusionProof.Hashes) != 1+3 { // two leaves → one sibling hash, plus the padding
		t.Fatalf("PadProof: %d hashes", len(e2.Verification.InclusionProof.Hashes))
	}
	f.Reset()

	f.Drop()
	for i := 0; i < 3; i++ { // sticky: every attempt, retries included
		if _, err := http.Get(f.URL + "/api/v1/log"); err == nil {
			t.Fatal("Drop must close every connection until Start")
		}
	}
	f.Start()
	resp, err = http.Get(f.URL + "/api/v1/log/publicKey")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("Start: %v", err)
	}
	_ = resp.Body.Close()
	f.Stop()
	if _, err := http.Get(f.URL + "/api/v1/log"); err == nil {
		t.Fatal("Stop is Drop's synonym")
	}
	f.Start()

	f.CorruptNext()
	_, id3, e3 := post(t, f.URL, propose(t, strings.Repeat("ef", 32)))
	body3, _ := base64.StdEncoding.DecodeString(e3.Body)
	if id3[16:] == hex.EncodeToString(rfc6962.DefaultHasher.HashLeaf(body3)) {
		t.Fatal("CorruptNext must serve a 201 whose body does not hash to its entry id")
	}
}

// TestRekorV1RejectsAnInvalidProposal: a hashedrekord whose signature does not
// verify under its embedded key is a 400 — so a client that passes the fake
// has sent a valid entry.
func TestRekorV1RejectsAnInvalidProposal(t *testing.T) {
	f := anchortest.NewRekorV1()
	t.Cleanup(f.Close)
	body := propose(t, strings.Repeat("ab", 32))
	body = bytes.Replace(body, []byte(`"value":"abab`), []byte(`"value":"cdab`), 1) // the digest no longer matches the signature
	status, _, _ := post(t, f.URL, body)
	if status != 400 {
		t.Fatalf("status %d, want 400", status)
	}
}
