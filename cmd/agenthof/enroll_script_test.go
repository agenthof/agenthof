package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"time"

	"github.com/rogpeppe/go-internal/testscript"

	"github.com/agenthof/agenthof/internal/agentcard"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/ledger"
)

// enrollKey keys a script's enrollment fixtures in its testscript Env.
type enrollKey struct{}

// enrollState is one script's curator key and tree snapshots.
type enrollState struct {
	priv      ed25519.PrivateKey
	snapshots map[string]string
}

const enrollCuratorKID = "curator"

// enrollArtifactPin is the digest-pinned artifact every fixture card names.
const enrollArtifactPin = "ghcr.io/acme/triage@sha256:" +
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func enrollOf(ts *testscript.TestScript) *enrollState {
	st, _ := ts.Value(enrollKey{}).(*enrollState)
	if st == nil {
		ts.Fatalf("no enrollment state")
	}
	return st
}

// cardsigner <gateway.yaml>: mints this script's curator key and appends it
// to the gateway file as a trusted signer.
func cmdCardSigner(ts *testscript.TestScript, neg bool, args []string) {
	if len(args) != 1 {
		ts.Fatalf("usage: cardsigner <gateway.yaml>")
	}
	st := enrollOf(ts)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	ts.Check(err)
	st.priv = priv
	p := ts.MkAbs(args[0])
	b, err := os.ReadFile(p)
	ts.Check(err)
	b = append(b, []byte("trusted_signers:\n  - {kid: "+enrollCuratorKID+", key: "+base64.StdEncoding.EncodeToString(pub)+"}\n")...)
	ts.Check(os.WriteFile(p, b, 0o644))
}

// mkcard <variant> <out>: writes a signed A2A card. Variants: good; the
// signature failures swap (body changed after signing), jku and algnone; and
// the validly signed but refused wildcard, spawn, notool, noartifact,
// unpinned and badinterface.
func cmdMkCard(ts *testscript.TestScript, neg bool, args []string) {
	if len(args) != 2 {
		ts.Fatalf("usage: mkcard <variant> <out>")
	}
	st := enrollOf(ts)
	variant := args[0]
	params := map[string]any{
		"artifact":  enrollArtifactPin,
		"interface": "a2a",
		"model":     "fast",
		"tools":     []any{map[string]any{"resource": "code-search", "tools": []string{"search"}, "mode": "read-only"}},
	}
	switch variant {
	case "good", "swap", "jku", "algnone":
	case "wildcard":
		params["tools"] = []any{map[string]any{"resource": "code-search", "tools": []string{"*"}, "mode": "read-only"}}
	case "spawn":
		params["spawn"] = []any{map[string]any{"role": "dev", "workflow": "main"}}
	case "notool":
		params["tools"] = []any{map[string]any{"resource": "no-such-tool", "tools": []string{"search"}, "mode": "read-only"}}
	case "noartifact":
		delete(params, "artifact")
	case "unpinned":
		params["artifact"] = "ghcr.io/acme/triage:latest"
	case "badinterface":
		params["interface"] = "grpc"
	default:
		ts.Fatalf("unknown card variant %q", variant)
	}
	body := map[string]any{
		"name":    "Triage Bot",
		"version": "1.2.0",
		"capabilities": map[string]any{"extensions": []any{map[string]any{
			"uri": agentcard.ExtensionURI, "params": params,
		}}},
	}
	enc := base64.RawURLEncoding
	hdr := map[string]any{"alg": "EdDSA", "kid": enrollCuratorKID}
	switch variant {
	case "jku":
		hdr["jku"] = "https://keys.example.invalid/jwks.json"
	case "algnone":
		hdr["alg"] = "none"
	}
	canon, err := json.Marshal(body) // compact, sorted keys: already JCS for these values
	ts.Check(err)
	ph, err := json.Marshal(hdr)
	ts.Check(err)
	p := enc.EncodeToString(ph)
	sigStr := enc.EncodeToString(ed25519.Sign(st.priv, []byte(p+"."+enc.EncodeToString(canon))))
	if variant == "algnone" {
		sigStr = ""
	}
	if variant == "swap" {
		// Swap the artifact after signing: the signature no longer covers it.
		params["artifact"] = "ghcr.io/evil/triage@sha256:" + strings.Repeat("b", 64)
	}
	body["signatures"] = []any{map[string]any{"protected": p, "signature": sigStr}}
	out, err := json.Marshal(body)
	ts.Check(err)
	ts.Check(os.WriteFile(ts.MkAbs(args[1]), out, 0o644))
}

// carddigest <card> <VAR>: exports the card's signed digest, in the
// sha256:<hex> form --accept takes, as $VAR.
func cmdCardDigest(ts *testscript.TestScript, neg bool, args []string) {
	if len(args) != 2 {
		ts.Fatalf("usage: carddigest <card> <VAR>")
	}
	b, err := os.ReadFile(ts.MkAbs(args[0]))
	ts.Check(err)
	c, err := agentcard.Parse(b)
	ts.Check(err)
	ts.Setenv(args[1], "sha256:"+c.SignedDigest())
}

// cardserve <card> <VAR>: serves the card over https from a per-script test
// server, exports its URL as $VAR, and exports the server's CA file as
// $AGENTHOF_TEST_CARD_CA, which the test binary's agenthof trusts.
func cmdCardServe(ts *testscript.TestScript, neg bool, args []string) {
	if len(args) != 2 {
		ts.Fatalf("usage: cardserve <card> <VAR>")
	}
	card, err := os.ReadFile(ts.MkAbs(args[0]))
	ts.Check(err)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(card)
	}))
	ts.Defer(srv.Close)
	ca := ts.MkAbs("card-ca.pem")
	ts.Check(os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o644))
	ts.Setenv("AGENTHOF_TEST_CARD_CA", ca)
	ts.Setenv(args[1], srv.URL+"/card.json")
}

// enrollSnapshot is the directory hash and the control head, together.
func enrollSnapshot(ts *testscript.TestScript, dir, log string) string {
	h, err := config.HashDir(ts.MkAbs(dir))
	ts.Check(err)
	_, head, err := ledger.ReadVerify(ts.MkAbs(log), ledger.Unlocked)
	ts.Check(err)
	return "dir=" + h + " head=" + head.Hash
}

// snapshot <name> <config-dir> <control-log> records the directory hash and
// the control head.
func cmdSnapshot(ts *testscript.TestScript, neg bool, args []string) {
	if len(args) != 3 {
		ts.Fatalf("usage: snapshot <name> <config-dir> <control-log>")
	}
	st := enrollOf(ts)
	if st.snapshots == nil {
		st.snapshots = map[string]string{}
	}
	st.snapshots[args[0]] = enrollSnapshot(ts, args[1], args[2])
}

// unchanged [-dir] <name> <config-dir> <control-log> fails unless both the
// directory hash and the control head are what the snapshot recorded; with
// -dir only the directory hash is compared (a recorded refusal moves the head).
func cmdUnchanged(ts *testscript.TestScript, neg bool, args []string) {
	dirOnly := len(args) > 0 && args[0] == "-dir"
	if dirOnly {
		args = args[1:]
	}
	if len(args) != 3 {
		ts.Fatalf("usage: unchanged [-dir] <name> <config-dir> <control-log>")
	}
	want, ok := enrollOf(ts).snapshots[args[0]]
	if !ok {
		ts.Fatalf("no snapshot %q", args[0])
	}
	got := enrollSnapshot(ts, args[1], args[2])
	if dirOnly {
		want, got = strings.SplitN(want, " ", 2)[0], strings.SplitN(got, " ", 2)[0]
	}
	if got != want {
		ts.Fatalf("config dir or control head changed:\n was %s\n now %s", want, got)
	}
}

// cpdir <src> <dst> copies a directory tree.
func cmdCpDir(ts *testscript.TestScript, neg bool, args []string) {
	if len(args) != 2 {
		ts.Fatalf("usage: cpdir <src> <dst>")
	}
	ts.Check(copyDir(ts.MkAbs(args[0]), ts.MkAbs(args[1])))
}

// trustCardServer makes the test binary's agenthof trust the CA a script's
// cardserve exported, so an https card source verifies against a test server.
func trustCardServer() {
	p := os.Getenv("AGENTHOF_TEST_CARD_CA")
	if p == "" {
		return
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(b)
	enrollHTTPClient = &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
	}
}
