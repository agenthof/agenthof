package main

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/agenthof/agenthof/internal/anchor"
	"github.com/agenthof/agenthof/internal/broker"
	"github.com/agenthof/agenthof/internal/config"
)

// audit verify control's two anchor exit codes, beside exitInstalledMismatch
// (installed.go) in the fixed precedence 1, 6, 3, 4, 5, 7: 6 is a definitive
// content disagreement — the chain does not reproduce a recorded head, or the
// stored proof under the trusted key says otherwise; 7 is the absence of a
// verdict — a log that could not be reached, a key the verifier does not
// hold. 7 never reads as tamper detected, and every definitive verdict
// outranks it.
const (
	exitAnchorMismatch     = 6
	exitAnchorUnverifiable = 7
)

// anchorPubPath is the transparency log's pinned checkpoint key, BESIDE the
// control ledger exactly as verify.pub is — a different file from verify.pub
// on purpose: verify.pub is the operator's Ed25519 signing key this point
// trusts; anchor.pub is the LOG's ECDSA key. Operator-written; Agenthof never
// writes it. Derived here and nowhere else.
func anchorPubPath(controlLog string) string {
	return filepath.Join(filepath.Dir(controlLog), "anchor.pub")
}

// anchorKeyPath decides whether anchor verification is pinned and where the
// key is — pinnedKeyPath's twin. With --anchor-key given, the flag IS the
// pin: the path is returned as pinned whether or not it exists (absent or
// unreadable fails closed at loadAnchorPub, never unpinned). Without it,
// anchor.pub is stat'ed: absent ⇒ unpinned ("as served by the log"); any
// stat error other than not-exist is a fault the caller reports.
func anchorKeyPath(controlLog, anchorKey string) (pinned bool, path string, err error) {
	if anchorKey != "" {
		return true, anchorKey, nil
	}
	path = anchorPubPath(controlLog)
	exists, err := fileExists(path)
	if err != nil {
		return false, path, fmt.Errorf("pinned log key %s: %w", path, err)
	}
	return exists, path, nil
}

// loadAnchorPub reads and parses the pinned log key at path with
// anchor.ParseLogKey (ECDSA P-256 only); every error names the file, so a
// refusal reads "pinned log key <path>: <cause>".
func loadAnchorPub(path string) (*ecdsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("pinned log key %s: %w", path, err)
	}
	pub, err := anchor.ParseLogKey(data)
	if err != nil {
		return nil, fmt.Errorf("pinned log key %s: %w", path, err)
	}
	return pub, nil
}

// pinnedLogKey is the pin both anchor commands resolve: nil, nil when unpinned.
func pinnedLogKey(controlLog, anchorKey string) (*ecdsa.PublicKey, error) {
	pinned, path, err := anchorKeyPath(controlLog, anchorKey)
	if err != nil || !pinned {
		return nil, err
	}
	return loadAnchorPub(path)
}

// anchorCredentialRef maps anchor_backend.credential — the BackendCredential
// shape ToolResource already spells — onto the broker's reference: the first
// consumer of that mapping. Every secret coordinate is an env NAME.
func anchorCredentialRef(c config.BackendCredential) broker.CredentialRef {
	return broker.CredentialRef{
		ResourceID: "integrity/anchor_backend",
		Source:     c.CredentialSource, Grant: c.GrantType, ClientAuth: c.ClientAuth,
		Issuer: c.Issuer, TokenURL: c.TokenEndpoint, Scope: c.Scope, Audience: c.Audience,
		TokenEnv: c.TokenEnv, ClientIDEnv: c.ClientIDEnv, ClientSecretEnv: c.ClientSecretEnv,
	}
}

// anchorBearer is the bearer resolver audit anchor hands the backend: nil for
// no credential (the public good is anonymous); otherwise the broker resolves
// the direct-bearer or client_credentials grant at call time and the value
// goes into the Authorization header and nowhere else. token_exchange needs a
// subject token no CLI has; Validate refuses it, and this guard keeps a nil
// broker from ever being dereferenced if a ref reaches here another way.
func anchorBearer(c config.BackendCredential, client *http.Client) func(context.Context) (string, error) {
	if c == (config.BackendCredential{}) {
		return nil
	}
	ref := anchorCredentialRef(c)
	if ref.Grant == "token_exchange" {
		return func(context.Context) (string, error) {
			return "", errors.New("broker: token_exchange is not supported for an anchor backend")
		}
	}
	d := broker.Dispatch{StaticEnv: broker.StaticEnv{}, ClientCredentials: broker.NewClientCredentials(client)}
	return func(ctx context.Context) (string, error) { return d.Resolve(ctx, ref) }
}

// backendSpec is what anchorBackendFor dispatches on: on the write path the
// posture's kind, url and credential; on the verify path the RECORD's own
// backend_kind and backend (never integrity.yaml), no credential, and the
// --offline flag. Key is the pinned log key, nil when unpinned.
type backendSpec struct {
	Kind, URL  string
	Key        *ecdsa.PublicKey
	Credential config.BackendCredential
	Offline    bool
}

// anchorHTTPClient is the one client every anchor backend is built over:
// system roots, no custom CA knob; anchor.NewRekor copies it and disables
// redirects on the copy.
var anchorHTTPClient = &http.Client{}

// anchorBackendFor is the one dispatch from a backend kind to a Backend.
// transparency-log is the only kind this build constructs; rfc3161 and every
// other kind are "not implemented" — on the verify path the caller reports
// that as unverifiable, never as a mismatch.
func anchorBackendFor(s backendSpec) (anchor.Backend, error) {
	switch s.Kind {
	case "transparency-log":
		return anchor.NewRekor(s.URL, anchor.RekorOptions{Client: anchorHTTPClient, Key: s.Key, Bearer: anchorBearer(s.Credential, anchorHTTPClient), Offline: s.Offline})
	default:
		return nil, fmt.Errorf("anchor backend kind %q is not implemented", s.Kind)
	}
}

// newAnchorBackend is anchorBackendFor behind a var so a test can hand in the
// stub (the statControlLog pattern): the stub is never reachable through a
// real posture, since Validate refuses kind rfc3161.
var newAnchorBackend = anchorBackendFor
