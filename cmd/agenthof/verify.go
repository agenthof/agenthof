package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"github.com/agenthof/agenthof/internal/config"
)

// sigKind is what verifySignatureFile found. It cannot produce stale or
// foreign-ledger: those are the floor's, judged by the caller.
type sigKind int

const (
	sigAbsent     sigKind = iota // no installed/<hex>.sig
	sigMalformed                 // ParseSignatureFile refused it (CR, unsupported format, line count, a bad line)
	sigUnknownKey                // key_id is not KeyID(pub)
	sigForeign                   // payload names another hash or another log_id
	sigNewer                     // payload names a version above the vouched install
	sigOlder                     // payload names a version below it, or another installed_at
	sigBad                       // the six lines match; Ed25519 fails
)

// signatureVerdict is every not-signed cause as one typed error. Error() is
// byte-identical to the strings the pull has logged since slice 2 —
// "not signed: " + Detail — and Is keeps errors.Is(err, errNotSigned) true
// for every kind and errors.Is(err, errSignatureNewer) true for sigNewer, so
// pullConfig, signingStartupWarning and configHost.Pull classify exactly as
// before. A caller that needs the kind reads it; nothing parses the text.
type signatureVerdict struct {
	Kind   sigKind
	Detail string               // today's text after "not signed: " — never a key, never file contents (a foreign first line is clipped to 64 bytes by ParseSignatureFile)
	File   config.SignatureFile // the parsed file for sigUnknownKey/sigForeign/sigNewer/sigOlder/sigBad; zero for sigAbsent/sigMalformed
}

func (v *signatureVerdict) Error() string { return errNotSigned.Error() + ": " + v.Detail }

func (v *signatureVerdict) Is(target error) bool {
	return target == errNotSigned || (target == errSignatureNewer && v.Kind == sigNewer)
}

// verifySignatureFile reads installed/<hex>.sig and decides whether it is THE
// signature of the install (hash, logID, version, at) under pub — the one
// verify both the pull (pub = signing.pub, the host's own key) and the
// execution read (pub = the pinned key) run. Order: the file (absent →
// sigAbsent; any other read error is returned as is — a store fault, not a
// verdict); ParseSignatureFile (→ sigMalformed, format judged first); key_id
// (→ sigUnknownKey, before any verify); the six lines against the payload
// rebuilt from the vouched fields and, when they differ, which field (→
// sigForeign / sigNewer / sigOlder, in that precedence); Ed25519 (→ sigBad).
// The floor is NOT applied here: the pull has none.
func verifySignatureFile(store, hash, logID string, version int, at time.Time, pub ed25519.PublicKey) (config.SignatureFile, error) {
	data, err := os.ReadFile(config.SignaturePath(store, hash))
	if errors.Is(err, fs.ErrNotExist) {
		return config.SignatureFile{}, &signatureVerdict{Kind: sigAbsent, Detail: "no signature file for " + hash}
	}
	if err != nil {
		return config.SignatureFile{}, err
	}
	f, err := config.ParseSignatureFile(data)
	if err != nil {
		return config.SignatureFile{}, &signatureVerdict{Kind: sigMalformed, Detail: err.Error()}
	}
	keyID := config.KeyID(pub)
	if f.KeyID != keyID {
		return config.SignatureFile{}, &signatureVerdict{Kind: sigUnknownKey, Detail: fmt.Sprintf("signature is by key %s; configured key is %s", f.KeyID, keyID), File: f}
	}
	expected, err := config.SignaturePayload(hash, logID, version, at, keyID)
	if err != nil {
		return config.SignatureFile{}, err
	}
	if !bytes.Equal(f.Payload, expected) {
		switch {
		case f.Hash != hash:
			return config.SignatureFile{}, &signatureVerdict{Kind: sigForeign, Detail: fmt.Sprintf("signature is for hash %s, installed is %s", f.Hash, hash), File: f}
		case f.LogID != logID:
			return config.SignatureFile{}, &signatureVerdict{Kind: sigForeign, Detail: fmt.Sprintf("signature is for log_id %s, installed is %s", f.LogID, logID), File: f}
		case f.Version > version:
			return config.SignatureFile{}, &signatureVerdict{Kind: sigNewer, Detail: errSignatureNewer.Error(), File: f}
		case f.Version < version:
			return config.SignatureFile{}, &signatureVerdict{Kind: sigOlder, Detail: fmt.Sprintf("signature is for version %d, installed is %d", f.Version, version), File: f}
		}
		return config.SignatureFile{}, &signatureVerdict{Kind: sigOlder, Detail: fmt.Sprintf("signature is for installed_at %s, installed is %s", f.InstalledAt, at.Format(time.RFC3339Nano)), File: f}
	}
	if !config.Verify(pub, f.Payload, f.Sig) {
		return config.SignatureFile{}, &signatureVerdict{Kind: sigBad, Detail: "signature does not verify", File: f}
	}
	return f, nil
}
