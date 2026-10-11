package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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

// verifyPubPath and verifyFloorPath are the execution point's pin and its
// memory, BESIDE the control ledger exactly as installed.lock, signing.key and
// signing.pub are: verify.pub is the operator public key this point TRUSTS
// (PKIX PEM, the format signing.pub holds and config keygen prints — a
// different file from signing.pub on purpose: signing.pub is the key the host
// signs WITH), and verify.floor is the highest (log_id, version) whose
// signature this point has verified. Agenthof never writes verify.pub —
// pinning is a deliberate operator act, out of band. Derived here and nowhere
// else.
func verifyPubPath(controlLog string) string {
	return filepath.Join(filepath.Dir(controlLog), "verify.pub")
}

func verifyFloorPath(controlLog string) string {
	return filepath.Join(filepath.Dir(controlLog), "verify.floor")
}

// loadVerifyPub reads and parses the pinned key at path with exactly the
// signing.pub codec; every error names the file, so a refusal reads
// "pinned key <path>: <cause>".
func loadVerifyPub(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("pinned key %s: %w", path, err)
	}
	pub, err := config.ParseSigningPub(data)
	if err != nil {
		return nil, fmt.Errorf("pinned key %s: %w", path, err)
	}
	return pub, nil
}

// readVerifyFloor reads verify.floor beside controlLog. Absent is the one
// "no floor" answer (present false, err nil); a corrupt or unreadable floor
// is an error naming the file — never read as absent (that would make
// truncating the file a rollback enabler) and never rewritten here.
func readVerifyFloor(controlLog string) (logID string, version int, present bool, err error) {
	data, err := os.ReadFile(verifyFloorPath(controlLog))
	if errors.Is(err, fs.ErrNotExist) {
		return "", 0, false, nil
	}
	if err != nil {
		return "", 0, false, fmt.Errorf("verify.floor: %w", err)
	}
	logID, version, err = config.ParseVerifyFloor(data)
	if err != nil {
		return "", 0, false, fmt.Errorf("verify.floor: %w", err)
	}
	return logID, version, true, nil
}

// writeVerifyFloor writes verify.floor atomically, as the pointer and the
// .sig are written: a .verify.floor-* temp beside the ledger (0600, as
// CreateTemp yields), fsync, rename over the final name, fsync the directory.
// On any failure the temp is removed and whatever floor was there is left
// untouched. The caller holds installed.lock shared; two shared holders that
// both advance write the same bytes to the same name — an idempotent
// duplicate, never a regression.
func writeVerifyFloor(controlLog, logID string, version int) error {
	dir := filepath.Dir(controlLog)
	f, err := os.CreateTemp(dir, ".verify.floor-*")
	if err != nil {
		return fmt.Errorf("verify.floor: %w", err)
	}
	tmp := f.Name()
	_, werr := f.Write(config.VerifyFloorBytes(logID, version))
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(tmp, verifyFloorPath(controlLog))
	}
	if werr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("verify.floor: %w", werr)
	}
	if d, derr := os.Open(dir); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
