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
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/ledger"
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
// byte-identical to the strings the pull logs —
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

// verifyKind is one outcome of the pinned verify short of a pass. The five
// judged kinds say the installed configuration is NOT the operator's current
// install for this root; notVerifiable says the verdict could not be reached
// because of a permanent fault — the pinned key, the floor, the ledger or the
// pointer — and names the cause; busy is the one transient: installed.lock
// (or the ledger flock inside it) could not be taken within the timeout.
// Everything but busy is recorded as a run refusal (Article III); busy is
// answered like every other busy in this codebase — retry, nothing recorded.
type verifyKind int

const (
	verifyUnsigned      verifyKind = iota // key pinned; no .sig, or a .sig that is not a v1 signature of THIS install
	verifyUnknownKey                      // the .sig is by a key other than the pinned one
	verifyBadSignature                    // Ed25519 fails over the matching payload
	verifyStale                           // same log_id, version below the floor
	verifyForeignLedger                   // the floor names another log_id
	verifyNotVerifiable                   // pinned key / floor unusable or unwritable; ledger damaged, genesis without log_id, pointer not on record
	verifyBusy                            // installed.lock or the ledger lock held past the timeout — UNRECORDED, retry
)

// verifyRefusal is the pinned verify's outcome short of a pass. Detail is
// bounded: hex ids, decimals and this package's fixed phrases, or a parser's
// fixed vocabulary (ParseSignatureFile, ParseSigningPub incl. x509's and a
// %T, ParseVerifyFloor, an OS error); never a key, never file contents.
type verifyRefusal struct {
	Kind   verifyKind
	Detail string
}

// notVerifiable is the permanent-fault refusal with its cause.
func notVerifiable(detail string) *verifyRefusal {
	return &verifyRefusal{Kind: verifyNotVerifiable, Detail: detail}
}

// Transient reports Kind == verifyBusy: not a verdict, not recorded.
func (r *verifyRefusal) Transient() bool { return r.Kind == verifyBusy }

// Headline is the fixed part a result line and an API body carry. Busy has
// no headline: it IS the printed busy line, never recorded.
func (r *verifyRefusal) Headline() string {
	switch r.Kind {
	case verifyUnsigned:
		return "configuration not verified: unsigned"
	case verifyUnknownKey:
		return "configuration not verified: unknown key"
	case verifyBadSignature:
		return "configuration not verified: bad signature"
	case verifyStale:
		return "configuration not verified: stale"
	case verifyForeignLedger:
		return "configuration not verified: foreign ledger"
	case verifyNotVerifiable:
		return "configuration not verifiable"
	case verifyBusy:
		return msgLockBusy
	}
	// An unhandled kind is a programming error; render it as a recorded fault,
	// never borrow busy's unrecorded line.
	return "configuration not verifiable"
}

// Error is the recorded reason: Headline + ": " + Detail (Detail is empty
// for bad signature, whose cause is the headline, and for busy).
func (r *verifyRefusal) Error() string {
	if r.Detail == "" {
		return r.Headline()
	}
	return r.Headline() + ": " + r.Detail
}

// verifyMode says whether a pass advances the floor.
type verifyMode int

const (
	verifyAndAdvance verifyMode = iota // the execution read: a verified install advances verify.floor
	verifyOnly                         // serve startup: judge, write nothing
)

// installFacts is the control ledger's account of the install the pinned
// verify rebuilds the payload from; At is normalized to UTC ONCE, here.
type installFacts struct {
	LogID   string
	Version int
	At      time.Time
}

// recordedInstall reads the control ledger's account of the install at hash,
// classified exactly as buildSignature does: a held ledger flock → busy
// (unrecorded); no file → an empty chain that vouches for nothing (the next
// step says "not on record", never "damaged"); torn or broken → damaged with
// the repair hint; the last installing event must name the pointer (under
// the shared installed.lock this is definitive: a crash in the install→record
// gap, a removed or truncated ledger, or a hand-moved pointer — never the
// millisecond between Append and sign); then the genesis log_id. The caller
// holds installed.lock shared; lock order is store → ledger, as for every
// writer. A damaged ledger is a RECORDED refusal here (the pull answers an
// unrecorded 500 for the same state): a run is a policy-bearing action an
// invoker attempted, and Article III wants the attempt and why it did not
// execute in the ledger.
func recordedInstall(controlLog, hash string) (installFacts, *verifyRefusal) {
	records, _, verr := ledger.ReadVerify(controlLog, ledger.Locked)
	switch {
	case errors.Is(verr, ledger.ErrLockHeld):
		return installFacts{}, &verifyRefusal{Kind: verifyBusy}
	case errors.Is(verr, fs.ErrNotExist):
		records = nil
	case verr != nil:
		return installFacts{}, notVerifiable("control ledger damaged; run: agenthof audit repair control --control-log " + controlLog)
	}
	last, found := control.LastInstalling(records)
	if !found || last.ConfigHash != hash {
		return installFacts{}, notVerifiable("installed configuration is not on record; re-apply, or run audit repair control")
	}
	logID, err := control.GenesisLogID(records)
	if err != nil {
		return installFacts{}, notVerifiable(err.Error())
	}
	return installFacts{LogID: logID, Version: last.Seq, At: last.Time.UTC()}, nil
}

// judgeFloor applies the staleness floor to a signature that VERIFIED as the
// install (logID, version) — both from the signed payload, byte-equal to the
// ledger's. The log_id comparison comes before the version comparison (a
// version comparison across ledgers is meaningless: seq restarts at 1 in a
// re-created root). absent → accept, created; same ledger above → accept,
// advanced; equal → accept, no write; below → stale; another ledger →
// foreign ledger until the operator removes the floor (the reset gesture;
// it re-accepts an older version too). A corrupt floor fails closed, never
// reads as absent, and is never rewritten. Under verifyOnly nothing is
// written. A write failure after a verified signature refuses the run: a
// verification that cannot be remembered leaves the next rollback
// undetectable. Called under installed.lock shared, so every shared holder
// in the same window sees the same (logID, version) and two advancing
// writers write the same bytes.
func judgeFloor(controlLog, logID string, version int, mode verifyMode) *verifyRefusal {
	floorLogID, floorVersion, present, err := readVerifyFloor(controlLog)
	if err != nil {
		return notVerifiable(err.Error())
	}
	if present {
		if floorLogID != logID {
			return &verifyRefusal{Kind: verifyForeignLedger, Detail: fmt.Sprintf("install is of ledger %s; this root last verified ledger %s (version %d); remove %s to accept the new ledger", logID, floorLogID, floorVersion, verifyFloorPath(controlLog))}
		}
		if version < floorVersion {
			return &verifyRefusal{Kind: verifyStale, Detail: fmt.Sprintf("version %d is below this root's verified floor %d (ledger %s)", version, floorVersion, logID)}
		}
		if version == floorVersion {
			return nil
		}
	}
	if mode == verifyOnly {
		return nil
	}
	if err := writeVerifyFloor(controlLog, logID, version); err != nil {
		return notVerifiable(err.Error())
	}
	return nil
}

// pinnedKeyPath decides whether verification is pinned and where the key is.
// With --verify-key given, the flag IS the pin: the path is returned as
// pinned whether or not it exists (an absent or unreadable named key fails
// closed at loadVerifyPub, never state A). Without it, the conventional
// verify.pub is stat'ed: absent ⇒ not pinned, today's behavior; any stat
// error other than not-exist is a fault the caller reports.
func pinnedKeyPath(controlLog, verifyKey string) (pinned bool, path string, err error) {
	if verifyKey != "" {
		return true, verifyKey, nil
	}
	path = verifyPubPath(controlLog)
	exists, err := fileExists(path)
	if err != nil {
		return false, path, fmt.Errorf("pinned key %s: %w", path, err)
	}
	return exists, path, nil
}

// pinnedVerify is the run-side check under the shared lock the caller holds:
// the ledger's account of the install; the signature under the pinned
// key, classified by kind — sigAbsent/sigMalformed/sigForeign/sigOlder →
// unsigned with the verdict's detail; sigNewer → unsigned, rendered as
// "signature is for version <sig>, installed is <ledger>" (under the shared
// lock nothing is mid-install, so the pull's "retry" wording would be false
// here); sigUnknownKey → unknown key; sigBad → bad signature; then the floor.
// A .sig read error other than not-exist is returned as the error: a store
// fault for the caller's errs, not a verdict.
func pinnedVerify(controlLog, hash string, pub ed25519.PublicKey, mode verifyMode) (*verifyRefusal, error) {
	inst, refusal := recordedInstall(controlLog, hash)
	if refusal != nil {
		return refusal, nil
	}
	f, err := verifySignatureFile(installedStore(controlLog), hash, inst.LogID, inst.Version, inst.At, pub)
	if err != nil {
		var v *signatureVerdict
		if !errors.As(err, &v) {
			return nil, err
		}
		switch v.Kind {
		case sigUnknownKey:
			return &verifyRefusal{Kind: verifyUnknownKey, Detail: v.Detail}, nil
		case sigBad:
			return &verifyRefusal{Kind: verifyBadSignature}, nil
		case sigNewer:
			return &verifyRefusal{Kind: verifyUnsigned, Detail: fmt.Sprintf("signature is for version %d, installed is %d", v.File.Version, inst.Version)}, nil
		default:
			return &verifyRefusal{Kind: verifyUnsigned, Detail: v.Detail}, nil
		}
	}
	return judgeFloor(controlLog, f.LogID, f.Version, mode), nil
}
