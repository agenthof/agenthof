package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"
	"unicode/utf8"

	"github.com/agenthof/agenthof/internal/apiclient"
	"github.com/agenthof/agenthof/internal/authz"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/ledger"
)

// pullRequest is one read of the installed configuration for distribution.
type pullRequest struct {
	ControlLog string
	// Authorize is true on the API path: Invoker is the verified token and
	// is authorized against the installed roles (pull, or apply). The local
	// reader (config pull without --server) passes false: the caller owns
	// the filesystem and reads the store as audit control reads the ledger,
	// with no identity and no gate.
	Authorize bool
	Invoker   identity.Invoker
}

// pullKind is the terminal outcome of pullConfig. The host maps it to a
// status and the handler to an HTTP code; none of them is recorded.
type pullKind int

const (
	pulled               pullKind = iota // 200
	pullNothingInstalled                 // 404: no pointer
	pullRefused                          // 403: no role grants pull or apply to the invoker
	pullStoreUnusable                    // 500: pointer unreadable or malformed, roles unreadable, snapshot gone or mismatched
	pullNotBundleable                    // 500: a file name or encoding a bundle cannot carry
	pullLedgerDamaged                    // 500: torn, broken or unreadable control ledger
	pullBusy                             // 503: the ledger's flock is held past the retry
	pullNotRecorded                      // 503: the ledger does not vouch for the pointer
	pullNotSigned                        // 503: signing is configured and installed/<hex>.sig is absent, stale, foreign or does not verify
)

// pullOutcome is what both callers read.
type pullOutcome struct {
	Kind     pullKind
	Snapshot apiclient.ConfigSnapshot // hash, version, installed_at (UTC), files, signature — set on pulled
	Err      error                    // the real cause for the host's log; never served
}

// errNotSigned wraps every cause of a not-signed verdict; errSignatureNewer
// is the one benign cause — the .sig names a version above the vouched
// install, so this read raced an install that landed between the ledger
// read and the file read; a retry gets 200 and no remedy is due.
var (
	errNotSigned      = errors.New("not signed")
	errSignatureNewer = errors.New("signature is newer than the vouched install; retry")
)

// pullAllowed is the pull action's authorization: pull, or apply, which
// includes it (constitution, Article VI). It is the ONE place the
// implication lives; authz.ControlAllows stays op-by-op.
func pullAllowed(roles []config.RoleDef, inv identity.Invoker) bool {
	return authz.ControlAllows(roles, inv, "pull") || authz.ControlAllows(roles, inv, "apply")
}

// pullConfig is THE pull — the server (Authorize) and the local reader
// both call it. It is a read: nothing here appends to the control ledger,
// nothing takes the installed-configuration writer lock, nothing writes
// under the store. Order, pinned: (1) the lenient roles read decides
// nothing-installed and store-unusable before anyone is authorized — with
// no readable roles there is nobody to decide with; (2) authorize; (3) the
// snapshot named by the hash step 1 returned, verified over the bytes
// returned — never a second pointer read, so a concurrent apply cannot
// make this serve one snapshot under another's roles; (4) every file must
// be text a bundle can carry; (5) the ledger, last, because it is the
// expensive step and the one that can block on a lock — a refused or empty
// pull never pays it; (6) the ledger must vouch for the hash served: the
// last installing event names it, or the answer is "not yet on record";
// (7) when a signing key is configured beside the ledger, installed/<hex>.sig
// must exist and verify — under signing.pub, for exactly the served hash,
// log_id, version and installed_at — or the answer is "not yet signed"; the
// pull never reads signing.key.
func pullConfig(req pullRequest) pullOutcome {
	store := installedStore(req.ControlLog)
	var (
		files map[string][]byte
		hash  string
	)
	if req.Authorize {
		roles, h, installed, err := config.InstalledRoles(store)
		if err != nil {
			return pullOutcome{Kind: pullStoreUnusable, Err: err}
		}
		if !installed {
			return pullOutcome{Kind: pullNothingInstalled}
		}
		if !pullAllowed(roles, req.Invoker) {
			return pullOutcome{Kind: pullRefused}
		}
		files, err = config.SnapshotBundle(store, h)
		if err != nil {
			return bundleFailure(err)
		}
		hash = h
	} else {
		f, h, installed, err := config.InstalledBundle(store)
		if err != nil {
			return bundleFailure(err)
		}
		if !installed {
			return pullOutcome{Kind: pullNothingInstalled}
		}
		files, hash = f, h
	}
	for rel, data := range files {
		if !utf8.Valid(data) {
			return pullOutcome{Kind: pullNotBundleable, Err: fmt.Errorf("installed config %s: %s: not valid UTF-8; a bundle carries text", hash, rel)}
		}
	}

	records, _, verr := ledger.ReadVerify(req.ControlLog, ledger.Locked)
	switch {
	case errors.Is(verr, ledger.ErrLockHeld):
		return pullOutcome{Kind: pullBusy, Err: verr}
	case errors.Is(verr, fs.ErrNotExist):
		// Something is installed and no ledger exists: an empty chain, which
		// vouches for nothing. Not damage — the answer below is "not yet on
		// record", the same answer as any unrecorded install.
		records = nil
	case verr != nil:
		// Torn, broken, or unreadable. The valid prefix of a torn ledger is
		// not used to vouch: the interrupted write may be the very record
		// this read needs, and a distribution read must not guess.
		return pullOutcome{Kind: pullLedgerDamaged, Err: verr}
	}
	last, found := control.LastInstalling(records)
	if !found || last.ConfigHash != hash {
		return pullOutcome{Kind: pullNotRecorded}
	}
	// The ONE normalization of the install time: the served installed_at
	// and — when signing — the signed line are both this value, so the two
	// strings are one rendering by construction. Nothing else touches last.Time.
	at := last.Time.UTC()
	snap := apiclient.ConfigSnapshot{Hash: hash, Version: last.Seq, InstalledAt: at, Files: make(map[string]string, len(files))}
	for rel, data := range files {
		snap.Files[rel] = string(data)
	}

	// (7) The signature, last: its payload needs the vouched (log_id,
	// version, time). Key-file faults are named before ledger faults, and
	// neither is reported as "not signed". Not configured → unsigned 200;
	// signing.key without signing.pub → store unusable (the keygen remedy
	// in the cause); signing.pub unreadable → store unusable; a genesis
	// without log_id → ledger damaged; then the .sig itself.
	state, err := signingStateOf(req.ControlLog)
	if err != nil {
		return pullOutcome{Kind: pullStoreUnusable, Err: err}
	}
	switch state {
	case signingOff:
		return pullOutcome{Kind: pulled, Snapshot: snap}
	case signingKeyOnly:
		return pullOutcome{Kind: pullStoreUnusable, Err: fmt.Errorf("%s present without %s; run: agenthof config keygen --control-log %s", signingKeyPath(req.ControlLog), signingPubPath(req.ControlLog), req.ControlLog)}
	}
	pub, err := loadSigningPub(req.ControlLog)
	if err != nil {
		return pullOutcome{Kind: pullStoreUnusable, Err: err}
	}
	logID, err := control.GenesisLogID(records)
	if err != nil {
		return pullOutcome{Kind: pullLedgerDamaged, Err: err}
	}
	sig, err := servedSignature(store, hash, logID, last.Seq, at, pub)
	switch {
	case errors.Is(err, errNotSigned):
		return pullOutcome{Kind: pullNotSigned, Err: err}
	case err != nil:
		return pullOutcome{Kind: pullStoreUnusable, Err: err}
	}
	snap.Signature = sig
	return pullOutcome{Kind: pulled, Snapshot: snap}
}

// servedSignature reads installed/<hex>.sig and decides whether it is THE
// signature of the vouched install — existence is never enough, since the
// file is overwritten on every install of <hex> and a stale one would make
// every edge see "bad signature" with nothing telling either side to retry.
// The order mirrors what an execution point does: the file's format line
// first (a future format is named as such, never as a wrong key); then its
// key id against the configured key (a rotated or foreign key is "by key",
// before any verify); then the first six lines must be byte-identical to
// the payload rebuilt from the vouched fields — and when they are not, WHICH
// field differs decides the verdict: a version above the vouched seq means
// this read raced an install (errSignatureNewer: benign, retry), a version
// below, another hash or another log_id is a genuine stale or foreign file;
// then the Ed25519 verify. Every not-signed cause wraps errNotSigned; a
// read failure other than not-exist is store damage.
func servedSignature(store, hash, logID string, version int, at time.Time, pub ed25519.PublicKey) (*apiclient.ConfigSignature, error) {
	data, err := os.ReadFile(config.SignaturePath(store, hash))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: no signature file for %s", errNotSigned, hash)
	}
	if err != nil {
		return nil, err
	}
	f, err := config.ParseSignatureFile(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errNotSigned, err)
	}
	keyID := config.KeyID(pub)
	if f.KeyID != keyID {
		return nil, fmt.Errorf("%w: signature is by key %s; configured key is %s", errNotSigned, f.KeyID, keyID)
	}
	expected, err := config.SignaturePayload(hash, logID, version, at, keyID)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(f.Payload, expected) {
		switch {
		case f.Version > version:
			return nil, fmt.Errorf("%w: %w", errNotSigned, errSignatureNewer)
		case f.Version < version:
			return nil, fmt.Errorf("%w: signature is for version %d, installed is %d", errNotSigned, f.Version, version)
		case f.Hash != hash:
			return nil, fmt.Errorf("%w: signature is for hash %s, installed is %s", errNotSigned, f.Hash, hash)
		case f.LogID != logID:
			return nil, fmt.Errorf("%w: signature is for log_id %s, installed is %s", errNotSigned, f.LogID, logID)
		}
		return nil, fmt.Errorf("%w: signature is for installed_at %s, installed is %s", errNotSigned, f.InstalledAt, at.Format(time.RFC3339Nano))
	}
	if !config.Verify(pub, f.Payload, f.Sig) {
		return nil, fmt.Errorf("%w: signature does not verify", errNotSigned)
	}
	return &apiclient.ConfigSignature{Format: config.SignatureFormatV1, LogID: f.LogID, KeyID: f.KeyID, Sig: f.Sig}, nil
}

// bundleFailure classifies a snapshot read that failed: a name a bundle
// cannot carry is its own kind; everything else — a malformed pointer, a
// snapshot that is gone, bytes that do not hash as the pointer — is store
// damage.
func bundleFailure(err error) pullOutcome {
	if errors.Is(err, config.ErrNotBundleable) {
		return pullOutcome{Kind: pullNotBundleable, Err: err}
	}
	return pullOutcome{Kind: pullStoreUnusable, Err: err}
}
