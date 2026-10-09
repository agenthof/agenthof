package main

import (
	"errors"
	"fmt"
	"io/fs"
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
)

// pullOutcome is what both callers read.
type pullOutcome struct {
	Kind     pullKind
	Snapshot apiclient.ConfigSnapshot // hash, version, installed_at, files — set on pulled
	Err      error                    // the real cause for the host's log; never served
}

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
// last installing event names it, or the answer is "not yet on record".
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
	snap := apiclient.ConfigSnapshot{Hash: hash, Version: last.Seq, InstalledAt: last.Time, Files: make(map[string]string, len(files))}
	for rel, data := range files {
		snap.Files[rel] = string(data)
	}
	return pullOutcome{Kind: pulled, Snapshot: snap}
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
