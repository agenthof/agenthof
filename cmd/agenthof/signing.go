package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/ledger"
)

// signingKeyPath and signingPubPath are the operator's signing pair for a
// control ledger: signing.key (the Ed25519 private key, a credential) and
// signing.pub (what the pull verifies with and what an execution point pins),
// BESIDE the store and scoped to the control root exactly as installed.lock
// is — the signature is about THIS root's installs. Never under the
// configuration directory (credentials are not law: never applied, never
// hashed, never bundled) and never inside installed/ (a store listing holds
// snapshots, the pointer and their .sig files). Derived here and nowhere
// else, so every path agrees where the pair lives.
func signingKeyPath(controlLog string) string {
	return filepath.Join(filepath.Dir(controlLog), "signing.key")
}

func signingPubPath(controlLog string) string {
	return filepath.Join(filepath.Dir(controlLog), "signing.pub")
}

// signingState is which of the two key files exist. Signing is CONFIGURED
// whenever either exists: the only off switch is removing both, so a lone
// credential is never silently ignored and an install and a pull can never
// disagree about whether signing is on. A lone signing.pub (the private key
// was lost) still serves an existing signature and fails the next install
// loudly; a lone signing.key is broken on every path until config keygen
// re-derives the public file.
type signingState int

const (
	signingOff     signingState = iota // neither file: unsigned, exactly as before
	signingPubOnly                     // signing.pub alone
	signingKeyOnly                     // signing.key alone
	signingOn                          // both
)

func (s signingState) configured() bool { return s != signingOff }

// signingStateOf stats both files. It never reads signing.key — the pull
// runs this and must stay least-privilege. A stat failure other than
// not-exist is an error, never "absent".
func signingStateOf(controlLog string) (signingState, error) {
	key, err := fileExists(signingKeyPath(controlLog))
	if err != nil {
		return signingOff, err
	}
	pub, err := fileExists(signingPubPath(controlLog))
	if err != nil {
		return signingOff, err
	}
	switch {
	case key && pub:
		return signingOn, nil
	case key:
		return signingKeyOnly, nil
	case pub:
		return signingPubOnly, nil
	}
	return signingOff, nil
}

func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// loadSigningPub reads and parses signing.pub; the error names the file.
func loadSigningPub(controlLog string) (ed25519.PublicKey, error) {
	p := signingPubPath(controlLog)
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	pub, err := config.ParseSigningPub(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	return pub, nil
}

// loadSigningKey reads and parses signing.key; the error names the file.
func loadSigningKey(controlLog string) (ed25519.PrivateKey, error) {
	p := signingKeyPath(controlLog)
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	priv, err := config.ParseSigningKey(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	return priv, nil
}

// writeExclusive creates path 0600 — O_EXCL, so it never overwrites —
// writes data and fsyncs before closing.
func writeExclusive(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// msgKeygenPin follows the printed public key.
const msgKeygenPin = "pin this public key at every execution point that verifies this host's configuration"

// cmdConfigKeygen is `config keygen`: generate the operator's Ed25519 signing
// pair beside the control ledger and print the public key to pin. It never
// overwrites a private key (rotation is not supported yet: to start over the
// operator removes both files and every pinning edge re-pins); it refuses a
// lone signing.pub (a new pair under a stale public file would make every
// signature unverifiable); and it repairs a lone signing.key by writing only
// the missing public file, derived from the private one. The private key is
// written first, the public file second; if the second write fails the first
// is removed, so the host is left with nothing rather than half a pair. It
// never prints the private key, never touches the ledger, and reads only
// the installed pointer — to say, when something is installed, that it is
// not signed yet. Exit 0; 1 on a refusal or a write failure; 2 for usage.
func cmdConfigKeygen(args []string, out io.Writer) int {
	flags := flag.NewFlagSet("config keygen", flag.ContinueOnError)
	controlLog := flags.String("control-log", ".agenthof/control.jsonl", "control-plane ledger path; the signing pair is written beside it")
	flags.SetOutput(out)
	if err := flags.Parse(args); err != nil {
		return 2
	}
	keyPath, pubPath := signingKeyPath(*controlLog), signingPubPath(*controlLog)
	if err := os.MkdirAll(filepath.Dir(*controlLog), 0o700); err != nil {
		_, _ = fmt.Fprintf(out, "config keygen: %v\n", err)
		return 1
	}
	state, err := signingStateOf(*controlLog)
	if err != nil {
		_, _ = fmt.Fprintf(out, "config keygen: %v\n", err)
		return 1
	}
	switch state {
	case signingOn:
		id := "unreadable"
		if pub, err := loadSigningPub(*controlLog); err == nil {
			id = config.KeyID(pub) // the public key's id — the one edges pin
		}
		_, _ = fmt.Fprintf(out, "config keygen: %s exists (key_id %s); key rotation is not supported yet — to start over, remove signing.key and signing.pub (every edge pinned to the old key must re-pin)\n", keyPath, id)
		return 1
	case signingPubOnly:
		_, _ = fmt.Fprintf(out, "config keygen: %s exists without its private key; remove it to generate a new pair (edges pinned to it must re-pin)\n", pubPath)
		return 1
	case signingKeyOnly:
		priv, err := loadSigningKey(*controlLog)
		if err != nil {
			_, _ = fmt.Fprintf(out, "config keygen: %v\n", err)
			return 1
		}
		pub := priv.Public().(ed25519.PublicKey)
		pubPEM, err := config.EncodeSigningPub(pub)
		if err != nil {
			_, _ = fmt.Fprintf(out, "config keygen: %v\n", err)
			return 1
		}
		if err := writeExclusive(pubPath, pubPEM); err != nil {
			_, _ = fmt.Fprintf(out, "config keygen: %v\n", err)
			return 1
		}
		return keygenDone(out, *controlLog, "", pubPath, pub, pubPEM)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		_, _ = fmt.Fprintf(out, "config keygen: %v\n", err)
		return 1
	}
	keyPEM, err := config.EncodeSigningKey(priv)
	if err != nil {
		_, _ = fmt.Fprintf(out, "config keygen: %v\n", err)
		return 1
	}
	pubPEM, err := config.EncodeSigningPub(pub)
	if err != nil {
		_, _ = fmt.Fprintf(out, "config keygen: %v\n", err)
		return 1
	}
	if err := writeExclusive(keyPath, keyPEM); err != nil {
		_, _ = fmt.Fprintf(out, "config keygen: %v\n", err)
		return 1
	}
	if err := writeExclusive(pubPath, pubPEM); err != nil {
		_ = os.Remove(keyPath)
		_, _ = fmt.Fprintf(out, "config keygen: %v; removed %s so the host holds no half-made pair\n", err, keyPath)
		return 1
	}
	return keygenDone(out, *controlLog, keyPath, pubPath, pub, pubPEM)
}

// keygenDone prints what was written (keyPath is "" when only the public
// file was re-derived), the key id, the public PEM verbatim, the pin line
// and — when something is installed under the control root — how to sign it.
// A fresh pair cannot have signed anything, so it says "not signed yet"; a
// re-derived public file may face an install already signed under the old
// pair, so it offers config sign conditionally rather than asserting the gap.
func keygenDone(out io.Writer, controlLog, keyPath, pubPath string, pub ed25519.PublicKey, pubPEM []byte) int {
	if keyPath != "" {
		_, _ = fmt.Fprintf(out, "wrote %s (private key, 0600 — keep it on this host)\n", keyPath)
	}
	_, _ = fmt.Fprintf(out, "wrote %s\n", pubPath)
	_, _ = fmt.Fprintf(out, "key_id: %s\n", config.KeyID(pub))
	_, _ = out.Write(pubPEM)
	_, _ = fmt.Fprintln(out, msgKeygenPin)
	if hash, installed, err := config.InstalledHash(installedStore(controlLog)); err == nil && installed {
		if keyPath != "" {
			_, _ = fmt.Fprintf(out, "installed configuration %s is not signed yet; run: agenthof config sign --control-log %s\n", hash, controlLog)
		} else {
			_, _ = fmt.Fprintf(out, "installed configuration %s: if it is not yet signed, run: agenthof config sign --control-log %s\n", hash, controlLog)
		}
	}
	return 0
}

// Every sign verdict an installer or config sign classifies by.
var (
	errSigningOff        = errors.New("no signing key")
	errSigningKeyMissing = errors.New("signing.key missing")
	errSigningPubMissing = errors.New("signing.pub missing")
	errNothingInstalled  = errors.New(msgNoConfigInstalled)
	errNotOnRecord       = errors.New("installed configuration is not yet on record")
	errLedgerDamaged     = errors.New("control ledger damaged")
)

// signatureInfo is one computed signature of the current install.
type signatureInfo struct {
	Hash    string
	Version int
	KeyID   string
	Payload []byte
	Sig     string
}

// buildSignature computes — and does not write — the operator's signature
// over what the control ledger vouches for. The caller holds the
// installed-configuration writer lock. Order: the key state (off →
// errSigningOff; public file alone → errSigningKeyMissing; private key
// alone → errSigningPubMissing); the pointer (absent → errNothingInstalled);
// the ledger, read and verified with exactly the pull's classification (lock
// held → ledger.ErrLockHeld; no file → nothing on record, never damage;
// torn or broken → errLedgerDamaged); the last installing event must name
// the pointer (else errNotOnRecord: the install→record gap — nothing to
// sign, and signing an unvouched pointer would make the ledger's "not yet
// on record" into a signature that lies); the genesis log_id; the pair,
// whose derived public key must equal signing.pub (a mismatch names both
// ids — otherwise an install would write a signature the pull can never
// verify); then the payload from (hash, log_id, seq, time, key_id) — where
// the time is normalized to UTC ONCE, here, exactly as the pull normalizes
// it before serving — and the signature. It never invents a version or a
// time: what is signed is what the ledger vouches for, by construction.
func buildSignature(controlLog string) (signatureInfo, error) {
	state, err := signingStateOf(controlLog)
	if err != nil {
		return signatureInfo{}, err
	}
	switch state {
	case signingOff:
		return signatureInfo{}, errSigningOff
	case signingPubOnly:
		return signatureInfo{}, errSigningKeyMissing
	case signingKeyOnly:
		return signatureInfo{}, errSigningPubMissing
	}
	store := installedStore(controlLog)
	hash, installed, err := config.InstalledHash(store)
	if err != nil {
		return signatureInfo{}, err
	}
	if !installed {
		return signatureInfo{}, errNothingInstalled
	}
	records, _, verr := ledger.ReadVerify(controlLog, ledger.Locked)
	switch {
	case errors.Is(verr, ledger.ErrLockHeld):
		return signatureInfo{}, verr
	case errors.Is(verr, fs.ErrNotExist):
		records = nil
	case verr != nil:
		return signatureInfo{}, fmt.Errorf("%w: %w", errLedgerDamaged, verr)
	}
	last, found := control.LastInstalling(records)
	if !found || last.ConfigHash != hash {
		return signatureInfo{}, errNotOnRecord
	}
	logID, err := control.GenesisLogID(records)
	if err != nil {
		return signatureInfo{}, err
	}
	priv, err := loadSigningKey(controlLog)
	if err != nil {
		return signatureInfo{}, err
	}
	pub, err := loadSigningPub(controlLog)
	if err != nil {
		return signatureInfo{}, err
	}
	keyID := config.KeyID(pub)
	if derived := config.KeyID(priv.Public().(ed25519.PublicKey)); derived != keyID {
		return signatureInfo{}, fmt.Errorf("%s (key_id %s) is not the private key of %s (key_id %s)", signingKeyPath(controlLog), derived, signingPubPath(controlLog), keyID)
	}
	at := last.Time.UTC()
	payload, err := config.SignaturePayload(hash, logID, last.Seq, at, keyID)
	if err != nil {
		return signatureInfo{}, err
	}
	return signatureInfo{Hash: hash, Version: last.Seq, KeyID: keyID, Payload: payload, Sig: config.Sign(priv, payload)}, nil
}

// signInstalled is buildSignature plus the atomic write of installed/<hex>.sig.
func signInstalled(controlLog string) (signatureInfo, error) {
	info, err := buildSignature(controlLog)
	if err != nil {
		return signatureInfo{}, err
	}
	if err := config.WriteSignatureFile(installedStore(controlLog), info.Hash, info.Payload, info.Sig); err != nil {
		return signatureInfo{}, err
	}
	return info, nil
}

// signIfConfigured is the installers' sign step: with signing off it does
// nothing (signed false, err nil — the unsigned success); otherwise
// signInstalled, whose failure the caller reports as installed-but-not-signed.
func signIfConfigured(controlLog string) (info signatureInfo, signed bool, err error) {
	state, err := signingStateOf(controlLog)
	if err != nil {
		return signatureInfo{}, false, err
	}
	if !state.configured() {
		return signatureInfo{}, false, nil
	}
	info, err = signInstalled(controlLog)
	if err != nil {
		return signatureInfo{}, false, err
	}
	return info, true, nil
}

// signRemedy names the one command that repairs a sign failure: config
// keygen when the public file is missing (it re-derives it), config sign
// otherwise.
func signRemedy(controlLog string, cause error) string {
	if errors.Is(cause, errSigningPubMissing) {
		return "run: agenthof config keygen --control-log " + controlLog
	}
	return "run: agenthof config sign --control-log " + controlLog
}

// cmdConfigSign is `config sign`: write (or confirm) the operator's
// signature of the installed configuration — the remedy for an install
// whose sign step failed or was interrupted, and for a configuration
// installed before the key existed. It takes the installed-configuration
// writer lock, as apply does, so its read-pointer → read-ledger → write
// sequence never interleaves with an apply or a flip (an identical re-apply
// in between would otherwise leave a stale .sig over a fresh one); then it
// computes exactly what an install would have written and, when a
// byte-identical .sig is already there, says so and touches nothing. Local
// only: signing needs signing.key, which lives on the install host. No
// identity, no control event. Exit 0; 1 for every refusal; 2 for usage.
func cmdConfigSign(args []string, out io.Writer) int {
	fs := flag.NewFlagSet("config sign", flag.ContinueOnError)
	controlLog := fs.String("control-log", ".agenthof/control.jsonl", "control-plane ledger path; the installed configuration and the signing pair are read beside it")
	fs.SetOutput(out)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	unlock, lockErr := ledger.LockFile(installedLock(*controlLog))
	if lockErr != nil {
		if errors.Is(lockErr, ledger.ErrLockHeld) {
			_, _ = fmt.Fprintf(out, "config sign: %s\n", msgLockBusy)
			return 1
		}
		_, _ = fmt.Fprintf(out, "config sign: %v\n", lockErr)
		return 1
	}
	defer unlock()
	store := installedStore(*controlLog)
	info, err := buildSignature(*controlLog)
	switch {
	case err == nil:
	case errors.Is(err, errSigningOff):
		_, _ = fmt.Fprintf(out, "config sign: no signing key; run: agenthof config keygen --control-log %s\n", *controlLog)
		return 1
	case errors.Is(err, errSigningKeyMissing):
		_, _ = fmt.Fprintf(out, "config sign: %v\n", err)
		return 1
	case errors.Is(err, errSigningPubMissing):
		_, _ = fmt.Fprintf(out, "config sign: %v; run: agenthof config keygen --control-log %s\n", err, *controlLog)
		return 1
	case errors.Is(err, errNothingInstalled):
		_, _ = fmt.Fprintf(out, "config sign: %s under %s; run: agenthof apply --config <dir> --control-log %s\n", msgNoConfigInstalled, store, *controlLog)
		return 1
	case errors.Is(err, errNotOnRecord):
		_, _ = fmt.Fprintln(out, "config sign: installed configuration is not yet on record; re-apply (or audit repair control) first")
		return 1
	case errors.Is(err, ledger.ErrLockHeld):
		_, _ = fmt.Fprintf(out, "config sign: %s\n", msgLockBusy)
		return 1
	case errors.Is(err, errLedgerDamaged):
		_, _ = fmt.Fprintf(out, "control ledger damaged; run: agenthof audit repair control --control-log %s\n", *controlLog)
		return 1
	default:
		_, _ = fmt.Fprintf(out, "config sign: %v\n", err)
		return 1
	}
	want := config.SignatureFileBytes(info.Payload, info.Sig)
	if existing, rerr := os.ReadFile(config.SignaturePath(store, info.Hash)); rerr == nil && bytes.Equal(existing, want) {
		_, _ = fmt.Fprintf(out, "already signed: %s  version: %d  key_id: %s\n", info.Hash, info.Version, info.KeyID)
		return 0
	}
	if err := config.WriteSignatureFile(store, info.Hash, info.Payload, info.Sig); err != nil {
		_, _ = fmt.Fprintf(out, "config sign: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(out, "signed: %s\nversion: %d  key_id: %s\n", info.Hash, info.Version, info.KeyID)
	return 0
}

// signingStartupWarning is serve's one look at the signature at startup —
// a read that takes a shared read and not the writer lock, no write and no
// re-drive (serve never holds the writer lock at startup and must not start
// signing on its own; audit
// verify control is the operator's reconcile). It returns "" when signing
// is off or the vouched install is signed; the keygen remedy for a private
// key without its public file; the config sign remedy when the ledger
// vouches for the pointer and no .sig verifies. A ledger that is busy,
// damaged or does not vouch says nothing here: those are the pull's and the
// audit readers' verdicts.
func signingStartupWarning(controlLog string) string {
	state, err := signingStateOf(controlLog)
	if err != nil || !state.configured() {
		return ""
	}
	if state == signingKeyOnly {
		return fmt.Sprintf("%s present without %s; run: agenthof config keygen --control-log %s", signingKeyPath(controlLog), signingPubPath(controlLog), controlLog)
	}
	pub, err := loadSigningPub(controlLog)
	if err != nil {
		return fmt.Sprintf("%v; every pull will answer 500 until it is restored", err)
	}
	store := installedStore(controlLog)
	hash, installed, err := config.InstalledHash(store)
	if err != nil || !installed {
		return ""
	}
	records, _, verr := ledger.ReadVerify(controlLog, ledger.Locked)
	if verr != nil {
		return ""
	}
	last, found := control.LastInstalling(records)
	if !found || last.ConfigHash != hash {
		return ""
	}
	logID, err := control.GenesisLogID(records)
	if err != nil {
		return ""
	}
	// Only a sign gap earns the config sign remedy. A signature newer than
	// the vouched install is a read racing a re-apply (the pull retries to
	// 200), and any other error is a store fault the sign remedy cannot fix.
	_, err = servedSignature(store, hash, logID, last.Seq, last.Time.UTC(), pub)
	switch {
	case err == nil, errors.Is(err, errSignatureNewer):
		return ""
	case errors.Is(err, errNotSigned):
		return fmt.Sprintf("installed configuration is not signed; every pull will answer 503 until signed; run: agenthof config sign --control-log %s", controlLog)
	default:
		return fmt.Sprintf("installed configuration signature is unreadable (%v); every pull will answer 500 until it is repaired", err)
	}
}
