package main

import (
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
		if priv, err := loadSigningKey(*controlLog); err == nil {
			id = config.KeyID(priv.Public().(ed25519.PublicKey))
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
// and — when something is installed under the control root — that it is
// not signed yet and how to sign it.
func keygenDone(out io.Writer, controlLog, keyPath, pubPath string, pub ed25519.PublicKey, pubPEM []byte) int {
	if keyPath != "" {
		_, _ = fmt.Fprintf(out, "wrote %s (private key, 0600 — keep it on this host)\n", keyPath)
	}
	_, _ = fmt.Fprintf(out, "wrote %s\n", pubPath)
	_, _ = fmt.Fprintf(out, "key_id: %s\n", config.KeyID(pub))
	_, _ = out.Write(pubPEM)
	_, _ = fmt.Fprintln(out, msgKeygenPin)
	if hash, installed, err := config.InstalledHash(installedStore(controlLog)); err == nil && installed {
		_, _ = fmt.Fprintf(out, "installed configuration %s is not signed yet; run: agenthof config sign --control-log %s\n", hash, controlLog)
	}
	return 0
}
