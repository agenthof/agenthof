package config

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// SignaturePath is where the signature of the CURRENT install of the
// snapshot named by hash lives: installed/<hex>.sig, a sibling of the
// snapshot directory — never inside it, so the snapshot's bytes stay
// exactly what files/v1 hashes and a store listing shows snapshots, the
// pointer and their .sig files side by side. It is overwritten on every
// install of <hex> (an identical re-apply, a flip back): the payload binds
// the install's version, so the file is never a per-version archive.
func SignaturePath(store, hash string) string { return SnapshotDir(store, hash) + ".sig" }

// SignatureFile is a parsed installed/<hex>.sig: the payload's six lines
// verbatim (Payload — what was signed, compared byte for byte by the pull,
// never re-rendered) plus the fields and the trailer's signature.
type SignatureFile struct {
	Payload     []byte
	Hash        string
	LogID       string
	Version     int
	InstalledAt string
	KeyID       string
	Sig         string
}

// versionRE is the shortest decimal: no sign, no leading zero, no fraction.
var versionRE = regexp.MustCompile(`^[1-9][0-9]*$`)

// SignatureFileBytes is the on-disk form: the payload followed by one
// "signature: <base64>\n" trailer — seven lines, nothing else. Self-
// describing so an operator can cat it, config sign can tell "already
// signed for this version" from stale, and the pull can say WHY a file does
// not serve instead of a bare verify failure.
func SignatureFileBytes(payload []byte, sig string) []byte {
	return []byte(string(payload) + "signature: " + sig + "\n")
}

// ParseSignatureFile reads a .sig. A carriage return anywhere is refused
// first (a CRLF file is a transfer fault, and its first line would
// otherwise read as an unknown format). Then the first line is judged
// alone: anything but the v1 format string is "unsupported signature
// format" — before any line is counted or any field compared — so a file in
// a future format is named as such, never as a wrong key or a stale
// version. Then exactly seven "\n"-terminated lines, each field on its own
// line with its grammar; the version must be the shortest decimal (07, +7
// and 7.0 are malformed, not "a different version"); the signature must be
// base64 of 64 bytes. Every refusal names its line.
func ParseSignatureFile(data []byte) (SignatureFile, error) {
	if bytes.Contains(data, []byte("\r")) {
		return SignatureFile{}, errors.New("signature file: carriage return; lines end with \\n only")
	}
	first, _, _ := bytes.Cut(data, []byte("\n"))
	if string(first) != SignatureFormatV1 {
		return SignatureFile{}, fmt.Errorf("unsupported signature format %q", clip(first))
	}
	if !bytes.HasSuffix(data, []byte("\n")) {
		return SignatureFile{}, errors.New("signature file: missing trailing newline")
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) != 7 {
		return SignatureFile{}, fmt.Errorf("signature file: %d lines; want 7", len(lines))
	}
	f := SignatureFile{Payload: []byte(strings.Join(lines[:6], "\n") + "\n")}
	value := func(n int, name string) (string, error) {
		prefix := name + ": "
		if !strings.HasPrefix(lines[n], prefix) {
			return "", fmt.Errorf("signature file: line %d: want %q", n+1, prefix+"<value>")
		}
		return strings.TrimPrefix(lines[n], prefix), nil
	}
	var err error
	if f.Hash, err = value(1, "hash"); err != nil {
		return SignatureFile{}, err
	}
	if !installedHashRE.MatchString(f.Hash) {
		return SignatureFile{}, errors.New("signature file: line 2: malformed hash (want sha256:<64 lowercase hex>)")
	}
	if f.LogID, err = value(2, "log_id"); err != nil {
		return SignatureFile{}, err
	}
	if !logIDRE.MatchString(f.LogID) {
		return SignatureFile{}, errors.New("signature file: line 3: malformed log_id (want 32 lowercase hex)")
	}
	v, err := value(3, "version")
	if err != nil {
		return SignatureFile{}, err
	}
	if !versionRE.MatchString(v) {
		return SignatureFile{}, errors.New("signature file: line 4: malformed version (want the shortest decimal)")
	}
	if f.Version, err = strconv.Atoi(v); err != nil {
		return SignatureFile{}, fmt.Errorf("signature file: line 4: %w", err)
	}
	if f.InstalledAt, err = value(4, "installed_at"); err != nil {
		return SignatureFile{}, err
	}
	if f.InstalledAt == "" || strings.ContainsAny(f.InstalledAt, " \t") {
		return SignatureFile{}, errors.New("signature file: line 5: malformed installed_at")
	}
	if f.KeyID, err = value(5, "key_id"); err != nil {
		return SignatureFile{}, err
	}
	if !keyIDRE.MatchString(f.KeyID) {
		return SignatureFile{}, errors.New("signature file: line 6: malformed key_id (want 64 lowercase hex)")
	}
	if f.Sig, err = value(6, "signature"); err != nil {
		return SignatureFile{}, err
	}
	if raw, derr := base64.StdEncoding.DecodeString(f.Sig); derr != nil || len(raw) != ed25519.SignatureSize {
		return SignatureFile{}, errors.New("signature file: line 7: malformed signature (want base64 of 64 bytes)")
	}
	return f, nil
}

// clip bounds a foreign first line for an error message.
func clip(b []byte) string {
	if len(b) > 64 {
		b = b[:64]
	}
	return string(b)
}

// WriteSignatureFile writes installed/<hex>.sig atomically, as CommitSnapshot
// writes the pointer: a .sig-* temp under store, fsync, rename over the
// final name, fsync the store directory. On any failure the temp is removed
// and whatever .sig was there before is untouched.
func WriteSignatureFile(store, hash string, payload []byte, sig string) error {
	if !installedHashRE.MatchString(hash) {
		return fmt.Errorf("signature file: refusing to write under malformed hash %q", hash)
	}
	f, err := os.CreateTemp(store, ".sig-*")
	if err != nil {
		return fmt.Errorf("signature file: %w", err)
	}
	tmp := f.Name()
	_, werr := f.Write(SignatureFileBytes(payload, sig))
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(tmp, SignaturePath(store, hash))
	}
	if werr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("signature file: %w", werr)
	}
	if d, derr := os.Open(store); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
