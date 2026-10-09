package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// goldenSigFile is the seven-line file for golden vector 1.
func goldenSigFile(t *testing.T) []byte {
	t.Helper()
	return SignatureFileBytes(mustPayload(t, goldenHash, goldenLogID, 7, goldenAt7, goldenKeyID), goldenSig7)
}

func TestSignatureFileRoundTrip(t *testing.T) {
	_, pub := goldenKey(t)
	store := t.TempDir()
	payload := mustPayload(t, goldenHash, goldenLogID, 7, goldenAt7, goldenKeyID)
	if err := WriteSignatureFile(store, goldenHash, payload, goldenSig7); err != nil {
		t.Fatal(err)
	}
	p := SignaturePath(store, goldenHash)
	if p != filepath.Join(store, strings.TrimPrefix(goldenHash, "sha256:")+".sig") {
		t.Fatalf("SignaturePath = %s", p)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	want := string(payload) + "signature: " + goldenSig7 + "\n"
	if string(data) != want || strings.Count(want, "\n") != 7 {
		t.Fatalf("file:\n%q\nwant\n%q", data, want)
	}
	if info, _ := os.Stat(p); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o, want 0600", info.Mode().Perm())
	}
	f, err := ParseSignatureFile(data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(f.Payload, payload) || f.Hash != goldenHash || f.LogID != goldenLogID || f.Version != 7 ||
		f.InstalledAt != "2026-10-09T02:12:01.5Z" || f.KeyID != goldenKeyID || f.Sig != goldenSig7 {
		t.Fatalf("parsed %+v", f)
	}
	if !Verify(pub, f.Payload, f.Sig) {
		t.Fatal("the parsed payload must verify under the parsed signature")
	}
	// Overwrite: the file is the signature of the CURRENT install, never an archive.
	payload8 := mustPayload(t, goldenHash, goldenLogID, 8, goldenAt8, goldenKeyID)
	if err := WriteSignatureFile(store, goldenHash, payload8, goldenSig8); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(p); !bytes.Equal(data, SignatureFileBytes(payload8, goldenSig8)) {
		t.Fatal("a second write must replace the file")
	}
	for _, e := range mustReadDir(t, store) {
		if strings.HasPrefix(e, ".sig-") {
			t.Fatalf("temp residue: %s", e)
		}
	}
}

func mustReadDir(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

// TestSignatureFileParseRefusals: the format line is judged FIRST and alone
// — a v2 or garbage first line is "unsupported signature format" and names
// no line, no key, no version — then structure and each field's grammar,
// every refusal naming its line.
func TestSignatureFileParseRefusals(t *testing.T) {
	good := string(goldenSigFile(t))
	lines := strings.Split(strings.TrimSuffix(good, "\n"), "\n")
	withLine := func(n int, text string) string {
		l := append([]string{}, lines...)
		l[n] = text
		return strings.Join(l, "\n") + "\n"
	}
	cases := []struct{ name, data, want, never string }{
		{"v2 first line", withLine(0, "agenthof-config-signature/v2"), `unsupported signature format "agenthof-config-signature/v2"`, "line"},
		{"garbage first line", "\x00\xff not a signature", "unsupported signature format", "line"},
		{"v2 with different shape", "agenthof-config-signature/v2\nkey_id: nope\n", "unsupported signature format", "key"},
		{"six lines", strings.Join(lines[:6], "\n") + "\n", "6 lines; want 7", ""},
		{"eight lines", good + "extra\n", "8 lines; want 7", ""},
		{"CRLF", strings.ReplaceAll(good, "\n", "\r\n"), "carriage return", ""},
		{"no trailing newline", strings.TrimSuffix(good, "\n"), "trailing newline", ""},
		{"hash uppercase", withLine(1, "hash: sha256:"+strings.Repeat("A", 64)), "line 2", ""},
		{"hash wrong name", withLine(1, "digest: "+goldenHash), "line 2", ""},
		{"log_id short", withLine(2, "log_id: 0011"), "line 3", ""},
		{"version 07", withLine(3, "version: 07"), "line 4", ""},
		{"version +7", withLine(3, "version: +7"), "line 4", ""},
		{"version 7.0", withLine(3, "version: 7.0"), "line 4", ""},
		{"version 0", withLine(3, "version: 0"), "line 4", ""},
		{"version huge", withLine(3, "version: 99999999999999999999999"), "line 4", ""},
		{"installed_at empty", withLine(4, "installed_at: "), "line 5", ""},
		{"installed_at with space", withLine(4, "installed_at: 2026-10-09 02:12:01Z"), "line 5", ""},
		{"key_id short", withLine(5, "key_id: 5647"), "line 6", ""},
		{"signature not base64", withLine(6, "signature: not*base64"), "line 7", ""},
		{"signature wrong length", withLine(6, "signature: "+goldenSig7[:40]), "line 7", ""},
		{"signature wrong name", withLine(6, "sig: "+goldenSig7), "line 7", ""},
		{"empty", "", "unsupported signature format", "line"},
	}
	for _, c := range cases {
		_, err := ParseSignatureFile([]byte(c.data))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: err %v, want %q", c.name, err, c.want)
		}
		if c.never != "" && strings.Contains(err.Error(), c.never) {
			t.Fatalf("%s: err %v must not mention %q", c.name, err, c.never)
		}
	}
	// A different-but-valid version parses (the pull compares bytes; the parser only checks grammar).
	if f, err := ParseSignatureFile([]byte(withLine(3, "version: 12"))); err != nil || f.Version != 12 {
		t.Fatalf("version 12: %v %+v", err, f)
	}
}

// TestSignatureFileWriteIsAtomic: a write that cannot rename leaves no
// .sig-* temp behind and reports the error.
func TestSignatureFileWriteIsAtomic(t *testing.T) {
	store := t.TempDir()
	// Occupy the final name with a non-empty directory: rename fails.
	blocker := SignaturePath(store, goldenHash)
	if err := os.MkdirAll(filepath.Join(blocker, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	err := WriteSignatureFile(store, goldenHash, mustPayload(t, goldenHash, goldenLogID, 7, goldenAt7, goldenKeyID), goldenSig7)
	if err == nil {
		t.Fatal("rename over a non-empty directory must fail")
	}
	for _, e := range mustReadDir(t, store) {
		if strings.HasPrefix(e, ".sig-") {
			t.Fatalf("temp residue after a failed write: %s", e)
		}
	}
	if err := WriteSignatureFile(store, "sha256:nope", nil, ""); err == nil || !strings.Contains(err.Error(), "malformed hash") {
		t.Fatalf("a malformed hash must be refused before any write: %v", err)
	}
}
