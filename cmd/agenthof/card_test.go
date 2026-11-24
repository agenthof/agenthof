package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/agentcard"
)

const goodCardJSON = `{"name":"Triage Bot","version":"1.2.0","capabilities":{"extensions":[{"uri":"https://agenthof.dev/ext/agent/v1","params":{"artifact":"ghcr.io/acme/triage@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","interface":"a2a"}}]}}`

func runCard(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := dispatch(append([]string{"card"}, args...), &out, &errb)
	return code, out.String(), errb.String()
}

var (
	pubLine = regexp.MustCompile(`(?m)^public_key: (\S+)$`)
	kidLine = regexp.MustCompile(`(?m)^kid: (\S+)$`)
)

func keygenInto(t *testing.T, dir string) (pub ed25519.PublicKey, kid string) {
	t.Helper()
	code, out, errs := runCard("keygen", "--dir", dir)
	if code != 0 {
		t.Fatalf("keygen exit %d: %s%s", code, out, errs)
	}
	m := pubLine.FindStringSubmatch(out)
	k := kidLine.FindStringSubmatch(out)
	if m == nil || k == nil {
		t.Fatalf("keygen output lacks public_key/kid:\n%s", out)
	}
	raw, err := base64.StdEncoding.DecodeString(m[1])
	if err != nil || len(raw) != ed25519.PublicKeySize || len(m[1]) != 44 {
		t.Fatalf("public_key %q is not 44-char raw-32 std base64", m[1])
	}
	return raw, k[1]
}

func TestCardKeygenWritesPairAndPrints(t *testing.T) {
	dir := t.TempDir()
	keygenInto(t, dir)
	fi, err := os.Stat(filepath.Join(dir, "curator.key"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("curator.key: %v %v", fi, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "curator.pub")); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "curator.key"))
	code, out, errs := runCard("keygen", "--dir", dir)
	if code == 0 || out != "" || !strings.Contains(errs, "refusing to overwrite") {
		t.Fatalf("second keygen = %d %q %q; want refusal", code, out, errs)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "curator.key"))
	if !bytes.Equal(before, after) {
		t.Fatal("second keygen changed the private key")
	}
}

func TestCardSignProducesEnrollableCard(t *testing.T) {
	dir := t.TempDir()
	pub, kid := keygenInto(t, dir)
	cardPath := filepath.Join(dir, "card.json")
	if err := os.WriteFile(cardPath, []byte(goodCardJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errs := runCard("sign", "--key", filepath.Join(dir, "curator.key"), "--kid", kid, cardPath)
	if code != 0 {
		t.Fatalf("sign exit %d: %s", code, errs)
	}
	c, err := agentcard.Parse([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	got, err := agentcard.Verify(c, []agentcard.Anchor{{KID: kid, Key: pub}})
	if err != nil || got != kid {
		t.Fatalf("Verify = %q, %v", got, err)
	}
	// a different key does not verify
	other, _ := keygenOther(t)
	if _, err := agentcard.Verify(c, []agentcard.Anchor{{KID: kid, Key: other}}); err == nil {
		t.Fatal("card verified under the wrong key")
	}
}

func keygenOther(t *testing.T) (ed25519.PublicKey, string) {
	t.Helper()
	return keygenInto(t, t.TempDir())
}

func TestCardSignRefusesBadInput(t *testing.T) {
	dir := t.TempDir()
	_, kid := keygenInto(t, dir)
	key := filepath.Join(dir, "curator.key")
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	noExt := write("noext.json", `{"name":"x","version":"1","capabilities":{"extensions":[]}}`)
	dupExt := strings.Replace(goodCardJSON, `"extensions":[`, `"extensions":[{"uri":"https://agenthof.dev/ext/agent/v1","params":{"artifact":"a@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","interface":"a2a"}},`, 1)
	short := write("short.key", "not a key")
	type refusal struct {
		args   []string
		stderr string
	}
	cases := map[string]refusal{
		"malformed":     {[]string{"--key", key, "--kid", kid, write("bad.json", `{not json`)}, "card sign"},
		"no extension":  {[]string{"--key", key, "--kid", kid, noExt}, "no https://agenthof.dev/ext/agent/v1 extension"},
		"two ext":       {[]string{"--key", key, "--kid", kid, write("dup.json", dupExt)}, "card sign"},
		"bad key":       {[]string{"--key", short, "--kid", kid, write("c1.json", goodCardJSON)}, "short.key"},
		"missing key":   {[]string{"--key", filepath.Join(dir, "none.key"), "--kid", kid, write("c2.json", goodCardJSON)}, "none.key"},
		"long kid":      {[]string{"--key", key, "--kid", strings.Repeat("k", 129), write("c3.json", goodCardJSON)}, "printable ASCII"},
		"kid space":     {[]string{"--key", key, "--kid", "a b", write("c5.json", goodCardJSON)}, "printable ASCII"},
		"kid newline":   {[]string{"--key", key, "--kid", "a\nb", write("c6.json", goodCardJSON)}, "printable ASCII"},
		"kid non-ASCII": {[]string{"--key", key, "--kid", "k\u00e9y", write("c7.json", goodCardJSON)}, "printable ASCII"},
		"missing card":  {[]string{"--key", key, "--kid", kid, filepath.Join(dir, "absent.json")}, "absent.json"},
		"dup keys":      {[]string{"--key", key, "--kid", kid, write("c8.json", `{"name":"a","name":"b"}`)}, "card sign"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			code, out, errs := runCard(append([]string{"sign"}, c.args...)...)
			if code == 0 || out != "" || !strings.Contains(errs, c.stderr) {
				t.Fatalf("exit %d, stdout %q, stderr %q; want refusal mentioning %q, no output", code, out, errs, c.stderr)
			}
		})
	}
	if code, out, _ := runCard("sign", "--key", key, "--kid", "", write("c4.json", goodCardJSON)); code == 0 || out != "" {
		t.Fatalf("empty kid: exit %d out %q", code, out)
	}
}

func TestCardSignOutNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	_, kid := keygenInto(t, dir)
	key := filepath.Join(dir, "curator.key")
	card := filepath.Join(dir, "card.json")
	if err := os.WriteFile(card, []byte(goodCardJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "signed.json")
	if code, _, errs := runCard("sign", "--key", key, "--kid", kid, "--out", out, card); code != 0 {
		t.Fatalf("first sign exit %d: %s", code, errs)
	}
	before, _ := os.ReadFile(out)
	if code, _, errs := runCard("sign", "--key", key, "--kid", kid, "--out", out, card); code == 0 || errs == "" {
		t.Fatalf("second sign over an existing --out = %d %q; want refusal", code, errs)
	}
	if after, _ := os.ReadFile(out); !bytes.Equal(before, after) {
		t.Fatal("refused sign changed the existing --out file")
	}
	// a refused sign leaves no file behind
	refused := filepath.Join(dir, "refused.json")
	if code, _, _ := runCard("sign", "--key", key, "--kid", "a b", "--out", refused, card); code == 0 {
		t.Fatal("bad kid signed")
	}
	if _, err := os.Stat(refused); !os.IsNotExist(err) {
		t.Fatalf("refused sign left %s behind: %v", refused, err)
	}
}

func TestCardUsage(t *testing.T) {
	for _, args := range [][]string{{}, {"bogus"}} {
		var out, errb bytes.Buffer
		if code := dispatch(append([]string{"card"}, args...), &out, &errb); code != 2 || errb.Len() == 0 {
			t.Errorf("card %v = %d %q; want exit 2 with a message", args, code, errb.String())
		}
	}
}

func TestCardKeygenLonePieces(t *testing.T) {
	// a lone public file is refused and left alone
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "curator.pub")
	if err := os.WriteFile(pubPath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := runCard("keygen", "--dir", dir); code == 0 || !strings.Contains(errs, "without its private key") {
		t.Fatalf("lone pub = %d %q; want refusal", code, errs)
	}
	if _, err := os.Stat(filepath.Join(dir, "curator.key")); !os.IsNotExist(err) {
		t.Fatal("lone-pub refusal wrote a key")
	}
	// a lone private key is kept and its public half re-derived
	full := t.TempDir()
	pub, kid := keygenInto(t, full)
	keyBefore, _ := os.ReadFile(filepath.Join(full, "curator.key"))
	if err := os.Remove(filepath.Join(full, "curator.pub")); err != nil {
		t.Fatal(err)
	}
	code, out, errs := runCard("keygen", "--dir", full)
	if code != 0 {
		t.Fatalf("lone key exit %d: %s", code, errs)
	}
	if !strings.Contains(out, base64.StdEncoding.EncodeToString(pub)) || !strings.Contains(out, kid) {
		t.Fatalf("lone key did not re-derive the same public key:\n%s", out)
	}
	if keyAfter, _ := os.ReadFile(filepath.Join(full, "curator.key")); !bytes.Equal(keyBefore, keyAfter) {
		t.Fatal("the private key was changed")
	}
	if _, err := os.Stat(filepath.Join(full, "curator.pub")); err != nil {
		t.Fatal(err)
	}
}

func TestCardKeygenNeverPrintsPrivateKey(t *testing.T) {
	dir := t.TempDir()
	code, out, errs := runCard("keygen", "--dir", dir)
	if code != 0 {
		t.Fatal(errs)
	}
	if strings.Contains(out+errs, "PRIVATE KEY") || strings.Contains(out+errs, "BEGIN") {
		t.Fatalf("keygen printed PEM:\n%s", out)
	}
	pem, _ := os.ReadFile(filepath.Join(dir, "curator.key"))
	for _, line := range strings.Split(strings.TrimSpace(string(pem)), "\n")[1:] {
		if len(line) > 8 && strings.Contains(out, line) && !strings.HasPrefix(line, "-----") {
			t.Fatalf("keygen stdout contains private key material %q", line)
		}
	}
}
