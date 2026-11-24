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
	cases := map[string][]string{
		"malformed":    {"--key", key, "--kid", kid, write("bad.json", `{not json`)},
		"no extension": {"--key", key, "--kid", kid, noExt},
		"two ext":      {"--key", key, "--kid", kid, write("dup.json", dupExt)},
		"bad key":      {"--key", short, "--kid", kid, write("c1.json", goodCardJSON)},
		"missing key":  {"--key", filepath.Join(dir, "none.key"), "--kid", kid, write("c2.json", goodCardJSON)},
		"long kid":     {"--key", key, "--kid", strings.Repeat("k", 129), write("c3.json", goodCardJSON)},
		"missing card": {"--key", key, "--kid", kid, filepath.Join(dir, "absent.json")},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			code, out, errs := runCard(append([]string{"sign"}, args...)...)
			if code == 0 || out != "" || errs == "" {
				t.Fatalf("exit %d, stdout %q, stderr %q; want refusal, no output", code, out, errs)
			}
		})
	}
	if code, out, _ := runCard("sign", "--key", key, "--kid", "", write("c4.json", goodCardJSON)); code == 0 || out != "" {
		t.Fatalf("empty kid: exit %d out %q", code, out)
	}
}
