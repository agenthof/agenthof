package main

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/config"
)

var keyIDLineRE = regexp.MustCompile(`(?m)^key_id: ([0-9a-f]{64})$`)

// keygenAt runs config keygen for ctl, asserts success and returns the
// printed key_id and the whole output.
func keygenAt(t *testing.T, ctl string) (keyID, out string) {
	t.Helper()
	var buf bytes.Buffer
	if code := cmdConfigKeygen([]string{"--control-log", ctl}, &buf); code != 0 {
		t.Fatalf("keygen: exit %d\n%s", code, buf.String())
	}
	m := keyIDLineRE.FindStringSubmatch(buf.String())
	if m == nil {
		t.Fatalf("no key_id line:\n%s", buf.String())
	}
	return m[1], buf.String()
}

// signingPub parses signing.pub beside ctl.
func signingPub(t *testing.T, ctl string) ed25519.PublicKey {
	t.Helper()
	pub, err := config.ParseSigningPub(mustRead(t, signingPubPath(ctl)))
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestSigningPathsAreBesideTheStore(t *testing.T) {
	ctl := "/srv/agenthof/control.jsonl"
	if signingKeyPath(ctl) != "/srv/agenthof/signing.key" || signingPubPath(ctl) != "/srv/agenthof/signing.pub" {
		t.Fatalf("%s %s", signingKeyPath(ctl), signingPubPath(ctl))
	}
	if filepath.Dir(signingKeyPath(ctl)) != filepath.Dir(installedStore(ctl)) {
		t.Fatal("the pair lives beside installed/, never inside it")
	}
}

func TestSigningStateOf(t *testing.T) {
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	if s, err := signingStateOf(ctl); err != nil || s != signingOff || s.configured() {
		t.Fatalf("fresh: %v %v", s, err)
	}
	keygenAt(t, ctl)
	if s, _ := signingStateOf(ctl); s != signingOn || !s.configured() {
		t.Fatalf("after keygen: %v", s)
	}
	if err := os.Remove(signingKeyPath(ctl)); err != nil {
		t.Fatal(err)
	}
	if s, _ := signingStateOf(ctl); s != signingPubOnly || !s.configured() {
		t.Fatalf("pub only: %v", s)
	}
	if err := os.Rename(signingPubPath(ctl), signingKeyPath(ctl)); err != nil {
		t.Fatal(err)
	}
	if s, _ := signingStateOf(ctl); s != signingKeyOnly || !s.configured() {
		t.Fatalf("key only: %v", s)
	}
}

func TestLoadSigningKeyAndPubNameThePathOnError(t *testing.T) {
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	id, _ := keygenAt(t, ctl)
	pub, err := loadSigningPub(ctl)
	if err != nil || config.KeyID(pub) != id {
		t.Fatalf("pub: %v", err)
	}
	priv, err := loadSigningKey(ctl)
	if err != nil || !pub.Equal(priv.Public()) {
		t.Fatalf("key: %v", err)
	}
	for _, p := range []string{signingPubPath(ctl), signingKeyPath(ctl)} {
		if err := os.WriteFile(p, []byte("not a pem"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := loadSigningPub(ctl); err == nil || !strings.Contains(err.Error(), signingPubPath(ctl)) {
		t.Fatalf("the pub error must name its path: %v", err)
	}
	if _, err := loadSigningKey(ctl); err == nil || !strings.Contains(err.Error(), signingKeyPath(ctl)) {
		t.Fatalf("the key error must name its path: %v", err)
	}
}

func TestConfigKeygenWritesThePairAndPrintsThePublicKey(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := filepath.Join(t.TempDir(), "root", "control.jsonl") // the directory does not exist yet
	id, out := keygenAt(t, ctl)
	for _, p := range []string{signingKeyPath(ctl), signingPubPath(ctl)} {
		info, err := os.Stat(p)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v mode %o", p, err, info.Mode().Perm())
		}
	}
	for _, want := range []string{
		"wrote " + signingKeyPath(ctl) + " (private key, 0600 — keep it on this host)\n",
		"wrote " + signingPubPath(ctl) + "\n",
		"key_id: " + id + "\n",
		"-----BEGIN PUBLIC KEY-----\n",
		"-----END PUBLIC KEY-----\n",
		msgKeygenPin + "\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "PRIVATE KEY") || strings.Contains(out, "not signed yet") {
		t.Fatalf("never the private key; no sign hint with nothing installed:\n%s", out)
	}
	priv, err := config.ParseSigningKey(mustRead(t, signingKeyPath(ctl)))
	if err != nil {
		t.Fatal(err)
	}
	pub := signingPub(t, ctl)
	if !pub.Equal(priv.Public()) || config.KeyID(pub) != id {
		t.Fatal("the pair must match and the printed key_id must be the public key's")
	}
	if !strings.Contains(out, string(mustRead(t, signingPubPath(ctl)))) {
		t.Fatal("the printed PEM must be signing.pub verbatim")
	}

	// With something installed, the output names the sign remedy.
	ctl2 := filepath.Join(t.TempDir(), "control.jsonl")
	applyAs(t, pullSample(t), ctl2)
	hash := readPointer(t, ctl2)
	if _, out := keygenAt(t, ctl2); !strings.HasSuffix(out, "installed configuration "+hash+" is not signed yet; run: agenthof config sign --control-log "+ctl2+"\n") {
		t.Fatalf("the sign hint must be the last line:\n%s", out)
	}
	if _, err := os.Stat(ctl2); err != nil {
		t.Fatal(err)
	}
	if ents := mustReadDirNames(t, installedStore(ctl2)); len(ents) != 2 {
		t.Fatalf("keygen writes nothing under the store: %v", ents)
	}
}

func mustReadDirNames(t *testing.T, dir string) []string {
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

func TestConfigKeygenRefusesToOverwrite(t *testing.T) {
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	id, _ := keygenAt(t, ctl)
	before := mustRead(t, signingKeyPath(ctl))
	var out bytes.Buffer
	if code := cmdConfigKeygen([]string{"--control-log", ctl}, &out); code != 1 ||
		!strings.Contains(out.String(), "config keygen: "+signingKeyPath(ctl)+" exists (key_id "+id+"); key rotation is not supported yet") ||
		!strings.Contains(out.String(), "remove signing.key and signing.pub") {
		t.Fatalf("%d %q", code, out.String())
	}
	if !bytes.Equal(before, mustRead(t, signingKeyPath(ctl))) {
		t.Fatal("the private key must be untouched")
	}
	if strings.Contains(out.String(), "PRIVATE KEY") {
		t.Fatal("never the private key")
	}
}

func TestConfigKeygenWithAnUnreadablePublicFileSparesThePrivateKey(t *testing.T) {
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	keygenAt(t, ctl)
	before := mustRead(t, signingKeyPath(ctl))
	if err := os.WriteFile(signingPubPath(ctl), []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if code := cmdConfigKeygen([]string{"--control-log", ctl}, &out); code != 1 ||
		!strings.Contains(out.String(), "config keygen: "+signingPubPath(ctl)+" is unreadable") ||
		!strings.Contains(out.String(), "re-derive it from "+signingKeyPath(ctl)) ||
		strings.Contains(out.String(), "remove signing.key and signing.pub") {
		t.Fatalf("%d %q", code, out.String())
	}
	if !bytes.Equal(before, mustRead(t, signingKeyPath(ctl))) {
		t.Fatal("the private key must be untouched when only the public file is bad")
	}
}

func TestConfigKeygenRefusesALonePublicFile(t *testing.T) {
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	keygenAt(t, ctl)
	if err := os.Remove(signingKeyPath(ctl)); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if code := cmdConfigKeygen([]string{"--control-log", ctl}, &out); code != 1 ||
		out.String() != "config keygen: "+signingPubPath(ctl)+" exists without its private key; remove it to generate a new pair (edges pinned to it must re-pin)\n" {
		t.Fatalf("%d %q", code, out.String())
	}
	if _, err := os.Stat(signingKeyPath(ctl)); !os.IsNotExist(err) {
		t.Fatal("no private key may be generated under a stale public file")
	}
}

func TestConfigKeygenRederivesALostPublicFile(t *testing.T) {
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	id, _ := keygenAt(t, ctl)
	pubBefore := mustRead(t, signingPubPath(ctl))
	if err := os.Remove(signingPubPath(ctl)); err != nil {
		t.Fatal(err)
	}
	again, out := keygenAt(t, ctl)
	if again != id {
		t.Fatalf("the re-derived key_id must be the original: %s vs %s", again, id)
	}
	if strings.Contains(out, "wrote "+signingKeyPath(ctl)) || !strings.Contains(out, "wrote "+signingPubPath(ctl)+"\n") {
		t.Fatalf("only the public file is written:\n%s", out)
	}
	if !bytes.Equal(pubBefore, mustRead(t, signingPubPath(ctl))) {
		t.Fatal("the re-derived public file must be byte-identical")
	}
	if info, _ := os.Stat(signingPubPath(ctl)); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
}

func TestConfigKeygenUsage(t *testing.T) {
	var out bytes.Buffer
	if code := cmdConfigKeygen([]string{"--bogus"}, &out); code != 2 {
		t.Fatalf("unknown flag: %d", code)
	}
	out.Reset()
	if code := cmdConfig([]string{"keygen", "--bogus"}, &out); code != 2 {
		t.Fatalf("through cmdConfig: %d", code)
	}
	if !strings.Contains(usage, "agenthof config keygen [--control-log <path>]") {
		t.Fatal("usage must list config keygen")
	}
}
