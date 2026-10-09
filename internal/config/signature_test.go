package config

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/ledger"
)

// The golden vectors: the Ed25519 seed whose byte i is i, the files/v1
// golden hash, a fixed log_id, and two installs of it. They were computed
// independently of this code; a drift here breaks the wire contract and is
// a bug to fix in the code, never a constant to update.
const (
	goldenHash   = "sha256:3a2f6d0c0df4546527ad1ba5c5ae63cc803851f99614247fcbf38b16b4a5d885"
	goldenLogID  = "00112233445566778899aabbccddeeff"
	goldenPubHex = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
	goldenKeyID  = "56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c"
	goldenSig7   = "7Zj+G/3H5lmX+zAr8dVH+/R9r0f08gA7DLnMYD4x7OkIn/JG51vkZsUybg4O7USrgfhnQJgw488YTrPxqsGODg=="
	goldenSig8   = "sxxfqeWsc7jbxXGCdaaHUZ2+qjq6Ifenc0uow6kyyX3/k4s3dpSzG79KlqDktBbnuFtnOMJ77QlOrcs3d9FYDQ=="
	goldenPKCS8  = "MC4CAQAwBQYDK2VwBCIEIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
	goldenPKIX   = "MCowBQYDK2VwAyEAA6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg="
	// A second seed (byte i is 0xff-i): the "unknown key" fixture.
	otherKeyID = "2642177f804d1ab6c7fd3d7678399a81c802d8018419eb5851c26c3aa30cde48"
	// version 7, installed_at 2026-10-09T02:12:01.5Z — 269 bytes.
	goldenPayload7Hex = "6167656e74686f662d636f6e6669672d7369676e61747572652f76310a686173683a207368613235363a336132663664306330646634353436353237616431626135633561653633636338303338353166393936313432343766636266333862313662346135643838350a6c6f675f69643a2030303131323233333434353536363737383839396161626263636464656566660a76657273696f6e3a20370a696e7374616c6c65645f61743a20323032362d31302d30395430323a31323a30312e355a0a6b65795f69643a20353634373561613735343633343734633032383564663564626632626361623733646136353133353838333965396237373438316232656162313037373038630a"
	// version 8, installed_at 2026-10-09T02:12:01Z (zero fraction: no ".f") — 267 bytes.
	goldenPayload8Hex = "6167656e74686f662d636f6e6669672d7369676e61747572652f76310a686173683a207368613235363a336132663664306330646634353436353237616431626135633561653633636338303338353166393936313432343766636266333862313662346135643838350a6c6f675f69643a2030303131323233333434353536363737383839396161626263636464656566660a76657273696f6e3a20380a696e7374616c6c65645f61743a20323032362d31302d30395430323a31323a30315a0a6b65795f69643a20353634373561613735343633343734633032383564663564626632626361623733646136353133353838333965396237373438316232656162313037373038630a"
)

var (
	goldenAt7 = time.Date(2026, 10, 9, 2, 12, 1, 500000000, time.UTC)
	goldenAt8 = time.Date(2026, 10, 9, 2, 12, 1, 0, time.UTC)
)

// goldenKey is the seed-0..31 pair.
func goldenKey(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv, priv.Public().(ed25519.PublicKey)
}

// otherKey is the second seed.
func otherKey(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(0xff - i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv, priv.Public().(ed25519.PublicKey)
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustPayload(t *testing.T, hash, logID string, version int, at time.Time, keyID string) []byte {
	t.Helper()
	p, err := SignaturePayload(hash, logID, version, at, keyID)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestSignatureGoldenVector pins the whole canon absolutely: the key id, the
// payload bytes of two installs (fractional and whole-second time), both
// signatures, and that each verifies.
func TestSignatureGoldenVector(t *testing.T) {
	priv, pub := goldenKey(t)
	if hex.EncodeToString(pub) != goldenPubHex {
		t.Fatalf("public key %x", pub)
	}
	if got := KeyID(pub); got != goldenKeyID {
		t.Fatalf("KeyID = %s, want %s", got, goldenKeyID)
	}
	p7 := mustPayload(t, goldenHash, goldenLogID, 7, goldenAt7, goldenKeyID)
	if want := mustHex(t, goldenPayload7Hex); !bytes.Equal(p7, want) || len(p7) != 269 {
		t.Fatalf("payload 7 drifted (%d bytes):\n%q\nwant\n%q", len(p7), p7, want)
	}
	if got := Sign(priv, p7); got != goldenSig7 {
		t.Fatalf("Sign(7) = %s, want %s", got, goldenSig7)
	}
	if !Verify(pub, p7, goldenSig7) {
		t.Fatal("the golden signature 7 must verify")
	}
	p8 := mustPayload(t, goldenHash, goldenLogID, 8, goldenAt8, goldenKeyID)
	if want := mustHex(t, goldenPayload8Hex); !bytes.Equal(p8, want) || len(p8) != 267 {
		t.Fatalf("payload 8 drifted (%d bytes):\n%q\nwant\n%q", len(p8), p8, want)
	}
	if got := Sign(priv, p8); got != goldenSig8 {
		t.Fatalf("Sign(8) = %s, want %s", got, goldenSig8)
	}
	if !Verify(pub, p8, goldenSig8) {
		t.Fatal("the golden signature 8 must verify")
	}
	if len(goldenSig7) != 88 || strings.ContainsAny(goldenSig7, "\n ") {
		t.Fatal("a signature is 88 characters of standard base64 with padding, no line breaks")
	}
}

// TestSignaturePEMsParseToTheGoldenKey pins the PKCS#8 and PKIX encodings of
// the golden pair (the key-file formats) through the standard library.
func TestSignaturePEMsParseToTheGoldenKey(t *testing.T) {
	priv, pub := goldenKey(t)
	der, err := base64.StdEncoding.DecodeString(goldenPKCS8)
	if err != nil {
		t.Fatal(err)
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil || !priv.Equal(k) {
		t.Fatalf("PKCS#8 golden: %v %T", err, k)
	}
	if got, _ := x509.MarshalPKCS8PrivateKey(priv); base64.StdEncoding.EncodeToString(got) != goldenPKCS8 {
		t.Fatalf("PKCS#8 encoding drifted: %s", base64.StdEncoding.EncodeToString(got))
	}
	pder, err := base64.StdEncoding.DecodeString(goldenPKIX)
	if err != nil {
		t.Fatal(err)
	}
	p, err := x509.ParsePKIXPublicKey(pder)
	if err != nil || !pub.Equal(p) {
		t.Fatalf("PKIX golden: %v %T", err, p)
	}
}

// TestInstalledAtIsOneRendering: for a time.Date value (fractional,
// whole-second, nine-digit), a time decoded from a real control ledger line,
// and a NON-UTC input, the payload's installed_at line equals the JSON
// rendering of the same UTC value — one rendering, by construction. A zoned
// value is refused by the canon; its .UTC() yields the UTC bytes.
func TestInstalledAtIsOneRendering(t *testing.T) {
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	if _, err := control.Append(ctl, control.Event{
		Action: "apply", Outcome: "success", ConfigHash: goldenHash,
		Invoker: identity.Invoker{Subject: "dana@example.com", Issuer: "local", Method: "asserted"},
		Witness: control.CaptureWitness(),
	}); err != nil {
		t.Fatal(err)
	}
	recs, _, err := ledger.ReadVerify(ctl, ledger.Locked)
	if err != nil || len(recs) != 1 {
		t.Fatalf("ledger: %v (%d records)", err, len(recs))
	}
	decoded, err := control.Decode(recs[0].Raw)
	if err != nil {
		t.Fatal(err)
	}
	zoned := time.Date(2026, 10, 9, 3, 12, 1, 500000000, time.FixedZone("CET", 3600))

	for name, in := range map[string]time.Time{
		"fractional":       goldenAt7,
		"whole second":     goldenAt8,
		"nine digits":      time.Date(2026, 10, 9, 2, 12, 1, 123, time.UTC),
		"decoded ledger":   decoded.Time,
		"non-UTC (+01:00)": zoned,
	} {
		at := in.UTC()
		p := mustPayload(t, goldenHash, goldenLogID, 7, at, goldenKeyID)
		j, err := json.Marshal(at)
		if err != nil {
			t.Fatal(err)
		}
		line := "installed_at: " + strings.Trim(string(j), `"`) + "\n"
		if !strings.Contains(string(p), "\n"+line) {
			t.Fatalf("%s: payload line must equal the JSON rendering %s:\n%q", name, j, p)
		}
		if strings.Contains(string(p), "+01:00") || !strings.Contains(line, "Z\n") {
			t.Fatalf("%s: the zone is always the literal Z: %q", name, line)
		}
	}
	// The zoned input, normalized, IS the first golden vector.
	if p := mustPayload(t, goldenHash, goldenLogID, 7, zoned.UTC(), goldenKeyID); !bytes.Equal(p, mustHex(t, goldenPayload7Hex)) {
		t.Fatalf("zoned.UTC() must produce vector 1:\n%q", p)
	}
	// The zoned input itself is refused: the canon never re-renders a zone.
	if _, err := SignaturePayload(goldenHash, goldenLogID, 7, zoned, goldenKeyID); err == nil || !strings.Contains(err.Error(), "must be UTC") {
		t.Fatalf("a non-UTC installed_at must be refused, got %v", err)
	}
	// Nine digits keep their leading zeros; only trailing zeros are stripped.
	if p := mustPayload(t, goldenHash, goldenLogID, 7, time.Date(2026, 10, 9, 2, 12, 1, 123, time.UTC), goldenKeyID); !strings.Contains(string(p), "installed_at: 2026-10-09T02:12:01.000000123Z\n") {
		t.Fatalf("nine-digit fraction:\n%q", p)
	}
}

// TestSignaturePayloadVersionGrammar: the shortest decimal, nothing else; a
// payload rebuilt with "07" is a different payload and does not verify.
func TestSignaturePayloadVersionGrammar(t *testing.T) {
	_, pub := goldenKey(t)
	p7 := mustPayload(t, goldenHash, goldenLogID, 7, goldenAt7, goldenKeyID)
	if !strings.Contains(string(p7), "\nversion: 7\n") {
		t.Fatalf("version line:\n%q", p7)
	}
	if p := mustPayload(t, goldenHash, goldenLogID, 10, goldenAt7, goldenKeyID); !strings.Contains(string(p), "\nversion: 10\n") {
		t.Fatalf("version 10:\n%q", p)
	}
	for _, bad := range []string{"version: 07\n", "version: +7\n", "version: 7.0\n"} {
		rebuilt := bytes.Replace(p7, []byte("version: 7\n"), []byte(bad), 1)
		if Verify(pub, rebuilt, goldenSig7) {
			t.Fatalf("%q must not verify under the golden signature", bad)
		}
	}
	for _, v := range []int{0, -1} {
		if _, err := SignaturePayload(goldenHash, goldenLogID, v, goldenAt7, goldenKeyID); err == nil {
			t.Fatalf("version %d must be refused", v)
		}
	}
}

// TestSignatureTamperedBytesDoNotVerify: one byte of the payload, one byte
// of the signature, and each field changed.
func TestSignatureTamperedBytesDoNotVerify(t *testing.T) {
	_, pub := goldenKey(t)
	p7 := mustPayload(t, goldenHash, goldenLogID, 7, goldenAt7, goldenKeyID)
	flipped := append([]byte{}, p7...)
	flipped[len(flipped)-2] ^= 0x01
	if Verify(pub, flipped, goldenSig7) {
		t.Fatal("a flipped payload byte must not verify")
	}
	raw, _ := base64.StdEncoding.DecodeString(goldenSig7)
	raw[0] ^= 0x01
	if Verify(pub, p7, base64.StdEncoding.EncodeToString(raw)) {
		t.Fatal("a flipped signature byte must not verify")
	}
	if Verify(pub, p7, "not base64!") || Verify(pub, p7, base64.StdEncoding.EncodeToString(raw[:63])) {
		t.Fatal("a malformed signature string verifies as false")
	}
	for name, p := range map[string][]byte{
		"version":   mustPayload(t, goldenHash, goldenLogID, 8, goldenAt7, goldenKeyID),
		"time +1ns": mustPayload(t, goldenHash, goldenLogID, 7, goldenAt7.Add(time.Nanosecond), goldenKeyID),
		"time -1ns": mustPayload(t, goldenHash, goldenLogID, 7, goldenAt7.Add(-time.Nanosecond), goldenKeyID),
		"hash":      mustPayload(t, "sha256:"+strings.Repeat("0", 64), goldenLogID, 7, goldenAt7, goldenKeyID),
		"log_id":    mustPayload(t, goldenHash, strings.Repeat("f", 32), 7, goldenAt7, goldenKeyID),
		"key_id":    mustPayload(t, goldenHash, goldenLogID, 7, goldenAt7, otherKeyID),
	} {
		if Verify(pub, p, goldenSig7) {
			t.Fatalf("a payload with a different %s must not verify", name)
		}
	}
}

// TestSignatureWrongKeyIsUnknownByID: another key's signature does not
// verify, and its key_id differs — the "unknown key" distinction is by id,
// before any verify.
func TestSignatureWrongKeyIsUnknownByID(t *testing.T) {
	_, pub := goldenKey(t)
	priv2, pub2 := otherKey(t)
	if got := KeyID(pub2); got != otherKeyID || got == goldenKeyID {
		t.Fatalf("other key id %s", got)
	}
	p7 := mustPayload(t, goldenHash, goldenLogID, 7, goldenAt7, goldenKeyID)
	if Verify(pub, p7, Sign(priv2, p7)) {
		t.Fatal("another key's signature must not verify")
	}
}

// TestSignaturePayloadRejectsMalformedInputs: the grammar is checked, never
// trusted.
func TestSignaturePayloadRejectsMalformedInputs(t *testing.T) {
	cases := map[string][5]any{
		"hash without prefix": {strings.Repeat("a", 64), goldenLogID, 7, goldenAt7, goldenKeyID},
		"hash uppercase":      {"sha256:" + strings.Repeat("A", 64), goldenLogID, 7, goldenAt7, goldenKeyID},
		"log_id short":        {goldenHash, "0011", 7, goldenAt7, goldenKeyID},
		"log_id uppercase":    {goldenHash, strings.ToUpper(goldenLogID), 7, goldenAt7, goldenKeyID},
		"key_id short":        {goldenHash, goldenLogID, 7, goldenAt7, "5647"},
		"key_id with prefix":  {goldenHash, goldenLogID, 7, goldenAt7, "sha256:" + goldenKeyID},
	}
	for name, c := range cases {
		if _, err := SignaturePayload(c[0].(string), c[1].(string), c[2].(int), c[3].(time.Time), c[4].(string)); err == nil {
			t.Fatalf("%s must be refused", name)
		}
	}
}
