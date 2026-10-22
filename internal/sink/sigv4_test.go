package sink

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/broker"
)

// The fixed inputs of AWS's published SigV4 test suite (testdata/sigv4,
// copied verbatim): one credential, one region, one service, one instant.
var (
	suiteKey    = broker.KeyPair{ID: "AKIDEXAMPLE", Secret: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}
	suiteNow    = time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	suiteRegion = "us-east-1"
	suiteSvc    = "service"
	emptyHash   = hex.EncodeToString(func() []byte { s := sha256.Sum256(nil); return s[:] }())
)

// readVector reads one file of a suite case, byte for byte.
func readVector(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// requestFrom builds the request a suite's req file describes: the request
// line's method and target, then Name:value header lines (Host is the
// request's host, not a header). None of the pinned cases carries a body.
func requestFrom(t *testing.T, raw string) *http.Request {
	t.Helper()
	sc := bufio.NewScanner(strings.NewReader(raw))
	if !sc.Scan() {
		t.Fatal("empty req")
	}
	parts := strings.SplitN(sc.Text(), " ", 3)
	if len(parts) != 3 {
		t.Fatalf("request line %q", sc.Text())
	}
	method, target := parts[0], parts[1]
	headers := http.Header{}
	host := ""
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			t.Fatalf("header line %q", line)
		}
		if strings.EqualFold(name, "Host") {
			host = value
			continue
		}
		headers.Add(name, value)
	}
	if host == "" {
		t.Fatal("req names no host")
	}
	req, err := http.NewRequest(method, "https://"+host+target, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header = headers
	return req
}

// TestSigV4Vectors: for each case dir, build the request from req, run
// canonicalRequest / stringToSign / signV4 with the fixed clock and compare
// to creq, sts and the Authorization header in authz byte for byte. The
// suite's normalize-path cases are deliberately absent: S3 is the one
// service whose canonical URI is not normalized.
func TestSigV4Vectors(t *testing.T) {
	dirs, err := filepath.Glob(filepath.Join("testdata", "sigv4", "*", "req"))
	if err != nil || len(dirs) == 0 {
		t.Fatalf("no vectors: %v", err)
	}
	for _, reqPath := range dirs {
		dir := filepath.Dir(reqPath)
		t.Run(filepath.Base(dir), func(t *testing.T) {
			req := requestFrom(t, readVector(t, dir, "req"))
			kp := suiteKey
			if tok := req.Header.Get("X-Amz-Security-Token"); tok != "" {
				// The signer sets the token from the key pair; the vector
				// lists it as a request header. Same bytes either way.
				kp.Session = tok
				req.Header.Del("X-Amz-Security-Token")
				req.Header.Set("X-Amz-Security-Token", tok)
			}
			creq := canonicalRequest(req, signedHeaderNames(req), emptyHash)
			if want := readVector(t, dir, "creq"); creq != want {
				t.Errorf("canonical request\n got: %q\nwant: %q", creq, want)
			}
			sum := sha256.Sum256([]byte(creq))
			sts := stringToSign(suiteNow, credentialScope(suiteNow, suiteRegion, suiteSvc), hex.EncodeToString(sum[:]))
			if want := readVector(t, dir, "sts"); sts != want {
				t.Errorf("string to sign\n got: %q\nwant: %q", sts, want)
			}
			signV4(req, kp, suiteRegion, suiteSvc, suiteNow, emptyHash)
			if got, want := req.Header.Get("Authorization"), readVector(t, dir, "authz"); got != want {
				t.Errorf("authorization\n got: %q\nwant: %q", got, want)
			}
		})
	}
}

// TestSigV4PathEncodedOnce: a key "my prefix/a+b/seg-000001" canonicalizes
// to "/worm/my%20prefix/a%2Bb/seg-000001" — one encoding, "/" kept, never
// "%2520"; and a key already containing "%2F" encodes to "%252F" ONLY because
// the raw key contained a literal percent (the input is the raw key, never a
// pre-encoded one). The same holds for a request whose URL carries the
// encoded path: the canonical URI is computed from the decoded path, so the
// wire form and the signed form agree.
func TestSigV4PathEncodedOnce(t *testing.T) {
	cases := map[string]string{
		"/worm/my prefix/a+b/seg-000001":     "/worm/my%20prefix/a%2Bb/seg-000001",
		"/worm/a%2Fb/seg-000001":             "/worm/a%252Fb/seg-000001",
		"/":                                  "/",
		"/worm/-._~AZaz09/x":                 "/worm/-._~AZaz09/x",
		"/worm/ሴ/x":                          "/worm/%E1%88%B4/x",
		"/worm/a b/./..//seg":                "/worm/a%20b/./..//seg", // never normalized: S3's rule
		"/worm/:@!$&'()*+,;=/x":              "/worm/%3A%40%21%24%26%27%28%29%2A%2B%2C%3B%3D/x",
		"/worm/agenthof/0123abcd/seg-000001": "/worm/agenthof/0123abcd/seg-000001",
	}
	for in, want := range cases {
		if got := uriEncodePath(in); got != want {
			t.Errorf("uriEncodePath(%q) = %q, want %q", in, got, want)
		}
	}
	req, err := http.NewRequest(http.MethodGet, "https://h.example/worm/my%20prefix/a%2Bb/seg-000001?versionId=v-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	creq := canonicalRequest(req, []string{"host"}, emptyHash)
	lines := strings.Split(creq, "\n")
	if lines[1] != "/worm/my%20prefix/a%2Bb/seg-000001" {
		t.Errorf("canonical URI from an encoded wire path = %q", lines[1])
	}
	if strings.Contains(creq, "%25") {
		t.Errorf("canonical request double-encodes: %q", creq)
	}
	if lines[2] != "versionId=v-1" {
		t.Errorf("canonical query = %q", lines[2])
	}
}

// TestSigV4CanonicalQuery: a bare subresource ("?versions") canonicalizes as
// "versions=", values are encoded once per RFC 3986 (a "+" in a prefix is
// "%2B", never a space), and pairs sort by encoded NAME, then encoded value
// — never by the joined "name=value" string: "x-y=1&x=2" is "x=2&x-y=1"
// ("x" sorts before "x-y"), although as joined strings "-" (0x2D) sorts
// before "=" (0x3D) and would put x-y first.
func TestSigV4CanonicalQuery(t *testing.T) {
	for raw, want := range map[string]string{
		"versions&prefix=p%2Bq%2Fseg-&key-marker=k": "key-marker=k&prefix=p%2Bq%2Fseg-&versions=",
		"x-y=1&x=2":    "x=2&x-y=1",
		"a=2&a=1&a=10": "a=1&a=10&a=2",
		"b=&a=1":       "a=1&b=",
	} {
		req, err := http.NewRequest(http.MethodGet, "https://h.example/worm?"+raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		creq := canonicalRequest(req, []string{"host"}, emptyHash)
		if got := strings.Split(creq, "\n")[2]; got != want {
			t.Errorf("canonical query of %q = %q, want %q", raw, got, want)
		}
	}
}

// TestSigV4OneInstant: x-amz-date and the credential scope's date come from
// the same now; a now of 2026-10-20T23:59:59Z yields scope day 20261020 and
// x-amz-date 20261020T235959Z (never a day boundary mismatch) — and a clock
// in another zone is read in UTC, so 01:30+02:00 on the 21st is still the
// 20th.
func TestSigV4OneInstant(t *testing.T) {
	for _, now := range []time.Time{
		time.Date(2026, 10, 20, 23, 59, 59, 0, time.UTC),
		time.Date(2026, 10, 21, 1, 59, 59, 0, time.FixedZone("CEST", 2*3600)),
	} {
		req, err := http.NewRequest(http.MethodGet, "https://h.example/worm", nil)
		if err != nil {
			t.Fatal(err)
		}
		signV4(req, suiteKey, "eu-central-1", "s3", now, emptyHash)
		if got := req.Header.Get("X-Amz-Date"); got != "20261020T235959Z" {
			t.Errorf("x-amz-date = %q", got)
		}
		authz := req.Header.Get("Authorization")
		if !strings.Contains(authz, "Credential=AKIDEXAMPLE/20261020/eu-central-1/s3/aws4_request,") {
			t.Errorf("scope in %q", authz)
		}
	}
}

// TestSigV4SessionToken: a KeyPair with Session sets x-amz-security-token,
// includes it in SignedHeaders and reproduces the suite's signed-token vector
// (post-sts-header-before: the token is signed, as S3 requires) byte for
// byte; without one the header is absent and unsigned.
func TestSigV4SessionToken(t *testing.T) {
	dir := filepath.Join("testdata", "sigv4", "post-sts-header-before")
	req := requestFrom(t, readVector(t, dir, "req"))
	token := req.Header.Get("X-Amz-Security-Token")
	if token == "" {
		t.Fatal("vector carries no token")
	}
	req.Header.Del("X-Amz-Security-Token")
	kp := suiteKey
	kp.Session = token
	signV4(req, kp, suiteRegion, suiteSvc, suiteNow, emptyHash)
	if got := req.Header.Get("X-Amz-Security-Token"); got != token {
		t.Errorf("token header = %q", got)
	}
	if got, want := req.Header.Get("Authorization"), readVector(t, dir, "authz"); got != want {
		t.Errorf("authorization\n got: %q\nwant: %q", got, want)
	}

	plain := requestFrom(t, readVector(t, dir, "req"))
	plain.Header.Del("X-Amz-Security-Token")
	signV4(plain, suiteKey, suiteRegion, suiteSvc, suiteNow, emptyHash)
	if _, ok := plain.Header["X-Amz-Security-Token"]; ok {
		t.Error("a permanent key pair set a token header")
	}
	if authz := plain.Header.Get("Authorization"); !strings.Contains(authz, "SignedHeaders=host;x-amz-date,") {
		t.Errorf("signed headers in %q", authz)
	}
}

// TestSigV4SignsEveryHeaderSent: whatever is on the request is signed — the
// lock, checksum and content headers of a PUT included — sorted, lowercase.
func TestSigV4SignsEveryHeaderSent(t *testing.T) {
	req, err := http.NewRequest(http.MethodPut, "https://h.example/worm/k", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Amz-Object-Lock-Mode", "COMPLIANCE")
	req.Header.Set("Content-MD5", "abc=")
	req.Header.Set("Content-Type", "application/x-ndjson")
	req.Header.Set("X-Amz-Checksum-Sha256", "def=")
	req.Header.Set("X-Amz-Content-Sha256", emptyHash)
	req.Header.Set("X-Amz-Object-Lock-Retain-Until-Date", "2033-10-18T09:12:00Z")
	signV4(req, suiteKey, "us-east-1", "s3", suiteNow, emptyHash)
	want := "SignedHeaders=content-md5;content-type;host;x-amz-checksum-sha256;x-amz-content-sha256;x-amz-date;x-amz-object-lock-mode;x-amz-object-lock-retain-until-date,"
	if authz := req.Header.Get("Authorization"); !strings.Contains(authz, want) {
		t.Errorf("authorization %q lacks %q", authz, want)
	}
}
