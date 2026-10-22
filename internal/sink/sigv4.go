package sink

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/agenthof/agenthof/internal/broker"
)

// AWS Signature Version 4 over crypto/hmac and crypto/sha256, as the SigV4
// specification lays it out: canonical request → string to sign → signature.
// The service is a parameter ("s3" in production; "service" in AWS's
// published vectors, which pin this file byte for byte). Two S3 specifics
// are built in: the canonical URI is the path URI-encoded ONCE per segment
// and never normalized, and the payload hash is always the real digest
// (the caller sets x-amz-content-sha256; this file signs whatever is on the
// request).

const (
	sigV4Algorithm = "AWS4-HMAC-SHA256"
	amzDateLayout  = "20060102T150405Z"
	amzDayLayout   = "20060102"
)

// signV4 signs req in place for kp over region and service at now: it sets
// X-Amz-Date from now (and X-Amz-Security-Token when kp carries a session),
// signs every header on the request plus host, and sets Authorization.
// payloadHash is the hex SHA-256 of the body — the canonical request's last
// line. The secret is read here and nowhere else.
func signV4(req *http.Request, kp broker.KeyPair, region, service string, now time.Time, payloadHash string) {
	now = now.UTC()
	req.Header.Set("X-Amz-Date", now.Format(amzDateLayout))
	if kp.Session != "" {
		req.Header.Set("X-Amz-Security-Token", kp.Session)
	}
	signed := signedHeaderNames(req)
	creq := canonicalRequest(req, signed, payloadHash)
	sum := sha256.Sum256([]byte(creq))
	scope := credentialScope(now, region, service)
	sts := stringToSign(now, scope, hex.EncodeToString(sum[:]))
	key := signingKey(kp.Secret, now.Format(amzDayLayout), region, service)
	sig := hex.EncodeToString(hmacSHA256(key, []byte(sts)))
	req.Header.Set("Authorization", sigV4Algorithm+" Credential="+kp.ID+"/"+scope+", SignedHeaders="+strings.Join(signed, ";")+", Signature="+sig)
}

// signedHeaderNames is every header on the request plus host, lowercase and
// sorted: whatever this client sends is signed.
func signedHeaderNames(req *http.Request) []string {
	names := make([]string, 0, len(req.Header)+1)
	for name := range req.Header {
		names = append(names, strings.ToLower(name))
	}
	names = append(names, "host")
	sort.Strings(names)
	return names
}

// canonicalRequest is the SigV4 canonical request: method, canonical URI,
// canonical query, canonical headers (one per signed name, values trimmed
// and inner runs of spaces collapsed), the signed-header list, and the
// payload hash.
func canonicalRequest(req *http.Request, signedHeaders []string, payloadHash string) string {
	var b strings.Builder
	b.WriteString(req.Method)
	b.WriteByte('\n')
	b.WriteString(uriEncodePath(req.URL.Path))
	b.WriteByte('\n')
	b.WriteString(canonicalQuery(req.URL.RawQuery))
	b.WriteByte('\n')
	for _, name := range signedHeaders {
		var value string
		if name == "host" {
			value = req.Host
			if value == "" {
				value = req.URL.Host
			}
		} else {
			value = strings.Join(req.Header.Values(name), ",")
		}
		b.WriteString(name)
		b.WriteByte(':')
		b.WriteString(strings.Join(strings.Fields(value), " "))
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	b.WriteString(strings.Join(signedHeaders, ";"))
	b.WriteByte('\n')
	b.WriteString(payloadHash)
	return b.String()
}

// credentialScope is "<day>/<region>/<service>/aws4_request" for now's UTC
// day — the same instant X-Amz-Date is formatted from.
func credentialScope(now time.Time, region, service string) string {
	return now.UTC().Format(amzDayLayout) + "/" + region + "/" + service + "/aws4_request"
}

// stringToSign is the algorithm, the request time, the scope and the hex
// hash of the canonical request, one per line.
func stringToSign(now time.Time, scope, canonicalHash string) string {
	return sigV4Algorithm + "\n" + now.UTC().Format(amzDateLayout) + "\n" + scope + "\n" + canonicalHash
}

// signingKey derives the per-day signing key: HMAC chain over the date,
// region, service and the literal aws4_request, seeded with "AWS4"+secret.
func signingKey(secret, date, region, service string) []byte {
	k := hmacSHA256([]byte("AWS4"+secret), []byte(date))
	k = hmacSHA256(k, []byte(region))
	k = hmacSHA256(k, []byte(service))
	return hmacSHA256(k, []byte("aws4_request"))
}

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// uriEncodePath encodes a RAW (decoded) path once, per segment: every byte
// outside RFC 3986's unreserved set becomes %XX (uppercase hex), "/" is kept
// as the separator, and nothing is normalized — "." , ".." and "//" stay,
// because S3's canonical URI is the path as sent. A literal "%" in the raw
// path becomes "%25", which is the one way "%252F" can ever appear.
func uriEncodePath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = uriEncode(s)
	}
	return strings.Join(segs, "/")
}

// uriEncode is the SigV4 URI-encoding of one component: unreserved bytes
// (A-Z a-z 0-9 - _ . ~) verbatim, every other byte %XX.
func uriEncode(s string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&15])
		}
	}
	return b.String()
}

// canonicalQuery parses the raw query as sent, percent-decodes each name
// and value (a "+" is a plus, never a space), re-encodes them once, and
// sorts by encoded name then encoded value. A bare name ("versions") is
// "versions=".
func canonicalQuery(raw string) string {
	if raw == "" {
		return ""
	}
	var pairs []string
	for _, p := range strings.Split(raw, "&") {
		if p == "" {
			continue
		}
		name, value, _ := strings.Cut(p, "=")
		pairs = append(pairs, uriEncode(pathUnescape(name))+"="+uriEncode(pathUnescape(value)))
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

// pathUnescape percent-decodes s, leaving it unchanged when it is not a
// valid escape (the value is then signed as sent).
func pathUnescape(s string) string {
	u, err := url.PathUnescape(s)
	if err != nil {
		return s
	}
	return u
}
