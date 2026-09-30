// Command obo-idp is a stand-in identity provider and token-exchange server
// for the on-behalf-of demonstration and its hermetic proof. It serves OIDC
// discovery and a JWKS for an RSA key generated at start (nothing is
// embedded), mints RS256 subject tokens on request at /mint — a demo
// affordance standing in for a real provider's login flow — and answers RFC
// 8693 token exchange at /token: it verifies the subject token as one of its
// own, authenticates the requesting client with client_secret_basic, and
// issues a decodable upstream token carrying the subject's sub and the
// requested audience. Every error_description it writes carries the phrase
// "never-in-a-ledger", so a proof can show the authorization server's own
// words never reach Agenthof's ledger. Loopback only; no real identity.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	kid              = "obo-idp"
	grantExchange    = "urn:ietf:params:oauth:grant-type:token-exchange"
	issuedTokenType  = "urn:ietf:params:oauth:token-type:access_token"
	errorSentinel    = "never-in-a-ledger"
	defaultSubjectTT = "urn:ietf:params:oauth:token-type:id_token"
)

// idp is the stand-in provider: one key, one client, one audience allowlist.
type idp struct {
	issuer           string
	key              *rsa.PrivateKey
	clientID         string
	clientSecret     string
	audiences        map[string]bool
	subjectTokenType string
	lifetime         time.Duration
	now              func() time.Time
	tokenLog         io.Writer  // JSONL of every issued upstream token; nil = none
	mu               sync.Mutex // serializes tokenLog writes
}

// newIDP generates the signing key. tokenLog, when non-nil, receives one
// JSON line per exchanged token so a proof can grep for the token's absence
// elsewhere without printing it.
func newIDP(issuer, clientID, clientSecret string, audiences []string, subjectTokenType string, lifetime time.Duration, tokenLog io.Writer) (*idp, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	allowed := map[string]bool{}
	for _, a := range audiences {
		if a = strings.TrimSpace(a); a != "" {
			allowed[a] = true
		}
	}
	if subjectTokenType == "" {
		subjectTokenType = defaultSubjectTT
	}
	return &idp{
		issuer: issuer, key: key, clientID: clientID, clientSecret: clientSecret,
		audiences: allowed, subjectTokenType: subjectTokenType, lifetime: lifetime,
		now: time.Now, tokenLog: tokenLog,
	}, nil
}

func (p *idp) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("/keys", p.jwks)
	mux.HandleFunc("/mint", p.mint)
	mux.HandleFunc("/token", p.token)
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeOAuthError writes an RFC 6749 §5.2 error. The description always
// carries errorSentinel: it is the authorization server's own text, and the
// proof asserts it never reaches a ledger.
func writeOAuthError(w http.ResponseWriter, status int, code, detail string) {
	writeJSON(w, status, map[string]string{
		"error":             code,
		"error_description": "obo-idp: " + detail + " (" + errorSentinel + ")",
	})
}

func (p *idp) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                p.issuer,
		"jwks_uri":                              p.issuer + "/keys",
		"token_endpoint":                        p.issuer + "/token",
		"response_types_supported":              []string{"id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"grant_types_supported":                 []string{grantExchange},
	})
}

func (p *idp) jwks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(p.key.N.Bytes()),
			"e": "AQAB",
		}},
	})
}

// mint issues a subject token for the demo. A real provider mints through a
// login flow; here the caller states the subject.
func (p *idp) mint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Sub    string   `json:"sub"`
		Email  string   `json:"email"`
		Groups []string `json:"groups"`
		Aud    string   `json:"aud"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil || req.Sub == "" || req.Aud == "" {
		http.Error(w, "mint needs a JSON body with sub and aud", http.StatusBadRequest)
		return
	}
	now := p.now()
	claims := map[string]any{"iss": p.issuer, "sub": req.Sub, "aud": req.Aud, "iat": now.Unix(), "exp": now.Add(p.lifetime).Unix()}
	if req.Email != "" {
		claims["email"] = req.Email
	}
	if len(req.Groups) > 0 {
		claims["groups"] = req.Groups
	}
	tok, err := p.sign(claims)
	if err != nil {
		http.Error(w, "sign failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": tok})
}

// sign builds a compact RS256 JWT over claims with this provider's key.
func (p *idp) sign(claims map[string]any) (string, error) {
	header, err := json.Marshal(map[string]any{"alg": "RS256", "kid": kid, "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// verify checks raw is a compact RS256 JWT signed by this provider's key,
// issued by it, and unexpired, returning its claims.
func (p *idp) verify(raw string) (map[string]any, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("not a compact JWT")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("bad header encoding")
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if json.Unmarshal(headerJSON, &header) != nil || header.Alg != "RS256" {
		return nil, errors.New("unsupported algorithm")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("bad signature encoding")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&p.key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		return nil, errors.New("signature does not verify")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("bad payload encoding")
	}
	var claims map[string]any
	if json.Unmarshal(payload, &claims) != nil {
		return nil, errors.New("bad claims")
	}
	if iss, _ := claims["iss"].(string); iss != p.issuer {
		return nil, errors.New("issuer mismatch")
	}
	exp, _ := claims["exp"].(float64)
	if exp == 0 || p.now().After(time.Unix(int64(exp), 0)) {
		return nil, errors.New("token expired")
	}
	return claims, nil
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8090", "loopback address to listen on; the issuer is http://<addr>")
	clientID := flag.String("client-id", "agenthof-broker", "the OAuth client id Agenthof exchanges with")
	clientSecretEnv := flag.String("client-secret-env", "OBO_IDP_CLIENT_SECRET", "name of the environment variable holding that client's secret")
	audiences := flag.String("audiences", "", "comma-separated audiences the exchange will issue tokens for")
	subjectTokenType := flag.String("subject-token-type", defaultSubjectTT, "the subject_token_type an exchange must present")
	lifetime := flag.Duration("lifetime", time.Hour, "lifetime of minted and exchanged tokens")
	tokenLogPath := flag.String("token-log", "", "append one JSON line per exchanged token here (for a proof's no-leak grep); empty = off")
	flag.Parse()

	secret := os.Getenv(*clientSecretEnv)
	if secret == "" {
		log.Fatalf("obo-idp: %s must be set in the environment", *clientSecretEnv)
	}
	var tokenLog io.Writer
	if *tokenLogPath != "" {
		f, err := os.OpenFile(*tokenLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			log.Fatalf("obo-idp: open token log: %v", err)
		}
		defer func() { _ = f.Close() }()
		tokenLog = f
	}
	p, err := newIDP("http://"+*addr, *clientID, secret, strings.Split(*audiences, ","), *subjectTokenType, *lifetime, tokenLog)
	if err != nil {
		log.Fatalf("obo-idp: %v", err)
	}
	log.Printf("obo-idp: issuer %s; exchange audiences %v", p.issuer, *audiences)
	log.Fatal(http.ListenAndServe(*addr, p.handler()))
}
