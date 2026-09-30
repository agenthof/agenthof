package broker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testSubjectToken   = "zq9subjecttokenAAAA1111"
	testExchangedToken = "zq9exchangedtokenBBBB2222"
	testSubjectType    = "urn:ietf:params:oauth:token-type:id_token"
)

// exchangeEndpoint is a stand-in RFC 8693 token endpoint that records every
// subject_token it was asked to exchange.
type exchangeEndpoint struct {
	mu       sync.Mutex
	subjects []string
	srv      *httptest.Server
}

func newExchangeEndpoint(t *testing.T, token string, expiresIn int) *exchangeEndpoint {
	t.Helper()
	e := &exchangeEndpoint{}
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
			t.Errorf("content-type = %q", ct)
		}
		user, pass, ok := r.BasicAuth()
		if !ok {
			t.Error("missing Basic auth")
		}
		if u, _ := url.QueryUnescape(user); u != "agenthof-broker" {
			t.Errorf("client id = %q", u)
		}
		if p, _ := url.QueryUnescape(pass); p != "shh secret" {
			t.Errorf("client secret = %q", p)
		}
		_ = r.ParseForm()
		if g := r.Form.Get("grant_type"); g != "urn:ietf:params:oauth:grant-type:token-exchange" {
			t.Errorf("grant_type = %q", g)
		}
		if st := r.Form.Get("subject_token_type"); st != testSubjectType {
			t.Errorf("subject_token_type = %q", st)
		}
		if a := r.Form.Get("audience"); a != "https://up.example" {
			t.Errorf("audience = %q", a)
		}
		if s := r.Form.Get("scope"); s != "mcp.read" {
			t.Errorf("scope = %q", s)
		}
		e.mu.Lock()
		e.subjects = append(e.subjects, r.Form.Get("subject_token"))
		e.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":      token,
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
			"token_type":        "Bearer",
			"expires_in":        expiresIn,
		})
	}))
	t.Cleanup(e.srv.Close)
	return e
}

func (e *exchangeEndpoint) seen() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.subjects...)
}

func teRef(tokenURL, subject string) CredentialRef {
	return CredentialRef{
		ResourceID: "github-mcp", Source: "static_env", Grant: "token_exchange",
		ClientAuth: "client_secret_basic", TokenURL: tokenURL, Scope: "mcp.read",
		Audience: "https://up.example", ClientIDEnv: "TE_ID", ClientSecretEnv: "TE_SECRET",
		SubjectToken: subject,
	}
}

func setTEEnv(t *testing.T) {
	t.Helper()
	t.Setenv("TE_ID", "agenthof-broker")
	t.Setenv("TE_SECRET", "shh secret") // space exercises form-urlencoding
}

func TestTokenExchangeRequestShape(t *testing.T) {
	setTEEnv(t)
	e := newExchangeEndpoint(t, testExchangedToken, 3600)
	b := NewTokenExchange(e.srv.Client(), testSubjectType)
	got, err := b.Resolve(context.Background(), teRef(e.srv.URL, testSubjectToken))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != testExchangedToken {
		t.Fatalf("token = %q, want the exchanged token", got)
	}
	if seen := e.seen(); len(seen) != 1 || seen[0] != testSubjectToken {
		t.Fatalf("endpoint saw subjects %v, want exactly the subject token once", len(seen))
	}
}

func TestTokenExchangeCacheKeyedBySubjectHash(t *testing.T) {
	setTEEnv(t)
	e := newExchangeEndpoint(t, testExchangedToken, 3600)
	b := NewTokenExchange(e.srv.Client(), testSubjectType)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, err := b.Resolve(ctx, teRef(e.srv.URL, testSubjectToken)); err != nil {
			t.Fatalf("Resolve #%d: %v", i, err)
		}
	}
	if n := len(e.seen()); n != 1 {
		t.Fatalf("exchanges = %d, want 1 (same subject must hit the cache)", n)
	}
	if _, err := b.Resolve(ctx, teRef(e.srv.URL, "zq9othersubjectCCCC3333")); err != nil {
		t.Fatal(err)
	}
	if n := len(e.seen()); n != 2 {
		t.Fatalf("exchanges = %d, want 2 (a different subject is a different user: no cache sharing)", n)
	}
}

func TestTokenExchangeRefreshReexchangesSameSubject(t *testing.T) {
	setTEEnv(t)
	e := newExchangeEndpoint(t, testExchangedToken, 60)
	now := time.Unix(1_000_000, 0)
	b := NewTokenExchange(e.srv.Client(), testSubjectType)
	b.Now = func() time.Time { return now }
	ctx := context.Background()
	if _, err := b.Resolve(ctx, teRef(e.srv.URL, testSubjectToken)); err != nil {
		t.Fatal(err)
	}
	now = now.Add(90 * time.Second) // past the 60s lifetime
	if _, err := b.Resolve(ctx, teRef(e.srv.URL, testSubjectToken)); err != nil {
		t.Fatal(err)
	}
	seen := e.seen()
	if len(seen) != 2 {
		t.Fatalf("exchanges = %d, want 2 (expired token must be re-exchanged)", len(seen))
	}
	if seen[0] != testSubjectToken || seen[1] != testSubjectToken {
		t.Fatal("a refresh must re-exchange the SAME subject token")
	}
}

func TestTokenExchangeNoCacheWhenExpiresInAbsent(t *testing.T) {
	setTEEnv(t)
	e := newExchangeEndpoint(t, testExchangedToken, 0)
	b := NewTokenExchange(e.srv.Client(), testSubjectType)
	for i := 0; i < 2; i++ {
		if _, err := b.Resolve(context.Background(), teRef(e.srv.URL, testSubjectToken)); err != nil {
			t.Fatalf("Resolve #%d: %v", i, err)
		}
	}
	if n := len(e.seen()); n != 2 {
		t.Fatalf("exchanges = %d, want 2 (absent expires_in must not cache)", n)
	}
}

// TestTokenExchangeErrorsAreFixedVocabulary: whatever the authorization
// server answers — an RFC 6749 error code, a description, a 5xx, garbage —
// the broker's error names the resource and a fixed outcome, never the AS's
// text and never either token. These errors can reach the ledger as a
// tool_call reason, so this is the leak guard for the AS-controlled channel.
func TestTokenExchangeErrorsAreFixedVocabulary(t *testing.T) {
	setTEEnv(t)
	const sentinel = "never-in-a-ledger"
	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"4xx", http.StatusBadRequest, `{"error":"invalid_grant","error_description":"` + sentinel + " " + testSubjectToken + `"}`, "was rejected by the authorization server"},
		{"401", http.StatusUnauthorized, `{"error":"invalid_client","error_description":"` + sentinel + `"}`, "was rejected by the authorization server"},
		{"5xx", http.StatusBadGateway, sentinel, "failed at the authorization server"},
		{"garbage 200", http.StatusOK, "<html>" + sentinel, "returned an unusable response"},
		{"no access_token", http.StatusOK, `{"token_type":"Bearer","expires_in":3600,"x":"` + sentinel + `"}`, "returned an unusable response"},
		{"non-bearer", http.StatusOK, `{"access_token":"` + testExchangedToken + `","token_type":"mac"}`, "returned an unusable response"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(c.status)
				_, _ = w.Write([]byte(c.body))
			}))
			defer srv.Close()
			b := NewTokenExchange(srv.Client(), testSubjectType)
			_, err := b.Resolve(context.Background(), teRef(srv.URL, testSubjectToken))
			if err == nil {
				t.Fatal("expected an error")
			}
			msg := err.Error()
			for _, forbidden := range []string{sentinel, testSubjectToken, testExchangedToken, "invalid_grant", "invalid_client", "mac"} {
				if strings.Contains(msg, forbidden) {
					t.Fatalf("error echoed %q: %q", forbidden, msg)
				}
			}
			if !strings.Contains(msg, "github-mcp") || !strings.Contains(msg, c.want) {
				t.Fatalf("error = %q, want the resource id and %q", msg, c.want)
			}
		})
	}
	t.Run("endpoint down", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		addr := srv.URL
		srv.Close()
		b := NewTokenExchange(nil, testSubjectType)
		_, err := b.Resolve(context.Background(), teRef(addr, testSubjectToken))
		if err == nil || !strings.Contains(err.Error(), "token exchange for resource \"github-mcp\" failed") {
			t.Fatalf("transport failure must be the fixed message, got %v", err)
		}
		if strings.Contains(err.Error(), testSubjectToken) || strings.Contains(err.Error(), addr) {
			t.Fatalf("transport error leaked: %v", err)
		}
	})
}

func TestTokenExchangeRefusesIncompleteRef(t *testing.T) {
	setTEEnv(t)
	e := newExchangeEndpoint(t, testExchangedToken, 3600)
	b := NewTokenExchange(e.srv.Client(), testSubjectType)
	ctx := context.Background()
	noSubject := teRef(e.srv.URL, "")
	if _, err := b.Resolve(ctx, noSubject); err == nil || !strings.Contains(err.Error(), "has no subject token") {
		t.Fatalf("empty subject token must be refused before any request, got %v", err)
	}
	noAud := teRef(e.srv.URL, testSubjectToken)
	noAud.Audience = ""
	if _, err := b.Resolve(ctx, noAud); err == nil || !strings.Contains(err.Error(), "has no audience") {
		t.Fatalf("empty audience must be refused before any request, got %v", err)
	}
	wrongGrant := teRef(e.srv.URL, testSubjectToken)
	wrongGrant.Grant = "client_credentials"
	if _, err := b.Resolve(ctx, wrongGrant); err == nil {
		t.Fatal("a non-token_exchange grant must be refused")
	}
	wrongAuth := teRef(e.srv.URL, testSubjectToken)
	wrongAuth.ClientAuth = "private_key_jwt"
	if _, err := b.Resolve(ctx, wrongAuth); err == nil {
		t.Fatal("an unimplemented client_auth must be refused")
	}
	if n := len(e.seen()); n != 0 {
		t.Fatalf("no request may be sent for an incomplete ref, saw %d", n)
	}
	t.Setenv("TE_SECRET", "")
	_, err := b.Resolve(ctx, teRef(e.srv.URL, testSubjectToken))
	if err == nil || !strings.Contains(err.Error(), "TE_SECRET") || strings.Contains(err.Error(), "shh") {
		t.Fatalf("missing secret must name the variable, never a value: %v", err)
	}
}
