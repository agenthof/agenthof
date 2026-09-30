package broker

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// grantTokenExchange is the RFC 8693 grant_type.
const grantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"

// SubjectTokenTypeAccessToken is the default RFC 8693 subject_token_type: the
// inbound token Agenthof verified is an access token. A deployment whose
// invokers present ID tokens sets urn:ietf:params:oauth:token-type:id_token
// instead (AGENTHOF_OIDC_SUBJECT_TOKEN_TYPE).
const SubjectTokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"

// TokenExchange obtains a per-user upstream token on behalf of the invoker
// via RFC 8693 token exchange: the invoker's verified inbound token (the
// subject token, carried on the ref) is exchanged at the resource's token
// endpoint for a token audienced to that upstream, with Agenthof
// authenticating as an OAuth client (client_secret_basic). This is
// impersonation, not delegation: no actor_token is sent, so the upstream
// sees the human directly (Agenthof's own ledger still names agent, role,
// and run).
//
// Tokens are cached per (resource, sha256(subject token)) — one user's
// token is never served to another — and re-exchanged near expiry, always
// from the SAME subject token: once that token expires the next exchange
// fails and the call is recorded failed. There is no refresh token and no
// re-auth. Neither token is ever logged, and every error is drawn from a
// fixed vocabulary: the authorization server's response body and error code
// never enter an error string, because a broker error can reach the ledger
// verbatim as a mid-step tool_call reason.
type TokenExchange struct {
	client *http.Client
	// subjectTokenType is sent as subject_token_type on every exchange: the
	// kind of inbound token this deployment presents (see
	// SubjectTokenTypeAccessToken).
	subjectTokenType string
	// Now is the clock (nil → time.Now); overridden in tests for expiry.
	Now func() time.Time

	mu    sync.Mutex
	cache map[string]cachedToken
}

var _ Broker = (*TokenExchange)(nil)

// NewTokenExchange builds the broker over client (nil → http.DefaultClient)
// for a deployment whose inbound tokens are of subjectTokenType.
func NewTokenExchange(client *http.Client, subjectTokenType string) *TokenExchange {
	if client == nil {
		client = http.DefaultClient
	}
	if subjectTokenType == "" {
		subjectTokenType = SubjectTokenTypeAccessToken
	}
	return &TokenExchange{client: client, subjectTokenType: subjectTokenType, cache: map[string]cachedToken{}}
}

func (x *TokenExchange) now() time.Time {
	if x.Now != nil {
		return x.Now()
	}
	return time.Now()
}

// Resolve returns a valid upstream bearer for ref's subject, exchanging one
// if the cache has none for this (resource, subject) or the cached one is
// within its refresh margin of expiry.
func (x *TokenExchange) Resolve(ctx context.Context, ref CredentialRef) (string, error) {
	if ref.Grant != "token_exchange" {
		return "", fmt.Errorf("broker: token_exchange broker got grant %q", ref.Grant)
	}
	if ref.ClientAuth != "client_secret_basic" {
		return "", fmt.Errorf("broker: client_auth %q is not implemented (only client_secret_basic)", ref.ClientAuth)
	}
	if ref.SubjectToken == "" {
		return "", fmt.Errorf("broker: token exchange for resource %q has no subject token", ref.ResourceID)
	}
	if ref.Audience == "" {
		return "", fmt.Errorf("broker: token exchange for resource %q has no audience", ref.ResourceID)
	}
	// Key by the subject token's HASH: the map must distinguish users
	// without holding the token as a key anyone could enumerate.
	sum := sha256.Sum256([]byte(ref.SubjectToken))
	key := ref.ResourceID + "\x00" + hex.EncodeToString(sum[:])

	x.mu.Lock()
	defer x.mu.Unlock()
	if ent, ok := x.cache[key]; ok && !ent.refreshAt.IsZero() && x.now().Before(ent.refreshAt) {
		return ent.token, nil
	}

	tok, expiresIn, err := x.exchange(ctx, ref)
	if err != nil {
		return "", err
	}
	if at := cacheRefreshAt(x.now(), expiresIn); !at.IsZero() {
		x.cache[key] = cachedToken{token: tok, refreshAt: at}
	} else {
		delete(x.cache, key)
	}
	return tok, nil
}

// exchange performs one RFC 8693 token-exchange request with
// client_secret_basic. Every error it returns is fixed text plus the
// resource id: not the request error (it can carry the URL), not the
// response body, not the RFC 6749 error code.
func (x *TokenExchange) exchange(ctx context.Context, ref CredentialRef) (string, int, error) {
	clientID := os.Getenv(ref.ClientIDEnv)
	if clientID == "" {
		return "", 0, fmt.Errorf("broker: client id env %s is not set", ref.ClientIDEnv)
	}
	clientSecret := os.Getenv(ref.ClientSecretEnv)
	if clientSecret == "" {
		return "", 0, fmt.Errorf("broker: client secret env %s is not set", ref.ClientSecretEnv)
	}

	form := url.Values{
		"grant_type":         {grantTokenExchange},
		"subject_token":      {ref.SubjectToken},
		"subject_token_type": {x.subjectTokenType},
		"audience":           {ref.Audience},
	}
	if ref.Scope != "" {
		form.Set("scope", ref.Scope)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ref.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("broker: token exchange for resource %q failed", ref.ResourceID)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// RFC 6749 §2.3.1: form-urlencode client id/secret, then HTTP Basic.
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString(
		[]byte(url.QueryEscape(clientID)+":"+url.QueryEscape(clientSecret))))

	resp, err := x.client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("broker: token exchange for resource %q failed", ref.ResourceID)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	switch {
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return "", 0, fmt.Errorf("broker: token exchange for resource %q was rejected by the authorization server", ref.ResourceID)
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return "", 0, fmt.Errorf("broker: token exchange for resource %q failed at the authorization server", ref.ResourceID)
	}

	// RFC 8693 §2.2.1 also returns issued_token_type; it is not needed to
	// use the token as a bearer, so it is not validated. RFC 6749 §7.1: a
	// token type the client does not understand must not be used; empty is
	// treated as bearer.
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" ||
		(tr.TokenType != "" && !strings.EqualFold(tr.TokenType, "bearer")) {
		return "", 0, fmt.Errorf("broker: token exchange for resource %q returned an unusable response", ref.ResourceID)
	}
	return tr.AccessToken, tr.ExpiresIn, nil
}
