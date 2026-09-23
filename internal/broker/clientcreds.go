package broker

import (
	"context"
	"encoding/base64"
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

// refreshMargin re-mints a token slightly before its stated expiry so a call
// never uses a token that expires in flight.
const refreshMargin = 30 * time.Second

// ClientCredentials mints upstream OAuth tokens via the client_credentials
// grant (RFC 6749 §4.4), caches them per (resource, issuer), and re-mints past
// expiry. The client secret is read from the environment at mint time and never
// held beyond the request; the minted token is cached in memory only and never
// logged or written to the ledger.
type ClientCredentials struct {
	client *http.Client
	// Now is the clock (nil → time.Now); overridden in tests for expiry.
	Now func() time.Time

	mu    sync.Mutex
	cache map[string]cachedToken
}

type cachedToken struct {
	token  string
	expiry time.Time // zero => not cacheable (mint every resolve)
}

var _ Broker = (*ClientCredentials)(nil)

// NewClientCredentials builds the broker over client (nil → http.DefaultClient).
func NewClientCredentials(client *http.Client) *ClientCredentials {
	if client == nil {
		client = http.DefaultClient
	}
	return &ClientCredentials{client: client, cache: map[string]cachedToken{}}
}

func (c *ClientCredentials) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Resolve returns a valid upstream bearer for ref, minting one if the cache has
// none or the cached one is within refreshMargin of expiry.
func (c *ClientCredentials) Resolve(ctx context.Context, ref CredentialRef) (string, error) {
	if ref.Grant != "client_credentials" {
		return "", fmt.Errorf("broker: client_credentials broker got grant %q", ref.Grant)
	}
	if ref.ClientAuth != "client_secret_basic" {
		return "", fmt.Errorf("broker: client_auth %q is not implemented (only client_secret_basic)", ref.ClientAuth)
	}
	key := ref.ResourceID + "\x00" + ref.Issuer

	c.mu.Lock()
	defer c.mu.Unlock()
	if ent, ok := c.cache[key]; ok && !ent.expiry.IsZero() && c.now().Before(ent.expiry.Add(-refreshMargin)) {
		return ent.token, nil
	}

	tok, expiresIn, err := c.mint(ctx, ref)
	if err != nil {
		return "", err
	}
	if expiresIn > 0 {
		c.cache[key] = cachedToken{token: tok, expiry: c.now().Add(time.Duration(expiresIn) * time.Second)}
	} else {
		// No usable lifetime: do not cache; mint on every resolve.
		delete(c.cache, key)
	}
	return tok, nil
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// mint performs one client_credentials token request with client_secret_basic.
func (c *ClientCredentials) mint(ctx context.Context, ref CredentialRef) (string, int, error) {
	clientID := os.Getenv(ref.ClientIDEnv)
	if clientID == "" {
		return "", 0, fmt.Errorf("broker: client id env %s is not set", ref.ClientIDEnv)
	}
	clientSecret := os.Getenv(ref.ClientSecretEnv)
	if clientSecret == "" {
		return "", 0, fmt.Errorf("broker: client secret env %s is not set", ref.ClientSecretEnv)
	}

	form := url.Values{"grant_type": {"client_credentials"}}
	if ref.Scope != "" {
		form.Set("scope", ref.Scope)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ref.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("broker: build token request for resource %q: %w", ref.ResourceID, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// RFC 6749 §2.3.1: form-urlencode client id/secret, then HTTP Basic.
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString(
		[]byte(url.QueryEscape(clientID)+":"+url.QueryEscape(clientSecret))))

	resp, err := c.client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("broker: token request for resource %q failed", ref.ResourceID)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", 0, fmt.Errorf("broker: token endpoint for resource %q returned status %d%s",
			ref.ResourceID, resp.StatusCode, oauthErrorCode(body))
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", 0, fmt.Errorf("broker: token endpoint for resource %q returned an unparseable response", ref.ResourceID)
	}
	if tr.AccessToken == "" {
		return "", 0, fmt.Errorf("broker: token endpoint for resource %q returned no access_token", ref.ResourceID)
	}
	return tr.AccessToken, tr.ExpiresIn, nil
}

// oauthErrorCode extracts only the RFC 6749 §5.2 "error" code from a token
// endpoint error body — never error_description, never any token — to keep
// secrets out of error strings.
func oauthErrorCode(body []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error != "" {
		return " (error: " + e.Error + ")"
	}
	return ""
}
