package identity

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
)

// ErrProviderUnavailable marks an Authenticate failure that is the
// provider's, not the token's: discovery for the configured issuer could
// not complete. A server answers it with 503 — the token was never judged
// — where every other failure is the token's (401).
var ErrProviderUnavailable = errors.New("oidc provider unavailable")

// CachedOIDC is OIDC for a long-lived process: discovery runs once and the
// provider — with its remote key set — is reused for every call. The
// provider is looked up by the CONFIGURED issuer only; a token's own iss
// claim is unverified input and never chooses a URL to fetch (SSRF guard).
// A failed discovery is not cached, so a provider that was down at start
// is retried on the next call. The base context must outlive every call:
// the provider keeps it for later key refreshes, so a request's context
// would be the wrong thing to build it from.
type CachedOIDC struct {
	o    OIDC
	base context.Context

	mu       sync.Mutex
	provider *oidc.Provider
}

// NewCachedOIDC returns a verifier for o whose provider lives as long as base.
func NewCachedOIDC(base context.Context, o OIDC) *CachedOIDC {
	return &CachedOIDC{o: o, base: base}
}

// Authenticate verifies rawToken against the cached provider for the
// configured issuer, discovering it first if this is the first call (or
// every earlier discovery failed).
func (c *CachedOIDC) Authenticate(ctx context.Context, rawToken string) (Invoker, error) {
	provider, err := c.providerFor()
	if err != nil {
		// The text is fixed: the discovery error names the configured
		// issuer URL and the transport failure, neither of which a caller
		// of this method should relay to a client.
		return Invoker{}, fmt.Errorf("%w: discovery for the configured issuer failed", ErrProviderUnavailable)
	}
	return c.o.verify(oidc.ClientContext(ctx, c.o.httpClient()), provider, rawToken)
}

func (c *CachedOIDC) providerFor() (*oidc.Provider, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.provider != nil {
		return c.provider, nil
	}
	p, err := oidc.NewProvider(oidc.ClientContext(c.base, c.o.httpClient()), c.o.IssuerURL)
	if err != nil {
		return nil, err
	}
	c.provider = p
	return p, nil
}
