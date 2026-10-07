package identity

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/coreos/go-oidc/v3/oidc"
)

// OIDC authenticates raw ID tokens against an OpenID Connect provider,
// producing an Invoker from the verified claims.
type OIDC struct {
	IssuerURL string
	ClientID  string
	// Audience is the resource-server audience Agenthof also accepts, next
	// to ClientID (an access token minted for the API rather than for the
	// login client). Empty means only ClientID is accepted — exactly the
	// behaviour before this field existed.
	Audience string
	// HTTP is the client used for discovery and verification requests. If
	// nil, http.DefaultClient is used. Exposed so tests can inject an
	// httptest server's client without touching the network.
	HTTP *http.Client
}

func (o OIDC) httpClient() *http.Client {
	if o.HTTP != nil {
		return o.HTTP
	}
	return http.DefaultClient
}

// Authenticate verifies rawToken as an OIDC token issued by o.IssuerURL for
// o.ClientID — or, when o.Audience is set, for either o.ClientID or
// o.Audience — returning the resulting Invoker. Discovery runs on every
// call; a long-lived process uses CachedOIDC instead.
func (o OIDC) Authenticate(ctx context.Context, rawToken string) (Invoker, error) {
	clientCtx := oidc.ClientContext(ctx, o.httpClient())

	provider, err := oidc.NewProvider(clientCtx, o.IssuerURL)
	if err != nil {
		return Invoker{}, fmt.Errorf("oidc discovery: %w", err)
	}
	return o.verify(clientCtx, provider, rawToken)
}

// verify checks rawToken against provider's keys and o's audience rule and
// builds the Invoker. It is the half of Authenticate that is per-token;
// the provider is the per-issuer half.
func (o OIDC) verify(clientCtx context.Context, provider *oidc.Provider, rawToken string) (Invoker, error) {
	var idToken *oidc.IDToken
	var err error
	if o.Audience == "" {
		idToken, err = provider.Verifier(&oidc.Config{ClientID: o.ClientID}).Verify(clientCtx, rawToken)
		if err != nil {
			return Invoker{}, fmt.Errorf("oidc verify: %w", err)
		}
	} else {
		// go-oidc checks exactly one audience (ClientID). Accepting EITHER
		// the client id OR the resource-server audience means skipping that
		// check and replacing it here — before any claim is read, so a token
		// audienced to neither can never yield an Invoker. The message is
		// fixed: the token's own aud values are unverified input.
		idToken, err = provider.Verifier(&oidc.Config{SkipClientIDCheck: true}).Verify(clientCtx, rawToken)
		if err != nil {
			return Invoker{}, fmt.Errorf("oidc verify: %w", err)
		}
		// An unset client id matches nothing: without the guard, a token
		// whose aud is the empty string would satisfy the check.
		clientIDMatch := o.ClientID != "" && slices.Contains(idToken.Audience, o.ClientID)
		if !clientIDMatch && !slices.Contains(idToken.Audience, o.Audience) {
			return Invoker{}, errors.New("oidc verify: token audience does not include the client id or the configured audience")
		}
	}

	var claims struct {
		Email  string   `json:"email"`
		Groups []string `json:"groups"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return Invoker{}, fmt.Errorf("oidc claims: %w", err)
	}

	subject := claims.Email
	if subject == "" {
		subject = idToken.Subject
	}

	return Invoker{
		Subject: subject,
		Issuer:  o.IssuerURL,
		Method:  "oidc",
		Groups:  claims.Groups,
	}, nil
}
