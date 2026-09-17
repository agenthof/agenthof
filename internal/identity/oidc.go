package identity

import (
	"context"
	"fmt"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
)

// OIDC authenticates raw ID tokens against an OpenID Connect provider,
// producing an Invoker from the verified claims.
type OIDC struct {
	IssuerURL string
	ClientID  string
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

// Authenticate verifies rawToken as an OIDC ID token issued by o.IssuerURL
// for o.ClientID, returning the resulting Invoker.
func (o OIDC) Authenticate(ctx context.Context, rawToken string) (Invoker, error) {
	clientCtx := oidc.ClientContext(ctx, o.httpClient())

	provider, err := oidc.NewProvider(clientCtx, o.IssuerURL)
	if err != nil {
		return Invoker{}, fmt.Errorf("oidc discovery: %w", err)
	}

	idToken, err := provider.Verifier(&oidc.Config{ClientID: o.ClientID}).Verify(clientCtx, rawToken)
	if err != nil {
		return Invoker{}, fmt.Errorf("oidc verify: %w", err)
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
