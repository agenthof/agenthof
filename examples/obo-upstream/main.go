// Command obo-upstream is a stand-in per-user MCP server for the
// on-behalf-of demonstration: the kind of resource where each human has
// their own account. It exposes one tool, whoami, which verifies the bearer
// token it was called with against the issuer's JWKS, rejects a token whose
// aud does not name this server — the audience check lives here, at the
// resource that the token is for, not in Agenthof's gateway — and answers
// "acting as: <sub>", so a proof can show the upstream saw the invoking
// human rather than a service identity. It holds no credential of its own.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// audience decodes the aud claim, which RFC 7519 allows as a string or an
// array of strings.
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = audience(many)
	return nil
}

type claims struct {
	Sub string   `json:"sub"`
	Aud audience `json:"aud"`
	Exp int64    `json:"exp"`
}

type whoamiArgs struct {
	Text string `json:"text,omitempty"`
}

func errorResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}

// identify verifies raw against keys and this server's audience, returning
// the subject it names. The reasons are fixed strings a ledger may carry.
func identify(ctx context.Context, keys oidc.KeySet, want string, now time.Time, raw string) (string, error) {
	if raw == "" {
		return "", errors.New("unauthorized: bearer token rejected")
	}
	payload, err := keys.VerifySignature(ctx, raw)
	if err != nil {
		return "", errors.New("unauthorized: bearer token rejected")
	}
	var c claims
	if err := json.Unmarshal(payload, &c); err != nil || c.Sub == "" || c.Exp == 0 || now.After(time.Unix(c.Exp, 0)) {
		return "", errors.New("unauthorized: bearer token rejected")
	}
	if !slices.Contains(c.Aud, want) {
		return "", errors.New("audience mismatch: this server is not the token's audience")
	}
	return c.Sub, nil
}

// newServer builds the MCP server. keys and now are injected so tests can
// supply a local JWKS and a fixed clock.
func newServer(keys oidc.KeySet, want string, now func() time.Time) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "obo-upstream", Version: "v0.1.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "whoami", Description: "the subject this server sees the caller acting as"},
		func(ctx context.Context, req *mcp.CallToolRequest, _ whoamiArgs) (*mcp.CallToolResult, any, error) {
			var raw string
			if req.Extra != nil && req.Extra.Header != nil {
				raw = strings.TrimPrefix(req.Extra.Header.Get("Authorization"), "Bearer ")
			}
			sub, err := identify(ctx, keys, want, now(), raw)
			if err != nil {
				return errorResult(err.Error()), nil, nil
			}
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "acting as: " + sub}}}, nil, nil
		})
	return server
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8091", "loopback address to listen on")
	jwksURL := flag.String("jwks-url", "", "the issuer's JWKS url, used to verify every bearer")
	aud := flag.String("audience", "", "the audience a bearer must name to be accepted here")
	flag.Parse()
	if *jwksURL == "" || *aud == "" {
		log.Fatal("obo-upstream: -jwks-url and -audience are required")
	}
	keys := oidc.NewRemoteKeySet(context.Background(), *jwksURL)
	server := newServer(keys, *aud, time.Now)
	log.Printf("obo-upstream: listening on %s for audience %s", *addr, *aud)
	log.Fatal(http.ListenAndServe(*addr, mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)))
}
