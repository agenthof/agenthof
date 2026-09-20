package main

import (
	"context"
	"os"
	"strings"

	"github.com/agenthof/agenthof/internal/identity"
)

// resolveInvoker mirrors cmdRun's flags exactly. token (or $AGENTHOF_TOKEN):
//
//	verified -> Invoker{method:"oidc",...}, assertedAs = --as (never overwrites subject).
//	verification failed -> refused=true, inv = {"(unverified)", <issuer>, "oidc-rejected"}, verifyErr is the underlying OIDC error.
//	--token set but AGENTHOF_OIDC_ISSUER unset -> usageErr=true (exit 2, no event).
//
// no token -> identity.Static(--as) + parsed --groups; method "asserted".
//
// verifyErr is for stdout only. Callers that write a CONTROL event on a
// failed token (apply/registry, later tasks) must use refused/usageErr and a
// FIXED reason message — never verifyErr's text — because the go-oidc error
// can echo unverified claim values from the (unverified) token. This is the
// same reason cmdRun keeps it out of the ledgered refusal event today: it
// only interpolates verifyErr into the printed "token authentication
// failed: %v" line, and passes the fixed string "token verification failed"
// to engine.Refuse.
func resolveInvoker(as, groups, token string) (inv identity.Invoker, assertedAs string, refused bool, usageErr bool, verifyErr error) {
	rawToken := token
	if rawToken == "" {
		rawToken = os.Getenv("AGENTHOF_TOKEN")
	}
	if rawToken != "" {
		issuerURL := os.Getenv("AGENTHOF_OIDC_ISSUER")
		if issuerURL == "" {
			return identity.Invoker{}, "", false, true, nil
		}
		clientID := os.Getenv("AGENTHOF_OIDC_CLIENT_ID")
		if clientID == "" {
			clientID = "agenthof"
		}
		authInv, err := (identity.OIDC{IssuerURL: issuerURL, ClientID: clientID}).Authenticate(context.Background(), rawToken)
		if err != nil {
			refusedInv := identity.Invoker{Subject: "(unverified)", Issuer: issuerURL, Method: "oidc-rejected"}
			return refusedInv, "", true, false, err
		}
		return authInv, as, false, false, nil
	}

	var g []string
	for _, raw := range strings.Split(groups, ",") {
		trimmed := strings.TrimSpace(raw)
		if trimmed != "" {
			g = append(g, trimmed)
		}
	}
	// identity.Static only takes --as; it's set here rather than adding a
	// groups parameter, since ~15 existing call sites across the engine,
	// audit, and identity test suites call Static with a single arg.
	// Invoker.Groups is a plain exported field, so mutating the returned
	// value is equivalent to threading it through the constructor.
	inv = identity.Static(as)
	inv.Groups = g
	return inv, "", false, false, nil
}
