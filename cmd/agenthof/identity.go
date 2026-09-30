package main

import (
	"context"
	"os"
	"strings"

	"github.com/agenthof/agenthof/internal/identity"
)

// runInvoker is resolveInvoker's result plus the raw token that was
// VERIFIED, for cmdRun only: the data plane exchanges it (RFC 8693) for a
// per-user upstream credential. subjectToken is a bearer credential — never
// logged, never on engine.Binding, never in an event — and is empty unless
// inv.Method is "oidc" (an asserted --as identity has nothing to exchange).
type runInvoker struct {
	inv          identity.Invoker
	assertedAs   string
	refused      bool
	usageErr     bool
	verifyErr    error
	subjectToken string
}

// resolveInvoker mirrors cmdRun's flags exactly. token (or $AGENTHOF_TOKEN):
//
//	verified -> Invoker{method:"oidc",...}, assertedAs = --as (never overwrites subject).
//	verification failed -> refused=true, inv = {"(unverified)", <issuer>, "oidc-rejected"}, verifyErr is the underlying OIDC error.
//	--token set but AGENTHOF_OIDC_ISSUER unset -> usageErr=true (exit 2, no event).
//
// no token -> identity.Static(--as) + parsed --groups; method "asserted".
//
// verifyErr is for stdout only. Callers that write a CONTROL event on a
// failed token (apply/registry) must use refused/usageErr and a FIXED reason
// message — never verifyErr's text — because the go-oidc error can echo
// unverified claim values from the (unverified) token. cmdRun likewise
// passes the fixed string "token verification failed" to engine.Refuse.
//
// The control-plane commands use this five-value form; only cmdRun needs
// the verified token itself and calls resolveInvokerForRun directly.
func resolveInvoker(as, groups, token string) (inv identity.Invoker, assertedAs string, refused bool, usageErr bool, verifyErr error) {
	r := resolveInvokerForRun(as, groups, token)
	return r.inv, r.assertedAs, r.refused, r.usageErr, r.verifyErr
}

// resolveInvokerForRun is resolveInvoker plus the verified subject token.
// The OIDC verifier accepts AGENTHOF_OIDC_CLIENT_ID (default "agenthof") and,
// when set, AGENTHOF_OIDC_AUDIENCE — the resource-server audience a token
// presented TO Agenthof may name instead of the client id.
func resolveInvokerForRun(as, groups, token string) runInvoker {
	rawToken := token
	if rawToken == "" {
		rawToken = os.Getenv("AGENTHOF_TOKEN")
	}
	if rawToken != "" {
		issuerURL := os.Getenv("AGENTHOF_OIDC_ISSUER")
		if issuerURL == "" {
			return runInvoker{usageErr: true}
		}
		clientID := os.Getenv("AGENTHOF_OIDC_CLIENT_ID")
		if clientID == "" {
			clientID = "agenthof"
		}
		o := identity.OIDC{IssuerURL: issuerURL, ClientID: clientID, Audience: os.Getenv("AGENTHOF_OIDC_AUDIENCE")}
		authInv, err := o.Authenticate(context.Background(), rawToken)
		if err != nil {
			return runInvoker{
				inv:       identity.Invoker{Subject: "(unverified)", Issuer: issuerURL, Method: "oidc-rejected"},
				refused:   true,
				verifyErr: err,
			}
		}
		return runInvoker{inv: authInv, assertedAs: as, subjectToken: rawToken}
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
	inv := identity.Static(as)
	inv.Groups = g
	return runInvoker{inv: inv}
}
