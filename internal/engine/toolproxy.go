package engine

import (
	"context"

	"github.com/agenthof/agenthof/internal/config"
)

// ToolProxy serves the per-run listener for ONE fronted step: the tool, exec,
// model, and spawn doors. Start mints a token, authorizes calls against the
// agent's grants, injects resource credentials, forwards to the upstream, and
// appends a ledger event per call via appendEvent (the engine's serialized
// ledger appender). ctx is the step's context: it carries the step deadline
// and is cancelled when the step is over, so any child work a door starts
// (a spawned run) is derived from it and torn down with the step. It
// returns the URL the agent calls and the token it must present. The token
// is handed to the agent via headers only — never stored on Binding or the
// ledger (Article III).
type ToolProxy interface {
	Start(ctx context.Context, bind Binding, agent config.AgentDef, appendEvent func(Event)) (url, token string, err error)
	Stop()
}

type proxyCoordKey struct{}

type proxyCoords struct{ url, token string }

// WithProxyCoordinates returns ctx carrying the per-step proxy URL + token for
// the fronted adapter to forward. Transient transport coordinates only.
func WithProxyCoordinates(ctx context.Context, url, token string) context.Context {
	return context.WithValue(ctx, proxyCoordKey{}, proxyCoords{url: url, token: token})
}

// ProxyCoordinatesFrom reports the proxy URL + token if present.
func ProxyCoordinatesFrom(ctx context.Context) (url, token string, ok bool) {
	c, ok := ctx.Value(proxyCoordKey{}).(proxyCoords)
	return c.url, c.token, ok
}
