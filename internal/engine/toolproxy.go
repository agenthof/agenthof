package engine

import (
	"context"

	"github.com/agenthof/agenthof/internal/config"
)

// ToolProxy serves an inbound MCP proxy for ONE fronted step. Start mints a
// token, authorizes calls against agent.Tools, injects resource credentials,
// forwards to the upstream resource, and appends a tool_call event per call via
// appendEvent (the engine's serialized ledger appender). It returns the URL the
// agent calls and the token it must present. The token is handed to the agent
// via headers only — never stored on Binding or the ledger (Article III).
type ToolProxy interface {
	Start(bind Binding, agent config.AgentDef, appendEvent func(Event)) (url, token string, err error)
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
