package rungateway

import (
	"bytes"
	"log/slog"
	"net"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/agenthof/agenthof/internal/broker"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/obs"
)

func TestNewNilLoggerDoesNotPanic(t *testing.T) {
	gw := New(config.GatewayConfig{}, ".", broker.StaticEnv{}, nil)
	url, _, err := gw.Start(engine.Binding{RunID: "r-nil"}, config.AgentDef{Name: "a"}, func(engine.Event) {})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !strings.HasPrefix(url, "http://127.0.0.1:") {
		t.Fatalf("url = %q", url)
	}
	gw.Stop() // must not panic either
}

func TestStartStopLogListenerLifecycle(t *testing.T) {
	var buf bytes.Buffer
	logger := obs.New(&buf, slog.LevelDebug, obs.FormatText)
	gw := New(config.GatewayConfig{}, ".", broker.StaticEnv{}, logger)
	url, token, err := gw.Start(engine.Binding{RunID: "r-log"}, config.AgentDef{Name: "a"}, func(engine.Event) {})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	gw.Stop()
	out := buf.String()
	for _, want := range []string{"gateway listener started", "gateway listener stopped", "run=r-log", "agent=a", "network=tcp"} {
		if !strings.Contains(out, want) {
			t.Errorf("log missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, token) || strings.Contains(out, token[:8]) {
		t.Fatalf("run token leaked into the operational log:\n%s", out)
	}
	if strings.Contains(out, url) {
		t.Fatalf("listener URL must not be logged (identifiers only):\n%s", out)
	}
}

func TestStartStopSilentAtWarnLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := obs.New(&buf, slog.LevelWarn, obs.FormatText)
	gw := New(config.GatewayConfig{}, ".", broker.StaticEnv{}, logger)
	if _, _, err := gw.Start(engine.Binding{RunID: "r-quiet"}, config.AgentDef{Name: "a"}, func(engine.Event) {}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	gw.Stop()
	if buf.Len() != 0 {
		t.Fatalf("a clean start/stop must log nothing at Warn:\n%s", buf.String())
	}
}

func TestStartUpstreamConnectFailureLogsClassNotURL(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	// "zq9" prefixes keep every 8-char prefix out of the dictionary: a bare
	// "upstreamsecret…"[:8] is "upstream", which the message itself contains.
	const querySecret = "zq9querysecretQQQ999"
	const bearer = "zq9upstreamsecretXYZ111"
	t.Setenv("UP_TOKEN", bearer)

	var buf bytes.Buffer
	logger := obs.New(&buf, slog.LevelDebug, obs.FormatText)
	tools := map[string]config.ToolResource{
		"up": {Kind: "mcp", URL: "http://" + addr + "/?key=" + querySecret, CredentialSource: "static_env", TokenEnv: "UP_TOKEN"},
	}
	gw := New(config.GatewayConfig{Tools: tools}, "", broker.StaticEnv{}, logger)
	_, _, err = gw.Start(testBinding(), testAgentDef("up"), func(engine.Event) {})
	if err == nil {
		t.Fatal("Start must fail when the upstream is unreachable")
	}
	out := buf.String()
	if !strings.Contains(out, "upstream connect failed") || !strings.Contains(out, "resource=up") {
		t.Fatalf("expected the fixed message with the resource id:\n%s", out)
	}
	if !strings.Contains(out, "class=") || strings.Contains(out, "class=none") {
		t.Fatalf("expected an error class attr:\n%s", out)
	}
	for _, leak := range []string{querySecret, querySecret[:8], bearer, bearer[:8], addr, "http://"} {
		if strings.Contains(out, leak) {
			t.Fatalf("log must not carry %q (error text / URL echoed):\n%s", leak, out)
		}
	}
}

func TestToolCallRoutingLoggedAtDebugWithoutCredential(t *testing.T) {
	const upstreamToken = "zq9upstreamsecretABC222"
	t.Setenv("GITHUB_TOKEN", upstreamToken)
	ts, _ := newStubUpstream(t, upstreamToken)
	tools := map[string]config.ToolResource{
		"github": {Kind: "mcp", URL: ts.URL, CredentialSource: "static_env", TokenEnv: "GITHUB_TOKEN"},
	}
	var buf bytes.Buffer
	logger := obs.New(&buf, slog.LevelDebug, obs.FormatText)
	p := New(config.GatewayConfig{Tools: tools}, "", broker.StaticEnv{}, logger)
	proxyURL, runToken, err := p.Start(testBinding(), testAgentDef("github"), func(engine.Event) {})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop()
	ctx := t.Context()
	sess, err := stubAgentSession(ctx, proxyURL, runToken)
	if err != nil {
		t.Fatalf("agent session: %v", err)
	}
	defer func() { _ = sess.Close() }()
	if _, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": "hi"}}); err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"tool mirrored", "tool call routed", "resource=github", "tool=echo"} {
		if !strings.Contains(out, want) {
			t.Errorf("log missing %q:\n%s", want, out)
		}
	}
	for _, leak := range []string{upstreamToken, upstreamToken[:8], runToken, runToken[:8], ts.URL} {
		if strings.Contains(out, leak) {
			t.Fatalf("log must not carry %q:\n%s", leak, out)
		}
	}
}
