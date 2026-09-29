package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func connect(t *testing.T, server *mcp.Server) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	clientT, serverT := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, serverT, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "v0"}, nil).Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (string, bool) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool %s: %v", name, err)
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("CallTool %s: content %T is not text", name, res.Content[0])
	}
	return text.Text, res.IsError
}

func env(vars map[string]string) (func(string) (string, bool), func() []string) {
	lookup := func(name string) (string, bool) { v, ok := vars[name]; return v, ok }
	environ := func() []string {
		out := make([]string, 0, len(vars))
		for k, v := range vars {
			out = append(out, k+"="+v)
		}
		return out
	}
	return lookup, environ
}

func TestEchoReturnsText(t *testing.T) {
	lookup, environ := env(map[string]string{})
	cs := connect(t, newServer("DEMO_TOKEN", lookup, environ))
	got, isErr := call(t, cs, "echo", map[string]any{"text": "hello"})
	if isErr || got != "hello" {
		t.Fatalf("echo = %q (error %v), want hello", got, isErr)
	}
}

func TestCredentialReturnsFingerprintNeverValue(t *testing.T) {
	lookup, environ := env(map[string]string{"DEMO_TOKEN": "s3cret-value"})
	cs := connect(t, newServer("DEMO_TOKEN", lookup, environ))
	got, isErr := call(t, cs, "credential", map[string]any{})
	sum := sha256.Sum256([]byte("s3cret-value"))
	if isErr || got != hex.EncodeToString(sum[:]) {
		t.Fatalf("credential = %q (error %v), want the sha256 hex of the value", got, isErr)
	}
	if strings.Contains(got, "s3cret") {
		t.Fatal("credential tool leaked the value")
	}
}

func TestCredentialUnsetIsErrorResult(t *testing.T) {
	lookup, environ := env(map[string]string{})
	cs := connect(t, newServer("DEMO_TOKEN", lookup, environ))
	got, isErr := call(t, cs, "credential", map[string]any{})
	if !isErr || got != "credential environment variable DEMO_TOKEN is not set" {
		t.Fatalf("credential = %q (error %v), want the fixed not-set error", got, isErr)
	}
}

func TestEnvironmentListsSortedNamesOnly(t *testing.T) {
	lookup, environ := env(map[string]string{"ZED": "z-value", "DEMO_TOKEN": "t-value", "ALPHA": "a-value"})
	cs := connect(t, newServer("DEMO_TOKEN", lookup, environ))
	got, isErr := call(t, cs, "environment", map[string]any{})
	if isErr || got != "ALPHA,DEMO_TOKEN,ZED" {
		t.Fatalf("environment = %q (error %v), want ALPHA,DEMO_TOKEN,ZED", got, isErr)
	}
	if strings.Contains(got, "value") {
		t.Fatal("environment tool leaked a value")
	}
}
