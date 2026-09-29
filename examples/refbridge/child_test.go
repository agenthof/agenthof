package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// childFlag re-executes this test binary as the stdio MCP server the bridge
// spawns. The child is the test binary itself — not a separately built
// program — so the tests need no `go` on PATH and no build step, and they
// run under `go test ./...` on any machine. The flag is passed in argv, not
// the environment, because the bridge hands the child an EMPTY environment.
const childFlag = "-refbridge-test-child"

func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == childFlag {
		runTestChild(os.Args[2])
		return
	}
	os.Exit(m.Run())
}

func text(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

// runTestChild serves echo, credential (SHA-256 of the named variable, never
// the value), environment (variable NAMES, sorted) and pid, so a test can
// prove what was materialized, that nothing else leaked, and which process
// answered.
func runTestChild(credEnv string) {
	server := mcp.NewServer(&mcp.Implementation{Name: "test-child", Version: "v0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "echo", Description: "echo"},
		func(_ context.Context, _ *mcp.CallToolRequest, args struct {
			Text string `json:"text,omitempty"`
		}) (*mcp.CallToolResult, any, error) {
			return text(args.Text), nil, nil
		})
	mcp.AddTool(server, &mcp.Tool{Name: "credential", Description: "fingerprint"},
		func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
			sum := sha256.Sum256([]byte(os.Getenv(credEnv)))
			return text(hex.EncodeToString(sum[:])), nil, nil
		})
	mcp.AddTool(server, &mcp.Tool{Name: "environment", Description: "names"},
		func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
			var names []string
			for _, kv := range os.Environ() {
				name, _, _ := strings.Cut(kv, "=")
				names = append(names, name)
			}
			sort.Strings(names)
			return text(strings.Join(names, ",")), nil, nil
		})
	mcp.AddTool(server, &mcp.Tool{Name: "pid", Description: "pid"},
		func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
			return text(strconv.Itoa(os.Getpid())), nil, nil
		})
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		os.Exit(1)
	}
}
