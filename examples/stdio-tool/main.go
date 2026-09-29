// Command stdio-tool is a minimal stdio MCP server: the reference payload a
// refbridge fronts in tests and in CI. It exposes three tools — echo, which
// returns its text argument; credential, which returns the SHA-256 of the
// credential environment variable's value (never the value itself, so a
// proof can compare fingerprints without printing a secret); and
// environment, which lists the NAMES of the variables in its environment
// (never values), so a test can show the environment it was spawned with is
// exactly the allowlist plus the credential. It makes no network calls and
// writes nothing but the MCP stream to stdout.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type echoArgs struct {
	Text string `json:"text,omitempty"`
}

// newServer builds the MCP server. lookupEnv and environ are injected so the
// tests can supply an environment without touching the process's own.
func newServer(credEnv string, lookupEnv func(string) (string, bool), environ func() []string) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "stdio-tool", Version: "v0.1.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "echo", Description: "return the given text"},
		func(_ context.Context, _ *mcp.CallToolRequest, args echoArgs) (*mcp.CallToolResult, any, error) {
			return textResult(args.Text), nil, nil
		})
	mcp.AddTool(server, &mcp.Tool{Name: "credential", Description: "SHA-256 fingerprint of the credential this server was spawned with (never the value)"},
		func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
			v, ok := lookupEnv(credEnv)
			if !ok || v == "" {
				return &mcp.CallToolResult{
					IsError: true,
					Content: []mcp.Content{&mcp.TextContent{Text: "credential environment variable " + credEnv + " is not set"}},
				}, nil, nil
			}
			return textResult(fingerprint(v)), nil, nil
		})
	mcp.AddTool(server, &mcp.Tool{Name: "environment", Description: "sorted, comma-separated NAMES of the environment variables this server was spawned with (never values)"},
		func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
			return textResult(strings.Join(envNames(environ()), ",")), nil, nil
		})
	return server
}

func textResult(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

func fingerprint(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}

func envNames(environ []string) []string {
	names := make([]string, 0, len(environ))
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func main() {
	credEnv := flag.String("credential-env", "DEMO_TOKEN", "name of the environment variable holding this server's credential")
	flag.Parse()
	// Diagnostics go to stderr only: stdout is the MCP stream.
	fmt.Fprintf(os.Stderr, "stdio-tool: serving over stdio; credential env %s\n", *credEnv)
	if err := newServer(*credEnv, os.LookupEnv, os.Environ).Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
