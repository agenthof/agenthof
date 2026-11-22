// Command fake-drive-mcp is a stdio MCP test double shaped like a Google
// Drive MCP server: the payload a refbridge fronts in tests and in CI. It
// exposes search, readGoogleDoc and downloadFile with canned, deterministic
// results and makes no network calls. The tool and argument names mirror the
// real server so a grant written against this double also fits the real one.
//
// downloadFile exists only so a genuine upstream tool name is present in
// ListTools for a grant to exclude; it is never expected to be called.
//
// At startup it prints a fingerprint of the credential environment variable
// (never the value) to stderr, so a test can show the value reached the
// process without a callable credential tool. Stdout carries only the MCP
// stream.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const credentialEnv = "GOOGLE_DRIVE_MCP_REFRESH_TOKEN"

// errorPrefix marks a readGoogleDoc id that asks for an error result carrying
// the text after the prefix.
const errorPrefix = "__error__:"

// errorPadding makes an error result longer than any plausible truncation cap.
const errorPadding = " (canned upstream failure detail, repeated to exceed a truncation cap) "

type note struct{ id, title, body string }

var notes = []note{
	{"note-1", "Roadmap notes", "Roadmap: ship the governed read path first, then widen the grant."},
	{"note-2", "Meeting notes", "Meeting: agreed to review the audit ledger every Friday."},
}

type searchArgs struct {
	Query string `json:"query"`
}

type readArgs struct {
	DocumentID string `json:"documentId"`
}

type downloadArgs struct {
	FileID    string `json:"fileId"`
	LocalPath string `json:"localPath"`
}

// newServer builds the MCP server. The tools return canned data and read no
// environment.
func newServer() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "fake-drive-mcp", Version: "v0.1.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "search", Description: "search the drive; one line per hit: id and title"},
		func(_ context.Context, _ *mcp.CallToolRequest, args searchArgs) (*mcp.CallToolResult, any, error) {
			q := strings.ToLower(args.Query)
			var lines []string
			for _, n := range notes {
				if strings.Contains(strings.ToLower(n.title), q) {
					lines = append(lines, n.id+" "+n.title)
				}
			}
			return textResult(strings.Join(lines, "\n")), nil, nil
		})
	mcp.AddTool(server, &mcp.Tool{Name: "readGoogleDoc", Description: "read the text of a document by id"},
		func(_ context.Context, _ *mcp.CallToolRequest, args readArgs) (*mcp.CallToolResult, any, error) {
			if canary, ok := strings.CutPrefix(args.DocumentID, errorPrefix); ok {
				return errorResult(canary + errorPadding + errorPadding + errorPadding), nil, nil
			}
			for _, n := range notes {
				if n.id == args.DocumentID {
					return textResult(n.body), nil, nil
				}
			}
			return errorResult("document not found: " + args.DocumentID), nil, nil
		})
	mcp.AddTool(server, &mcp.Tool{Name: "downloadFile", Description: "download a file to a local path"},
		func(_ context.Context, _ *mcp.CallToolRequest, args downloadArgs) (*mcp.CallToolResult, any, error) {
			return textResult("downloaded " + args.FileID), nil, nil
		})
	return server
}

func textResult(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

func errorResult(s string) *mcp.CallToolResult {
	r := textResult(s)
	r.IsError = true
	return r
}

// credentialFingerprintLine reports the SHA-256 of the credential variable's
// value, never the value itself.
func credentialFingerprintLine(lookupEnv func(string) (string, bool)) string {
	v, ok := lookupEnv(credentialEnv)
	if !ok || v == "" {
		return "fake-drive-mcp: credential " + credentialEnv + " not set"
	}
	sum := sha256.Sum256([]byte(v))
	return "fake-drive-mcp: credential " + credentialEnv + " fingerprint " + hex.EncodeToString(sum[:])
}

func main() {
	// Diagnostics go to stderr only: stdout is the MCP stream.
	fmt.Fprintln(os.Stderr, credentialFingerprintLine(os.LookupEnv))
	if err := newServer().Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
