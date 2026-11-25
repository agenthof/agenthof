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
	{"note-3", "Entitlements sync", entitlementsNote},
	{"note-4", "Token handling sync", tokenNote},
	{"note-5", "Offsite logistics sync", offsiteNote},
}

// The dated notes below are shaped like a sanitised meeting-notes export: a
// leading "Meeting notes - <date>" line, then several paragraphs. They give a
// retrieval test distinct topics to select between (entitlements, tokens) and
// an unrelated distractor (offsite). Titles avoid the words in notes 1 and 2,
// so a search for either of those still returns exactly one hit.
const entitlementsNote = `Meeting notes - 2026-09-14

Attendees: dana@example.com and the platform group.

Entitlements. The team agreed that every entitlement is granted to a named agent, never to a whole team. An entitlement lists the tools an agent may call and nothing else. Dana raised that a broad entitlement is hard to review, so the group decided each one stays narrow and is reviewed when it is issued.

Revocation. Revoking an entitlement takes effect on the next run. A run already in flight keeps the entitlement it started with. The group noted that the ledger records the entitlement in force for each run, so a later audit can see exactly what was allowed at the time.

Action items. Dana will draft the entitlement review checklist. The platform group will add a test that an agent without an entitlement is refused.`

const tokenNote = `Meeting notes - 2026-09-21

Attendees: dana@example.com and the security group.

JWT handling. The group agreed that a JWT is only ever accepted after its signature, issuer and expiry are verified. A token that fails any check is rejected and the rejection is logged. Dana pointed out that clock skew should be bounded to a few seconds, and the group settled on thirty.

Token lifetime. Access tokens stay short-lived and are refreshed rather than extended. Refresh tokens are stored only on the host and are never passed into an agent compartment. The group noted that a leaked refresh token is the larger risk, so rotation happens on every use.

Action items. Dana will write up the token rotation rule. The security group will add a negative test for an expired JWT.`

const offsiteNote = `Meeting notes - 2026-09-28

Attendees: dana@example.com and the events volunteers.

Catering. The group compared two caterers for the autumn offsite and preferred the one with vegetarian lunch options and a flat per-head price. Coffee and fruit will be available all day. Dana will confirm the headcount a week before.

Venue. The hall holds forty people with a projector and a quiet breakout room. Parking is limited, so the group suggested a shared shuttle from the station. Name tags and a printed schedule will be at the door.

Action items. Dana will book the caterer. The volunteers will arrange the shuttle and the signage.`

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
