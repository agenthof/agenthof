// Command memory-store is a reference MCP server exposing a governed vector
// memory over stdio: memory_upsert stores a text chunk with its embedding and
// metadata, memory_search returns the nearest stored chunks. Storage is either
// an embedded file-backed index or a Qdrant instance.
//
// Diagnostics go to stderr; stdout carries only the MCP stream.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// newServer builds the MCP server with both tools registered.
func newServer(be Backend, limits Limits) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "memory-store", Version: "v0.1.0"}, nil)
	registerTools(server, be, limits)
	return server
}

// flagError marks an error the flag package has already reported on stderr.
type flagError struct{ error }

func (e flagError) Unwrap() error { return e.error }

type config struct {
	backend     Backend
	backendName string
	limits      Limits
}

// parseCollections turns a comma-separated list into an allowlist. Empty input
// yields nil (allow any); a malformed element is an error.
func parseCollections(csv string) (map[string]struct{}, error) {
	// Only the exact empty string means "allow any": a whitespace-only value
	// is an entry that fails the name check, so a malformed flag fails closed.
	if csv == "" {
		return nil, nil
	}
	out := map[string]struct{}{}
	for _, c := range strings.Split(csv, ",") {
		c = strings.TrimSpace(c)
		if !collectionRe.MatchString(c) {
			return nil, errors.New("-collections: each entry must match [A-Za-z0-9_-]{1,64}")
		}
		out[c] = struct{}{}
	}
	return out, nil
}

// buildBackend selects the backend named by the flags. Qdrant authentication
// comes only from qdrantAuth; no other credential is ever passed upstream.
func buildBackend(name, storeFile, qdrantURL, qdrantAuth string, maxEntries int) (Backend, error) {
	switch name {
	case "embedded":
		if strings.TrimSpace(storeFile) == "" {
			return nil, errors.New("-store-file must not be empty for the embedded backend")
		}
		if maxEntries < 1 {
			return nil, errors.New("-max-entries must be at least 1")
		}
		return newEmbeddedBackend(storeFile, maxEntries), nil
	case "qdrant":
		return newQdrantBackend(qdrantURL, qdrantAuth)
	default:
		return nil, errors.New("-backend must be embedded or qdrant")
	}
}

func parseConfig(args []string, stderr io.Writer) (*config, error) {
	fs := flag.NewFlagSet("memory-store", flag.ContinueOnError)
	fs.SetOutput(stderr)
	backend := fs.String("backend", "embedded", "storage backend: embedded or qdrant")
	storeFile := fs.String("store-file", "memory-store.json", "embedded backend: path of the store file")
	qdrantURL := fs.String("qdrant-url", "", "qdrant backend: base URL of the Qdrant REST API")
	qdrantAuth := fs.String("qdrant-auth", "", "qdrant backend: name of the environment variable holding the Qdrant API key (empty: none)")
	collections := fs.String("collections", "", "comma-separated allowlist of collection names (empty: any)")
	// The placeholder bearer is consumed by the bridge in front of this
	// server; the server itself never uses it, least of all for Qdrant.
	_ = fs.String("credential-env", "", "name of the environment variable carrying the caller's placeholder bearer; not used for Qdrant auth")
	maxEntries := fs.Int("max-entries", embeddedMaxEntries, "embedded backend: maximum records across all collections")
	if err := fs.Parse(args); err != nil {
		return nil, flagError{err}
	}
	// flag stops at the first non-flag token; any flag after it would be
	// silently dropped, including -collections, so refuse the whole line.
	if fs.NArg() != 0 {
		return nil, fmt.Errorf("unexpected positional arguments (%d); all options are flags", fs.NArg())
	}
	allow, err := parseCollections(*collections)
	if err != nil {
		return nil, err
	}
	be, err := buildBackend(*backend, *storeFile, *qdrantURL, *qdrantAuth, *maxEntries)
	if err != nil {
		return nil, err
	}
	limits := DefaultLimits
	limits.Collections = allow
	return &config{backend: be, backendName: *backend, limits: limits}, nil
}

// banner writes the startup diagnostic. It names no credential.
func banner(w io.Writer, c *config) {
	scope := "any collection"
	if n := len(c.limits.Collections); n > 0 {
		scope = fmt.Sprintf("%d allowed collection(s)", n)
	}
	_, _ = fmt.Fprintf(w, "memory-store: serving on stdio (backend=%s, %s)\n", c.backendName, scope)
}

func main() {
	cfg, err := parseConfig(os.Args[1:], os.Stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		var fe flagError
		if !errors.As(err, &fe) {
			_, _ = fmt.Fprintln(os.Stderr, "memory-store:", err)
		}
		os.Exit(2)
	}
	banner(os.Stderr, cfg)
	if err := newServer(cfg.backend, cfg.limits).Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "memory-store: server stopped:", err)
		os.Exit(1)
	}
}
