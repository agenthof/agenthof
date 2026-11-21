// Command memory-agent is an optional fronted agent that exercises Agenthof's
// tool door against the memory-store server. Each step's input is a JSON
// script — {"upserts":[...],"searches":[...]} — that it runs against the
// per-run gateway named in X-Agenthof-Proxy-URL as ONE MCP session per step,
// presenting only the run token: every upsert (memory_upsert), then every
// search (memory_search). The artifact is one line per operation —
// "upserted <id>" and "hit <id> <score>" — so it is deterministic. It holds
// no credential and never sees the store's.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// stepTimeout is below the engine's 5-minute step budget so this agent
// reports a failed step itself rather than the adapter timing out on it.
const stepTimeout = 240 * time.Second

// The fixed failure reasons. A reason never carries the proxy URL, a tool's
// error text or an upstream body: the operator's log gets the detail.
const (
	reasonNoProxy    = "tool proxy coordinates missing"
	reasonBadScript  = "bad script"
	reasonCallFailed = "memory call failed"
)

type request struct {
	Input     string            `json:"input"`
	Artifacts map[string]string `json:"artifacts"`
	Agent     string            `json:"agent"`
}

type response struct {
	Artifact string `json:"artifact"`
	Success  bool   `json:"success"`
	Reason   string `json:"reason,omitempty"`
}

type upsertOp struct {
	Collection string          `json:"collection"`
	Text       string          `json:"text"`
	Vector     []float64       `json:"vector"`
	Metadata   json.RawMessage `json:"metadata"`
	ID         string          `json:"id"`
}

type searchOp struct {
	Collection string    `json:"collection"`
	Vector     []float64 `json:"vector"`
	K          int       `json:"k"`
}

type script struct {
	Upserts  []upsertOp `json:"upserts"`
	Searches []searchOp `json:"searches"`
}

func parseScript(input string) (script, error) {
	var s script
	dec := json.NewDecoder(strings.NewReader(input))
	if err := dec.Decode(&s); err != nil {
		return script{}, errors.New("input is not a JSON script")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return script{}, errors.New("trailing data after the script")
	}
	if len(s.Upserts)+len(s.Searches) == 0 {
		return script{}, errors.New("empty script")
	}
	return s, nil
}

// bearerTransport presents the run token on every request to the gateway.
type bearerTransport struct {
	base  http.RoundTripper
	token string
}

func (t *bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(req)
}

// CloseIdleConnections lets http.Client.CloseIdleConnections reach the base
// transport; without it the client's call stops at this wrapper.
func (t *bearerTransport) CloseIdleConnections() {
	if c, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

// gatewayClient returns the HTTP client and MCP endpoint for the proxy URL:
// for unix://<path> a transport that dials that socket and the placeholder
// endpoint http://agenthof/ (the route is the gateway's root either way).
func gatewayClient(proxyURL, runToken string) (*http.Client, string) {
	base := http.RoundTripper(http.DefaultTransport)
	endpoint := proxyURL
	if path, ok := strings.CutPrefix(proxyURL, "unix://"); ok {
		base = &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		}}
		endpoint = "http://agenthof/"
	}
	return &http.Client{Transport: &bearerTransport{base: base, token: runToken}}, endpoint
}

type upsertResult struct {
	ID string `json:"id"`
}

type searchResult struct {
	Results []struct {
		ID    string  `json:"id"`
		Score float64 `json:"score"`
	} `json:"results"`
}

// decodeStructured reads a tool result's structured content into out. The
// memory-store returns its result there, not as text Content.
func decodeStructured(res *mcp.CallToolResult, out any) error {
	if res.StructuredContent == nil {
		return errors.New("tool result has no structured content")
	}
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

func call(ctx context.Context, sess *mcp.ClientSession, tool string, args map[string]any, out any) error {
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		return err
	}
	if res.IsError {
		var parts []string
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				parts = append(parts, tc.Text)
			}
		}
		return fmt.Errorf("tool %s returned an error: %s", tool, strings.Join(parts, " "))
	}
	return decodeStructured(res, out)
}

// runScript opens one MCP session to the gateway for the whole script.
func runScript(ctx context.Context, proxyURL, runToken string, s script) (string, error) {
	httpClient, endpoint := gatewayClient(proxyURL, runToken)
	defer httpClient.CloseIdleConnections()
	client := mcp.NewClient(&mcp.Implementation{Name: "memory-agent", Version: "v0.1.0"}, nil)
	sess, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: endpoint, HTTPClient: httpClient}, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = sess.Close() }()
	var lines []string
	for _, u := range s.Upserts {
		meta := u.Metadata
		if len(bytes.TrimSpace(meta)) == 0 {
			meta = json.RawMessage(`{}`)
		}
		args := map[string]any{"collection": u.Collection, "text": u.Text, "vector": u.Vector, "metadata": meta}
		if u.ID != "" {
			args["id"] = u.ID
		}
		var r upsertResult
		if err := call(ctx, sess, "memory_upsert", args, &r); err != nil {
			return "", err
		}
		lines = append(lines, "upserted "+r.ID)
	}
	for _, q := range s.Searches {
		args := map[string]any{"collection": q.Collection, "vector": q.Vector, "k": q.K}
		var r searchResult
		if err := call(ctx, sess, "memory_search", args, &r); err != nil {
			return "", err
		}
		for _, h := range r.Results {
			lines = append(lines, fmt.Sprintf("hit %s %.4f", h.ID, h.Score))
		}
	}
	return strings.Join(lines, "\n"), nil
}

func writeJSON(w http.ResponseWriter, out response) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func handleStep(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req request
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	proxyURL := r.Header.Get("X-Agenthof-Proxy-URL")
	runToken := r.Header.Get("X-Agenthof-Run-Token")
	if proxyURL == "" || runToken == "" {
		writeJSON(w, response{Success: false, Reason: reasonNoProxy})
		return
	}
	s, err := parseScript(req.Input)
	if err != nil {
		log.Printf("memory-agent: bad script: %v", err)
		writeJSON(w, response{Success: false, Reason: reasonBadScript})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), stepTimeout)
	defer cancel()
	artifact, err := runScript(ctx, proxyURL, runToken, s)
	if err != nil {
		log.Printf("memory-agent: call failed: %v", err)
		writeJSON(w, response{Success: false, Reason: reasonCallFailed})
		return
	}
	writeJSON(w, response{Artifact: artifact, Success: true})
}

func newMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleStep)
	return mux
}

// listenUnix listens on a Unix socket, removing any stale file first.
func listenUnix(path string) (net.Listener, error) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return net.Listen("unix", path)
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8084", "TCP listen address (ignored when -socket is set)")
	socket := flag.String("socket", "", "Unix socket path to listen on; overrides -addr")
	flag.Parse()
	srv := &http.Server{Handler: newMux()}
	var ln net.Listener
	var err error
	if *socket != "" {
		ln, err = listenUnix(*socket)
		log.Printf("memory-agent listening on unix:%s", *socket)
	} else {
		ln, err = net.Listen("tcp", *addr)
		log.Printf("memory-agent listening on %s", *addr)
	}
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(srv.Serve(ln))
}
