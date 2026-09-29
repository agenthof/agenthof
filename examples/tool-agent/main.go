// Command tool-agent is an optional fronted agent that exercises Agenthof's
// tool door. Each step's input is a small script — `call <tool> [text]` and
// `sleep <seconds>`, separated by `;` — that it runs against the per-run
// gateway named in X-Agenthof-Proxy-URL as ONE MCP session per step,
// presenting only the run token. The artifact is one line per call: the
// text the tool returned. It holds no credential and never sees the
// resource's. `sleep` exists so a proof can make two calls within one step
// with time between them for a credential to rotate.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// stepTimeout is below the engine's 5-minute step budget so this agent
// reports a failed step itself rather than the adapter timing out on it.
const stepTimeout = 240 * time.Second

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

// command is one script step: a tool call (tool + args) or a pause (sleep).
type command struct {
	tool  string
	args  map[string]any
	sleep time.Duration
}

func parseScript(input string) ([]command, error) {
	var cmds []command
	for _, raw := range strings.Split(input, ";") {
		fields := strings.Fields(raw)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "call":
			if len(fields) < 2 {
				return nil, errors.New("call needs a tool name")
			}
			args := map[string]any{}
			if len(fields) > 2 {
				args["text"] = strings.Join(fields[2:], " ")
			}
			cmds = append(cmds, command{tool: fields[1], args: args})
		case "sleep":
			if len(fields) != 2 {
				return nil, errors.New("sleep needs a number of seconds")
			}
			secs, err := strconv.Atoi(fields[1])
			if err != nil || secs < 0 || secs > 240 {
				return nil, errors.New("sleep seconds must be a whole number from 0 to 240")
			}
			cmds = append(cmds, command{sleep: time.Duration(secs) * time.Second})
		default:
			return nil, fmt.Errorf("unknown command %q (want call or sleep)", fields[0])
		}
	}
	if len(cmds) == 0 {
		return nil, errors.New("empty script")
	}
	return cmds, nil
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

func textOf(res *mcp.CallToolResult) string {
	var parts []string
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			parts = append(parts, tc.Text)
		}
	}
	return strings.Join(parts, " ")
}

// runScript opens one MCP session to the gateway for the whole script.
func runScript(ctx context.Context, proxyURL, runToken string, cmds []command) (string, error) {
	httpClient, endpoint := gatewayClient(proxyURL, runToken)
	defer httpClient.CloseIdleConnections()
	client := mcp.NewClient(&mcp.Implementation{Name: "tool-agent", Version: "v0.1.0"}, nil)
	sess, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: endpoint, HTTPClient: httpClient}, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = sess.Close() }()
	var lines []string
	for _, c := range cmds {
		if c.tool == "" {
			select {
			case <-time.After(c.sleep):
			case <-ctx.Done():
				return "", ctx.Err()
			}
			continue
		}
		res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: c.tool, Arguments: c.args})
		if err != nil {
			return "", err
		}
		text := textOf(res)
		if res.IsError {
			return "", fmt.Errorf("tool %s returned an error: %s", c.tool, text)
		}
		lines = append(lines, text)
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
		writeJSON(w, response{Success: false, Reason: "tool proxy coordinates missing"})
		return
	}
	cmds, err := parseScript(req.Input)
	if err != nil {
		writeJSON(w, response{Success: false, Reason: "bad script: " + err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), stepTimeout)
	defer cancel()
	artifact, err := runScript(ctx, proxyURL, runToken, cmds)
	if err != nil {
		// The reason is fixed: the error can carry the proxy URL or an
		// upstream error body, neither of which belongs in a ledger. The
		// operator's log gets the detail.
		log.Printf("tool-agent: tool call failed: %v", err)
		writeJSON(w, response{Success: false, Reason: "tool call failed"})
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
	addr := flag.String("addr", "127.0.0.1:8083", "TCP listen address (ignored when -socket is set)")
	socket := flag.String("socket", "", "Unix socket path to listen on; overrides -addr")
	flag.Parse()
	srv := &http.Server{Handler: newMux()}
	var ln net.Listener
	var err error
	if *socket != "" {
		ln, err = listenUnix(*socket)
		log.Printf("tool-agent listening on unix:%s", *socket)
	} else {
		ln, err = net.Listen("tcp", *addr)
		log.Printf("tool-agent listening on %s", *addr)
	}
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(srv.Serve(ln))
}
