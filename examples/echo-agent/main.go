// Command echo-agent is a minimal reference fronted agent: it implements
// Agenthof's fronted-agent HTTP contract and echoes each step's input back as
// the artifact. It holds no credentials and keeps no state — a starting point
// for writing a conforming agent, and what the quickstart/demo run against.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
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

func newMux(callGateway bool) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleStep(w, r, callGateway)
	})
	return mux
}

func handleStep(w http.ResponseWriter, r *http.Request, callGateway bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req request
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if callGateway {
		if err := probeGateway(r.Header.Get("X-Agenthof-Proxy-URL"), r.Header.Get("X-Agenthof-Run-Token")); err != nil {
			_ = json.NewEncoder(w).Encode(response{Success: false, Reason: "gateway unreachable: " + err.Error()})
			return
		}
	}
	_ = json.NewEncoder(w).Encode(response{Artifact: req.Input, Success: true})
}

// probeGateway confirms the Agenthof gateway is reachable over the socket named
// by proxyURL, by POSTing to /exec/authorize with the run token. A 200 (any
// allowed value) means the socket path works end to end.
func probeGateway(proxyURL, token string) error {
	if proxyURL == "" {
		return fmt.Errorf("no proxy URL")
	}
	var client *http.Client
	var route string
	if p, ok := strings.CutPrefix(proxyURL, "unix://"); ok {
		client = &http.Client{Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", p)
			},
		}}
		route = "http://agenthof/exec/authorize"
	} else {
		client = http.DefaultClient
		route = strings.TrimRight(proxyURL, "/") + "/exec/authorize"
	}
	body := bytes.NewReader([]byte(`{"command":["true"]}`))
	rq, err := http.NewRequest(http.MethodPost, route, body)
	if err != nil {
		return err
	}
	rq.Header.Set("Content-Type", "application/json")
	rq.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(rq)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gateway returned %d", resp.StatusCode)
	}
	return nil
}

// listenUnix listens on a Unix socket, removing any stale file first
// (net.Listen fails if a path already exists). The listener unlinks on Close.
func listenUnix(path string) (net.Listener, error) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return net.Listen("unix", path)
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "TCP listen address (ignored when -socket is set)")
	socket := flag.String("socket", "", "Unix socket path to listen on; overrides -addr")
	callGateway := flag.Bool("call-gateway", false, "probe the Agenthof gateway (X-Agenthof-Proxy-URL) on each step")
	flag.Parse()

	srv := &http.Server{Handler: newMux(*callGateway)}
	var ln net.Listener
	var err error
	if *socket != "" {
		ln, err = listenUnix(*socket)
		log.Printf("echo-agent listening on unix:%s", *socket)
	} else {
		ln, err = net.Listen("tcp", *addr)
		log.Printf("echo-agent listening on %s", *addr)
	}
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(srv.Serve(ln))
}
