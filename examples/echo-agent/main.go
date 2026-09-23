// Command echo-agent is a minimal reference fronted agent: it implements
// Agenthof's fronted-agent HTTP contract and echoes each step's input back as
// the artifact. It holds no credentials and keeps no state — a starting point
// for writing a conforming agent, and what the quickstart/demo run against.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
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

func handler(w http.ResponseWriter, r *http.Request) {
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
	_ = json.NewEncoder(w).Encode(response{Artifact: req.Input, Success: true})
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	flag.Parse()
	http.HandleFunc("/", handler)
	log.Printf("echo-agent listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
