// Command model-agent is an optional fronted agent that makes one model call
// through Agenthof's model gateway. It reads the per-run proxy URL and run
// token from the request headers, sends the step input as a chat completion,
// and returns the reply text as its artifact. It holds no provider key.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

type stepRequest struct {
	Input string `json:"input"`
	Agent string `json:"agent"`
}

type stepResponse struct {
	Artifact string `json:"artifact"`
	Success  bool   `json:"success"`
	Reason   string `json:"reason,omitempty"`
}

type handler struct {
	model  string
	client *http.Client
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var step stepRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&step); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	proxyURL := r.Header.Get("X-Agenthof-Proxy-URL")
	runToken := r.Header.Get("X-Agenthof-Run-Token")
	if proxyURL == "" || runToken == "" {
		writeJSON(w, stepResponse{Success: false, Reason: "model proxy coordinates missing"})
		return
	}

	payload, err := json.Marshal(map[string]any{
		"model": h.model,
		"messages": []map[string]string{
			{"role": "user", "content": step.Input},
		},
	})
	if err != nil {
		writeJSON(w, stepResponse{Success: false, Reason: "could not build model request"})
		return
	}
	endpoint := strings.TrimRight(proxyURL, "/") + "/v1/chat/completions"
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		writeJSON(w, stepResponse{Success: false, Reason: "could not build model request"})
		return
	}
	req.Header.Set("Authorization", "Bearer "+runToken)
	req.Header.Set("Content-Type", "application/json")

	client := h.client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		writeJSON(w, stepResponse{Success: false, Reason: "model proxy request failed"})
		return
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		writeJSON(w, stepResponse{Success: false, Reason: "model proxy response unreadable"})
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		writeJSON(w, stepResponse{Success: false, Reason: "model proxy returned " + resp.Status})
		return
	}
	var parsed struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil || len(parsed.Choices) == 0 {
		writeJSON(w, stepResponse{Success: false, Reason: "model proxy response had no reply"})
		return
	}
	writeJSON(w, stepResponse{Artifact: parsed.Choices[0].Message.Content, Success: true})
}

func writeJSON(w http.ResponseWriter, resp stepResponse) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8081", "listen address")
	model := flag.String("model", "fast", "logical model name declared for this agent")
	flag.Parse()
	h := &handler{model: *model, client: &http.Client{Timeout: 5 * time.Minute}}
	http.Handle("/", h)
	log.Printf("model-agent listening on %s, logical model %s", *addr, *model)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
