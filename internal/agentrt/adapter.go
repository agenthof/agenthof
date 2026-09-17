package agentrt

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/engine"
)

// defaultAdapterTimeout is used when AdapterExecutor.Timeout is zero.
const defaultAdapterTimeout = 60 * time.Second

// maxAdapterResponseBytes caps how much of a fronted agent's response body
// Execute will read. The adapter is a trust boundary: a misbehaving or
// compromised fronted agent must not be able to exhaust platform memory by
// returning an unbounded response body.
const maxAdapterResponseBytes = 1 << 20 // 1 MiB

// AdapterExecutor runs a config.AgentDef as a "fronted" agent: it POSTs the
// step input to the agent's HTTP endpoint and maps the adapter's JSON
// response onto a StepResult. It implements engine.StepExecutor.
//
// Known limitation (deferred to V2): the engine.StepExecutor interface does
// not give executors the engine.Binding for the current run, so the
// adapter cannot forward binding/identity headers (invoker, role, workflow,
// run ID) to the fronted agent over HTTP. The ledger still records the
// binding for every step regardless; only the outbound request to the
// fronted agent lacks it. Forwarding it requires widening StepExecutor to
// carry the Binding.
type AdapterExecutor struct {
	// Timeout bounds the whole request/response round trip. Zero means
	// defaultAdapterTimeout.
	Timeout time.Duration
}

// adapterRequest is the JSON body POSTed to the fronted agent's endpoint.
type adapterRequest struct {
	Input     string            `json:"input"`
	Artifacts map[string]string `json:"artifacts"`
	Agent     string            `json:"agent"`
}

// adapterResponse is the JSON body expected back from the fronted agent's
// endpoint on a 200 response.
type adapterResponse struct {
	Artifact string `json:"artifact"`
	Success  bool   `json:"success"`
	Reason   string `json:"reason"`
}

// Execute POSTs {"input", "artifacts", "agent"} as JSON to a.Endpoint, with
// header X-Agenthof-Agent set to a.Name. A 200 response is decoded and
// mapped verbatim onto StepResult. A non-200 response, a transport error, a
// timeout, or a response body over maxAdapterResponseBytes is reported as a
// failed step (Success: false) with a nil error, since those reflect the
// fronted agent's own availability or behavior, not a problem with the
// engine driving it. An empty endpoint — which validation should already
// have rejected — is a configuration error wrapping engine.ErrStepConfig.
func (x AdapterExecutor) Execute(ctx context.Context, a config.AgentDef, input string, artifacts map[string]string) (engine.StepResult, error) {
	if a.Endpoint == "" {
		return engine.StepResult{}, fmt.Errorf("agent %q has no endpoint: %w", a.Name, engine.ErrStepConfig)
	}

	timeout := x.Timeout
	if timeout == 0 {
		timeout = defaultAdapterTimeout
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	reqBody, err := json.Marshal(adapterRequest{Input: input, Artifacts: artifacts, Agent: a.Name})
	if err != nil {
		return engine.StepResult{}, fmt.Errorf("marshal adapter request: %w", err)
	}

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, a.Endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return engine.StepResult{Success: false, Reason: err.Error()}, nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agenthof-Agent", a.Name)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return engine.StepResult{Success: false, Reason: err.Error()}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return engine.StepResult{Success: false, Reason: fmt.Sprintf("adapter returned %d", resp.StatusCode)}, nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAdapterResponseBytes+1))
	if err != nil {
		return engine.StepResult{Success: false, Reason: err.Error()}, nil
	}
	if len(body) > maxAdapterResponseBytes {
		return engine.StepResult{Success: false, Reason: "adapter response exceeds 1 MiB limit"}, nil
	}
	var out adapterResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return engine.StepResult{Success: false, Reason: err.Error()}, nil
	}

	return engine.StepResult{Success: out.Success, Artifact: out.Artifact, Reason: out.Reason}, nil
}
