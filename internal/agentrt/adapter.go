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

// maxAdapterReasonChars caps the length of an endpoint-supplied reason
// string (the success:false path) before it's stored on StepResult. The
// adapter is a trust boundary: a misbehaving or compromised fronted agent
// must not be able to bloat the ledger/audit output with an unbounded
// reason string.
const maxAdapterReasonChars = 300

// adapterClient is used for all outbound requests to fronted agents. It
// must not follow redirects: a fronted agent is an untrusted trust
// boundary, and following a 3xx Location it names would let it redirect
// the platform's outbound request to an arbitrary third party. This is a
// dedicated client rather than a mutation of http.DefaultClient, since
// OIDC discovery elsewhere in the platform relies on DefaultClient's
// normal (redirect-following) behavior.
var adapterClient = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// AdapterExecutor runs a config.AgentDef as a "fronted" agent: it POSTs the
// step input to the agent's HTTP endpoint and maps the adapter's JSON
// response onto a StepResult. It implements engine.StepExecutor.
//
// It forwards the run's delegation binding (invoker, role, workflow, run ID)
// to the agent as X-Agenthof-* headers. This is attested, not enforced: a
// non-conforming agent can ignore the headers.
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

// Reserved for later (additive, not implemented here): a signed
// binding header (X-Agenthof-Binding-Signature) for authenticity, and a
// run_id echo field on the response for attestability.

// adapterResponse is the JSON body expected back from the fronted agent's
// endpoint on a 200 response.
type adapterResponse struct {
	Artifact string `json:"artifact"`
	Success  bool   `json:"success"`
	Reason   string `json:"reason"`
}

// Execute POSTs {"input", "artifacts", "agent"} as JSON to a.Endpoint, with
// the X-Agenthof-Agent header and the X-Agenthof-* identity headers (invoker,
// issuer, method, role, workflow, run id), using a client that does not follow
// redirects (a fronted agent is a trust boundary; a 3xx is reported as a
// failed step like any other non-200). A 200 response is decoded and mapped
// onto StepResult, except that an endpoint-supplied failure reason
// (success:false) is capped at maxAdapterReasonChars. A non-200 response, a
// transport error, a timeout, or a response body over maxAdapterResponseBytes
// is reported as a failed step (Success: false) with a nil error, since those
// reflect the fronted agent's own availability or behavior, not a problem
// with the engine driving it. An empty endpoint — which validation should
// already have rejected — is a configuration error wrapping
// engine.ErrStepConfig.
func (x AdapterExecutor) Execute(ctx context.Context, binding engine.Binding, a config.AgentDef, input string, artifacts map[string]string) (engine.StepResult, error) {
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
	// Forward the delegation binding as the identity envelope for this gateway
	// call (Article II). Attested, not enforced: a non-conforming agent can
	// ignore these; Agenthof records the call as fronted regardless.
	req.Header.Set("X-Agenthof-Invoker", binding.Invoker.Subject)
	req.Header.Set("X-Agenthof-Invoker-Issuer", binding.Invoker.Issuer)
	req.Header.Set("X-Agenthof-Invoker-Method", binding.Invoker.Method)
	req.Header.Set("X-Agenthof-Role", binding.Role)
	req.Header.Set("X-Agenthof-Workflow", binding.Workflow)
	req.Header.Set("X-Agenthof-Run-Id", binding.RunID)

	resp, err := adapterClient.Do(req)
	if err != nil {
		return engine.StepResult{Success: false, Reason: err.Error()}, nil
	}
	defer func() { _ = resp.Body.Close() }()

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

	reason := out.Reason
	if !out.Success && len(reason) > maxAdapterReasonChars {
		reason = reason[:maxAdapterReasonChars] + "… (truncated)"
	}

	return engine.StepResult{Success: out.Success, Artifact: out.Artifact, Reason: reason}, nil
}
