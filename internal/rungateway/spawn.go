package rungateway

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/engine"
)

// The spawn door's ledger reasons are fixed strings, so no path can put the
// agent's text into an event.
const (
	reasonSpawnUnavailable = "spawn is not available to this run"
	reasonSpawnNotAllowed  = "spawn target is not on the agent's may_spawn list"
	reasonSpawnDepth       = "spawn would exceed max_depth"
	reasonSpawnParallel    = "spawn would exceed max_parallel"
	reasonSpawnTotal       = "spawn would exceed max_total_spawns"
	reasonSpawnIncomplete  = "spawn did not complete"

	reasonSpawnRequestMalformed = "spawn request malformed"
)

// SpawnResult is what a Spawner reports back for one child run. Status is
// the child's outcome — succeeded, failed, or refused — and ChildRunID
// names the child's own ledger whenever one was written (a refused child
// still has one). OutputSHA and OutputPreview are the child's final
// artifact as the ledger carries it: a hash and a capped preview, never the
// body. Reason is Agenthof's own text for a refused child; the door caps it
// before recording. Provisioned reports whether a compartment set was
// consumed for this child: it is what max_total_spawns counts. A child
// refused before provisioning (the pre-run gate), a provision that failed,
// or an internal failure before provisioning gives its slot back; a
// provisioned child counts whatever happened next, even a registry refusal.
// ChildConfiner and ChildConfinerOpts are the isolation tier the child's
// runtime applied and any loosenings of it, as the supervisor named them
// ("" when none was reported); they ride on the parent's spawn event.
type SpawnResult struct {
	ChildRunID        string
	Status            string
	Reason            string
	OutputSHA         string
	OutputPreview     string
	Provisioned       bool
	ChildConfiner     string
	ChildConfinerOpts []string
	// ChildArtifact is, per child agent, the artifact its compartment was
	// measured to run (nil when none was measured); it rides on the parent's
	// spawn event of a provisioned child, whatever its outcome.
	ChildArtifact map[string]engine.ChildArtifactRef
}

// Spawner runs one governed child run on the door's behalf and returns when
// it is over. It is the seam a durable executor would later implement; the
// in-process implementation lives with the CLI, the one place that holds
// the registry and the executor. parent is the spawning run's binding: the
// child inherits its Invoker unchanged and links to its RunID. ctx is
// derived from the parent step's context, so cancelling the parent step
// cancels the child. A non-nil error is an internal failure only (a ledger
// that could not be written); a child that ran and failed, or was refused,
// is a result.
type Spawner interface {
	Spawn(ctx context.Context, childRole, childWorkflow, input string, parent engine.Binding) (SpawnResult, error)
}

// WithSpawner gives the gateway its Spawner and returns the gateway. Call it
// before the first Start. Without one, /spawn refuses every request with a
// recorded, fixed reason — a run with no Spawner can start no child.
func (p *Gateway) WithSpawner(s Spawner) *Gateway {
	p.spawner = s
	return p
}

// spawnRequest is the door's wire body.
type spawnRequest struct {
	Role     string `json:"role"`
	Workflow string `json:"workflow"`
	Input    string `json:"input"`
}

// spawnResponse is the door's wire answer: the child's outcome as the
// ledger records it. The child's artifact body never crosses back.
type spawnResponse struct {
	Status        string `json:"status"`
	ChildRunID    string `json:"child_run_id,omitempty"`
	OutputSHA     string `json:"output_sha,omitempty"`
	OutputPreview string `json:"output_preview,omitempty"`
	Reason        string `json:"reason,omitempty"`
}

// errSpawnIncomplete marks the internal-failure path of authorizeAndSpawn: the
// Spawner returned an error, and the ledger already carries the fixed-reason
// failed event.
var errSpawnIncomplete = errors.New(reasonSpawnIncomplete)

// authorizeAndSpawn is the spawn gate, independent of any transport. It
// authorizes the target against the agent's may_spawn list, reserves a slot
// under the run's caps in one step under mu, runs the child through the
// Spawner under ctx, gives the max_total_spawns reservation back unless a
// compartment set was consumed, and records exactly one spawn event on the
// parent's ledger through appendEvent. It returns the outcome: a gate refusal
// is Status "refused" with a fixed Reason; a child's own outcome is returned as
// the Spawner reported it (an unknown status becomes "failed", the reason is
// capped). A non-nil error is the internal-failure path only (errSpawnIncomplete);
// its event is already recorded. The caller must hold whatever keeps the run's
// ledger open (registerDoor's admission hold) across the call, and ctx is the
// context the child runs under.
func (p *Gateway) authorizeAndSpawn(ctx context.Context, bind engine.Binding, agent config.AgentDef, role, workflow, input string, appendEvent func(engine.Event), logger *slog.Logger) (SpawnResult, error) {
	depth := bind.Depth + 1
	// The role and workflow are agent-supplied: capped before they enter
	// the ledger or a log line, and matched exactly against config.
	childRole, childWorkflow := capRunes(role, 200), capRunes(workflow, 200)
	refuse := func(reason string) (SpawnResult, error) {
		logger.Warn("spawn refused", "child_role", childRole, "child_workflow", childWorkflow, "reason", reason)
		appendEvent(engine.Event{Type: "spawn", Agent: agent.Name, Status: "refused", Reason: reason,
			ChildRole: childRole, ChildWorkflow: childWorkflow, Depth: depth, Binding: bind})
		return SpawnResult{Status: "refused", Reason: reason}, nil
	}
	if p.spawner == nil {
		return refuse(reasonSpawnUnavailable)
	}
	if !agent.MaySpawnTarget(role, workflow) {
		return refuse(reasonSpawnNotAllowed)
	}
	// Check-and-reserve is one step under mu, so N concurrent requests
	// cannot each see room for one more. A refused attempt reserves
	// nothing and so never counts; the reservation taken here is given
	// back below unless the Spawner reports that a compartment set was
	// consumed (SpawnResult.Provisioned).
	p.mu.Lock()
	switch {
	case depth > p.gwcfg.Spawn.MaxDepth:
		p.mu.Unlock()
		return refuse(reasonSpawnDepth)
	case p.spawnInflight >= p.gwcfg.Spawn.MaxParallel:
		p.mu.Unlock()
		return refuse(reasonSpawnParallel)
	case p.spawnTotal >= p.gwcfg.Spawn.MaxTotalSpawns:
		p.mu.Unlock()
		return refuse(reasonSpawnTotal)
	}
	p.spawnInflight++
	p.spawnTotal++
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.spawnInflight--
		p.mu.Unlock()
	}()

	logger.Info("spawn started", "child_role", childRole, "child_workflow", childWorkflow, "depth", depth)
	res, err := p.spawner.Spawn(ctx, role, workflow, input, bind)
	if !res.Provisioned {
		// No compartment set was consumed: give the max_total_spawns
		// reservation back, on this path and on the error path alike. The
		// attempt is still recorded below.
		p.mu.Lock()
		p.spawnTotal--
		p.mu.Unlock()
	}
	if err != nil {
		// The error can carry a path or whatever an adapter said; the
		// ledger gets a fixed reason and the log an error class.
		logger.Error("spawn did not complete", "child_run", res.ChildRunID, "class", errClass(err))
		appendEvent(engine.Event{Type: "spawn", Agent: agent.Name, Status: "failed", Reason: reasonSpawnIncomplete,
			ChildRunID: res.ChildRunID, ChildRole: childRole, ChildWorkflow: childWorkflow, Depth: depth, Binding: bind,
			ChildConfiner: res.ChildConfiner, ChildConfinerOpts: res.ChildConfinerOpts, ChildArtifact: res.ChildArtifact})
		return res, errSpawnIncomplete
	}
	switch res.Status {
	case "succeeded", "failed", "refused":
	default:
		// A Spawner that reports a status the ledger does not know has
		// broken its contract: recorded as failed, never as anything
		// that could read as success.
		logger.Error("spawn reported an unknown status", "child_run", res.ChildRunID, "status", capRunes(res.Status, 40))
		res.Status = "failed"
	}
	res.Reason = capRunes(res.Reason, 200)
	logger.Info("spawn finished", "child_run", res.ChildRunID, "status", res.Status)
	appendEvent(engine.Event{Type: "spawn", Agent: agent.Name, Status: res.Status, Reason: res.Reason,
		ChildRunID: res.ChildRunID, ChildRole: childRole, ChildWorkflow: childWorkflow, Depth: depth,
		OutputSHA: res.OutputSHA, Binding: bind,
		ChildConfiner: res.ChildConfiner, ChildConfinerOpts: res.ChildConfinerOpts,
		ChildArtifact: res.ChildArtifact})
	return res, nil
}

// spawnHandler is the spawn door: POST /spawn {role, workflow, input}. It
// decodes the request and runs it through authorizeAndSpawn under a context
// derived from the step's (stepCtx) that is also cancelled when the agent
// hangs up. The whole call runs under the admission hold registerDoor took,
// so Stop waits for it and for its append; a request that arrives once the
// proxy is closing is answered 503 by registerDoor before it is a door call —
// neither counted nor recorded. A body that is a JSON object but not the
// request's shape is a recorded refusal answered 400.
func (p *Gateway) spawnHandler(stepCtx context.Context, bind engine.Binding, agent config.AgentDef, appendEvent func(engine.Event), logger *slog.Logger) doorHandler {
	return func(w http.ResponseWriter, r *http.Request, body []byte) {
		var req spawnRequest
		answer := func(code int, resp spawnResponse) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(resp)
		}
		if err := json.Unmarshal(body, &req); err != nil {
			logger.Warn("spawn refused", "reason", reasonSpawnRequestMalformed)
			appendEvent(engine.Event{Type: "spawn", Agent: agent.Name, Status: "refused", Reason: reasonSpawnRequestMalformed, Depth: bind.Depth + 1, Binding: bind})
			answer(http.StatusBadRequest, spawnResponse{Status: "refused", Reason: reasonSpawnRequestMalformed})
			return
		}
		// The child runs under the parent step's context — the step's
		// deadline or cancel tears the child down with it — and is cancelled
		// too when the agent that asked hangs up.
		ctx, cancel := context.WithCancel(stepCtx)
		defer cancel()
		stop := context.AfterFunc(r.Context(), cancel)
		defer stop()

		res, err := p.authorizeAndSpawn(ctx, bind, agent, req.Role, req.Workflow, req.Input, appendEvent, logger)
		if err != nil {
			http.Error(w, reasonSpawnIncomplete, http.StatusBadGateway)
			return
		}
		code := http.StatusOK
		if res.Status == "refused" {
			code = http.StatusForbidden
		}
		answer(code, spawnResponse{Status: res.Status, ChildRunID: res.ChildRunID,
			OutputSHA: res.OutputSHA, OutputPreview: res.OutputPreview, Reason: res.Reason})
	}
}
