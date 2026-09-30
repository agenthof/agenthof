package rungateway

import (
	"context"
	"encoding/json"
	"io"
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
)

// SpawnResult is what a Spawner reports back for one child run. Status is
// the child's outcome — succeeded, failed, or refused — and ChildRunID
// names the child's own ledger whenever one was written (a refused child
// still has one). OutputSHA and OutputPreview are the child's final
// artifact as the ledger carries it: a hash and a capped preview, never the
// body. Reason is Agenthof's own text for a refused child; the door caps it
// before recording.
type SpawnResult struct {
	ChildRunID    string
	Status        string
	Reason        string
	OutputSHA     string
	OutputPreview string
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

// spawnHandler is the spawn door: POST /spawn {role, workflow, input}. It
// authorizes the target against the agent's may_spawn list, reserves a slot
// under the run's caps in one step under mu, runs the child through the
// Spawner under a context derived from the step's (stepCtx) that is also
// cancelled when the agent hangs up, and records one spawn event on the
// parent's ledger once the child is over. The whole call runs under the
// proxy's closing/inflight bookkeeping, like the first-hand exec door: Stop
// waits for it and for its append, so the append is unguarded (guardedAppend
// would drop an event once closing is set, and a spawn Stop is waiting on
// must still be recorded). A request that arrives once the proxy is already
// closing is answered 503 and NOT recorded: the step is over and the run's
// ledger may already be closed, so an append there would race log.Close.
// That is the one deliberately unrecorded refusal.
func (p *Gateway) spawnHandler(stepCtx context.Context, bind engine.Binding, agent config.AgentDef, appendEvent func(engine.Event), logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req spawnRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		// Drain to EOF: only then does the server watch the connection, so a
		// closed one — Stop cutting it, or the agent gone — cancels r.Context()
		// and with it the child.
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
		p.mu.Lock()
		if p.closing {
			p.mu.Unlock()
			http.Error(w, "gateway is shutting down", http.StatusServiceUnavailable)
			return
		}
		p.inflight.Add(1)
		p.mu.Unlock()
		defer p.inflight.Done()

		// The role and workflow are agent-supplied: capped before they enter
		// the ledger or a log line, and matched exactly against config.
		childRole, childWorkflow := capRunes(req.Role, 200), capRunes(req.Workflow, 200)
		depth := bind.Depth + 1
		answer := func(code int, resp spawnResponse) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(resp)
		}
		refuse := func(reason string) {
			logger.Warn("spawn refused", "child_role", childRole, "child_workflow", childWorkflow, "reason", reason)
			appendEvent(engine.Event{Type: "spawn", Agent: agent.Name, Status: "refused", Reason: reason,
				ChildRole: childRole, ChildWorkflow: childWorkflow, Depth: depth, Binding: bind})
			answer(http.StatusForbidden, spawnResponse{Status: "refused", Reason: reason})
		}
		if p.spawner == nil {
			refuse(reasonSpawnUnavailable)
			return
		}
		if !agent.MaySpawnTarget(req.Role, req.Workflow) {
			refuse(reasonSpawnNotAllowed)
			return
		}
		// Check-and-reserve is one step under mu, so N concurrent requests
		// cannot each see room for one more. A refused attempt reserves
		// nothing and so never counts; a child that starts counts toward
		// max_total_spawns whatever its outcome — it has a ledger of its own.
		p.mu.Lock()
		switch {
		case depth > p.gwcfg.Spawn.MaxDepth:
			p.mu.Unlock()
			refuse(reasonSpawnDepth)
			return
		case p.spawnInflight >= p.gwcfg.Spawn.MaxParallel:
			p.mu.Unlock()
			refuse(reasonSpawnParallel)
			return
		case p.spawnTotal >= p.gwcfg.Spawn.MaxTotalSpawns:
			p.mu.Unlock()
			refuse(reasonSpawnTotal)
			return
		}
		p.spawnInflight++
		p.spawnTotal++
		p.mu.Unlock()
		defer func() {
			p.mu.Lock()
			p.spawnInflight--
			p.mu.Unlock()
		}()

		// The child runs under the parent step's context — the step's
		// deadline or cancel tears the child down with it — and is cancelled
		// too when the agent that asked hangs up.
		ctx, cancel := context.WithCancel(stepCtx)
		defer cancel()
		stop := context.AfterFunc(r.Context(), cancel)
		defer stop()

		logger.Info("spawn started", "child_role", childRole, "child_workflow", childWorkflow, "depth", depth)
		res, err := p.spawner.Spawn(ctx, req.Role, req.Workflow, req.Input, bind)
		if err != nil {
			// The error can carry a path or whatever an adapter said; the
			// ledger gets a fixed reason and the log an error class.
			logger.Error("spawn did not complete", "child_run", res.ChildRunID, "class", errClass(err))
			appendEvent(engine.Event{Type: "spawn", Agent: agent.Name, Status: "failed", Reason: reasonSpawnIncomplete,
				ChildRunID: res.ChildRunID, ChildRole: childRole, ChildWorkflow: childWorkflow, Depth: depth, Binding: bind})
			http.Error(w, reasonSpawnIncomplete, http.StatusBadGateway)
			return
		}
		status := res.Status
		switch status {
		case "succeeded", "failed", "refused":
		default:
			// A Spawner that reports a status the ledger does not know has
			// broken its contract: recorded as failed, never as anything
			// that could read as success.
			logger.Error("spawn reported an unknown status", "child_run", res.ChildRunID, "status", capRunes(status, 40))
			status = "failed"
		}
		reason := capRunes(res.Reason, 200)
		logger.Info("spawn finished", "child_run", res.ChildRunID, "status", status)
		appendEvent(engine.Event{Type: "spawn", Agent: agent.Name, Status: status, Reason: reason,
			ChildRunID: res.ChildRunID, ChildRole: childRole, ChildWorkflow: childWorkflow, Depth: depth,
			OutputSHA: res.OutputSHA, Binding: bind})
		code := http.StatusOK
		if status == "refused" {
			code = http.StatusForbidden
		}
		answer(code, spawnResponse{Status: status, ChildRunID: res.ChildRunID,
			OutputSHA: res.OutputSHA, OutputPreview: res.OutputPreview, Reason: reason})
	}
}
