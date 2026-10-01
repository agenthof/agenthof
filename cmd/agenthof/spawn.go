package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/agenthof/agenthof/internal/agentrt"
	"github.com/agenthof/agenthof/internal/broker"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/registry"
	"github.com/agenthof/agenthof/internal/rungateway"
)

// runDeps is everything one `agenthof run` needs to start a governed run —
// root or spawned child: the validated config and registry, the process
// broker, the ledger and artifact locations, and the one step-timeout knob.
// It is also the in-process Spawner: a child run is engine.Run called again
// with the same deps, the parent's invoker, and a fresh per-run gateway that
// carries this same Spawner — which is what lets a child spawn in turn. A
// durable executor would replace only this implementation.
type runDeps struct {
	cfg         config.Config
	reg         *registry.Registry
	broker      broker.Broker
	logger      *slog.Logger
	logDir      string
	artifactDir string
	configHash  string
	// stepTimeout drives BOTH the engine's per-step deadline and the
	// adapter's request timeout. They must be the same number: the adapter
	// applies its own timeout inside the step context, and a context keeps
	// the earlier of two deadlines, so raising only the step deadline would
	// leave every step — and every spawned subtree under it — cut at the
	// adapter's default.
	stepTimeout time.Duration
	// subjectToken is the invoker's verified inbound token, handed to every
	// gateway in this run's tree (a child acts for the same human) and to
	// nothing else — never the engine, a Binding, or the ledger.
	subjectToken string
}

func newRunDeps(cfg config.Config, reg *registry.Registry, b broker.Broker, logger *slog.Logger, logDir, artifactDir, configHash, subjectToken string) *runDeps {
	return &runDeps{cfg: cfg, reg: reg, broker: b, logger: logger, logDir: logDir, artifactDir: artifactDir,
		configHash: configHash, stepTimeout: cfg.Gateway.EffectiveStepTimeout(), subjectToken: subjectToken}
}

// executor is the fronted adapter under the same deadline as the step.
func (d *runDeps) executor() agentrt.AdapterExecutor {
	return agentrt.AdapterExecutor{Timeout: d.stepTimeout}
}

// options builds the engine options for one run; parent is nil for a root.
func (d *runDeps) options(parent *engine.Binding) engine.Options {
	return engine.Options{LogDir: d.logDir, ArtifactDir: d.artifactDir, ConfigHash: d.configHash,
		StepTimeout: d.stepTimeout, NewGateway: d.newGateway, Logger: d.logger, Parent: parent}
}

// newGateway is the per-run gateway factory. Each run gets its own Gateway
// (it holds per-run listener state and the spawn caps). keyRoot is ".", the
// working directory gateway provision writes role keys under. The gateway
// carries this runDeps as its Spawner, so a child's gateway can spawn too.
func (d *runDeps) newGateway() engine.ToolProxy {
	return rungateway.New(d.cfg.Gateway, ".", d.broker, d.logger, d.subjectToken).WithSpawner(d)
}

// preRunRefusal is the gate every run passes before the engine starts, root
// and spawned child alike: an on-behalf-of workflow needs the invoker's
// verified token to exchange, and a dev --as identity (or no token) has
// none. It returns the fixed, ledgered reason and true when the run must be
// refused — a proper refused run, never a mid-run "tool proxy start failed",
// and the exchange endpoint is never contacted.
func preRunRefusal(cfg config.Config, reg *registry.Registry, workflow string, inv identity.Invoker) (string, bool) {
	if inv.Method != "oidc" && workflowRequiresOBO(cfg, reg, workflow) {
		return oboRefusalReason, true
	}
	return "", false
}

// Spawn implements rungateway.Spawner: a full governed child run, in
// process, under the parent's invoker (unchanged — a child never gains
// authority the human lacks) and linked to the parent's binding. The child's
// outcome comes back as a result; only an internal failure (a ledger that
// could not be opened or written) is an error.
func (d *runDeps) Spawn(ctx context.Context, childRole, childWorkflow, input string, parent engine.Binding) (rungateway.SpawnResult, error) {
	if reason, refused := preRunRefusal(d.cfg, d.reg, childWorkflow, parent.Invoker); refused {
		id, err := engine.Refuse(d.logDir, childRole, childWorkflow, parent.Invoker, reason, &parent)
		return rungateway.SpawnResult{ChildRunID: id, Status: "refused", Reason: reason}, err
	}
	res, err := engine.Run(ctx, d.reg, childRole, childWorkflow, input, parent.Invoker, d.executor(), d.options(&parent))
	if err != nil {
		if res.Status == "refused" && !errors.Is(err, engine.ErrLedgerWrite) {
			// A recorded refusal — the child's own ledger holds run_refused
			// — not a transport failure. The error here is the engine's own
			// refusal text, the same string it wrote to that event, so it is
			// safe as a reason. A refusal whose record failed is joined with
			// ErrLedgerWrite and carries a filesystem path: that is not a
			// reason, so it takes the error path below and the door records
			// its own fixed "spawn did not complete".
			return rungateway.SpawnResult{ChildRunID: res.RunID, Status: "refused", Reason: err.Error(), Provisioned: true}, nil
		}
		return rungateway.SpawnResult{ChildRunID: res.RunID, Status: "failed", Provisioned: true}, err
	}
	status := res.Status
	if status == "cancelled" {
		status = "failed" // the door's vocabulary: a child torn down with its parent did not succeed
	}
	return rungateway.SpawnResult{ChildRunID: res.RunID, Status: status, OutputSHA: res.OutputSHA, OutputPreview: res.OutputPreview, Provisioned: true}, nil
}
