package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sort"
	"time"

	"github.com/agenthof/agenthof/internal/agentrt"
	"github.com/agenthof/agenthof/internal/broker"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/obs"
	"github.com/agenthof/agenthof/internal/refspawn"
	"github.com/agenthof/agenthof/internal/registry"
	"github.com/agenthof/agenthof/internal/rungateway"
)

// reasonCompartmentUnavailable is the fixed, ledgered reason for a child
// that could not be given compartments of its own: no supervisor, a
// provision that failed or was refused, or an answer that would have let an
// agent reach the runtime directly. Fail-closed: such a child never runs.
const reasonCompartmentUnavailable = "spawn compartment unavailable"

// reasonChildRefusedByPolicy is the fixed reason the parent's spawn event and
// the door's answer carry when the engine refuses the child at its registry
// gate (RBAC, role/workflow ownership, an unknown role). It classifies the
// refusal — policy, so retrying with the same binding will not help — without
// disclosing the role's required groups to the spawning agent, which is
// untrusted and cannot act on that detail anyway. The FULL engine reason is
// still written to the child's own ledger (its run_refused event), where an
// operator reaches it by the spawn event's child_run_id.
const reasonChildRefusedByPolicy = "child refused by its access policy"

// runDeps is everything one `agenthof run` needs to start a governed run —
// root or spawned child: the validated config and registry, the process
// broker, the ledger and artifact locations, the one step-timeout knob,
// and the supervisor that provisions a child's compartments. It is also
// the Spawner: a child run is engine.Run called again with the same deps
// and the parent's invoker, against the sockets the supervisor provisioned
// for that child, with a fresh per-child gateway that carries this same
// Spawner — which is what lets a child spawn in turn. A durable executor
// would replace only this implementation.
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
	// sup provisions a spawned child's isolated set; nil means no supervisor
	// is configured and every spawn is refused (fail-closed).
	sup refspawn.Provisioner
	// origin is the request channel the ROOT run arrived on, when it came
	// over the API; nil for a CLI run. Every run in this tree — the root and
	// each spawned child — stamps it, because a child's provenance is its
	// root's request.
	origin *engine.Origin
}

func newRunDeps(cfg config.Config, reg *registry.Registry, b broker.Broker, logger *slog.Logger, logDir, artifactDir, configHash, subjectToken string, sup refspawn.Provisioner) *runDeps {
	return &runDeps{cfg: cfg, reg: reg, broker: b, logger: obs.OrDiscard(logger), logDir: logDir, artifactDir: artifactDir,
		configHash: configHash, stepTimeout: cfg.Gateway.EffectiveStepTimeout(), subjectToken: subjectToken, sup: sup}
}

// executor is the fronted adapter under the same deadline as the step.
func (d *runDeps) executor() agentrt.AdapterExecutor {
	return agentrt.AdapterExecutor{Timeout: d.stepTimeout}
}

// options builds the engine options for one run; parent is nil for a root.
func (d *runDeps) options(parent *engine.Binding) engine.Options {
	return engine.Options{LogDir: d.logDir, ArtifactDir: d.artifactDir, ConfigHash: d.configHash,
		StepTimeout: d.stepTimeout, NewGateway: d.newGateway, Logger: d.logger, Parent: parent, Origin: d.origin}
}

// newGateway is the root run's gateway factory. Each run gets its own
// Gateway (it holds per-run listener state and the spawn caps). keyRoot is
// ".", the working directory gateway provision writes role keys under. The
// gateway carries this runDeps as its Spawner.
func (d *runDeps) newGateway() engine.ToolProxy {
	return rungateway.New(d.cfg.Gateway, ".", d.broker, d.logger, d.subjectToken).WithSpawner(d)
}

// childGateway is a spawned child's gateway factory: the same config with
// the child's own socket directory (so the child's per-step gateway socket
// lands where only the child's compartments can see it), the child's own
// refexec in place of every agent's exec.url, and a Spawner of its own, so
// a child can spawn in turn — measured against the child's directory, not
// the root's.
type childGateway struct {
	deps      *runDeps
	socketDir string
	execURL   string
}

func (g childGateway) newGateway() engine.ToolProxy {
	gw := g.deps.cfg.Gateway
	gw.RefboxSocketDir = g.socketDir
	return rungateway.New(gw, ".", g.deps.broker, g.deps.logger, g.deps.subjectToken).WithSpawner(g).WithExecURL(g.execURL)
}

// Spawn implements rungateway.Spawner for a spawned child's own gateway. It
// is runDeps.Spawn with one difference, and it is the whole reason this type
// carries the Spawner rather than runDeps doing it for the whole tree: the
// directory a grandchild's compartments are measured against is THIS child's
// socket directory — the one actually mounted into the compartments that are
// asking — not the root deployment's refbox_socket_dir. runDeps is shared by
// every run in the tree and cannot know which of them asked.
func (g childGateway) Spawn(ctx context.Context, childRole, childWorkflow, input string, parent engine.Binding) (rungateway.SpawnResult, error) {
	return g.deps.spawn(ctx, childRole, childWorkflow, input, parent, g.socketDir)
}

// childExecutor serves a spawned child's steps over the sockets the
// supervisor provisioned: each step's agent is dialed at its own
// compartment, whatever endpoint the config names (config is law for the
// root deployment; under spawn the supervisor's sockets win). An agent the
// supervisor gave no socket for is a configuration error the engine fails
// outright — never bounced to an earlier step, never dialed at its
// configured endpoint.
type childExecutor struct {
	sockets map[string]string
	inner   agentrt.AdapterExecutor
}

func (c childExecutor) Execute(ctx context.Context, bind engine.Binding, agent config.AgentDef, input string, artifacts map[string]string) (engine.StepResult, error) {
	sock, ok := c.sockets[agent.Name]
	if !ok {
		return engine.StepResult{}, fmt.Errorf("agent %q has no compartment in this child run: %w", agent.Name, engine.ErrStepConfig)
	}
	agent.Endpoint = config.UnixScheme + sock
	return c.inner.Execute(ctx, bind, agent, input, artifacts)
}

// distinctStepAgents lists every agent a workflow's steps name, once each,
// sorted: the compartments a child of that workflow needs.
func distinctStepAgents(wf config.WorkflowDef) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range wf.Steps {
		if !seen[s.Agent] {
			seen[s.Agent] = true
			out = append(out, s.Agent)
		}
	}
	sort.Strings(out)
	return out
}

// checkPlacement is the fail-closed containment check on what the
// supervisor handed back, done here so it holds whatever supervisor
// answers: the child's refexec socket must sit outside the child's socket
// directory (which is mounted into the child's compartments — inside it, an
// agent could dial the runtime directly and bypass the governed exec door),
// and neither of the child's directories may sit under mountedDir, the
// socket directory mounted into the compartments of the run that asked for
// this child — refbox_socket_dir for a root run, the spawning child's own
// ChildDir for a nested one. Empty means that run has no mounted directory.
func checkPlacement(mountedDir string, lease *refspawn.Lease) error {
	execDir := filepath.Dir(lease.ExecSocket)
	if registry.InsideDir(execDir, lease.ChildDir) {
		return errors.New("the child's exec socket is inside its mounted socket directory")
	}
	if mountedDir != "" {
		if registry.InsideDir(lease.ChildDir, mountedDir) {
			return errors.New("the child's socket directory is inside the spawning run's mounted socket directory")
		}
		if registry.InsideDir(execDir, mountedDir) {
			return errors.New("the child's exec socket is inside the spawning run's mounted socket directory")
		}
	}
	return nil
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
// authority the human lacks), linked to the parent's binding, and served
// in compartments of its own. Order matters: the pre-run gate first (an
// on-behalf-of refusal provisions nothing), then the supervisor, then the
// engine. Any failure to provision is a recorded refusal with a fixed
// reason and Provisioned false, so the door gives the max_total_spawns
// slot back; a provisioned child counts whatever happens next. Closing the
// lease is the teardown: the supervisor removes the set when the child is
// over. The child's outcome comes back as a result; only an internal
// failure (a ledger that could not be opened or written) is an error.
//
// This is the ROOT run's Spawner, so the directory the child's own
// directories are measured against is the configured refbox_socket_dir. A
// spawned child's gateway carries childGateway instead, which measures
// against that child's socket directory.
func (d *runDeps) Spawn(ctx context.Context, childRole, childWorkflow, input string, parent engine.Binding) (rungateway.SpawnResult, error) {
	return d.spawn(ctx, childRole, childWorkflow, input, parent, d.cfg.Gateway.RefboxSocketDir)
}

// spawn is Spawn with the one thing that differs by depth made explicit:
// mountedDir is the socket directory mounted into the compartments of the
// run that asked, which checkPlacement measures the answer against.
func (d *runDeps) spawn(ctx context.Context, childRole, childWorkflow, input string, parent engine.Binding, mountedDir string) (rungateway.SpawnResult, error) {
	logger := d.logger.With("parent_run", parent.RunID, "child_role", childRole, "child_workflow", childWorkflow)
	if reason, refused := preRunRefusal(d.cfg, d.reg, childWorkflow, parent.Invoker); refused {
		// Through options, not Refuse: a child refused here is still a run
		// of this tree, so its refusal carries the root's origin like every
		// other run under it.
		id, err := engine.RecordRefused(d.options(&parent), parent.Invoker, childRole, childWorkflow, reason)
		return rungateway.SpawnResult{ChildRunID: id, Status: "refused", Reason: reason}, err
	}
	wf, ok := d.reg.Workflow(childWorkflow)
	if !ok {
		// Nothing to provision: the engine refuses an unknown workflow with
		// its own recorded reason — before it ever builds a gateway. Null the
		// factory anyway so this path cannot run a child on the ROOT gateway
		// (unreachable today; impossible rather than merely unreachable).
		opts := d.options(&parent)
		opts.NewGateway = nil
		return d.runChild(ctx, childRole, childWorkflow, input, parent, d.executor(), opts, false)
	}
	if d.sup == nil {
		logger.Warn("spawn refused", "reason", "no compartment supervisor configured")
		return rungateway.SpawnResult{Status: "refused", Reason: reasonCompartmentUnavailable}, nil
	}
	childID := engine.NewRunID()
	lease, err := d.sup.Provision(ctx, childID, distinctStepAgents(wf))
	if err != nil {
		// The client already logged the failure by class; the ledger gets
		// the fixed reason and nothing of the supervisor's text.
		logger.Warn("spawn refused", "reason", "compartments not provisioned", "child_run", childID)
		return rungateway.SpawnResult{Status: "refused", Reason: reasonCompartmentUnavailable}, nil
	}
	defer lease.Release()
	if err := checkPlacement(mountedDir, lease); err != nil {
		logger.Error("spawn refused", "reason", err.Error(), "child_run", childID) // our own fixed text, no path
		return rungateway.SpawnResult{Status: "refused", Reason: reasonCompartmentUnavailable}, nil
	}
	// The child runs until the parent step's context ends — or until the
	// supervisor ends the set (a compartment died): a child with nothing to
	// run on is cancelled, not left to time out.
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-lease.Done():
			logger.Warn("child compartments ended before the child; cancelling it", "child_run", childID)
			cancel()
		case <-childCtx.Done():
		}
	}()
	exec := childExecutor{sockets: lease.AgentSockets, inner: d.executor()}
	opts := d.options(&parent)
	opts.RunID = childID
	opts.NewGateway = childGateway{deps: d, socketDir: lease.ChildDir, execURL: config.UnixScheme + lease.ExecSocket}.newGateway
	return d.runChild(childCtx, childRole, childWorkflow, input, parent, exec, opts, true)
}

// runChild runs the engine for a child and maps its outcome onto a
// SpawnResult. provisioned is what the door counts.
func (d *runDeps) runChild(ctx context.Context, role, workflow, input string, parent engine.Binding, exec engine.StepExecutor, opts engine.Options, provisioned bool) (rungateway.SpawnResult, error) {
	res, err := engine.Run(ctx, d.reg, role, workflow, input, parent.Invoker, exec, opts)
	if err != nil {
		if res.Status == "refused" && !errors.Is(err, engine.ErrLedgerWrite) {
			// A recorded refusal — the child's own ledger holds run_refused
			// with the engine's FULL reason — not a transport failure. The
			// wire and the parent's spawn event carry only the fixed,
			// classifying reason: the full text (which names the role's
			// required groups) stays in the child ledger, reached by this
			// event's child_run_id, and is never echoed to the spawning agent.
			// A refusal whose record failed is joined with ErrLedgerWrite and
			// carries a filesystem path: it takes the error path below, where
			// the door records its own fixed "spawn did not complete".
			return rungateway.SpawnResult{ChildRunID: res.RunID, Status: "refused", Reason: reasonChildRefusedByPolicy, Provisioned: provisioned}, nil
		}
		return rungateway.SpawnResult{ChildRunID: res.RunID, Status: "failed", Provisioned: provisioned}, err
	}
	status := res.Status
	if status == "cancelled" {
		status = "failed" // the door's vocabulary: a child torn down with its parent did not succeed
	}
	return rungateway.SpawnResult{ChildRunID: res.RunID, Status: status, OutputSHA: res.OutputSHA, OutputPreview: res.OutputPreview, Provisioned: provisioned}, nil
}
