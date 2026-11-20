package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"slices"
	"sort"
	"strings"
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

// reasonArtifactRefused is the fixed, ledgered reason when the supervisor
// refused the set because the artifact an agent would run is not one its
// enrollment consented to: a binding refusal, not an outage.
const reasonArtifactRefused = "spawn artifact refused"

// reasonArtifactNotConsented is the fixed, ledgered reason when the gateway's
// own admission check finds that a provenance agent's measured artifact is
// absent or is not one of its consented forms. Distinct from
// reasonArtifactRefused (the supervisor refused) and
// reasonCompartmentUnavailable.
const reasonArtifactNotConsented = "spawn artifact not consented"

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
		return d.runChild(ctx, childRole, childWorkflow, input, parent, d.executor(), opts, false, "", nil, nil)
	}
	if d.sup == nil {
		logger.Warn("spawn refused", "reason", "no compartment supervisor configured")
		return rungateway.SpawnResult{Status: "refused", Reason: reasonCompartmentUnavailable}, nil
	}
	childID := engine.NewRunID()
	agents := distinctStepAgents(wf)
	lease, err := d.sup.Provision(ctx, childID, agents, d.expectedArtifacts(agents))
	if errors.Is(err, refspawn.ErrArtifactRefused) {
		logger.Warn("spawn refused", "reason", "artifact binding refused", "child_run", childID)
		return rungateway.SpawnResult{Status: "refused", Reason: reasonArtifactRefused}, nil
	}
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
	// The trust anchor: whatever the supervisor said or omitted, a provenance
	// agent runs only if its measured artifact is one it consented to.
	// Provisioned stays true — a compartment set was consumed — so the
	// refusal counts against max_total_spawns.
	if evidence, failed := d.admitArtifacts(agents, lease); len(failed) > 0 {
		logger.Warn("spawn refused", "reason", "measured artifact not consented", "child_run", childID, "agents", failed)
		return rungateway.SpawnResult{Status: "refused", Reason: reasonArtifactNotConsented, Provisioned: true, ChildArtifact: evidence}, nil
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
	return d.runChild(childCtx, childRole, childWorkflow, input, parent, exec, opts, true, lease.Tier, lease.TierOpts, childArtifacts(lease.Ran))
}

// consentedForms returns the artifact forms a provenance agent consented to
// at enrollment, digest-only: an oci-image form (the image's sha256 digest)
// and/or a host-program form (its builds' content hashes). Nil for an agent
// with no provenance.
func consentedForms(a config.AgentDef) []refspawn.ExpectedArtifact {
	if a.Provenance == nil {
		return nil
	}
	var out []refspawn.ExpectedArtifact
	if dg := a.Provenance.ImageDigest(); wellFormedSHA256(dg) {
		out = append(out, refspawn.ExpectedArtifact{Kind: "oci-image", Values: []string{dg}})
	}
	if a.Provenance.Program != "" && len(a.Provenance.Builds) > 0 {
		hashes := make([]string, 0, len(a.Provenance.Builds))
		for _, b := range a.Provenance.Builds {
			// Self-sufficient: an empty or malformed value can never match,
			// whatever the client's own shape gate does.
			if wellFormedSHA256(b.SHA256) {
				hashes = append(hashes, b.SHA256)
			}
		}
		if len(hashes) > 0 {
			out = append(out, refspawn.ExpectedArtifact{Kind: "host-program", Values: hashes})
		}
	}
	return out
}

// wellFormedSHA256 reports whether v is "sha256:" followed by 64 lowercase hex.
func wellFormedSHA256(v string) bool {
	h, ok := strings.CutPrefix(v, "sha256:")
	if !ok || len(h) != 64 {
		return false
	}
	for _, c := range h {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// expectedArtifacts is what the supervisor is asked to enforce: each
// provenance agent's consented forms (nil when no agent has any).
func (d *runDeps) expectedArtifacts(agents []string) map[string][]refspawn.ExpectedArtifact {
	var out map[string][]refspawn.ExpectedArtifact
	for _, name := range agents {
		def, ok := d.reg.Agent(name)
		if !ok {
			continue
		}
		if forms := consentedForms(def); len(forms) > 0 {
			if out == nil {
				out = map[string][]refspawn.ExpectedArtifact{}
			}
			out[name] = forms
		}
	}
	return out
}

// ranConsented reports whether a measured artifact of the given kind shares
// a value with a consented form of the same kind (exact string compare).
func ranConsented(kind string, ran []string, forms []refspawn.ExpectedArtifact) bool {
	for _, f := range forms {
		if f.Kind != kind {
			continue
		}
		for _, v := range f.Values {
			if slices.Contains(ran, v) {
				return true
			}
		}
	}
	return false
}

// admitArtifacts is the gateway's own check, independent of what was sent to
// the supervisor (provenance is read fresh from the registry): every
// spawn-only agent must have a measured artifact that shares a value with a
// consented form of the same kind. One failure refuses the whole set; the
// evidence is the measured artifact of each failing agent that had one. A
// supervisor that echoes the consented value back as a fake measurement
// defeats this check — it guards a lenient or older supervisor and a wrongly
// mapped image, not a lying one.
func (d *runDeps) admitArtifacts(agents []string, lease *refspawn.Lease) (map[string]engine.ChildArtifactRef, []string) {
	var evidence map[string]engine.ChildArtifactRef
	var failed []string
	for _, name := range agents {
		def, ok := d.reg.Agent(name)
		if !ok {
			// An agent the registry cannot name cannot be vetted: refuse.
			failed = append(failed, name)
			continue
		}
		if !def.SpawnOnly() {
			continue
		}
		kind, values, measured := lease.RanArtifact(name)
		if measured && ranConsented(kind, values, consentedForms(def)) {
			continue
		}
		failed = append(failed, name)
		if measured {
			if evidence == nil {
				evidence = map[string]engine.ChildArtifactRef{}
			}
			evidence[name] = engine.ChildArtifactRef{Kind: kind, Values: values}
		}
	}
	return evidence, failed
}

// childArtifacts converts what the supervisor measured each child agent's
// compartment to run into the engine's ledger shape (nil when none was).
func childArtifacts(ran map[string]refspawn.RanArtifact) map[string]engine.ChildArtifactRef {
	if len(ran) == 0 {
		return nil
	}
	out := make(map[string]engine.ChildArtifactRef, len(ran))
	for agent, r := range ran {
		out[agent] = engine.ChildArtifactRef{Kind: r.Kind, Values: r.Values}
	}
	return out
}

// runChild runs the engine for a child and maps its outcome onto a
// SpawnResult. provisioned is what the door counts; tier and tierOpts are the
// isolation tier the supervisor reported for the child's set (empty when the
// child was never provisioned), carried onto every outcome so the parent's
// spawn event records it. ran is the artifact each child agent was measured
// to run (nil when none).
func (d *runDeps) runChild(ctx context.Context, role, workflow, input string, parent engine.Binding, exec engine.StepExecutor, opts engine.Options, provisioned bool, tier string, tierOpts []string, ran map[string]engine.ChildArtifactRef) (rungateway.SpawnResult, error) {
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
			return rungateway.SpawnResult{ChildRunID: res.RunID, Status: "refused", Reason: reasonChildRefusedByPolicy, Provisioned: provisioned,
				ChildConfiner: tier, ChildConfinerOpts: tierOpts, ChildArtifact: ran}, nil
		}
		return rungateway.SpawnResult{ChildRunID: res.RunID, Status: "failed", Provisioned: provisioned,
			ChildConfiner: tier, ChildConfinerOpts: tierOpts, ChildArtifact: ran}, err
	}
	status := res.Status
	if status == "cancelled" {
		status = "failed" // the door's vocabulary: a child torn down with its parent did not succeed
	}
	return rungateway.SpawnResult{ChildRunID: res.RunID, Status: status, OutputSHA: res.OutputSHA, OutputPreview: res.OutputPreview, Provisioned: provisioned,
		ChildConfiner: tier, ChildConfinerOpts: tierOpts, ChildArtifact: ran}, nil
}
