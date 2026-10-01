package registry

import (
	"fmt"
	"net/url"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/agenthof/agenthof/internal/config"
)

type ValidationError struct{ File, Entity, Code, Msg string }

func (e ValidationError) Error() string { return fmt.Sprintf("%s: %s: %s", e.File, e.Entity, e.Msg) }

func Validate(cfg config.Config) []ValidationError {
	var errs []ValidationError
	add := func(file, entity, code, msg string) {
		errs = append(errs, ValidationError{File: file, Entity: entity, Code: code, Msg: msg})
	}

	agents := map[string]config.AgentDef{}
	for _, a := range cfg.Agents {
		if a.Name == "" {
			add(a.SourceFile, "(agent)", "missing-name", "agent has no name")
			continue
		}
		if _, dup := agents[a.Name]; dup {
			add(a.SourceFile, a.Name, "duplicate-name", "agent name already defined")
			continue
		}
		agents[a.Name] = a

		// Validate execution tier and endpoint. "contained" is rejected: the
		// tier was removed, and every agent is fronted.
		if a.Execution == "contained" {
			add(a.SourceFile, a.Name, "bad-execution",
				"execution \"contained\" was removed; set execution: fronted and an endpoint")
		} else if a.Execution != "" && a.Execution != "fronted" {
			add(a.SourceFile, a.Name, "bad-execution",
				fmt.Sprintf("execution %q must be \"fronted\"", a.Execution))
		}

		effectiveExec := a.EffectiveExecution()
		if a.Endpoint == "" {
			msg := "fronted agents must have an endpoint"
			if a.Execution == "" {
				msg = "agents are fronted and must declare an endpoint (the contained tier was removed)"
			}
			add(a.SourceFile, a.Name, "fronted-needs-endpoint", msg)
		} else if !validSecureOrUnixEndpoint(a.Endpoint) {
			add(a.SourceFile, a.Name, "bad-endpoint",
				"endpoint must be https, loopback http, or unix:// socket")
		}

		// Tools are gateway tool-resource grants. Each must name a declared
		// gateway.tools resource and either a non-empty tools list or a
		// mode; a grant with neither is the struct twin of the retired bare
		// id and is rejected here, before it can reach a duplicate bucket or
		// be scoped. A resource may be granted more than once only when
		// every grant is ScopeAll (mode: all; Start dedups those). Any
		// ScopeReadOnly or ScopeNamed grant makes a second grant of that
		// resource bad-tool-grant. Tool NAMES cannot be checked against the
		// upstream here (no network at apply); Start fails the step when an
		// allowlisted name is not exposed.
		grantedAll := map[string]bool{}
		grantedLimited := map[string]bool{}
		for _, grant := range a.Tools {
			if grant.Resource == "" {
				add(a.SourceFile, a.Name, "bad-tool-grant", "tool grant has an empty resource id")
				continue
			}
			if grant.Mode == "" && len(grant.Tools) == 0 {
				add(a.SourceFile, a.Name, "bad-tool-grant",
					fmt.Sprintf("tool grant for resource %q must list tools or set mode (all|read-only)", grant.Resource))
				continue
			}
			known := true
			res, ok := cfg.Gateway.Tools[grant.Resource]
			if !ok {
				known = false
				add(a.SourceFile, a.Name, "unknown-tool",
					fmt.Sprintf("agent references tool %q, which is not a declared gateway tool resource", grant.Resource))
			}
			switch grant.Mode {
			case "", "all", "read-only":
			default:
				add(a.SourceFile, a.Name, "bad-tool-grant",
					fmt.Sprintf("tool grant for resource %q has mode %q (want all or read-only)", grant.Resource, grant.Mode))
			}
			if grant.Mode == "all" && len(grant.Tools) > 0 {
				add(a.SourceFile, a.Name, "bad-tool-grant",
					fmt.Sprintf("tool grant for resource %q sets mode all and a tools list", grant.Resource))
			}
			for _, name := range grant.Tools {
				if name == "" {
					add(a.SourceFile, a.Name, "bad-tool-grant",
						fmt.Sprintf("tool grant for resource %q lists an empty tool name", grant.Resource))
				}
			}
			// Resource-dependent checks need the gateway entry. An unknown
			// resource is already unknown-tool; do not also complain that
			// its zero ReadOnlyTools list is missing.
			if known && grant.Mode == "read-only" {
				if len(res.ReadOnlyTools) == 0 {
					add(a.SourceFile, a.Name, "bad-tool-grant",
						fmt.Sprintf("tool grant for resource %q is mode read-only but the resource declares no read_only_tools", grant.Resource))
				} else {
					// Only meaningful once the resource classifies something;
					// otherwise every listed tool would also report "not in
					// read_only_tools", double-reporting one root cause.
					classified := map[string]bool{}
					for _, name := range res.ReadOnlyTools {
						classified[name] = true
					}
					for _, name := range grant.Tools {
						if name != "" && !classified[name] {
							add(a.SourceFile, a.Name, "bad-tool-grant",
								fmt.Sprintf("tool grant for resource %q lists %q, which is not in read_only_tools", grant.Resource, name))
						}
					}
				}
			}
			seen := grantedAll[grant.Resource] || grantedLimited[grant.Resource]
			if seen && (grant.Scope() != config.ScopeAll || grantedLimited[grant.Resource]) {
				add(a.SourceFile, a.Name, "bad-tool-grant",
					fmt.Sprintf("resource %q is granted more than once and at least one of those grants is not an all-tools grant; merge them into one grant", grant.Resource))
			}
			if grant.Scope() == config.ScopeAll {
				grantedAll[grant.Resource] = true
			} else {
				grantedLimited[grant.Resource] = true
			}
		}

		if a.Exec.Declared() {
			if effectiveExec != "fronted" {
				add(a.SourceFile, a.Name, "bad-exec-config", "exec is only valid on fronted agents")
			}
			switch a.Exec.Mode {
			case "attested":
				if a.Exec.Runtime != "" || a.Exec.URL != "" || a.Exec.Timeout != 0 {
					add(a.SourceFile, a.Name, "bad-exec-config",
						"exec.mode attested takes no runtime, url or timeout; those belong to mode: runtime")
				}
			case "runtime":
				// A trusted runtime is reached only over a local socket (its
				// directory permissions are what make it trusted), exactly as
				// runtime: refbridge on a tool resource.
				if a.Exec.Runtime != "refexec" {
					add(a.SourceFile, a.Name, "bad-exec-config",
						fmt.Sprintf("exec.runtime %q is not implemented (only refexec)", a.Exec.Runtime))
				}
				if !strings.HasPrefix(a.Exec.URL, config.UnixScheme) || !validSecureOrUnixEndpoint(a.Exec.URL) {
					add(a.SourceFile, a.Name, "bad-exec-config",
						"exec.url must be a unix:// socket path (absolute) when exec.mode is runtime")
				}
				if a.Exec.Timeout < time.Second {
					add(a.SourceFile, a.Name, "bad-exec-config",
						"exec.timeout is required with exec.mode runtime: a duration of at least 1s, such as 5m")
				}
				// The refexec socket must live outside gateway.refbox_socket_dir:
				// that directory is bind-mounted into the agent's compartment, so a
				// socket inside it would let the agent dial the runtime directly —
				// un-allowlisted and un-recorded. Make it impossible, not merely
				// forbidden in prose.
				if cfg.Gateway.RefboxSocketDir != "" && strings.HasPrefix(a.Exec.URL, config.UnixScheme) &&
					InsideDir(filepath.Dir(strings.TrimPrefix(a.Exec.URL, config.UnixScheme)), cfg.Gateway.RefboxSocketDir) {
					add(a.SourceFile, a.Name, "bad-exec-config",
						"exec.url must not be inside gateway.refbox_socket_dir: that directory is mounted into the agent's compartment, so the agent could reach the runtime directly")
				}
			default:
				add(a.SourceFile, a.Name, "bad-exec-config",
					fmt.Sprintf("exec.mode %q is not implemented (attested or runtime)", a.Exec.Mode))
			}
			if len(a.Exec.Allow) == 0 {
				add(a.SourceFile, a.Name, "bad-exec-config", "exec.mode is set but exec.allow is empty")
			}
			for _, e := range a.Exec.Allow {
				if e.Exe == "" {
					add(a.SourceFile, a.Name, "bad-exec-config", "exec.allow entry has an empty exe")
				}
			}
		}
	}

	for id, r := range cfg.Gateway.Tools {
		if r.Kind != "mcp" {
			add("gateway.yaml", id, "bad-tool-resource",
				fmt.Sprintf("tool resource %q must set kind: mcp", id))
		}
		if !validSecureOrUnixEndpoint(r.URL) {
			add("gateway.yaml", id, "bad-tool-resource",
				fmt.Sprintf("tool resource %q: url must be set and https (or loopback http, or a unix:// socket)", id))
		}
		switch r.Runtime {
		case "":
		case "refbridge":
			// A trusted runtime is reached only over a local socket (its
			// directory permissions are what make it trusted); a remote url
			// declaring one would let a remote server write attestations.
			if !strings.HasPrefix(r.URL, config.UnixScheme) {
				add("gateway.yaml", id, "bad-tool-resource",
					fmt.Sprintf("tool resource %q: runtime refbridge requires a unix:// url", id))
			}
		default:
			add("gateway.yaml", id, "bad-tool-resource",
				fmt.Sprintf("tool resource %q: runtime %q is not implemented (only refbridge)", id, r.Runtime))
		}
		if r.CredentialSource != "static_env" {
			add("gateway.yaml", id, "bad-tool-resource",
				fmt.Sprintf("tool resource %q: credential_source %q is not implemented (only static_env)", id, r.CredentialSource))
		}
		switch r.GrantType {
		case "":
			if r.TokenEnv == "" {
				add("gateway.yaml", id, "bad-tool-resource",
					fmt.Sprintf("tool resource %q: token_env is required for the direct-bearer grant", id))
			}
		case "client_credentials":
			if r.ClientAuth != "client_secret_basic" {
				add("gateway.yaml", id, "bad-tool-resource",
					fmt.Sprintf("tool resource %q: client_auth %q is not implemented (only client_secret_basic)", id, r.ClientAuth))
			}
			if r.Issuer == "" {
				add("gateway.yaml", id, "bad-tool-resource",
					fmt.Sprintf("tool resource %q: issuer is required for client_credentials", id))
			}
			if r.ClientIDEnv == "" {
				add("gateway.yaml", id, "bad-tool-resource",
					fmt.Sprintf("tool resource %q: client_id_env is required for client_credentials", id))
			}
			if r.ClientSecretEnv == "" {
				add("gateway.yaml", id, "bad-tool-resource",
					fmt.Sprintf("tool resource %q: client_secret_env is required for client_credentials", id))
			}
			if !validSecureEndpoint(r.TokenEndpoint) {
				add("gateway.yaml", id, "bad-tool-resource",
					fmt.Sprintf("tool resource %q: token_endpoint must be set and https (or loopback http)", id))
			}
		case "token_exchange":
			// On behalf of the invoker: the invoker's verified token is
			// exchanged at token_endpoint for a token audienced to this
			// upstream. Agenthof authenticates as an OAuth client, so the
			// client coordinates are required exactly as for
			// client_credentials; audience is what the exchange is FOR and
			// must be stated (config is law — no default upstream).
			if r.ClientAuth != "client_secret_basic" {
				add("gateway.yaml", id, "bad-tool-resource",
					fmt.Sprintf("tool resource %q: client_auth %q is not implemented (only client_secret_basic)", id, r.ClientAuth))
			}
			if r.Audience == "" {
				add("gateway.yaml", id, "bad-tool-resource",
					fmt.Sprintf("tool resource %q: audience is required for token_exchange", id))
			}
			if r.ClientIDEnv == "" {
				add("gateway.yaml", id, "bad-tool-resource",
					fmt.Sprintf("tool resource %q: client_id_env is required for token_exchange", id))
			}
			if r.ClientSecretEnv == "" {
				add("gateway.yaml", id, "bad-tool-resource",
					fmt.Sprintf("tool resource %q: client_secret_env is required for token_exchange", id))
			}
			if !validSecureEndpoint(r.TokenEndpoint) {
				add("gateway.yaml", id, "bad-tool-resource",
					fmt.Sprintf("tool resource %q: token_endpoint must be set and https (or loopback http)", id))
			}
			// An on-behalf-of resource has exactly one credential path — the
			// exchanged token. A direct bearer beside it is contradictory,
			// and issuer is the client_credentials cache key (token_exchange
			// keys by the subject token and reaches the server through
			// token_endpoint), so both are rejected rather than ignored.
			if r.TokenEnv != "" {
				add("gateway.yaml", id, "bad-tool-resource",
					fmt.Sprintf("tool resource %q: token_env must not be set with grant_type token_exchange (an on-behalf-of resource has no direct bearer)", id))
			}
			if r.Issuer != "" {
				add("gateway.yaml", id, "bad-tool-resource",
					fmt.Sprintf("tool resource %q: issuer must not be set with grant_type token_exchange (the exchange is keyed by the subject token, not an issuer)", id))
			}
		default:
			add("gateway.yaml", id, "bad-tool-resource",
				fmt.Sprintf("tool resource %q: grant_type %q is not implemented (client_credentials or token_exchange)", id, r.GrantType))
		}
		if r.GrantType != "token_exchange" && r.Audience != "" {
			add("gateway.yaml", id, "bad-tool-resource",
				fmt.Sprintf("tool resource %q: audience is only valid with grant_type token_exchange", id))
		}
		seenRO := map[string]bool{}
		for _, name := range r.ReadOnlyTools {
			if name == "" || seenRO[name] {
				add("gateway.yaml", id, "bad-tool-resource",
					fmt.Sprintf("tool resource %q: read_only_tools entries must be non-empty and unique", id))
				break
			}
			seenRO[name] = true
		}
	}

	workflows := map[string]config.WorkflowDef{}
	for _, w := range cfg.Workflows {
		if w.Name == "" {
			add(w.SourceFile, "(workflow)", "missing-name", "workflow has no name")
			continue
		}
		if _, dup := workflows[w.Name]; dup {
			add(w.SourceFile, w.Name, "duplicate-name", "workflow name already defined")
			continue
		}
		workflows[w.Name] = w
		if len(w.Steps) == 0 {
			add(w.SourceFile, w.Name, "no-steps", "workflow has no steps")
			continue
		}
		index := map[string]int{}
		for i, s := range w.Steps {
			index[s.Name] = i
		}
		for i, s := range w.Steps {
			if a, ok := agents[s.Agent]; !ok {
				add(w.SourceFile, w.Name, "dangling-agent-ref",
					fmt.Sprintf("step %q references agent %q, which does not exist", s.Name, s.Agent))
			} else if !a.IsEnabled() {
				add(w.SourceFile, w.Name, "disabled-agent-ref",
					fmt.Sprintf("workflow %q depends on agent %q, which is disabled in the registry", w.Name, s.Agent))
			}
			if s.MaxBounces < 0 || s.MaxBounces > 10 {
				add(w.SourceFile, w.Name, "bad-bounces",
					fmt.Sprintf("step %q: max_bounces must be between 0 and 10", s.Name))
			}
			if s.OnSuccess != "" {
				last := i == len(w.Steps)-1
				if !last || s.OnSuccess != "finish" {
					j, ok := index[s.OnSuccess]
					if !ok || j != i+1 {
						add(w.SourceFile, w.Name, "bad-graph",
							fmt.Sprintf("step %q: on_success must be the next step (or \"finish\" on the last step); branching is not yet supported", s.Name))
					}
				}
			}
			if s.OnFailure != "" {
				j, ok := index[s.OnFailure]
				if !ok || j >= i {
					add(w.SourceFile, w.Name, "bad-graph",
						fmt.Sprintf("step %q: on_failure must name an earlier step; forward or unknown targets are not supported", s.Name))
				}
			}
		}
	}

	roles := map[string]config.RoleDef{}
	for _, r := range cfg.Roles {
		if r.Name == "" {
			add(r.SourceFile, "(role)", "missing-name", "role has no name")
			continue
		}
		if _, dup := roles[r.Name]; dup {
			add(r.SourceFile, r.Name, "duplicate-name", "role name already defined")
			continue
		}
		roles[r.Name] = r
		if len(r.Workflows) == 0 {
			add(r.SourceFile, r.Name, "no-workflows", "role owns no workflows")
		}
		if len(r.AllowedGroups) == 0 {
			add(r.SourceFile, r.Name, "no-access-floor",
				`role has no allowed_groups; list real groups or ["*"] to declare it public`)
		}
		for _, wf := range r.Workflows {
			if _, ok := workflows[wf]; !ok {
				add(r.SourceFile, r.Name, "dangling-workflow-ref",
					fmt.Sprintf("role references workflow %q, which does not exist", wf))
			}
		}
	}

	// Spawn: each may_spawn target must resolve to a role that exists and
	// owns a workflow that exists; the policy caps are required as soon as
	// any agent declares may_spawn (config is law — a gateway.yaml that is
	// missing altogether arrives here as a zero policy and is rejected the
	// same way); the optional static type-cycle check runs last.
	spawnDeclared := false
	for _, a := range cfg.Agents {
		if a.Name == "" {
			continue
		}
		seen := map[config.SpawnTarget]bool{}
		for _, t := range a.MaySpawn {
			spawnDeclared = true
			if t.Role == "" || t.Workflow == "" {
				add(a.SourceFile, a.Name, "bad-spawn-target", "may_spawn entries must name both a role and a workflow")
				continue
			}
			if seen[t] {
				add(a.SourceFile, a.Name, "bad-spawn-target",
					fmt.Sprintf("may_spawn lists %s/%s more than once", t.Role, t.Workflow))
				continue
			}
			seen[t] = true
			ro, ok := roles[t.Role]
			if !ok {
				add(a.SourceFile, a.Name, "bad-spawn-target",
					fmt.Sprintf("may_spawn names role %q, which does not exist", t.Role))
				continue
			}
			if _, ok := workflows[t.Workflow]; !ok {
				add(a.SourceFile, a.Name, "bad-spawn-target",
					fmt.Sprintf("may_spawn names workflow %q, which does not exist", t.Workflow))
				continue
			}
			if !slices.Contains(ro.Workflows, t.Workflow) {
				add(a.SourceFile, a.Name, "bad-spawn-target",
					fmt.Sprintf("may_spawn names %s/%s, but role %q does not own workflow %q", t.Role, t.Workflow, t.Role, t.Workflow))
			}
		}
	}
	policy := cfg.Gateway.Spawn
	for _, c := range []struct {
		key string
		val int
	}{{"max_depth", policy.MaxDepth}, {"max_parallel", policy.MaxParallel}, {"max_total_spawns", policy.MaxTotalSpawns}} {
		switch {
		case c.val < 0:
			add("gateway.yaml", "spawn", "bad-spawn-policy", fmt.Sprintf("spawn.%s must not be negative", c.key))
		case c.val == 0 && spawnDeclared:
			add("gateway.yaml", "spawn", "spawn-policy-required",
				fmt.Sprintf("an agent declares may_spawn, so gateway.yaml must set spawn.%s to at least 1: a missing cap is never unbounded", c.key))
		}
	}
	// refbox_socket_dir is mounted into agent compartments at the same path
	// inside and out, and it is the directory every containment check
	// measures a socket against. A relative value breaks both: it would
	// resolve against whatever directory Agenthof happens to run in, and it
	// cannot be compared with the absolute paths it guards — InsideDir fails
	// closed on such a pair, so every absolute socket path would be reported
	// as inside it. Config is law: reject the shape here instead.
	if dir := cfg.Gateway.RefboxSocketDir; dir != "" && !filepath.IsAbs(dir) {
		add("gateway.yaml", "refbox_socket_dir", "bad-refbox-socket-dir",
			"refbox_socket_dir must be an absolute path: it is mounted into agent compartments at the same path inside and out, and it is what every socket's placement is checked against")
	}
	// The supervisor is where a child's compartments come from. Without one
	// there is nowhere to run a child, so may_spawn is refused at apply
	// rather than at the door; with one, it is a local socket in a directory
	// no agent compartment can see.
	switch sup := cfg.Gateway.SpawnSupervisor; {
	case sup == "" && spawnDeclared:
		add("gateway.yaml", "spawn_supervisor", "spawn-supervisor-required",
			"an agent declares may_spawn, so gateway.yaml must set spawn_supervisor to the compartment supervisor's unix:// socket: a child run is never started without one")
	case sup != "" && (!strings.HasPrefix(sup, config.UnixScheme) || !validSecureOrUnixEndpoint(sup)):
		add("gateway.yaml", "spawn_supervisor", "bad-spawn-supervisor",
			"spawn_supervisor must be a unix:// socket path (absolute)")
	case sup != "" && cfg.Gateway.RefboxSocketDir != "" &&
		InsideDir(filepath.Dir(strings.TrimPrefix(sup, config.UnixScheme)), cfg.Gateway.RefboxSocketDir):
		add("gateway.yaml", "spawn_supervisor", "bad-spawn-supervisor",
			"spawn_supervisor must not be inside gateway.refbox_socket_dir: that directory is mounted into agent compartments, so an agent could reach the supervisor directly")
	}
	if cfg.Gateway.StepTimeout != 0 && cfg.Gateway.StepTimeout < time.Second {
		add("gateway.yaml", "step_timeout", "bad-step-timeout", "step_timeout must be a duration of at least 1s, such as 5m")
	}
	if policy.RejectCycles {
		if cycle := spawnCycle(agents, workflows); cycle != nil {
			add("gateway.yaml", "spawn", "spawn-cycle",
				fmt.Sprintf("spawn.reject_cycles is set and the may_spawn graph has a cycle: %s", strings.Join(cycle, " -> ")))
		}
	}
	return errs
}

// spawnCycle finds a directed cycle in the agent-type spawn graph: an edge
// A -> B exists when A's may_spawn names a workflow that has a step run by
// B. It returns one cycle as a path with its first node repeated at the end,
// or nil. Because may_spawn fully determines what a run can reach, this
// static check is complete. Nodes and edges are visited in sorted order so
// the reported cycle is deterministic.
func spawnCycle(agents map[string]config.AgentDef, workflows map[string]config.WorkflowDef) []string {
	edges := map[string][]string{}
	for name, a := range agents {
		seen := map[string]bool{}
		for _, t := range a.MaySpawn {
			wf, ok := workflows[t.Workflow]
			if !ok {
				continue // already reported as bad-spawn-target
			}
			for _, s := range wf.Steps {
				if !seen[s.Agent] {
					seen[s.Agent] = true
					edges[name] = append(edges[name], s.Agent)
				}
			}
		}
		sort.Strings(edges[name])
	}
	const (
		white = iota
		grey
		black
	)
	color := map[string]int{}
	var stack []string
	var walk func(n string) []string
	walk = func(n string) []string {
		color[n] = grey
		stack = append(stack, n)
		for _, m := range edges[n] {
			switch color[m] {
			case grey:
				for i, s := range stack {
					if s == m {
						return append(append([]string{}, stack[i:]...), m)
					}
				}
			case white:
				if c := walk(m); c != nil {
					return c
				}
			}
		}
		stack = stack[:len(stack)-1]
		color[n] = black
		return nil
	}
	names := make([]string, 0, len(agents))
	for name := range agents {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if color[name] == white {
			if c := walk(name); c != nil {
				return c
			}
		}
	}
	return nil
}

// validSecureEndpoint requires an https URL, or http only to a loopback host
// (for tests and local development). It guards any endpoint that receives a
// gateway-injected credential over the NETWORK: a client_credentials token
// endpoint directly, and — through validSecureOrUnixEndpoint — a tool
// resource's upstream url or an agent endpoint that is not a local socket. A
// credential over plaintext http to a remote host is exactly the leak
// Article I guards against, so it is rejected at apply time.
func validSecureEndpoint(raw string) bool {
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		return host == "localhost" || host == "127.0.0.1" || host == "::1"
	}
	return false
}

// validSecureOrUnixEndpoint is validSecureEndpoint plus the unix://<absolute
// socket path> form, for the two endpoints Agenthof dials on the operator's
// own host: a fronted agent's endpoint (a refbox agent is reached over a
// bind-mounted Unix socket) and a tool resource's url (a refbridge-fronted
// stdio server is reached the same way). A local Unix socket never touches
// the network and is gated by directory permissions and the mount namespace,
// so it is at least as strict as loopback http, which any local user can
// reach. token_endpoint keeps validSecureEndpoint: it is a remote endpoint
// that receives a client secret.
func validSecureOrUnixEndpoint(raw string) bool {
	if path, ok := strings.CutPrefix(raw, config.UnixScheme); ok {
		// The wire contract pins unix://<absolute-socket-path>. A relative path
		// would resolve against the process working directory at dial time —
		// silently not the socket the operator meant — so reject it here
		// (config is law). IsAbs also rejects the empty path.
		return filepath.IsAbs(path)
	}
	return validSecureEndpoint(raw)
}

// InsideDir reports whether dir is parent itself or anywhere below it, after
// cleaning both. It is the one rule for "this path would be visible inside a
// mounted directory"; a sibling whose name merely shares a prefix is outside.
// Exported for the spawn door's runtime check on what a supervisor hands back.
//
// Every caller reads it as "reject this path", so a pair it cannot relate at
// all — one absolute, the other relative, which filepath.Rel refuses — is
// reported as inside: an unanswerable containment question fails closed, not
// open.
func InsideDir(dir, parent string) bool {
	rel, err := filepath.Rel(filepath.Clean(parent), filepath.Clean(dir))
	if err != nil {
		return true
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
