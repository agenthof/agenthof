package config

import (
	"fmt"
	"slices"
	"time"

	"gopkg.in/yaml.v3"
)

// UnixScheme prefixes a gateway proxy URL, an AgentDef.Endpoint, or a ToolResource.URL that names a
// Unix domain socket to dial. The value after it is the socket PATH only; HTTP
// routes are fixed constants, never encoded in the URL.
const UnixScheme = "unix://"

type AgentDef struct {
	Name        string        `yaml:"name"`
	Description string        `yaml:"description"`
	Enabled     *bool         `yaml:"enabled"` // nil means true
	Model       string        `yaml:"model"`
	Instruction string        `yaml:"instruction"`
	Tools       []ToolGrant   `yaml:"tools"` // each {resource, tools: ["*"] | [a, b], mode: read-only | read-write}
	Output      string        `yaml:"output"`
	Execution   string        `yaml:"execution"` // "", or "fronted"; "" means fronted
	Endpoint    string        `yaml:"endpoint"`  // required: the agent's HTTP endpoint
	Exec        ExecConfig    `yaml:"exec"`      // fronted only: allowlisted exec, first-hand via a trusted runtime (refexec)
	MaySpawn    []SpawnTarget `yaml:"may_spawn"` // spawn door: the {role, workflow} child runs this agent may start; empty means none (default-deny)
	SourceFile  string        `yaml:"-"`
}

// SpawnTarget is one entry in an agent's `may_spawn:` list: a child run the
// agent may ask the spawn door to start, named as the role it runs as and
// the workflow it runs. Both are matched exactly. An agent with no
// may_spawn spawns nothing.
type SpawnTarget struct {
	Role     string `yaml:"role"`
	Workflow string `yaml:"workflow"`
}

// ToolGrant is one entry in an agent's `tools:` list. Every entry is an
// object that states both axes of its scope: which tools (tools: ["*"] for
// every tool the resource advertises, or a named list — "*" must be the only
// entry) and whether they may mutate (mode: read-write, or read-only — the
// resource's read_only_tools). Neither axis has a default: a grant missing
// either is rejected at load, at apply, and at Start, never widened
// (Article VI). The retired spellings — a bare resource id and mode: all —
// are rejected with their replacement named.
//
//	{resource, tools: ["*"],  mode: read-write}   every tool
//	{resource, tools: ["*"],  mode: read-only}    every read_only_tools entry
//	{resource, tools: [a, b], mode: read-write}   exactly those tools
//	{resource, tools: [a],    mode: read-only}    those tools, each in read_only_tools
type ToolGrant struct {
	Resource string   `yaml:"resource"`
	Tools    []string `yaml:"tools"` // required: ["*"] (all) or a named list
	Mode     string   `yaml:"mode"`  // required: "read-only" | "read-write"
}

// AllTools reports whether the grant's breadth is the whole resource: tools
// is exactly ["*"]. It says nothing about read/write — a ["*"] grant with
// mode: read-only is AllTools and resolves to the resource's read_only_tools,
// never to every tool. Every caller that reads Tools branches on this first,
// so the marker is never looked up as a tool name.
func (g ToolGrant) AllTools() bool { return len(g.Tools) == 1 && g.Tools[0] == "*" }

// ReadOnly reports whether the grant is mode: read-only, so its effective
// set is intersected with the resource's read_only_tools.
func (g ToolGrant) ReadOnly() bool { return g.Mode == "read-only" }

// EveryToolReadWrite reports whether the grant is the widest one — tools:
// ["*"] with mode: read-write. It is the only shape that resolves to the
// "every tool" (nil) allow set and the only shape a resource may carry twice.
// It is positive on the closed enum, deliberately not AllTools() &&
// !ReadOnly(): a grant whose mode is absent, retired, or unknown is never
// every-tool, whichever check a caller happens to run first. Fail-closed by
// construction, not by check ordering.
func (g ToolGrant) EveryToolReadWrite() bool { return g.AllTools() && g.Mode == "read-write" }

// rawGrant is ToolGrant without its methods, so the mapping form can be
// decoded with value.Decode without recursing back into UnmarshalYAML.
type rawGrant ToolGrant

// UnmarshalYAML accepts a {resource, tools, mode} mapping and rejects
// everything else, including the bare resource id and mode: all that once
// meant every tool. It fails closed: yaml.v3 silently drops unknown mapping
// keys, so the keys are checked by hand before decoding, and both tools and
// mode are required — the shape rules run in a fixed order (both absent,
// mode: all, unknown mode, no tools, "*" not alone, no mode) so that, since
// yaml.v3 stops at the first error per file, an old mode: all grant is told
// its replacement rather than "has no tools".
//
// A null list element (`tools: [~]`) never reaches this method: yaml.v3
// skips the Unmarshaler for a null node and drops the element from the
// slice, so it grants nothing. registry.Validate separately rejects a grant
// whose Resource is empty, which covers AgentDefs built in Go.
func (g *ToolGrant) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		if value.Value == "" {
			return fmt.Errorf("bad-tool-grant: line %d: tool grant has an empty resource id", value.Line)
		}
		return fmt.Errorf("bad-tool-grant: line %d: a bare tool grant is no longer accepted; a tool grant needs tools and mode: write {resource: %q, tools: [\"*\"], mode: read-write} for every tool, or list tools and set mode", value.Line, value.Value)
	case yaml.MappingNode:
		var toolsNode, modeNode *yaml.Node
		for i := 0; i+1 < len(value.Content); i += 2 {
			key := value.Content[i]
			switch key.Value {
			case "resource":
			case "tools":
				toolsNode = value.Content[i+1]
			case "mode":
				modeNode = value.Content[i+1]
			default:
				return fmt.Errorf("bad-tool-grant: line %d: unknown key %q in tool grant (allowed keys: resource, tools, mode)", key.Line, key.Value)
			}
		}
		var raw rawGrant
		if err := value.Decode(&raw); err != nil {
			return err
		}
		if raw.Resource == "" {
			return fmt.Errorf("bad-tool-grant: line %d: tool grant has an empty resource id", value.Line)
		}
		// value.Decode already resolved both axes: an absent or null tools
		// leaves raw.Tools empty, an absent or null mode leaves raw.Mode "".
		// toolsNode/modeNode are non-nil whenever the key was present, so a
		// present key's own line is cited and an absent one cites the grant.
		if toolsNode == nil && raw.Mode == "" {
			return fmt.Errorf("bad-tool-grant: line %d: a tool grant needs tools and mode: write {resource: %q, tools: [\"*\"], mode: read-write} for every tool, or list tools and set mode", value.Line, raw.Resource)
		}
		switch raw.Mode {
		case "all":
			return fmt.Errorf("bad-tool-grant: line %d: tool grant for resource %q: mode: all is retired; write tools: [\"*\"], mode: read-write for every tool, or mode: read-only", modeNode.Line, raw.Resource)
		case "", "read-only", "read-write":
		default:
			return fmt.Errorf("bad-tool-grant: line %d: tool grant for resource %q has mode %q (want read-only or read-write)", modeNode.Line, raw.Resource, raw.Mode)
		}
		if len(raw.Tools) == 0 {
			line := value.Line
			if toolsNode != nil {
				line = toolsNode.Line
			}
			return fmt.Errorf("bad-tool-grant: line %d: tool grant for resource %q has no tools: list the tools it may call, or tools: [\"*\"] for every tool", line, raw.Resource)
		}
		if slices.Contains(raw.Tools, "*") && len(raw.Tools) != 1 {
			return fmt.Errorf("bad-tool-grant: line %d: tool grant for resource %q lists \"*\" alongside other tools; \"*\" must be the only entry", toolsNode.Line, raw.Resource)
		}
		if raw.Mode == "" {
			line := value.Line
			if modeNode != nil {
				line = modeNode.Line
			}
			return fmt.Errorf("bad-tool-grant: line %d: tool grant for resource %q has no mode: set mode: read-only or read-write", line, raw.Resource)
		}
		*g = ToolGrant(raw)
		return nil
	default:
		return fmt.Errorf("bad-tool-grant: line %d: tool grant must be a {resource, tools, mode} object", value.Line)
	}
}

func (a AgentDef) IsEnabled() bool { return a.Enabled == nil || *a.Enabled }

// MaySpawnTarget reports whether {role, workflow} is on the agent's
// may_spawn list: exact match on both, and an empty list allows nothing.
func (a AgentDef) MaySpawnTarget(role, workflow string) bool {
	for _, t := range a.MaySpawn {
		if t.Role == role && t.Workflow == workflow {
			return true
		}
	}
	return false
}

// EffectiveExecution normalizes the execution tier: empty means fronted.
func (a AgentDef) EffectiveExecution() string {
	if a.Execution == "" {
		return "fronted"
	}
	return a.Execution
}

// ExecConfig declares the commands a fronted agent may have run on its
// behalf. Exec is first-hand only: a trusted operator-side runtime, named by
// Runtime and reached over URL, runs each allowlisted command and attests it
// first-hand; Agenthof authorizes against Allow, forwards, enforces Timeout
// and records that account. Agenthof itself never runs a command, and the
// agent never reports one — the retired mode key is rejected at load
// (UnmarshalYAML) and Runtime, URL and Timeout are all required (config is
// law). Ledgers written before exec became first-hand only may carry exec
// events the agent reported itself (mode "attested"); that is the read
// path's concern (engine.Event), not this struct's.
type ExecConfig struct {
	Allow   []ExecEntry   `yaml:"allow"`   // non-empty: the allowlist
	Runtime string        `yaml:"runtime"` // "refexec" (the only runtime implemented)
	URL     string        `yaml:"url"`     // unix://<absolute socket path> of that runtime
	Timeout time.Duration `yaml:"timeout"` // the per-command deadline Agenthof enforces, e.g. 5m
}

// rawExec is ExecConfig without its methods, so the mapping can be decoded
// with value.Decode without recursing back into UnmarshalYAML.
type rawExec ExecConfig

// UnmarshalYAML decodes an exec block and rejects the retired mode key by
// name. Exec is first-hand only; a config that still says mode: attested or
// mode: runtime is rejected at apply with the replacement stated, never read
// with the key silently dropped (yaml.v3 would otherwise ignore it). A null
// exec: never reaches this method — yaml.v3 skips the Unmarshaler for a null
// node — and leaves the block undeclared.
func (e *ExecConfig) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("bad-exec-config: line %d: exec must be a mapping (runtime, url, timeout, allow)", value.Line)
	}
	for i := 0; i+1 < len(value.Content); i += 2 {
		if key := value.Content[i]; key.Value == "mode" {
			return fmt.Errorf("bad-exec-config: line %d: exec.mode is no longer supported; exec is always first-hand via a runtime (set runtime/url/timeout)", key.Line)
		}
	}
	var raw rawExec
	if err := value.Decode(&raw); err != nil {
		return err
	}
	*e = ExecConfig(raw)
	return nil
}

// ExecEntry allowlists an executable and a required leading-argument prefix.
type ExecEntry struct {
	Exe        string   `yaml:"exe"`         // exact executable name/path (no glob)
	ArgsPrefix []string `yaml:"args_prefix"` // required leading args; empty = any args
}

// Declared reports whether an agent declares exec at all: any field set. A
// block that sets only some of the fields is declared (and then rejected at
// apply for what it is missing), never silently ignored.
func (e ExecConfig) Declared() bool {
	return len(e.Allow) > 0 || e.Runtime != "" || e.URL != "" || e.Timeout != 0
}

// Allows reports whether an argv matches any allowlist entry: argv[0]
// equals the entry's Exe and the entry's ArgsPrefix is a prefix of argv[1:].
// It is the authorization check before the runtime is asked; the runtime's
// compartment is what confines execution.
func (e ExecConfig) Allows(argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	for _, entry := range e.Allow {
		if argv[0] != entry.Exe || len(argv) < 1+len(entry.ArgsPrefix) {
			continue
		}
		match := true
		for i, p := range entry.ArgsPrefix {
			if argv[1+i] != p {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

type Step struct {
	Name       string `yaml:"name"`
	Agent      string `yaml:"agent"`
	OnSuccess  string `yaml:"on_success"`  // "" = next step, or "finish" on last
	OnFailure  string `yaml:"on_failure"`  // "" = previous step ("fail" if first)
	MaxBounces int    `yaml:"max_bounces"` // 0 means default 2
}

type WorkflowDef struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Steps       []Step `yaml:"steps"`
	SourceFile  string `yaml:"-"`
}

type RoleDef struct {
	Name          string   `yaml:"name"`
	Description   string   `yaml:"description"`
	Workflows     []string `yaml:"workflows"`
	AllowedGroups []string `yaml:"allowed_groups"`
	// Control is the role's optional control-plane grant: the operations
	// (apply, enable, disable, repair, provision, prune — the fixed set
	// authz.ControlOps owns) its allowed_groups members may perform. Absent or
	// null leaves it nil, which
	// means no control permission; a present-but-empty list decodes to a
	// non-nil empty slice and is rejected at apply — a grant that names none
	// is never widened (Article VI). There is no wildcard spelling.
	Control        []string `yaml:"control"`
	BudgetUSDMonth float64  `yaml:"budget_usd_month"`
	SourceFile     string   `yaml:"-"`
}

type ModelRoute struct {
	Endpoint  string `yaml:"endpoint"`
	Model     string `yaml:"model"`
	APIKeyEnv string `yaml:"api_key_env"`
}

// DefaultStepTimeout is the per-step deadline when gateway.yaml sets no
// step_timeout. The engine applies the same default on its own.
const DefaultStepTimeout = 5 * time.Minute

// SpawnPolicy bounds the delegation tree the spawn door may build. Config is
// law: as soon as any agent declares may_spawn, all three caps are required
// (a missing cap is rejected at apply, never read as unbounded). A run's
// depth rides its binding — a root run is 0 — and max_depth refuses a child
// whose depth would exceed it. max_parallel caps one run's in-flight
// children. max_total_spawns caps how many children one run may start over
// its whole life; a refused attempt starts nothing and does not count. The
// tree under one root is therefore bounded by the sum over k = 1..max_depth
// of max_total_spawns^k. reject_cycles turns on the static type-cycle check
// at apply (off, a type reused deeper in the tree is allowed; depth bounds
// it).
type SpawnPolicy struct {
	MaxDepth       int  `yaml:"max_depth"`
	MaxParallel    int  `yaml:"max_parallel"`
	MaxTotalSpawns int  `yaml:"max_total_spawns"`
	RejectCycles   bool `yaml:"reject_cycles"`
}

type GatewayConfig struct {
	Models   map[string]ModelRoute   `yaml:"models"`
	Tools    map[string]ToolResource `yaml:"tools"`
	Defaults struct {
		Model string `yaml:"model"`
	} `yaml:"defaults"`
	// RefboxSocketDir, when set, makes the per-run gateway listen on a Unix
	// domain socket under this directory instead of a TCP loopback port, so a
	// refbox compartment can reach it with no network. Empty means TCP loopback
	// (the default, unchanged).
	RefboxSocketDir string `yaml:"refbox_socket_dir"`
	// SpawnSupervisor is the compartment supervisor (refspawn) that
	// provisions every spawned child's compartments, as unix://<absolute
	// socket path>. Required as soon as any agent declares may_spawn: config
	// is law, and a child with nowhere to run is refused at apply, never run
	// in a shared process. The socket's directory must be private (0700,
	// this user) — checked when the door dials it — and must not be under
	// RefboxSocketDir, which is mounted into agent compartments. apply does
	// not check that the socket exists.
	SpawnSupervisor string `yaml:"spawn_supervisor"`
	// Spawn bounds the spawn door; required (all three caps) once any agent
	// declares may_spawn. See SpawnPolicy.
	Spawn SpawnPolicy `yaml:"spawn"`
	// StepTimeout is the deadline every step runs under: the engine's step
	// context AND the fronted adapter's request timeout, one knob (a context
	// keeps the earlier of two deadlines, so the two must be the same
	// number). Zero means DefaultStepTimeout. A spawned subtree runs under
	// its invoking step's deadline, so size it for the subtree.
	StepTimeout time.Duration `yaml:"step_timeout"`
}

// EffectiveStepTimeout is StepTimeout, or DefaultStepTimeout when unset.
func (g GatewayConfig) EffectiveStepTimeout() time.Duration {
	if g.StepTimeout == 0 {
		return DefaultStepTimeout
	}
	return g.StepTimeout
}

// ToolResource is a declared tool/MCP resource in the gateway catalog. Kind,
// CredentialSource=="static_env", and the three grants — direct-bearer,
// client_credentials, and token_exchange — are validated at config load; the
// tool proxy reads URL and TokenEnv (or mints an upstream token via
// client_credentials, or exchanges the invoker's verified token for a
// per-user one via token_exchange) to connect to the upstream MCP server and
// inject its credential. The remaining fields are the three-axis (grant ×
// client-auth × source) + multi-IdP shape, reserved so later additions to
// this catalog stay additive. Credential coordinates are env-var NAMES,
// never values (Article II).
type ToolResource struct {
	Kind             string `yaml:"kind"` // "mcp"
	URL              string `yaml:"url"`
	CredentialSource string `yaml:"credential_source"` // "static_env" | vault|spiffe|sts (reserved)
	TokenEnv         string `yaml:"token_env"`         // static_env bearer env NAME (direct-bearer grant only)
	GrantType        string `yaml:"grant_type"`        // "" (direct-bearer) | "client_credentials" | "token_exchange"
	ClientAuth       string `yaml:"client_auth"`       // client_credentials / token_exchange: "client_secret_basic" (other values reserved)
	Issuer           string `yaml:"issuer"`            // client_credentials: (resource,issuer) key; rejected on token_exchange
	TokenEndpoint    string `yaml:"token_endpoint"`    // client_credentials / token_exchange: https, or http to loopback only
	ClientIDEnv      string `yaml:"client_id_env"`     // client_credentials / token_exchange: env NAME
	ClientSecretEnv  string `yaml:"client_secret_env"` // client_credentials / token_exchange: client secret env NAME
	Scope            string `yaml:"scope"`             // client_credentials / token_exchange: optional, space-delimited
	// Audience is, for grant_type token_exchange, the audience the exchanged
	// per-user token is for (the RFC 8693 audience parameter — the upstream
	// this resource fronts). Required there; rejected on every other grant.
	// Distinct from AGENTHOF_OIDC_AUDIENCE, which is what tokens presented
	// TO Agenthof may name.
	Audience string `yaml:"audience"`
	// ReadOnlyTools names the tools that are safe under a read-only grant
	// (mode: read-only). Operator-declared. A tool not listed is mutating.
	// Empty means this resource has no read-only grant.
	ReadOnlyTools []string `yaml:"read_only_tools"`
	// Runtime declares that a trusted operator runtime fronts this resource
	// and attests first-hand, on every result, what it ran; the tool door
	// records that attestation on the tool_call event (runtime_attestation)
	// and fails a call whose result carries none. "" (the default) means no
	// runtime: any such claim on a result is stripped and never recorded.
	// Only "refbridge" is implemented; it requires a unix:// url.
	Runtime string `yaml:"runtime"`
}

type Config struct {
	Agents    []AgentDef
	Workflows []WorkflowDef
	Roles     []RoleDef
	Gateway   GatewayConfig
}
