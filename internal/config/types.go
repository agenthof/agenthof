package config

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// UnixScheme prefixes a gateway proxy URL, an AgentDef.Endpoint, or a ToolResource.URL that names a
// Unix domain socket to dial. The value after it is the socket PATH only; HTTP
// routes are fixed constants, never encoded in the URL.
const UnixScheme = "unix://"

type AgentDef struct {
	Name        string      `yaml:"name"`
	Description string      `yaml:"description"`
	Enabled     *bool       `yaml:"enabled"` // nil means true
	Model       string      `yaml:"model"`
	Instruction string      `yaml:"instruction"`
	Tools       []ToolGrant `yaml:"tools"` // mode: all, mode: read-only, tools: [...], or tools + read-only
	Output      string      `yaml:"output"`
	Execution   string      `yaml:"execution"` // "", or "fronted"; "" means fronted
	Endpoint    string      `yaml:"endpoint"`  // required: the agent's HTTP endpoint
	Exec        ExecConfig  `yaml:"exec"`      // fronted only: allowlisted exec (attested, or first-hand via a runtime)
	SourceFile  string      `yaml:"-"`
}

// ToolGrant is one entry in an agent's `tools:` list. Every entry is an
// object; a bare resource id is rejected at load, so every-tool access is
// always written out as mode: all.
//
//	{resource, mode: all}               every tool, explicit
//	{resource, mode: read-only}         the resource's read_only_tools
//	{resource, tools: [a, b]}           exactly those tools
//	{resource, tools: [a], mode: read-only}
//	                                    those tools, each must be read-only
type ToolGrant struct {
	Resource string   `yaml:"resource"`
	Tools    []string `yaml:"tools"`
	Mode     string   `yaml:"mode"` // "", "all", or "read-only"
}

// GrantScope is how wide a tool grant is. Callers branch on this, not on
// len(Tools): a read-only grant has no tools list and would otherwise look
// like a named grant with nothing named. The lone exception is the empty
// shape (no mode and no tools), which UnmarshalYAML, Validate, and Start
// reject on the raw fields before scoping — branching on Scope() there
// would misreport an unknown mode (it defaults to ScopeNamed) as a missing
// scope.
type GrantScope int

const (
	ScopeAll      GrantScope = iota // mode: all — the only every-tool spelling
	ScopeReadOnly                   // mode: read-only
	ScopeNamed                      // tools: [...], no mode
)

// Scope classifies the grant by intent: ScopeAll (mode: all), ScopeReadOnly
// (mode: read-only — the resource's read_only_tools, optionally narrowed by a
// tools list), or ScopeNamed (an explicit tools list, no mode). A read-only
// grant that also lists tools stays ScopeReadOnly, so a caller that needs its
// effective set must read Tools (narrowed) rather than assume read_only_tools.
// Any other Mode — including "" — is ScopeNamed so it cannot widen to every
// tool: a grant with no mode and no tools then resolves to an empty allowed
// set (nothing), never a nil one (everything). ScopeAll is reachable only
// through mode: all. UnmarshalYAML, Validate, and Start each reject the
// no-mode, no-tools shape before it is ever scoped.
func (g ToolGrant) Scope() GrantScope {
	switch g.Mode {
	case "read-only":
		return ScopeReadOnly
	case "all":
		return ScopeAll
	default:
		return ScopeNamed
	}
}

// rawGrant is ToolGrant without its methods, so the mapping form can be
// decoded with value.Decode without recursing back into UnmarshalYAML.
type rawGrant ToolGrant

// UnmarshalYAML accepts a mapping ({resource} with a tools list and/or a
// mode) and rejects everything else, including the bare resource id that
// once meant every tool. It fails closed: yaml.v3 silently drops unknown
// mapping keys, so resource, tools, and mode are checked by hand before
// decoding, and an object form with neither a tools list nor a mode is an
// error rather than an accidental all-tools grant.
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
		return fmt.Errorf("bad-tool-grant: line %d: a bare tool grant is no longer accepted; list the tools it may call ({resource: %q, tools: [...]}) or write {resource: %q, mode: all} to grant every tool", value.Line, value.Value, value.Value)
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
		// A present tools key that is null or an empty sequence is an error
		// even when mode is set. An absent tools key leaves toolsNode nil.
		if toolsNode != nil && len(raw.Tools) == 0 {
			return fmt.Errorf("bad-tool-grant: line %d: tool grant for resource %q must list at least one tool", toolsNode.Line, raw.Resource)
		}
		// value.Decode already resolved mode: an absent or null mode leaves
		// raw.Mode "". modeNode is non-nil whenever a mode key was present, so
		// it is safe to cite in the value errors below.
		switch raw.Mode {
		case "", "all", "read-only":
		default:
			return fmt.Errorf("bad-tool-grant: line %d: tool grant for resource %q has mode %q (want all or read-only)", modeNode.Line, raw.Resource, raw.Mode)
		}
		if raw.Mode == "all" && toolsNode != nil {
			return fmt.Errorf("bad-tool-grant: line %d: tool grant for resource %q sets mode all and a tools list; drop tools, or drop mode", modeNode.Line, raw.Resource)
		}
		if raw.Mode == "" && toolsNode == nil {
			return fmt.Errorf("bad-tool-grant: line %d: tool grant for resource %q must set tools or mode: list the tools it may call (tools: [...]) or write mode: all to grant every tool", value.Line, raw.Resource)
		}
		*g = ToolGrant(raw)
		return nil
	default:
		return fmt.Errorf("bad-tool-grant: line %d: tool grant must be a {resource, tools, mode} object", value.Line)
	}
}

func (a AgentDef) IsEnabled() bool { return a.Enabled == nil || *a.Enabled }

// EffectiveExecution normalizes the execution tier: empty means fronted.
func (a AgentDef) EffectiveExecution() string {
	if a.Execution == "" {
		return "fronted"
	}
	return a.Execution
}

// ExecConfig declares the commands a fronted agent may run and whose account
// of each the ledger gets. Mode "attested": the agent runs the command in its
// sandbox and reports it; Agenthof authorizes against Allow and records the
// report, but does not run or contain it. Mode "runtime": a trusted
// operator-side runtime, named by Runtime and reached over URL, runs the
// command on the agent's behalf and attests it first-hand; Agenthof
// authorizes, forwards, enforces Timeout and records that account. Agenthof
// itself never runs a command. Runtime, URL and Timeout are required with
// mode runtime and rejected with mode attested (config is law).
type ExecConfig struct {
	Mode    string        `yaml:"mode"`    // "attested" | "runtime"
	Allow   []ExecEntry   `yaml:"allow"`   // non-empty when Mode is set
	Runtime string        `yaml:"runtime"` // mode runtime: "refexec" (the only runtime implemented)
	URL     string        `yaml:"url"`     // mode runtime: unix://<absolute socket path> of that runtime
	Timeout time.Duration `yaml:"timeout"` // mode runtime: the per-command deadline Agenthof enforces, e.g. 5m
}

// ExecEntry allowlists an executable and a required leading-argument prefix.
type ExecEntry struct {
	Exe        string   `yaml:"exe"`         // exact executable name/path (no glob)
	ArgsPrefix []string `yaml:"args_prefix"` // required leading args; empty = any args
}

// Declared reports whether an agent declares exec at all: any field set. A
// block that sets only the runtime fields is declared (and then rejected for
// its empty mode), never silently ignored.
func (e ExecConfig) Declared() bool {
	return e.Mode != "" || len(e.Allow) > 0 || e.Runtime != "" || e.URL != "" || e.Timeout != 0
}

// FirstHand reports whether the agent's exec door is served by a declared
// trusted runtime (the ledger gets that runtime's account) rather than by
// the agent's own report.
func (e ExecConfig) FirstHand() bool { return e.Runtime == "refexec" }

// Allows reports whether a reported argv matches any allowlist entry: argv[0]
// equals the entry's Exe and the entry's ArgsPrefix is a prefix of argv[1:].
// It matches the argv the agent reports; the operator's sandbox is what
// actually confines execution.
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
	Name           string   `yaml:"name"`
	Description    string   `yaml:"description"`
	Workflows      []string `yaml:"workflows"`
	AllowedGroups  []string `yaml:"allowed_groups"`
	BudgetUSDMonth float64  `yaml:"budget_usd_month"`
	SourceFile     string   `yaml:"-"`
}

type ModelRoute struct {
	Endpoint  string `yaml:"endpoint"`
	Model     string `yaml:"model"`
	APIKeyEnv string `yaml:"api_key_env"`
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
	// ReadOnlyTools names the tools that are safe under a mode: read-only
	// grant. Operator-declared. A tool not listed is mutating. Empty means
	// this resource has no read-only grant.
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
