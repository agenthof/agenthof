package config

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// UnixScheme prefixes a gateway proxy URL or an AgentDef.Endpoint that names a
// Unix domain socket to dial. The value after it is the socket PATH only; HTTP
// routes are fixed constants, never encoded in the URL.
const UnixScheme = "unix://"

type AgentDef struct {
	Name        string     `yaml:"name"`
	Description string     `yaml:"description"`
	Enabled     *bool      `yaml:"enabled"` // nil means true
	Model       string     `yaml:"model"`
	Instruction string     `yaml:"instruction"`
	Tools       []string   `yaml:"tools"`
	Output      string     `yaml:"output"`
	Execution   string     `yaml:"execution"` // "", or "fronted"; "" means fronted
	Endpoint    string     `yaml:"endpoint"`  // required: the agent's HTTP endpoint
	Exec        ExecConfig `yaml:"exec"`      // fronted only: allowlisted attested exec
	SourceFile  string     `yaml:"-"`
}

// ToolGrant is one entry in an agent's `tools:` list. A bare string is the
// resource id and grants every tool the resource exposes (unchanged
// behavior). The object form restricts the grant to the named tools within
// that resource; it must list at least one tool — the bare string is the
// only spelling of "all tools", so a typo can never widen a grant.
//
// Reserved (additive, not implemented): a per-tool mode (read-only vs
// mutating).
type ToolGrant struct {
	Resource string   `yaml:"resource"`
	Tools    []string `yaml:"tools"` // object form: non-empty; bare string: nil (= every tool)
}

// Restricted reports whether the grant names specific tools (the object
// form) rather than every tool the resource exposes (the bare string).
func (g ToolGrant) Restricted() bool { return len(g.Tools) > 0 }

// rawGrant is ToolGrant without its methods, so the mapping form can be
// decoded with value.Decode without recursing back into UnmarshalYAML.
type rawGrant ToolGrant

// UnmarshalYAML accepts a scalar (resource id → every tool) or a mapping
// ({resource, tools} → only those tools) and rejects everything else. It
// fails closed: yaml.v3 silently drops unknown mapping keys, so the keys are
// checked by hand before decoding, and an object form with no tools is an
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
		*g = ToolGrant{Resource: value.Value}
		return nil
	case yaml.MappingNode:
		// Content alternates key, value, key, value. Only `resource` and
		// `tools` are known; anything else (a singular `tool:`, a future
		// `mode:` misspelled) is rejected rather than silently ignored.
		for i := 0; i+1 < len(value.Content); i += 2 {
			key := value.Content[i]
			switch key.Value {
			case "resource", "tools":
			default:
				return fmt.Errorf("bad-tool-grant: line %d: unknown key %q in tool grant (allowed keys: resource, tools)", key.Line, key.Value)
			}
		}
		var raw rawGrant
		if err := value.Decode(&raw); err != nil {
			return err
		}
		if raw.Resource == "" {
			return fmt.Errorf("bad-tool-grant: line %d: tool grant has an empty resource id", value.Line)
		}
		if len(raw.Tools) == 0 {
			return fmt.Errorf("bad-tool-grant: line %d: tool grant for resource %q must list at least one tool; write the bare string %q to grant every tool it exposes", value.Line, raw.Resource, raw.Resource)
		}
		*g = ToolGrant(raw)
		return nil
	default:
		return fmt.Errorf("bad-tool-grant: line %d: tool grant must be a resource id string or a {resource, tools} object", value.Line)
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

// ExecConfig declares the commands a fronted agent may run in its operator
// sandbox. Only Mode "attested" is implemented; "enforced" (Agenthof-run) is
// reserved. Attested: the agent runs the command and reports it; Agenthof
// authorizes against Allow and records it, but does not run or contain it.
type ExecConfig struct {
	Mode  string      `yaml:"mode"`  // "attested"; "enforced" reserved
	Allow []ExecEntry `yaml:"allow"` // non-empty when Mode is set
}

// ExecEntry allowlists an executable and a required leading-argument prefix.
type ExecEntry struct {
	Exe        string   `yaml:"exe"`         // exact executable name/path (no glob)
	ArgsPrefix []string `yaml:"args_prefix"` // required leading args; empty = any args
}

// Declared reports whether an agent declares exec at all.
func (e ExecConfig) Declared() bool { return e.Mode != "" || len(e.Allow) > 0 }

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
// CredentialSource=="static_env", and the direct-bearer and client_credentials
// grants are validated at config load; the tool proxy reads URL and TokenEnv
// (or mints an upstream token via GrantType=="client_credentials") to connect
// to the upstream MCP server and inject its credential. The remaining fields
// are the three-axis (grant × client-auth × source) + multi-IdP shape,
// reserved so later additions to this catalog stay additive. Credential
// coordinates are env-var NAMES, never values (Article II).
type ToolResource struct {
	Kind             string `yaml:"kind"` // "mcp"
	URL              string `yaml:"url"`
	CredentialSource string `yaml:"credential_source"` // "static_env" | vault|spiffe|sts (reserved)
	TokenEnv         string `yaml:"token_env"`         // static_env bearer env NAME
	GrantType        string `yaml:"grant_type"`        // "" (direct-bearer) | "client_credentials" | other (reserved)
	ClientAuth       string `yaml:"client_auth"`       // client_credentials: "client_secret_basic" (other values reserved)
	Issuer           string `yaml:"issuer"`            // client_credentials: (resource,issuer) key
	TokenEndpoint    string `yaml:"token_endpoint"`    // client_credentials: https, or http to loopback only
	ClientIDEnv      string `yaml:"client_id_env"`     // client_credentials: env NAME
	ClientSecretEnv  string `yaml:"client_secret_env"` // client_credentials: client secret env NAME
	Scope            string `yaml:"scope"`             // client_credentials: optional, space-delimited
}

type Config struct {
	Agents    []AgentDef
	Workflows []WorkflowDef
	Roles     []RoleDef
	Gateway   GatewayConfig
}
