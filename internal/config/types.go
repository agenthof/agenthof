package config

type AgentDef struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Enabled     *bool    `yaml:"enabled"` // nil means true
	Model       string   `yaml:"model"`
	Instruction string   `yaml:"instruction"`
	Tools       []string `yaml:"tools"`
	Output      string   `yaml:"output"`
	Execution   string   `yaml:"execution"` // "", "contained", or "fronted"; "" means contained
	Endpoint    string   `yaml:"endpoint"`  // fronted only: the agent's HTTP endpoint
	SourceFile  string   `yaml:"-"`
}

func (a AgentDef) IsEnabled() bool { return a.Enabled == nil || *a.Enabled }

// EffectiveExecution normalizes the execution tier: empty means contained.
func (a AgentDef) EffectiveExecution() string {
	if a.Execution == "" {
		return "contained"
	}
	return a.Execution
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
}

// ToolResource is a declared tool/MCP resource in the gateway catalog.
// Reserved shape: parsed, not yet read by any runtime path. The first
// consumer will read only Kind/URL/CredentialSource=="static_env"/TokenEnv;
// the remaining fields are the three-axis (grant × client-auth × source) +
// multi-IdP shape, present so later additions to this catalog stay additive.
// Credential coordinates are env-var NAMES, never values (Article II).
type ToolResource struct {
	Kind             string `yaml:"kind"` // "mcp"
	URL              string `yaml:"url"`
	CredentialSource string `yaml:"credential_source"` // "static_env" | vault|spiffe|sts (reserved)
	TokenEnv         string `yaml:"token_env"`         // static_env bearer env NAME
	GrantType        string `yaml:"grant_type"`        // reserved
	ClientAuth       string `yaml:"client_auth"`       // reserved
	Issuer           string `yaml:"issuer"`            // reserved: (resource,issuer) key
	TokenEndpoint    string `yaml:"token_endpoint"`    // reserved
	ClientIDEnv      string `yaml:"client_id_env"`     // reserved: env NAME
	Scope            string `yaml:"scope"`             // reserved
}

type Config struct {
	Agents    []AgentDef
	Workflows []WorkflowDef
	Roles     []RoleDef
	Gateway   GatewayConfig
}
