package main

import (
	"github.com/agenthof/agenthof/internal/broker"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/registry"
)

// subjectTokenTypeFromEnv is the RFC 8693 subject_token_type this deployment
// sends when exchanging the invoker's token: AGENTHOF_OIDC_SUBJECT_TOKEN_TYPE,
// defaulting to the access_token URN. It describes the INBOUND token's kind,
// so it is a deployment setting, not a per-resource one — one deployment
// presents one kind of inbound token.
func subjectTokenTypeFromEnv(getenv func(string) string) string {
	if v := getenv("AGENTHOF_OIDC_SUBJECT_TOKEN_TYPE"); v != "" {
		return v
	}
	return broker.SubjectTokenTypeAccessToken
}

// oboRefusalReason is the fixed, ledgered reason for a run that would reach
// an on-behalf-of resource without a verified invoker token to exchange.
const oboRefusalReason = "obo requires a verified invoker token"

// workflowRequiresOBO reports whether any agent stepping in workflow grants
// a token_exchange tool resource. The gateway exchanges the invoker's token
// for every such resource when the step starts, so a run without a verified
// token must be refused before the engine starts, not fail mid-run. An
// unknown workflow is false: the engine refuses that with its own reason.
func workflowRequiresOBO(cfg config.Config, reg *registry.Registry, workflow string) bool {
	wf, ok := reg.Workflow(workflow)
	if !ok {
		return false
	}
	for _, step := range wf.Steps {
		agent, ok := reg.Agent(step.Agent)
		if !ok {
			continue
		}
		for _, grant := range agent.Tools {
			if cfg.Gateway.Tools[grant.Resource].GrantType == "token_exchange" {
				return true
			}
		}
	}
	return false
}
