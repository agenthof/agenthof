package main

import "github.com/agenthof/agenthof/internal/broker"

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
