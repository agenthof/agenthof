#!/usr/bin/env bash
# e2e-obo-local: prove the REAL agenthof binary runs a tool call on behalf
# of the invoking human, hermetically over loopback, with no container
# runtime. Two Go stubs stand in for the operator's infrastructure: obo-idp
# (OIDC discovery + JWKS, mints the human's token, answers RFC 8693 token
# exchange) and obo-upstream (a per-user MCP server that verifies the bearer
# against the JWKS, rejects a wrong audience, and answers "acting as: <sub>").
# Asserts: a --token run's step artifact carries the human's sub and the
# ledger records the tool_call with auth_mode token_exchange; a --as run
# against an OBO resource is refused BEFORE the engine with the fixed reason;
# --groups is ignored when a token is present; AGENTHOF_OIDC_AUDIENCE admits
# a token audienced to the resource server and is a no-op when unset; an
# exchanged token for the wrong audience is rejected BY THE UPSTREAM and
# recorded failed; an exchange the issuer rejects in its own 4xx words and an
# issuer nothing listens for are each recorded as a failed step naming its
# own resource in the operational log; the subject token, every exchanged
# token, and the issuer's own error text appear in no ledger, artifact,
# operational log, or output; and config is law at apply. Requires go and
# python3. Runs on macOS and Linux.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

WORK="$(mktemp -d)"
PIDS=()
cleanup() {
	for p in ${PIDS[@]+"${PIDS[@]}"}; do
		kill "$p" >/dev/null 2>&1 || true
		wait "$p" >/dev/null 2>&1 || true
	done
	rm -rf "$WORK"
}
trap cleanup EXIT
unset AGENTHOF_TOKEN || true

fail() {
	echo "e2e-obo-local: FAIL — $*"
	exit 1
}
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'; }
wait_port() { # $1 = port, $2 = what
	for i in $(seq 1 60); do
		python3 -c "import socket; socket.create_connection(('127.0.0.1', $1), 1).close()" >/dev/null 2>&1 && return 0
		[ "$i" = 60 ] && { cat "$WORK"/*.err || true; fail "$2 never listened"; }
		sleep 0.2
	done
}
# no_leak VALUE WHAT...: VALUE must appear in no ledger, artifact, control
# log, apply-rejection output, process log, agenthof operational log, or
# captured agenthof stdout. Never prints VALUE. Absence proves something only
# where those places are populated, so section 8 asserts that before it calls
# this.
no_leak() {
	local value="$1"
	shift
	if grep -rqF -- "$value" "$WORK/logs" "$WORK/artifacts" "$WORK/control.jsonl" "$WORK/apply-bad.out" "$WORK"/*.err 2>/dev/null; then
		fail "$* reached the ledger, an artifact, the control log, the apply output, or a process log"
	fi
	if printf '%s\n' "${OUTS[@]}" | grep -qF -- "$value"; then
		fail "$* reached agenthof's output"
	fi
}

go build -o "$WORK/agenthof" ./cmd/agenthof
go build -o "$WORK/tool-agent" ./examples/tool-agent
go build -o "$WORK/obo-idp" ./examples/obo-idp
go build -o "$WORK/obo-upstream" ./examples/obo-upstream

NONCE="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
OUTS=()
IDP_PORT="$(free_port)"
UP_PORT="$(free_port)"
AGENT_PORT="$(free_port)"
DOWN_PORT="$(free_port)"   # nothing ever listens here
ISSUER="http://127.0.0.1:$IDP_PORT"
UP_AUD="https://obo-upstream.example"
OTHER_AUD="https://other-upstream.example"   # the issuer will exchange for it; the upstream is not it
NOWHERE_AUD="https://nowhere.example"        # on no allowlist: the issuer rejects an exchange for it
RS_AUD="https://agenthof.example/api"        # a resource-server audience for the inbound token
export OBO_IDP_CLIENT_SECRET="idp-side-secret-$NONCE"
export OBO_CLIENT_ID="agenthof-broker"
export OBO_CLIENT_SECRET="$OBO_IDP_CLIENT_SECRET"

# --- the stubs
"$WORK/obo-idp" -addr "127.0.0.1:$IDP_PORT" -client-id "$OBO_CLIENT_ID" -client-secret-env OBO_IDP_CLIENT_SECRET \
	-audiences "$UP_AUD,$OTHER_AUD" -subject-token-type urn:ietf:params:oauth:token-type:id_token \
	-token-log "$WORK/issued.jsonl" 2>"$WORK/idp.err" &
PIDS+=($!)
wait_port "$IDP_PORT" "obo-idp"
"$WORK/obo-upstream" -addr "127.0.0.1:$UP_PORT" -jwks-url "$ISSUER/keys" -audience "$UP_AUD" 2>"$WORK/upstream.err" &
PIDS+=($!)
"$WORK/tool-agent" -addr "127.0.0.1:$AGENT_PORT" 2>"$WORK/agent.err" &
PIDS+=($!)
wait_port "$UP_PORT" "obo-upstream"
wait_port "$AGENT_PORT" "tool-agent"

# mint SUB AUD [GROUPS]: a subject token from the stub issuer (a real IdP
# mints through a login flow). Prints the token; callers keep it in a variable.
mint() {
	python3 - "$ISSUER" "$1" "$2" "${3:-}" <<'PY'
import json, sys, urllib.request
issuer, sub, aud, groups = sys.argv[1:5]
body = {"sub": sub, "email": "dana@example.com", "aud": aud}
if groups:
    body["groups"] = groups.split(",")
req = urllib.request.Request(issuer + "/mint", data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
print(json.load(urllib.request.urlopen(req))["token"])
PY
}
TOKEN="$(mint u-dana agenthof obo-users)"
RS_TOKEN="$(mint u-dana "$RS_AUD" obo-users)"
if [ -z "$TOKEN" ] || [ -z "$RS_TOKEN" ]; then
	fail "the issuer minted no token"
fi

# --- a hermetic Agenthof config, written from scratch
mkdir -p "$WORK/config/agents" "$WORK/config/workflows" "$WORK/config/roles"
resource() { # $1 = id, $2 = audience, $3 = token_endpoint
	cat <<EOF
  $1:
    kind: mcp
    url: http://127.0.0.1:$UP_PORT/
    credential_source: static_env
    grant_type: token_exchange
    client_auth: client_secret_basic
    token_endpoint: $3
    audience: $2
    client_id_env: OBO_CLIENT_ID
    client_secret_env: OBO_CLIENT_SECRET
EOF
}
gateway_yaml() {
	cat <<EOF
models:
  fast:
    endpoint: http://127.0.0.1:9/v1
    model: fast
    api_key_env: AGENTHOF_GATEWAY_KEY
defaults:
  model: fast
tools:
EOF
	resource obo "$UP_AUD" "$ISSUER/token"
	resource obo-wrong-aud "$OTHER_AUD" "$ISSUER/token"
	resource obo-idp-rejects "$NOWHERE_AUD" "$ISSUER/token"
	resource obo-down "$UP_AUD" "http://127.0.0.1:$DOWN_PORT/token"
}
gateway_yaml >"$WORK/config/gateway.yaml"
agent() { # $1 = name, $2 = resource
	cat >"$WORK/config/agents/$1.yaml" <<EOF
name: $1
description: e2e agent $1
model: fast
instruction: Call the tool.
output: output
execution: fronted
endpoint: http://127.0.0.1:$AGENT_PORT/
tools:
  - resource: $2
    mode: all
EOF
	cat >"$WORK/config/workflows/$1.yaml" <<EOF
name: $1
description: one step through $1
steps:
  - name: call
    agent: $1
EOF
}
agent obo-run obo
agent obo-wrong obo-wrong-aud
agent obo-rejects obo-idp-rejects
agent obo-unreachable obo-down
cat >"$WORK/config/roles/obo-operator.yaml" <<EOF
name: obo-operator
description: Runs the OBO e2e workflows
workflows: [obo-run, obo-wrong, obo-rejects, obo-unreachable]
allowed_groups: ["obo-users"]
EOF
export AGENTHOF_GATEWAY_KEY="host-side-dummy-key-$NONCE"   # the model route is never called; the key only lets it resolve
export AGENTHOF_OIDC_ISSUER="$ISSUER"
export AGENTHOF_OIDC_CLIENT_ID=agenthof
export AGENTHOF_OIDC_SUBJECT_TOKEN_TYPE=urn:ietf:params:oauth:token-type:id_token

"$WORK/agenthof" apply --config "$WORK/config" --control-log "$WORK/control.jsonl" --as ci --groups obo-users

# Config is law at apply: an OBO resource without an audience, one with a
# direct bearer beside it, and an audience on a static resource are rejected.
reject_apply() { # $1 = gateway.yaml body, $2 = expected message fragment
	rm -rf "$WORK/badcfg"
	mkdir -p "$WORK/badcfg"
	cp -R "$WORK/config/." "$WORK/badcfg/"
	printf '%s\n' "$1" >"$WORK/badcfg/gateway.yaml"
	if "$WORK/agenthof" apply --config "$WORK/badcfg" --control-log "$WORK/control.jsonl" --as ci --groups obo-users >"$WORK/apply-bad.out" 2>&1; then
		fail "apply accepted: $2"
	fi
	grep -q "$2" "$WORK/apply-bad.out" || { cat "$WORK/apply-bad.out"; fail "apply did not say: $2"; }
}
reject_apply "$(gateway_yaml | sed '/^    audience: /d')" "audience is required for token_exchange"
# Appending a field at the resource indent continues the LAST resource's
# mapping (obo-down) — a portable way to add token_env beside its audience.
reject_apply "$(gateway_yaml)
    token_env: LEAKY" "token_env must not be set with grant_type token_exchange"
reject_apply "$(gateway_yaml | sed '/^  obo-down:/,$d')
  plain:
    kind: mcp
    url: http://127.0.0.1:$UP_PORT/
    credential_source: static_env
    token_env: PLAIN_TOKEN
    audience: $UP_AUD" "audience is only valid with grant_type token_exchange"

run() { # $1 = workflow, $2 = input, rest = identity flags; sets OUT, RUNID, AUDIT
	local wf="$1" input="$2"
	shift 2
	OUT="$("$WORK/agenthof" run obo-operator "$wf" --input "$input" "$@" \
		--config "$WORK/config" --log-dir "$WORK/logs" --artifact-dir "$WORK/artifacts" \
		--log-level debug 2>>"$WORK/agenthof.err" || true)"
	OUTS+=("$OUT")
	echo "$OUT"
	RUNID="$(echo "$OUT" | sed -E -n 's/^run (r-[a-f0-9]+) (finished|refused).*/\1/p')"
	[ -n "$RUNID" ] || fail "no run id in the output of $wf"
	AUDIT="$("$WORK/agenthof" audit "$RUNID" --log-dir "$WORK/logs" --control-log "$WORK/control.jsonl" || true)"
	OUTS+=("$AUDIT")
	echo "$AUDIT"
	echo "$AUDIT" | grep -q "ledger integrity: verified" || fail "$wf: ledger not verified"
}

# 1. On behalf of the human: the upstream saw her sub, the ledger says how.
run obo-run "call whoami" --token "$TOKEN"
echo "$OUT" | grep -q "finished: succeeded" || fail "the OBO run did not succeed"
grep -rqF "acting as: u-dana" "$WORK/artifacts" || fail "the upstream did not see the human's sub"
grep -q '"auth_mode":"token_exchange"' "$WORK/logs/$RUNID.jsonl" || fail "tool_call is not auth_mode token_exchange"
echo "$AUDIT" | grep -Eq "tool whoami — args [0-9a-f]{8} \(token_exchange\)" || fail "audit did not render the token_exchange mode"
echo "$AUDIT" | grep -q "invoked by dana@example.com (oidc, issuer $ISSUER)" || fail "the run is not attributed to the verified human"
echo "on-behalf-of run: upstream saw u-dana, ledger says token_exchange — ok"

# 2. A dev --as identity against an OBO resource is refused before the
#    engine, with the fixed reason — and the group is the allowed one, so
#    this cannot be an RBAC refusal in disguise.
run obo-run "call whoami" --as ci --groups obo-users
echo "$OUT" | grep -q "refused: obo requires a verified invoker token" || fail "--as against an OBO resource was not refused with the fixed reason"
grep -qF '"reason":"obo requires a verified invoker token"' "$WORK/logs/$RUNID.jsonl" || fail "the ledger's refusal reason is not the fixed OBO one (an RBAC refusal would read differently)"
[ "$(grep -c '"type":"run_refused"' "$WORK/logs/$RUNID.jsonl")" = 1 ] || fail "expected exactly one run_refused event"
if grep -q '"type":"workflow_started"\|"type":"step_' "$WORK/logs/$RUNID.jsonl"; then fail "a pre-engine refusal must start no workflow and no step"; fi
echo "$AUDIT" | grep -q "run refused — obo requires a verified invoker token" || fail "refusal not rendered"

# 3. --groups is ignored when a verified token is present: the token's
#    groups (obo-users) authorize, not the flag's. Both directions, so a run
#    that MERGED the two sets could not pass either. The flag naming a group
#    the role forbids does not spoil a token that carries the allowed one;
#    and for the SAME subject, a token carrying no groups at all is refused
#    on membership even though the flag names the very group the role
#    requires — the flag cannot supply what the token does not carry.
run obo-run "call whoami" --token "$TOKEN" --groups nope
echo "$OUT" | grep -q "finished: succeeded" || fail "--groups must be ignored when a token is present"
NOGROUPS_TOKEN="$(mint u-dana agenthof)"
[ -n "$NOGROUPS_TOKEN" ] || fail "the issuer minted no group-less token"
run obo-run "call whoami" --token "$NOGROUPS_TOKEN" --groups obo-users
echo "$OUT" | grep -qF 'refused: role "obo-operator" requires membership in one of its allowed groups (obo-users)' || fail "--groups must not supply groups the verified token does not carry"
[ "$(grep -c '"type":"run_refused"' "$WORK/logs/$RUNID.jsonl")" = 1 ] || fail "expected exactly one run_refused event for the group-less token"

# 4. The additive inbound audience: a token audienced to the resource
#    server is refused until AGENTHOF_OIDC_AUDIENCE names it.
run obo-run "call whoami" --token "$RS_TOKEN"
echo "$OUT" | grep -q "refused: token verification failed" || fail "a resource-audienced token must be refused while AGENTHOF_OIDC_AUDIENCE is unset"
export AGENTHOF_OIDC_AUDIENCE="$RS_AUD"   # export + unset, not a prefix on the function: unambiguous on bash 3.2 (macOS) and 5
run obo-run "call whoami" --token "$RS_TOKEN"
unset AGENTHOF_OIDC_AUDIENCE
echo "$OUT" | grep -q "finished: succeeded" || fail "AGENTHOF_OIDC_AUDIENCE must admit a resource-audienced token"

# 5. A token exchanged for another audience: the issuer issues it, the
#    UPSTREAM rejects it — that is where the audience is enforced. The call
#    is recorded as a failed tool_call, never as a quiet success.
run obo-wrong "call whoami" --token "$TOKEN"
echo "$OUT" | grep -q "finished: failed" || fail "a wrong-audience token must fail the step"
echo "$AUDIT" | grep -q "tool whoami failed — audience mismatch" || fail "upstream's audience rejection not recorded on the tool_call"
grep '"type":"tool_call"' "$WORK/logs/$RUNID.jsonl" | grep '"status":"failed"' | grep -q '"auth_mode":"token_exchange"' || fail "the ledger has no failed token_exchange tool_call for the wrong audience"
grep -q "\"aud\":\"$OTHER_AUD\"" "$WORK/issued.jsonl" || fail "the issuer did not exchange for the other audience (the test would prove nothing)"

# 6. The issuer rejects the exchange (unlisted audience): the step fails at
#    proxy start with the fixed reason; the issuer's own words go nowhere.
run obo-rejects "call whoami" --token "$TOKEN"
echo "$OUT" | grep -q "finished: failed" || fail "a rejected exchange must fail the step"
echo "$AUDIT" | grep -q "step call (agent obo-rejects) failed — tool proxy start failed" || fail "rejected exchange not recorded as a start failure"
grep -q 'msg="upstream connect failed".*resource=obo-idp-rejects class=other' "$WORK/agenthof.err" || fail "the operational log does not name obo-idp-rejects as the resource that could not be reached"
# The ledger reason is fixed, and so is the log's class: the broker's error
# is fixed text with no wrapped cause (the cause carries the token
# endpoint's URL), so errClass never sees a transport error and BOTH this
# case and an unreachable issuer are class=other. What actually tells them
# apart is asked here directly — this authorization server is up, it answers
# 4xx for an audience it does not issue for, and its error_description
# really does carry the sentinel, so section 8's absence check cannot pass
# on words that were never written.
# The client secret and the subject token go in the environment, never in
# argv: argv is world-readable in the process table.
REJECTION="$(PROBE_CLIENT_SECRET="$OBO_CLIENT_SECRET" PROBE_SUBJECT_TOKEN="$TOKEN" \
	python3 - "$ISSUER/token" "$OBO_CLIENT_ID" "$NOWHERE_AUD" <<'PY'
import base64, json, os, sys, urllib.error, urllib.parse, urllib.request
url, client_id, audience = sys.argv[1:4]
client_secret = os.environ["PROBE_CLIENT_SECRET"]
subject = os.environ["PROBE_SUBJECT_TOKEN"]
form = urllib.parse.urlencode({
    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
    "subject_token": subject,
    "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
    "audience": audience,
}).encode()
basic = urllib.parse.quote(client_id) + ":" + urllib.parse.quote(client_secret)
req = urllib.request.Request(url, data=form, headers={
    "Content-Type": "application/x-www-form-urlencoded",
    "Authorization": "Basic " + base64.b64encode(basic.encode()).decode(),
})
try:
    urllib.request.urlopen(req)
except urllib.error.HTTPError as e:
    body = json.load(e)
    print(e.code, body.get("error", ""), body.get("error_description", ""))
PY
)"
echo "$REJECTION" | grep -q '^4[0-9][0-9] invalid_target ' || fail "the issuer did not answer 4xx invalid_target for an unlisted audience, so a rejected exchange is indistinguishable from an unreachable one"
echo "$REJECTION" | grep -q "never-in-a-ledger" || fail "the issuer's rejection carried no error_description sentinel, so the absence check in section 8 would prove nothing"
echo "rejected exchange: the issuer answered 4xx invalid_target in its own words — ok"

# 7. The issuer is unreachable: the same fixed reason for a different cause.
#    Nothing has ever listened on this resource's token endpoint, which is
#    what separates it from the rejection above.
if python3 -c "import socket; socket.create_connection(('127.0.0.1', $DOWN_PORT), 1).close()" >/dev/null 2>&1; then
	fail "something is listening on the unreachable issuer's port, so this case proves nothing"
fi
run obo-unreachable "call whoami" --token "$TOKEN"
echo "$OUT" | grep -q "finished: failed" || fail "an unreachable issuer must fail the step"
echo "$AUDIT" | grep -q "step call (agent obo-unreachable) failed — tool proxy start failed" || fail "unreachable issuer not recorded as a start failure"
grep -q 'msg="upstream connect failed".*resource=obo-down class=other' "$WORK/agenthof.err" || fail "the operational log does not name obo-down as the resource that could not be reached"
echo "unreachable issuer: nothing listened, and the log names obo-down — ok"

# 8. Nothing secret, and nothing the issuer said, reached anywhere it must
#    not. An absence proves something only where the places searched are
#    populated and the on-behalf-of call really happened, so both are
#    asserted first — and the issuer's token log, whose write is
#    best-effort, must actually name the tokens to grep for.
grep -rqF "acting as: u-dana" "$WORK/artifacts" || fail "no artifact carries the upstream's answer, so the absence checks would search an empty tree"
[ "$(find "$WORK/logs" -name '*.jsonl' | wc -l | tr -d ' ')" -ge 9 ] || fail "fewer ledgers than runs, so the absence checks would search an incomplete tree"
# The operational log is the widest of the three, and the runs above asked
# for every debug record there is: an empty or info-only one would make the
# grep across it worthless.
[ -s "$WORK/agenthof.err" ] || fail "the operational log is empty, so the absence checks would search nothing"
grep -q "level=DEBUG" "$WORK/agenthof.err" || fail "the operational log carries no debug records, so the absence checks would search only what info-level says"
[ -s "$WORK/control.jsonl" ] || fail "the control log is empty, so the absence checks would search nothing there"
[ -s "$WORK/apply-bad.out" ] || fail "the apply-rejection output is empty, so the absence checks would search nothing there"
no_leak "$TOKEN" "the subject token"
no_leak "$RS_TOKEN" "the resource-audienced subject token"
no_leak "never-in-a-ledger" "the issuer's error_description"
[ -s "$WORK/issued.jsonl" ] || fail "the issuer logged no exchanged token"
grep -q '"sub":"u-dana"' "$WORK/issued.jsonl" || fail "the issuer exchanged for nobody in particular"
grep -q "\"aud\":\"$UP_AUD\"" "$WORK/issued.jsonl" || fail "the issuer exchanged for no token audienced to the upstream"
# Tokens are base64url: no whitespace, so word-splitting the output is safe,
# and a plain for loop (not a piped while) runs no_leak in THIS shell, where
# its fail exits the script.
EXCHANGED=0
for exchanged in $(python3 -c 'import json, sys; [print(json.loads(l)["token"]) for l in open(sys.argv[1]) if l.strip()]' "$WORK/issued.jsonl"); do
	no_leak "$exchanged" "an exchanged token"
	EXCHANGED=$((EXCHANGED + 1))
done
# At least one, never zero: the loop above proves nothing over an empty
# list. The floor stays at one on purpose — how MANY tokens exist is the
# broker cache's business, and the greps just above already pin what they
# are (u-dana's, audienced to the upstream).
[ "$EXCHANGED" -ge 1 ] || fail "the issuer's token log named no exchanged token, so the absence check above proved nothing"
echo "exchanged tokens: $EXCHANGED (none reached a ledger, artifact, log, or output)"
echo "e2e-obo-local: PASS"
