#!/usr/bin/env bash
# acceptance-lib: what the acceptance runs share — the ledger/audit helpers
# and the generator of the combined-scenario config — for
# scripts/e2e-acceptance-local.sh (hermetic, scripted), the scripts that
# source it (e2e-acceptance-llm-local.sh, showcase-combined.sh) and
# scripts/e2e-acceptance.sh (real rootless podman). Sourced, never run: it
# defines functions and nothing else — no options, no traps, no files.
# The helpers read the sourcing script's globals at CALL time: WORK (its
# scratch dir), ISSUER (the stub issuer's origin), OUTS (its array of
# captured outputs), ME (its name) and its fail function.

# field FILE TYPE KEY [STATUS]: print KEY of every TYPE event (optionally only
# those with STATUS) in a ledger, one per line; a dict value is printed as JSON.
field() {
	python3 - "$1" "$2" "$3" "${4:-}" <<'PY'
import json, sys
path, typ, key, status = sys.argv[1:5]
for line in open(path):
    if not line.strip():
        continue
    e = json.loads(line)
    if e.get("type") != typ or (status and e.get("status") != status):
        continue
    v = e.get(key, "")
    print(v if not isinstance(v, dict) else json.dumps(v))
PY
}
# count FILE TYPE [STATUS]: how many such events.
count() { field "$1" "$2" type "${3:-}" | wc -l | tr -d ' '; }
# tool_field FILE TOOL KEY: KEY of every tool_call event for TOOL.
tool_field() {
	python3 - "$1" "$2" "$3" <<'PY'
import json, sys
path, tool, key = sys.argv[1:4]
for line in open(path):
    if not line.strip():
        continue
    e = json.loads(line)
    if e.get("type") != "tool_call" or e.get("tool") != tool:
        continue
    v = e.get(key, "")
    print(v if not isinstance(v, dict) else json.dumps(v))
PY
}
# bound FILE RUN SUBJECT [PARENT]: every event in FILE carries a binding for
# RUN invoked by SUBJECT; with PARENT, every event is also linked under
# PARENT at depth 1, and without it none is linked to anything. Prints how
# many events it checked; fails unless all of them pass and there is one.
bound() {
	if ! python3 - "$1" "$2" "$3" "${4:-}" >"$WORK/bound.out" <<'PY'; then
import json, sys
path, run, subject, parent = sys.argv[1:5]
n = 0
for i, line in enumerate(open(path), 1):
    if not line.strip():
        continue
    b = json.loads(line).get("binding") or {}
    got = ((b.get("invoker") or {}).get("subject"), b.get("run_id"), b.get("parent_run_id", ""), b.get("depth", 0))
    want = (subject, run, parent, 1 if parent else 0)
    if got != want:
        print("event on line %d is bound as (subject, run, parent, depth) %r, not %r" % (i, got, want))
        sys.exit(1)
    n += 1
if n < 1:
    print("no events at all")
    sys.exit(1)
print(n)
PY
		fail "run $2 is not bound to $3 throughout: $(cat "$WORK/bound.out")"
	fi
	echo "bound: run $2 — $(cat "$WORK/bound.out") events, every one invoked by $3${4:+, linked under $4 at depth 1}"
}
# Output is captured into a variable before it is grepped — through a
# here-string, never piped straight in: under `set -o pipefail` a `grep -q`
# that matches early kills the writer with SIGPIPE and fails the pipeline —
# inverting a negative assertion, the one thing these scripts must never do.
out_of() { "$@" || true; }
# ere_escape: a literal string made safe inside a grep -E pattern.
ere_escape() { printf '%s' "$1" | sed 's/[][\\.*^$+?(){}|]/\\&/g'; }
# mint SUB AUD [GROUPS]: a subject token from the stub issuer (a real IdP
# mints through a login flow). Printed once, kept in a shell variable, never
# exported: the children act for the same human through the gateway, not
# through the environment.
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
# verify_run ID WHAT: `audit verify` exits 0 and names the head.
verify_run() {
	local v
	if ! v="$("$WORK/agenthof" audit verify "$1" --log-dir "$WORK/logs")"; then
		echo "$v"
		fail "$2 ($1): audit verify failed"
	fi
	OUTS+=("$v")
	echo "$v"
	grep -Eq "^head: [0-9a-f]{64} \([0-9]+ events\)$" <<<"$v" || fail "$2 ($1): audit verify reported no head"
}
# no_leak VALUE WHAT...: VALUE must appear in no ledger, artifact, control
# log, process log, agenthof operational log, or captured output. Never
# prints VALUE. (The upstream's "acting as: u-dana" and the step input are
# NOT secrets: they are in the artifact and the tool_call preview by design.
# provider.jsonl and issued.jsonl are not searched on purpose: the first
# records the injected host key, which is the model door's proof that the key
# was injected upstream; the second is the issuer's own list of what it
# issued, which is what the leak section searches FOR. Known limit: the per-run
# gateway token agenthof mints for the agent is not searched here — the harness
# never sees it, so no claim is made that it is checked.) The caller writes
# $WORK/outs.txt (the captured outputs) before calling.
no_leak() {
	[ -n "$1" ] || fail "${*:2} is empty, so searching for it would prove nothing"
	local value="$1"
	shift
	if grep -rqF -- "$value" "$WORK/logs" "$WORK/artifacts" "$WORK/control.jsonl" "$WORK"/*.err 2>/dev/null; then
		fail "$* reached a ledger, an artifact, the control log, or a process log"
	fi
	if grep -qF -- "$value" "$WORK/outs.txt"; then
		fail "$* reached agenthof's output"
	fi
}
# A JWT's payload and signature segments are searched alone too, so a copy
# cut before the token's start or capped before its end is still caught.
jwt_payload() {
	local rest="${1#*.}"
	printf '%s' "${rest%%.*}"
}

# --- the combined-scenario config -------------------------------------------
# acceptance_config DIR: write the combined scenario's Agenthof config into
# DIR from scratch — every door in one agent, a sub-agent the supervisor
# launches, two variants of the main agent for the recorded refusals, their
# workflows, and the two roles. What differs between a hermetic run and a
# real-podman run is where things listen, so that is what the AC_* variables
# carry; everything else is the scenario itself and is the same text in both:
#   AC_SOCK_DIR        refbox_socket_dir; the agents' socket directory (required)
#   AC_AGENT_SOCK      the main agent's socket file name          (default lc.sock)
#   AC_PROVIDER_URL    the model route's endpoint                 (required)
#   AC_PROVIDER_MODEL  the provider-side name of the fast route   (default fast)
#   AC_UP_URL          the on-behalf-of tool's url                (required)
#   AC_ISSUER          the token_endpoint's origin                (required)
#   AC_UP_AUD          the audience the exchange is for           (required)
#   AC_BRIDGE_URL      the bridged tool's unix:// url             (required)
#   AC_EXEC_URL        the main agents' exec.url                  (required)
#   AC_SUP_URL         spawn_supervisor                           (required)
#   AC_STEP_TIMEOUT    step_timeout                               (default 3m)
acceptance_config() {
	local dir="$1"
	: "${AC_SOCK_DIR:?acceptance_config: set AC_SOCK_DIR}" "${AC_PROVIDER_URL:?acceptance_config: set AC_PROVIDER_URL}"
	: "${AC_UP_URL:?acceptance_config: set AC_UP_URL}" "${AC_ISSUER:?acceptance_config: set AC_ISSUER}" "${AC_UP_AUD:?acceptance_config: set AC_UP_AUD}"
	: "${AC_BRIDGE_URL:?acceptance_config: set AC_BRIDGE_URL}" "${AC_EXEC_URL:?acceptance_config: set AC_EXEC_URL}" "${AC_SUP_URL:?acceptance_config: set AC_SUP_URL}"
	local model="${AC_PROVIDER_MODEL:-fast}" step_timeout="${AC_STEP_TIMEOUT:-3m}"
	mkdir -p "$dir/agents" "$dir/workflows" "$dir/roles"
	cat >"$dir/gateway.yaml" <<EOF
refbox_socket_dir: $AC_SOCK_DIR
models:
  fast:
    endpoint: $AC_PROVIDER_URL
    model: $model
    api_key_env: AGENTHOF_GATEWAY_KEY
defaults:
  model: fast
tools:
  obo-upstream:
    kind: mcp
    url: $AC_UP_URL
    credential_source: static_env
    grant_type: token_exchange
    client_auth: client_secret_basic
    token_endpoint: $AC_ISSUER/token
    audience: $AC_UP_AUD
    client_id_env: OBO_CLIENT_ID
    client_secret_env: OBO_CLIENT_SECRET
  stdio-tool:
    kind: mcp
    url: $AC_BRIDGE_URL
    runtime: refbridge
    credential_source: static_env
    token_env: E2E_TOOL_TOKEN
spawn_supervisor: $AC_SUP_URL
spawn:
  max_depth: 1
  max_parallel: 2
  max_total_spawns: 3
step_timeout: $step_timeout
EOF
	local may_spawn="may_spawn:
  - role: acceptance-worker
    workflow: acceptance-sub"
	ac_main_agent "$dir" acceptance env "$may_spawn"
	ac_main_agent "$dir" acceptance-noexec true "$may_spawn"   # the driver asks for env; this allowlist says otherwise
	ac_main_agent "$dir" acceptance-nospawn env ""              # the driver asks to spawn; nothing is on may_spawn
	# The sub-agent's configured endpoint is never dialed under spawn — the
	# supervisor's sockets win — so it names a socket nothing serves: a child
	# that reached it would fail loudly instead of quietly running elsewhere.
	cat >"$dir/agents/acceptance-sub.yaml" <<EOF
name: acceptance-sub
description: the sub-agent, one governed model call under the delegation binding (e2e)
model: fast
instruction: Answer the input with one model call.
output: reply
execution: fronted
endpoint: unix://$AC_SOCK_DIR/unused.sock
EOF
	cat >"$dir/workflows/acceptance-sub.yaml" <<EOF
name: acceptance-sub
description: one governed model call in a child run
steps:
  - name: answer
    agent: acceptance-sub
EOF
	cat >"$dir/roles/acceptance-operator.yaml" <<EOF
name: acceptance-operator
description: Runs the acceptance workflows
workflows: [acceptance, acceptance-noexec, acceptance-nospawn]
allowed_groups: ["acceptance-users"]
control: [apply]
EOF
	cat >"$dir/roles/acceptance-worker.yaml" <<EOF
name: acceptance-worker
description: Runs the sub-agent workflow
workflows: [acceptance-sub]
allowed_groups: ["acceptance-users"]
EOF
}
# ac_main_agent DIR NAME EXE MAY_SPAWN: one variant of the main agent (every
# door, one step) and its one-step workflow. EXE is the one allowlisted
# executable; MAY_SPAWN is the may_spawn block, or "" for none.
ac_main_agent() {
	local dir="$1" name="$2" exe="$3" may_spawn="$4"
	{
		cat <<EOF
name: $name
description: the LangChain agent, every door in one step (e2e)
model: fast
instruction: Drive every door once and report.
output: report
execution: fronted
endpoint: unix://$AC_SOCK_DIR/${AC_AGENT_SOCK:-lc.sock}
tools:
  - resource: obo-upstream
    mode: all
  - resource: stdio-tool
    mode: all
exec:
  runtime: refexec
  url: $AC_EXEC_URL
  timeout: 30s
  allow:
    - exe: $exe
EOF
		[ -z "$may_spawn" ] || printf '%s\n' "$may_spawn"
	} >"$dir/agents/$name.yaml"
	cat >"$dir/workflows/$name.yaml" <<EOF
name: $name
description: one step through $name
steps:
  - name: drive
    agent: $name
EOF
}
