#!/usr/bin/env bash
# e2e-acceptance-local: the combined acceptance run, hermetically. One real
# LangChain agent (examples/langchain-agent), in ONE governed run of the REAL
# agenthof binary, drives every door — a model call, a first-hand exec
# through refexec, an on-behalf-of HTTP tool call, a stdio tool call fronted
# by refbridge, and two parallel sub-agent runs whose children each make a
# governed model call of their own — and the audit shows all of it bound to
# the invoking human, every ledger verified. No container runtime: the
# provider is a loopback stand-in, the IdP and the per-user upstream are
# examples/obo-idp and examples/obo-upstream, refbridge fronts
# examples/stdio-tool over a Unix socket, and refexec and refspawn are the
# stand-ins built from their own test trees, in which a fake podman runs each
# "compartment" as a host process. This proves GOVERNANCE and AUDIT. It
# proves nothing about containment or egress — the compartments here are
# host processes; the walls are the podman proofs' job (scripts/e2e-*.sh
# without -local).
# Asserts: the combined run succeeds under a verified OIDC invoker and its
# ledger carries one model_call, one runtime-attested exec, one tool_call
# with auth_mode token_exchange, one runtime-attested tool_call through
# refbridge and two succeeded spawn events; the step artifact carries the
# upstream's "acting as: <sub>" (the on-behalf-of proof, with the issuer's
# token log), the provider's nonce'd reply, exactly the allowlisted
# variable from the exec, and the bridged echo; each child has its own
# ledger linked to the parent (parent_run_id, depth 1, the same human) with
# its own model_call, and the two children overlapped in time; audit verify
# passes on the parent and on each child separately and investigate --run
# shows the tree; an off-allowlist exec and a may_spawn-denied spawn are
# recorded refusals on runs of their own; and no secret — the subject token,
# every exchanged token, the broker's client secret, the bridged tool's
# credential, the provider key — reaches any ledger, artifact, log, or
# output. Requires go and a python with examples/langchain-agent/
# requirements.txt installed (PYTHON=... selects it; default python3). Runs
# on macOS and Linux.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PYTHON="${PYTHON:-python3}"

"$PYTHON" -c 'import langchain_openai, httpx, mcp' 2>/dev/null || {
	echo "e2e-acceptance-local: $PYTHON lacks the pinned deps; run: $PYTHON -m pip install -r examples/langchain-agent/requirements.txt"
	exit 1
}

# Short on purpose: Unix socket paths have a small OS length limit. Every
# socket directory is separate and mode 0700 (mktemp makes them so): the
# gateway's, the bridge's, the exec runtime's, the supervisor's, and the
# spawn root — the runtimes and the gateway all insist on it, and none may
# sit inside another.
SOCK_DIR="$(mktemp -d /tmp/ac.XXXXXX)"
BRIDGE_DIR="$(mktemp -d /tmp/ac.XXXXXX)"
EXEC_DIR="$(mktemp -d /tmp/ac.XXXXXX)"
SUP_DIR="$(mktemp -d /tmp/ac.XXXXXX)"
SPAWN_ROOT="$(mktemp -d /tmp/ac.XXXXXX)"
VOLROOT="$(mktemp -d /tmp/ac.XXXXXX)"
WORK="$(mktemp -d /tmp/ac.XXXXXX)"
PIDS=()
cleanup() {
	# ${PIDS[@]+...}: an empty array under set -u is an error on bash 3.2 (macOS).
	# wait after kill: otherwise bash prints a "Terminated" line per child at exit.
	for p in ${PIDS[@]+"${PIDS[@]}"}; do
		kill "$p" >/dev/null 2>&1 || true
		wait "$p" >/dev/null 2>&1 || true
	done
	rm -rf "$SOCK_DIR" "$BRIDGE_DIR" "$EXEC_DIR" "$SUP_DIR" "$SPAWN_ROOT" "$VOLROOT" "$WORK"
}
trap cleanup EXIT
unset AGENTHOF_TOKEN || true

fail() {
	echo "e2e-acceptance-local: FAIL — $*"
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
wait_socket() { # $1 = socket path, $2 = what, $3 = log to show on failure
	for i in $(seq 1 60); do
		[ -S "$1" ] && return 0
		[ "$i" = 60 ] && { cat "$3" >&2 || true; fail "$2 never appeared"; }
		sleep 0.5
	done
}
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
# Output is captured into a variable before it is grepped, never piped
# straight in: under `set -o pipefail` a `grep -q` that matches early kills
# the writer with SIGPIPE and fails the pipeline — inverting a negative
# assertion, the one thing this script must never do.
out_of() { "$@" || true; }
# ere_escape: a literal string made safe inside a grep -E pattern.
ere_escape() { printf '%s' "$1" | sed 's/[][\\.*^$+?(){}|]/\\&/g'; }
# starved: no secret this script will export later is in the environment
# NOW. Called right before the stand-ins start, because the refspawn
# stand-in's fake podman starts every child agent with its own environment:
# a secret exported earlier would be inherited by every "compartment".
starved() {
	for v in AGENTHOF_GATEWAY_KEY OBO_CLIENT_SECRET E2E_TOOL_TOKEN; do
		[ -z "${!v:-}" ] || fail "$v is exported before the stand-ins start; every child agent would inherit it"
	done
}

go build -o "$WORK/agenthof" ./cmd/agenthof
go build -o "$WORK/obo-idp" ./examples/obo-idp
go build -o "$WORK/obo-upstream" ./examples/obo-upstream
go build -o "$WORK/refbridge" ./deploy/refbridge
go build -o "$WORK/stdio-tool" ./examples/stdio-tool
go test -c -o "$WORK/refexec-stub" ./deploy/refexec
go test -c -o "$WORK/refspawn-stub" ./deploy/refspawn

NONCE="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
OUTS=()
PROVIDER_PORT="$(free_port)"
IDP_PORT="$(free_port)"
UP_PORT="$(free_port)"
ISSUER="http://127.0.0.1:$IDP_PORT"
UP_AUD="https://obo-upstream.example"
IDP_SECRET="idp-side-secret-$NONCE"
TOOL_SECRET="tool-secret-$NONCE"
GATEWAY_KEY="host-side-dummy-key-$NONCE"
export OBO_CLIENT_ID=agenthof-broker   # an id, not a secret: the broker reads it by name

# --- 1. The stand-ins, BEFORE any secret is exported (see starved). The
# IdP's own secret is a per-command variable on its line, nowhere else.
starved
python3 scripts/fake-openai-provider.py --bind "127.0.0.1:$PROVIDER_PORT" --reply "governed:$NONCE" --log "$WORK/provider.jsonl" >/dev/null 2>"$WORK/provider.err" &
PIDS+=($!)
OBO_IDP_CLIENT_SECRET="$IDP_SECRET" "$WORK/obo-idp" -addr "127.0.0.1:$IDP_PORT" -client-id "$OBO_CLIENT_ID" -client-secret-env OBO_IDP_CLIENT_SECRET \
	-audiences "$UP_AUD" -subject-token-type urn:ietf:params:oauth:token-type:id_token \
	-token-log "$WORK/issued.jsonl" 2>"$WORK/idp.err" &
PIDS+=($!)
wait_port "$IDP_PORT" "obo-idp"
"$WORK/obo-upstream" -addr "127.0.0.1:$UP_PORT" -jwks-url "$ISSUER/keys" -audience "$UP_AUD" 2>"$WORK/upstream.err" &
PIDS+=($!)

# refbridge fronts the stdio tool over a Unix socket; the credential it
# materializes comes from the gateway per session, never from this script's
# environment.
cat >"$WORK/bridge.yaml" <<EOF
socket: $BRIDGE_DIR/tool.sock
command: ["$WORK/stdio-tool", "-credential-env", "DEMO_TOKEN"]
credential:
  env: DEMO_TOKEN
  materialization: env-at-spawn
env_passthrough: ["REFBRIDGE_E2E_MARKER"]
egress:
  allow: []
sessions:
  max: 4
  idle_timeout: 10m
  max_lifetime: 30m
EOF
REFBRIDGE_E2E_MARKER=1 "$WORK/refbridge" -config "$WORK/bridge.yaml" 2>"$WORK/bridge.err" &
PIDS+=($!)

# The exec runtime stand-in: its fake podman gives the command an environment
# of exactly the allowlist, so `env` prints the one marker and nothing else —
# the proof that it was refexec that ran it, and that it ran it clean.
cat >"$WORK/refexec.yaml" <<EOF
socket: $EXEC_DIR/exec.sock
image: example.test/exec:1
workspace:
  volume: acceptance-work
  path: /work
timeout: 30s
limits:
  memory: 256m
  cpus: "1"
  pids: 64
compartments:
  max: 2
env_allow: ["ACCEPTANCE_E2E_MARKER"]
EOF
ACCEPTANCE_E2E_MARKER=1 "$WORK/refexec-stub" -refexec-test-stub -config "$WORK/refexec.yaml" 2>"$WORK/refexec.err" &
PIDS+=($!)

# The sub-agent "image": the supervisor stand-in's fake podman execs this
# path with "-socket <sock> -workspace <dir>" appended. Each child is the
# same LangChain agent in its one-model-call mode, on the Python this script
# runs with.
cat >"$WORK/langchain-image" <<EOF
#!/usr/bin/env bash
exec "$PYTHON" "$ROOT/examples/langchain-agent/agent.py" --driver model --model fast "\$@"
EOF
chmod 0755 "$WORK/langchain-image"
cat >"$WORK/refspawn.yaml" <<EOF
socket: $SUP_DIR/refspawn.sock
spawn_root: $SPAWN_ROOT
images:
  acceptance-sub: $WORK/langchain-image
timeout: 10m
ready_timeout: 60s
limits:
  memory: 256m
  cpus: "1"
  pids: 64
max_compartments: 2
refexec:
  command: [$WORK/refexec-stub, -refexec-test-stub]
  image: example.test/exec:1
  timeout: 30s
  limits:
    memory: 256m
    cpus: "1"
    pids: 64
  max_compartments: 2
  env_allow: []
EOF
REFSPAWN_TEST_VOLROOT="$VOLROOT" "$WORK/refspawn-stub" -refspawn-test-stub -config "$WORK/refspawn.yaml" 2>"$WORK/refspawn.err" &
PIDS+=($!)

# The host agent: the scripted driver, every door in a fixed order.
"$PYTHON" examples/langchain-agent/agent.py -socket "$SOCK_DIR/lc.sock" --model fast --driver scripted \
	--exec-argv env --obo-tool whoami --bridge-tool echo \
	--spawn-role acceptance-worker --spawn-workflow acceptance-sub --spawns 2 2>"$WORK/agent.err" &
PIDS+=($!)

wait_port "$UP_PORT" "obo-upstream"
wait_port "$PROVIDER_PORT" "the provider stand-in"
wait_socket "$BRIDGE_DIR/tool.sock" "the bridge socket" "$WORK/bridge.err"
wait_socket "$EXEC_DIR/exec.sock" "the exec runtime socket" "$WORK/refexec.err"
wait_socket "$SUP_DIR/refspawn.sock" "the supervisor socket" "$WORK/refspawn.err"
wait_socket "$SOCK_DIR/lc.sock" "the agent socket" "$WORK/agent.err"

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
TOKEN="$(mint u-dana agenthof acceptance-users)"
[ -n "$TOKEN" ] || fail "the issuer minted no token"

# --- 2. A hermetic Agenthof config, written from scratch: every door in one
# agent, a sub-agent the supervisor launches, and two variants of the main
# agent for the recorded refusals.
mkdir -p "$WORK/config/agents" "$WORK/config/workflows" "$WORK/config/roles"
cat >"$WORK/config/gateway.yaml" <<EOF
refbox_socket_dir: $SOCK_DIR
models:
  fast:
    endpoint: http://127.0.0.1:$PROVIDER_PORT
    model: fast
    api_key_env: AGENTHOF_GATEWAY_KEY
defaults:
  model: fast
tools:
  obo-upstream:
    kind: mcp
    url: http://127.0.0.1:$UP_PORT/
    credential_source: static_env
    grant_type: token_exchange
    client_auth: client_secret_basic
    token_endpoint: $ISSUER/token
    audience: $UP_AUD
    client_id_env: OBO_CLIENT_ID
    client_secret_env: OBO_CLIENT_SECRET
  stdio-tool:
    kind: mcp
    url: unix://$BRIDGE_DIR/tool.sock
    runtime: refbridge
    credential_source: static_env
    token_env: E2E_TOOL_TOKEN
spawn_supervisor: unix://$SUP_DIR/refspawn.sock
spawn:
  max_depth: 1
  max_parallel: 2
  max_total_spawns: 3
step_timeout: 3m
EOF
main_agent() { # $1 = name, $2 = the one allowlisted exe, $3 = may_spawn block ("" for none)
	{
		cat <<EOF
name: $1
description: the LangChain agent, every door in one step (e2e)
model: fast
instruction: Drive every door once and report.
output: report
execution: fronted
endpoint: unix://$SOCK_DIR/lc.sock
tools:
  - resource: obo-upstream
    mode: all
  - resource: stdio-tool
    mode: all
exec:
  runtime: refexec
  url: unix://$EXEC_DIR/exec.sock
  timeout: 30s
  allow:
    - exe: $2
EOF
		[ -z "$3" ] || printf '%s\n' "$3"
	} >"$WORK/config/agents/$1.yaml"
	cat >"$WORK/config/workflows/$1.yaml" <<EOF
name: $1
description: one step through $1
steps:
  - name: drive
    agent: $1
EOF
}
MAY_SPAWN="may_spawn:
  - role: acceptance-worker
    workflow: acceptance-sub"
main_agent acceptance env "$MAY_SPAWN"
main_agent acceptance-noexec true "$MAY_SPAWN"   # the driver asks for env; this allowlist says otherwise
main_agent acceptance-nospawn env ""              # the driver asks to spawn; nothing is on may_spawn
# The sub-agent's configured endpoint is never dialed under spawn — the
# supervisor's sockets win — so it names a socket nothing serves: a child
# that reached it would fail loudly instead of quietly running elsewhere.
cat >"$WORK/config/agents/acceptance-sub.yaml" <<EOF
name: acceptance-sub
description: the sub-agent, one governed model call under the delegation binding (e2e)
model: fast
instruction: Answer the input with one model call.
output: reply
execution: fronted
endpoint: unix://$SOCK_DIR/unused.sock
EOF
cat >"$WORK/config/workflows/acceptance-sub.yaml" <<EOF
name: acceptance-sub
description: one governed model call in a child run
steps:
  - name: answer
    agent: acceptance-sub
EOF
cat >"$WORK/config/roles/acceptance-operator.yaml" <<EOF
name: acceptance-operator
description: Runs the acceptance workflows
workflows: [acceptance, acceptance-noexec, acceptance-nospawn]
allowed_groups: ["acceptance-users"]
EOF
cat >"$WORK/config/roles/acceptance-worker.yaml" <<EOF
name: acceptance-worker
description: Runs the sub-agent workflow
workflows: [acceptance-sub]
allowed_groups: ["acceptance-users"]
EOF

# --- 3. Secrets, only now: everything that could inherit them is running.
export AGENTHOF_GATEWAY_KEY="$GATEWAY_KEY"
export OBO_CLIENT_SECRET="$IDP_SECRET"
export E2E_TOOL_TOKEN="$TOOL_SECRET"
export AGENTHOF_OIDC_ISSUER="$ISSUER"
export AGENTHOF_OIDC_CLIENT_ID=agenthof
export AGENTHOF_OIDC_SUBJECT_TOKEN_TYPE=urn:ietf:params:oauth:token-type:id_token

"$WORK/agenthof" apply --config "$WORK/config" --control-log "$WORK/control.jsonl" --as ci --groups acceptance-users
echo "apply: the combined config is valid — ok"
echo "e2e-acceptance-local: PASS"
