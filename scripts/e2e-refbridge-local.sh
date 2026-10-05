#!/usr/bin/env bash
# e2e-refbridge-local: prove the REAL agenthof binary governs a stdio MCP
# server fronted by refbridge over a Unix socket, with no container runtime.
# Two bridges run on the host: one in env-at-spawn mode fed by a static
# credential, one in respawn-on-rotation mode fed by client_credentials
# tokens minted by a stand-in endpoint that rotates every 10 seconds. A
# tool-agent (serving its step endpoint on a Unix socket, reaching the gateway
# over the gateway's Unix socket) runs the call scripts. Asserts: the step
# artifact carries the echo, the SHA-256 of the injected credential, and an
# environment of exactly the allowlist plus the credential variable; the
# ledger records each tool_call with the right auth mode and the bridge's
# first-hand attestation (argv, pid, generation, environment NAMES); the
# credential value is nowhere in the logs; within ONE step a rotated token
# reaches a respawned subprocess (attested as spawn 2); every subprocess is
# gone after its session; and a
# bridge config missing a guardrail, a relative unix:// tool url, and a
# unix:// token_endpoint are all rejected. Requires go and python3. Runs on
# macOS and Linux.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Short on purpose: Unix socket paths have a small OS length limit. The bridge
# directory is SEPARATE from the gateway socket dir (never under a dir an agent
# compartment would mount) and mode 0700, as refbridge requires.
SOCK_DIR="$(mktemp -d /tmp/rb.XXXXXX)"
BRIDGE_DIR="$(mktemp -d /tmp/rbb.XXXXXX)"
chmod 0700 "$BRIDGE_DIR"
WORK="$(mktemp -d)"
PIDS=()
cleanup() {
	for p in ${PIDS[@]+"${PIDS[@]}"}; do
		kill "$p" >/dev/null 2>&1 || true
		wait "$p" >/dev/null 2>&1 || true
	done
	rm -rf "$SOCK_DIR" "$BRIDGE_DIR" "$WORK"
}
trap cleanup EXIT
unset AGENTHOF_TOKEN || true

fail() {
	echo "e2e-refbridge-local: FAIL — $*"
	exit 1
}
# A token log view that never prints a token value: count, client ids, and a
# SHA-256 prefix per minted token.
tokens_redacted() {
	python3 - "$WORK/tokens.jsonl" <<'PY' || true
import hashlib, json, sys
lines = open(sys.argv[1], encoding="utf-8").read().splitlines()
print("minted tokens: %d" % len(lines))
for n, line in enumerate(lines, 1):
    t = json.loads(line)
    print("  %d: client_id=%s sha256=%s..." % (n, t["client_id"], hashlib.sha256(t["token"].encode()).hexdigest()[:12]))
PY
}
# no_leak VALUE WHAT...: VALUE must appear in no ledger, artifact, process
# log, or captured agenthof stdout. Never prints VALUE.
no_leak() {
	local value="$1"
	shift
	if grep -rqF -- "$value" "$WORK/logs" "$WORK/artifacts" "$WORK/bridge-static.err" "$WORK/bridge-rot.err" "$WORK/agent.err" "$WORK/tokens.err"; then
		fail "$* reached the ledger, an artifact, or a process log"
	fi
	if printf '%s\n' "${OUT:-}" "${AUDIT:-}" "${OUT2:-}" "${AUDIT2:-}" | grep -qF -- "$value"; then
		fail "$* reached agenthof's output"
	fi
}
# ere_escape: a literal string made safe inside a grep -E pattern.
ere_escape() { printf '%s' "$1" | sed 's/[][\\.*^$+?(){}|]/\\&/g'; }
sha() { python3 -c 'import hashlib, sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())' "$1"; }
command -v pgrep >/dev/null 2>&1 || fail "pgrep is required to prove every child is torn down"

go build -o "$WORK/agenthof" ./cmd/agenthof
go build -o "$WORK/refbridge" ./deploy/refbridge
go build -o "$WORK/stdio-tool" ./examples/stdio-tool
go build -o "$WORK/tool-agent" ./examples/tool-agent

ARGV_JSON="\"command\":[\"$WORK/stdio-tool\",\"-credential-env\",\"DEMO_TOKEN\"]"
ENV_JSON='"env_names":["DEMO_TOKEN","REFBRIDGE_E2E_MARKER"]'
ATTESTED="\\[runtime-attested: refbridge $(ere_escape "$WORK/stdio-tool") -credential-env DEMO_TOKEN pid [0-9]+"

NONCE="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"

# --- the rotating token stand-in (lifetime 10s → the broker re-mints after 9s)
TPORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
python3 scripts/fake-token-endpoint.py --bind "127.0.0.1:$TPORT" --lifetime 10 --log "$WORK/tokens.jsonl" >/dev/null 2>"$WORK/tokens.err" &
PIDS+=($!)
for i in $(seq 1 30); do
	python3 -c "import socket; socket.create_connection(('127.0.0.1', $TPORT), 1).close()" >/dev/null 2>&1 && break
	[ "$i" = 30 ] && fail "token endpoint never listened"
	sleep 0.2
done

# --- two bridges: static (env-at-spawn) and rotating (respawn-on-rotation)
bridge_config() { # $1 = socket file, $2 = materialization
	cat <<EOF
socket: $BRIDGE_DIR/$1
command: ["$WORK/stdio-tool", "-credential-env", "DEMO_TOKEN"]
credential:
  env: DEMO_TOKEN
  materialization: $2
env_passthrough: ["REFBRIDGE_E2E_MARKER"]
egress:
  allow: []
sessions:
  max: 4
  idle_timeout: 10m
  max_lifetime: 30m
EOF
}
bridge_config tool.sock env-at-spawn >"$WORK/bridge-static.yaml"
bridge_config tool-rot.sock respawn-on-rotation >"$WORK/bridge-rot.yaml"

# Config is law: a bridge config without a materialization mode is refused.
sed '/materialization:/d' "$WORK/bridge-static.yaml" >"$WORK/bridge-bad.yaml"
if "$WORK/refbridge" -config "$WORK/bridge-bad.yaml" -check >/dev/null 2>"$WORK/check.err"; then
	fail "a bridge config without credential.materialization was accepted"
fi
grep -q "credential.materialization" "$WORK/check.err" || fail "the refusal did not name credential.materialization"
[ "$("$WORK/refbridge" -config "$WORK/bridge-static.yaml" -check)" = "egress=none" ] || fail "-check did not print egress=none"

# REFBRIDGE_E2E_MARKER is allowlisted and must reach the child; LEAKED_SECRET
# is not and must never appear in the child's environment.
REFBRIDGE_E2E_MARKER=1 LEAKED_SECRET="not-for-the-child-$NONCE" "$WORK/refbridge" -config "$WORK/bridge-static.yaml" 2>"$WORK/bridge-static.err" &
PIDS+=($!)
REFBRIDGE_E2E_MARKER=1 LEAKED_SECRET="not-for-the-child-$NONCE" "$WORK/refbridge" -config "$WORK/bridge-rot.yaml" 2>"$WORK/bridge-rot.err" &
PIDS+=($!)
"$WORK/tool-agent" -socket "$SOCK_DIR/agent.sock" 2>"$WORK/agent.err" &
PIDS+=($!)
for i in $(seq 1 60); do
	[ -S "$BRIDGE_DIR/tool.sock" ] && [ -S "$BRIDGE_DIR/tool-rot.sock" ] && [ -S "$SOCK_DIR/agent.sock" ] && break
	[ "$i" = 60 ] && {
		cat "$WORK/bridge-static.err" "$WORK/bridge-rot.err" "$WORK/agent.err" || true
		fail "sockets never appeared"
	}
	sleep 0.5
done
[ "$(python3 -c 'import os, sys; print(oct(os.stat(sys.argv[1]).st_mode & 0o777))' "$BRIDGE_DIR/tool.sock")" = "0o600" ] || fail "bridge socket is not mode 0600"

# --- a hermetic Agenthof config (written from scratch: no sed -i on macOS)
mkdir -p "$WORK/config/agents" "$WORK/config/workflows" "$WORK/config/roles"
cat >"$WORK/config/gateway.yaml" <<EOF
refbox_socket_dir: $SOCK_DIR
models:
  fast:
    endpoint: http://127.0.0.1:9/v1
    model: fast
    api_key_env: AGENTHOF_GATEWAY_KEY
defaults:
  model: fast
tools:
  stdio-tool:
    kind: mcp
    url: unix://$BRIDGE_DIR/tool.sock
    runtime: refbridge
    credential_source: static_env
    token_env: E2E_TOOL_TOKEN
  stdio-tool-rot:
    kind: mcp
    url: unix://$BRIDGE_DIR/tool-rot.sock
    runtime: refbridge
    credential_source: static_env
    grant_type: client_credentials
    client_auth: client_secret_basic
    issuer: http://127.0.0.1:$TPORT
    token_endpoint: http://127.0.0.1:$TPORT/token
    client_id_env: E2E_CLIENT_ID
    client_secret_env: E2E_CLIENT_SECRET
EOF
cat >"$WORK/config/agents/bridge-user.yaml" <<EOF
name: bridge-user
description: Calls a bridged stdio MCP server through the tool door (e2e)
model: fast
instruction: Run the call script.
output: reply
execution: fronted
endpoint: unix://$SOCK_DIR/agent.sock
tools:
  - resource: stdio-tool
    mode: all
EOF
cat >"$WORK/config/agents/bridge-rot.yaml" <<EOF
name: bridge-rot
description: Same agent, granted the rotating-credential bridge (e2e)
model: fast
instruction: Run the call script.
output: reply
execution: fronted
endpoint: unix://$SOCK_DIR/agent.sock
tools:
  - resource: stdio-tool-rot
    mode: all
EOF
cat >"$WORK/config/workflows/bridge-demo.yaml" <<EOF
name: bridge-demo
description: One step through the bridged stdio server
steps:
  - name: call
    agent: bridge-user
EOF
cat >"$WORK/config/workflows/bridge-rotation.yaml" <<EOF
name: bridge-rotation
description: Two calls in one step, across a token rotation
steps:
  - name: call
    agent: bridge-rot
EOF
cat >"$WORK/config/roles/bridge-operator.yaml" <<EOF
name: bridge-operator
description: Runs the refbridge e2e workflows
workflows: [bridge-demo, bridge-rotation]
allowed_groups: ["bridge-users"]
control: [apply]
EOF

# Credentials live with the HOST agenthof process only.
export E2E_TOOL_TOKEN="tool-secret-$NONCE"
export E2E_CLIENT_ID="e2e-client"
export E2E_CLIENT_SECRET="e2e-client-secret-$NONCE"
export AGENTHOF_GATEWAY_KEY="host-side-dummy-key-$NONCE"   # the model route is never called; the key only lets it resolve

"$WORK/agenthof" apply --config "$WORK/config" --control-log "$WORK/control.jsonl" --as ci --groups bridge-users

# Config is law at apply too: a relative unix:// url and a unix:// token_endpoint are rejected.
mkdir -p "$WORK/badcfg" && cp -R "$WORK/config/." "$WORK/badcfg/"
python3 - "$WORK/badcfg/gateway.yaml" <<'EOF'
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read().replace("url: unix:///", "url: unix://", 1)
open(p, "w", encoding="utf-8").write(s)
EOF
if "$WORK/agenthof" apply --config "$WORK/badcfg" --control-log "$WORK/control.jsonl" --as ci --groups bridge-users >"$WORK/apply-bad.out" 2>&1; then
	fail "apply accepted a relative unix:// tool url"
fi
grep -q 'tool resource "stdio-tool": url must be set and https (or loopback http, or a unix:// socket)' "$WORK/apply-bad.out" || { cat "$WORK/apply-bad.out"; fail "apply did not reject the relative unix:// url with the url validation error"; }
cp -R "$WORK/config/." "$WORK/badcfg/"
python3 - "$WORK/badcfg/gateway.yaml" <<'EOF'
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s = s.replace("token_endpoint: http://127.0.0.1", "token_endpoint: unix:///tmp/never", 1)
open(p, "w", encoding="utf-8").write(s)
EOF
if "$WORK/agenthof" apply --config "$WORK/badcfg" --control-log "$WORK/control.jsonl" --as ci --groups bridge-users >"$WORK/apply-bad2.out" 2>&1; then
	fail "apply accepted a unix:// token_endpoint"
fi
grep -q 'tool resource "stdio-tool-rot": token_endpoint must be set and https (or loopback http)' "$WORK/apply-bad2.out" || { cat "$WORK/apply-bad2.out"; fail "apply did not reject the unix:// token_endpoint with the token_endpoint validation error"; }

# 1. Static credential, env-at-spawn: echo, the credential fingerprint, and a
#    clean environment (allowlist + DEMO_TOKEN; LEAKED_SECRET absent).
OUT="$("$WORK/agenthof" run bridge-operator bridge-demo --input "call echo hello-$NONCE; call credential; call environment" \
	--as ci --groups bridge-users --config "$WORK/config" \
	--log-dir "$WORK/logs" --artifact-dir "$WORK/artifacts")"
echo "$OUT"
echo "$OUT" | grep -q "finished: succeeded" || fail "bridge-demo did not succeed"
RUNID="$(echo "$OUT" | sed -n 's/^run \(r-[a-f0-9]*\) finished.*/\1/p')"
AUDIT="$("$WORK/agenthof" audit "$RUNID" --log-dir "$WORK/logs" --control-log "$WORK/control.jsonl")"
echo "$AUDIT"
echo "$AUDIT" | grep -q "ledger integrity: verified" || fail "ledger not verified"
for tool in echo credential environment; do
	echo "$AUDIT" | grep -Eq "tool $tool — args [0-9a-f]{8} \(static_env\)" || fail "no succeeded tool_call for $tool"
	# The bridge's first-hand attestation is on every call: audit renders it,
	# the ledger carries the child's argv, pid, generation and env NAMES.
	echo "$AUDIT" | grep -Eq "tool $tool — args [0-9a-f]{8} \(static_env\) $ATTESTED spawn 1\]" || fail "no runtime attestation rendered for $tool"
done
[ "$(grep -c '"runtime_attestation":{"runtime":"refbridge"' "$WORK/logs/$RUNID.jsonl")" = 3 ] || fail "want three attested tool_call events in the ledger"
[ "$(grep -cF "$ARGV_JSON" "$WORK/logs/$RUNID.jsonl")" = 3 ] || fail "want the child's exact argv attested on all three tool_call events"
[ "$(grep -cF "$ENV_JSON" "$WORK/logs/$RUNID.jsonl")" = 3 ] || fail "want env_names of exactly the allowlist plus the credential on all three tool_call events"
if grep -q "LEAKED_SECRET" "$WORK/logs/$RUNID.jsonl"; then fail "a non-allowlisted variable was attested in the child's environment"; fi
EXPECTED="$(printf 'hello-%s\n%s\nDEMO_TOKEN,REFBRIDGE_E2E_MARKER' "$NONCE" "$(sha "$E2E_TOOL_TOKEN")")"
ART="$WORK/artifacts/$(sha "$EXPECTED")"
[ -f "$ART" ] || { ls "$WORK/artifacts"; fail "no artifact with the expected content's hash (the child's env or credential differed)"; }
[ "$(cat "$ART")" = "$EXPECTED" ] || fail "artifact differs from the expected three lines"
no_leak "$E2E_TOOL_TOKEN" "the static credential value"
if grep -q "LEAKED_SECRET" "$ART"; then fail "a non-allowlisted variable reached the child's environment"; fi
echo "static: fingerprint, clean environment, three tool_call lines — ok"

# 2. Rotating credential, respawn-on-rotation, inside ONE step: the second
#    call, after the broker re-minted, reaches a child holding the NEW token.
OUT2="$("$WORK/agenthof" run bridge-operator bridge-rotation --input "call credential; sleep 10; call credential" \
	--as ci --groups bridge-users --config "$WORK/config" \
	--log-dir "$WORK/logs" --artifact-dir "$WORK/artifacts")"
echo "$OUT2"
echo "$OUT2" | grep -q "finished: succeeded" || fail "bridge-rotation did not succeed"
RUNID2="$(echo "$OUT2" | sed -n 's/^run \(r-[a-f0-9]*\) finished.*/\1/p')"
AUDIT2="$("$WORK/agenthof" audit "$RUNID2" --log-dir "$WORK/logs" --control-log "$WORK/control.jsonl")"
echo "$AUDIT2"
echo "$AUDIT2" | grep -q "ledger integrity: verified" || fail "rotation run ledger not verified"
[ "$(echo "$AUDIT2" | grep -Ec "tool credential — args [0-9a-f]{8} \(client_credentials\)")" = 2 ] || fail "want two client_credentials tool_call lines"
[ "$(wc -l <"$WORK/tokens.jsonl" | tr -d ' ')" = 2 ] || { tokens_redacted; fail "expected exactly two minted tokens (one mint per broker resolve past the 9s refresh point)"; }
TOK1="$(python3 -c 'import json, sys; print(json.loads(open(sys.argv[1]).readline())["token"])' "$WORK/tokens.jsonl")"
TOK2="$(python3 -c 'import json, sys; print(json.loads(open(sys.argv[1]).readlines()[1])["token"])' "$WORK/tokens.jsonl")"
EXPECTED2="$(printf '%s\n%s' "$(sha "$TOK1")" "$(sha "$TOK2")")"
ART2="$WORK/artifacts/$(sha "$EXPECTED2")"
[ -f "$ART2" ] || { ls "$WORK/artifacts"; fail "the rotated token did not reach a respawned child within the step"; }
no_leak "$TOK1" "the first minted token"
no_leak "$TOK2" "the second minted token"
no_leak "$E2E_CLIENT_SECRET" "the client secret"
no_leak "$E2E_TOOL_TOKEN" "the static credential value"
grep -q "credential rotated; respawning child" "$WORK/bridge-rot.err" || fail "the rotating bridge never logged a respawn"
if grep -q "respawning" "$WORK/bridge-static.err"; then fail "the env-at-spawn bridge respawned"; fi
# The respawn is first-hand evidence in the ledger, not just a bridge log line.
[ "$(grep -cF "$ARGV_JSON" "$WORK/logs/$RUNID2.jsonl")" = 2 ] || fail "want the child's exact argv attested on both rotation tool_call events"
[ "$(grep -cF "$ENV_JSON" "$WORK/logs/$RUNID2.jsonl")" = 2 ] || fail "want env_names of exactly the allowlist plus the credential on both rotation tool_call events"
python3 - "$WORK/logs/$RUNID2.jsonl" <<'PY' || fail "the rotation run's attestations are not spawn 1 then 2 of one session with a new pid"
import json, sys

def find(v):
    if isinstance(v, dict):
        if "runtime_attestation" in v:
            return v["runtime_attestation"]
        vs = v.values()
    elif isinstance(v, list):
        vs = v
    else:
        return None
    for x in vs:
        r = find(x)
        if r is not None:
            return r
    return None

atts = [a for a in (find(json.loads(l)) for l in open(sys.argv[1], encoding="utf-8") if l.strip()) if a is not None]
ok = (len(atts) == 2
      and [a["spawn"] for a in atts] == [1, 2]
      and atts[0]["session"] and atts[0]["session"] == atts[1]["session"]
      and atts[0]["pid"] != atts[1]["pid"]
      and all(a["materialization"] == "respawn-on-rotation" for a in atts))
if not ok:
    print("attestations: %s" % [(a.get("spawn"), a.get("pid"), a.get("materialization")) for a in atts], file=sys.stderr)
sys.exit(0 if ok else 1)
PY
[ "$(echo "$AUDIT2" | grep -Ec "\(client_credentials\) $ATTESTED spawn 1\]")" = 1 ] || fail "audit does not show the first child as spawn 1"
[ "$(echo "$AUDIT2" | grep -Ec "\(client_credentials\) $ATTESTED spawn 2\]")" = 1 ] || fail "audit does not show the respawned child as spawn 2"
echo "rotation: two tokens, two fingerprints, one session, spawn 1 then 2 — ok"

# 3. Per-session teardown: no stdio-tool child survives its session.
for i in $(seq 1 20); do
	pgrep -f "$WORK/stdio-tool" >/dev/null 2>&1 || break
	[ "$i" = 20 ] && { pgrep -fl "$WORK/stdio-tool"; fail "a stdio-tool child outlived its session"; }
	sleep 0.5
done
grep -q "session ended; child torn down" "$WORK/bridge-static.err" || fail "the static bridge logged no teardown"
grep -q "session ended; child torn down" "$WORK/bridge-rot.err" || fail "the rotating bridge logged no teardown"

echo "e2e-refbridge-local: PASS"
