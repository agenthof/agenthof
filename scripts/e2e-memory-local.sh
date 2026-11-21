#!/usr/bin/env bash
# e2e-memory-local: prove the REAL agenthof binary governs the memory-store MCP
# server (embedded backend, synthetic vectors, no model door) fronted by
# refbridge over a Unix socket, with no container runtime. A memory-agent
# (serving its step endpoint on a Unix socket) runs JSON scripts through the
# tool door as two agents: an upserting agent with a read-write grant and a
# search-only agent with a read-only grant. Asserts: an upsert then a search
# returns the nearest chunk first (not the first inserted) with exact scores; the ledger carries
# refbridge-attested tool_call events (argv, pid, environment NAMES) with
# integrity verified and completeness complete; the search-only agent's
# memory_upsert is refused as "tool is not available to this run" and records
# a refused tool_call with no resource or attestation; a SECOND, separate run's search finds the first run's upserts;
# a call naming an invalid collection fails with the fixed reason and its
# canary arguments reach no ledger, artifact, or log; and the credential value
# is in no ledger, artifact, or log. Requires go. Runs on macOS and Linux.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Short on purpose: Unix socket paths have a small OS length limit. The bridge
# directory is SEPARATE from the gateway socket dir and mode 0700, as
# refbridge requires; the store file lives in a 0700 directory of its own.
SOCK_DIR="$(mktemp -d /tmp/mm.XXXXXX)"
BRIDGE_DIR="$(mktemp -d /tmp/mmb.XXXXXX)"
STORE_DIR="$(mktemp -d /tmp/mms.XXXXXX)"
chmod 0700 "$BRIDGE_DIR" "$STORE_DIR"
WORK="$(mktemp -d)"
PIDS=()
cleanup() {
	for p in ${PIDS[@]+"${PIDS[@]}"}; do
		kill "$p" >/dev/null 2>&1 || true
		wait "$p" >/dev/null 2>&1 || true
	done
	rm -rf "$SOCK_DIR" "$BRIDGE_DIR" "$STORE_DIR" "$WORK"
}
trap cleanup EXIT
unset AGENTHOF_TOKEN || true

fail() {
	echo "e2e-memory-local: FAIL — $*"
	exit 1
}
# no_leak VALUE WHAT...: VALUE must appear in no ledger, artifact, process
# log, or captured agenthof stdout. Never prints VALUE.
no_leak() {
	local value="$1"
	shift
	if grep -rqF -- "$value" "$WORK/logs" "$WORK/artifacts" "$WORK/bridge.err" "$WORK/agent.err" "$WORK/control.jsonl" "$WORK/run1.err" "$WORK/run3.err" "$WORK/run4.err" "$STORE_DIR"; then
		fail "$* reached the ledger, an artifact, or a process log"
	fi
	if printf '%s\n' "${OUT1:-}" "${AUDIT1:-}" "${OUT2:-}" "${AUDIT2:-}" "${OUT3:-}" "${AUDIT3:-}" "${OUT4:-}" "${AUDIT4:-}" | grep -qF -- "$value"; then
		fail "$* reached agenthof's output"
	fi
}
# ere_escape: a literal string made safe inside a grep -E pattern.
ere_escape() { printf '%s' "$1" | sed 's/[][\\.*^$+?(){}|]/\\&/g'; }
runid_of() { printf '%s\n' "$1" | sed -n 's/^run \(r-[a-f0-9]*\) finished.*/\1/p'; }

go build -o "$WORK/agenthof" ./cmd/agenthof
go build -o "$WORK/refbridge" ./deploy/refbridge
go build -o "$WORK/memory-store" ./examples/memory-store
go build -o "$WORK/memory-agent" ./examples/memory-agent

STORE_FILE="$STORE_DIR/memory.json"
ARGV_JSON="\"command\":[\"$WORK/memory-store\",\"-backend\",\"embedded\",\"-store-file\",\"$STORE_FILE\",\"-credential-env\",\"MEMORY_TOKEN\"]"
ENV_JSON='"env_names":["MEMORY_TOKEN"]'

cat >"$WORK/bridge.yaml" <<EOF
socket: $BRIDGE_DIR/memory.sock
command: ["$WORK/memory-store", "-backend", "embedded", "-store-file", "$STORE_FILE", "-credential-env", "MEMORY_TOKEN"]
credential:
  env: MEMORY_TOKEN
  materialization: env-at-spawn
env_passthrough: []
egress:
  allow: []
sessions:
  max: 4
  idle_timeout: 10m
  max_lifetime: 30m
EOF

NONCE="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
# LEAKED_SECRET is not allowlisted and must never reach the child.
LEAKED_SECRET="not-for-the-child-$NONCE" "$WORK/refbridge" -config "$WORK/bridge.yaml" 2>"$WORK/bridge.err" &
PIDS+=($!)
"$WORK/memory-agent" -socket "$SOCK_DIR/agent.sock" 2>"$WORK/agent.err" &
PIDS+=($!)
for i in $(seq 1 60); do
	[ -S "$BRIDGE_DIR/memory.sock" ] && [ -S "$SOCK_DIR/agent.sock" ] && break
	[ "$i" = 60 ] && {
		cat "$WORK/bridge.err" "$WORK/agent.err" || true
		fail "sockets never appeared"
	}
	sleep 0.5
done

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
  memory:
    kind: mcp
    url: unix://$BRIDGE_DIR/memory.sock
    runtime: refbridge
    credential_source: static_env
    token_env: MEMORY_TOKEN
    read_only_tools: [memory_search]
EOF
agent_config() { # $1 = name, $2 = description, $3 = grant mode
	cat <<EOF
name: $1
description: $2
model: fast
instruction: Run the memory script.
output: reply
execution: fronted
endpoint: unix://$SOCK_DIR/agent.sock
tools:
  - resource: memory
    tools: ["*"]
    mode: $3
EOF
}
agent_config memory-writer "Upserts and searches memory through the tool door (e2e)" read-write >"$WORK/config/agents/memory-writer.yaml"
agent_config memory-reader "Searches memory through the tool door, read-only (e2e)" read-only >"$WORK/config/agents/memory-reader.yaml"
cat >"$WORK/config/workflows/memory-write.yaml" <<EOF
name: memory-write
description: One step as the upserting agent
steps:
  - name: call
    agent: memory-writer
EOF
cat >"$WORK/config/workflows/memory-read.yaml" <<EOF
name: memory-read
description: One step as the search-only agent
steps:
  - name: call
    agent: memory-reader
EOF
cat >"$WORK/config/roles/memory-operator.yaml" <<EOF
name: memory-operator
description: Runs the memory e2e workflows
workflows: [memory-write, memory-read]
allowed_groups: ["memory-users"]
control: [apply]
EOF

# Credentials live with the HOST agenthof process only.
export MEMORY_TOKEN="memory-secret-$NONCE"
export AGENTHOF_GATEWAY_KEY="host-side-dummy-key-$NONCE" # the model route is never called; the key only lets it resolve

"$WORK/agenthof" apply --config "$WORK/config" --control-log "$WORK/control.jsonl" --as ci --groups memory-users

run() { # $1 = workflow, $2 = step input JSON
	"$WORK/agenthof" run memory-operator "$1" --input "$2" \
		--as ci --groups memory-users --config "$WORK/config" --control-log "$WORK/control.jsonl" \
		--log-dir "$WORK/logs" --artifact-dir "$WORK/artifacts"
}
audit() { "$WORK/agenthof" audit "$1" --log-dir "$WORK/logs" --control-log "$WORK/control.jsonl"; }

# Synthetic 3-d vectors. A is inserted first, B second, and the query is B
# itself: the nearest chunk is NOT the first inserted, so only a real cosine
# ranking returns B then A. The scores are exact: 1.0000 and 0.0000.
VEC_A='[1,0,0]'
VEC_B='[0,1,0]'
QUERY='[0,1,0]'

# 1. Upsert two chunks then search, in ONE session of the upserting agent.
OUT1="$(run memory-write "{\"upserts\":[{\"collection\":\"notes\",\"text\":\"chunk-a $NONCE\",\"vector\":$VEC_A,\"metadata\":{}},{\"collection\":\"notes\",\"text\":\"chunk-b $NONCE\",\"vector\":$VEC_B,\"metadata\":{}}],\"searches\":[{\"collection\":\"notes\",\"vector\":$QUERY,\"k\":2}]}" 2>"$WORK/run1.err")"
echo "$OUT1"
echo "$OUT1" | grep -q "finished: succeeded" || fail "memory-write did not succeed"
RUNID1="$(runid_of "$OUT1")"
[ -n "$RUNID1" ] || fail "no run id for the upsert run"
AUDIT1="$(audit "$RUNID1")"
echo "$AUDIT1"
echo "$AUDIT1" | grep -q "ledger integrity: verified" || fail "upsert run ledger not verified"
echo "$AUDIT1" | grep -q "ledger completeness: complete (" || fail "upsert run ledger does not account for itself"

# 2. Attestation: every tools/call is a tool_call carrying the bridge's
#    first-hand attestation (argv incl. -store-file/-credential-env, pid, env NAMES).
LEDGER1="$WORK/logs/$RUNID1.jsonl"
[ "$(grep -c '"runtime_attestation":{"runtime":"refbridge"' "$LEDGER1")" = 3 ] || fail "want three attested tool_call events (two upserts, one search)"
[ "$(grep -cF "$ARGV_JSON" "$LEDGER1")" = 3 ] || fail "want the child's exact argv attested on all tool_call events"
[ "$(grep -cF "$ENV_JSON" "$LEDGER1")" = 3 ] || fail "want env_names of exactly the credential variable on all tool_call events"
if grep -q "LEAKED_SECRET" "$LEDGER1"; then fail "a non-allowlisted variable was attested in the child's environment"; fi
ATTESTED="\\[runtime-attested: refbridge $(ere_escape "$WORK/memory-store") -backend embedded -store-file $(ere_escape "$STORE_FILE") -credential-env MEMORY_TOKEN pid [0-9]+"
[ "$(echo "$AUDIT1" | grep -Ec "tool memory_upsert — args [0-9a-f]{8} \(static_env\) $ATTESTED")" = 2 ] || fail "audit does not render two attested memory_upsert calls"
[ "$(echo "$AUDIT1" | grep -Ec "tool memory_search — args [0-9a-f]{8} \(static_env\) $ATTESTED")" = 1 ] || fail "audit does not render the attested memory_search call"

# The artifact is content-addressed; find the one holding the upserted lines.
ART1="$(grep -rlE '^upserted ' "$WORK/artifacts" | head -n1 || true)"
[ -n "$ART1" ] || fail "no artifact from the upsert run"
[ "$(grep -Ec '^upserted [^ ]+$' "$ART1")" = 2 ] || fail "want two 'upserted <id>' lines"
[ "$(grep -Ec '^hit [^ ]+ -?[0-9]+\.[0-9]{4}$' "$ART1")" = 2 ] || fail "want two 'hit <id> <score>' lines with 4-decimal scores"
ID_A="$(sed -n '1s/^upserted //p' "$ART1")"
ID_B="$(sed -n '2s/^upserted //p' "$ART1")"
{ [ -n "$ID_A" ] && [ -n "$ID_B" ] && [ "$ID_A" != "$ID_B" ]; } || fail "upserted ids are missing or not distinct"
HITS="$(grep '^hit ' "$ART1")"
[ "$HITS" = "$(printf 'hit %s 1.0000\nhit %s 0.0000' "$ID_B" "$ID_A")" ] || fail "want exactly the nearest chunk (the second inserted) first at 1.0000, then the other at 0.0000"
echo "upsert + search: nearest chunk first, attested tool_call lines — ok"

# 3. The search-only agent cannot reach the mutating tool: refused, and no
#    resource or attestation is recorded on the refused tool_call (and nothing
#    is written to the store).
if OUT2="$(run memory-read "{\"upserts\":[{\"collection\":\"notes\",\"text\":\"forbidden $NONCE\",\"vector\":$VEC_A,\"metadata\":{}}]}" 2>&1)"; then
	fail "the search-only agent's memory_upsert was not refused"
fi
echo "$OUT2"
echo "$OUT2" | grep -q "finished: failed" || fail "refused read-only run did not finish failed"
RUNID2="$(runid_of "$OUT2")"
[ -n "$RUNID2" ] || fail "no run id for the refused run"
AUDIT2="$(audit "$RUNID2")"
echo "$AUDIT2"
echo "$AUDIT2" | grep -q "ledger integrity: verified" || fail "refused run ledger not verified"
echo "$AUDIT2" | grep -q "ledger completeness: complete (" || fail "refused run ledger does not account for itself"
echo "$AUDIT2" | grep -q "tool memory_upsert refused — tool is not available to this run" || fail "memory_upsert was not refused with the read-only reason"
if grep -q '"runtime_attestation"' "$WORK/logs/$RUNID2.jsonl"; then fail "the refused call recorded an attested tool_call"; fi
if grep -q '"resources_touched"' "$WORK/logs/$RUNID2.jsonl"; then fail "the refused call recorded a touched resource"; fi
if echo "$AUDIT2" | grep -Eq "tool memory_upsert — args"; then fail "the refused memory_upsert recorded a tool_call"; fi
echo "read-only grant: memory_upsert refused; no resource or attestation recorded — ok"

# 4. Persistence across SEPARATE runs: the search-only agent, in a new run,
#    finds the first run's upserts (and not the refused one).
OUT3="$(run memory-read "{\"searches\":[{\"collection\":\"notes\",\"vector\":$VEC_A,\"k\":5}]}" 2>"$WORK/run3.err")"
echo "$OUT3"
echo "$OUT3" | grep -q "finished: succeeded" || fail "the second read run did not succeed"
RUNID3="$(runid_of "$OUT3")"
[ -n "$RUNID3" ] || fail "no run id for the second read run"
AUDIT3="$(audit "$RUNID3")"
echo "$AUDIT3"
echo "$AUDIT3" | grep -q "ledger integrity: verified" || fail "second read run ledger not verified"
echo "$AUDIT3" | grep -q "ledger completeness: complete (" || fail "second read run ledger does not account for itself"
[ "$RUNID3" != "$RUNID1" ] || fail "the second search reused the first run"
[ "$(grep -c '"runtime_attestation":{"runtime":"refbridge"' "$WORK/logs/$RUNID3.jsonl")" = 1 ] || fail "want one attested tool_call in the second read run"
ART3=""
for f in "$WORK"/artifacts/*; do
	if [ "$f" != "$ART1" ] && grep -qE "^hit $ID_A " "$f"; then ART3="$f"; fi
done
[ -n "$ART3" ] || fail "the second run's search did not find the first run's chunk"
grep -qE "^hit $ID_B " "$ART3" || fail "the second run's search did not find the first run's second chunk"
[ "$(grep -c '^hit ' "$ART3")" = 2 ] || fail "the store holds something other than the two upserted chunks (a refused write landed?)"
echo "persistence: the second run found the first run's upserts — ok"

# 5. The load-bearing rule end to end: an invalid collection carrying canary
#    arguments fails with the FIXED reason, and no canary byte reaches a ledger,
#    artifact, or log. Nothing is printed from the canaries.
CANARY="canary-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
if OUT4="$(run memory-write "{\"upserts\":[{\"collection\":\"bad/$CANARY\",\"id\":\"id-$CANARY\",\"text\":\"text-$CANARY\",\"vector\":$VEC_A,\"metadata\":{\"k\":\"meta-$CANARY\"}}]}" 2>"$WORK/run4.err")"; then
	fail "an upsert into an invalid collection did not fail"
fi
echo "$OUT4"
RUNID4="$(runid_of "$OUT4")"
[ -n "$RUNID4" ] || fail "no run id for the invalid-collection run"
echo "$OUT4" | grep -q "finished: failed" || fail "the invalid-collection run did not finish failed"
AUDIT4="$(audit "$RUNID4")"
echo "$AUDIT4"
echo "$AUDIT4" | grep -q "ledger integrity: verified" || fail "invalid-collection run ledger not verified"
grep -qF "tool memory_upsert failed — collection must match [A-Za-z0-9_-]{1,64}" <<<"$AUDIT4" || fail "the audit does not show the fixed invalid-collection reason"
no_leak "$CANARY" "the invalid-collection canary"
echo "invalid collection: fixed reason surfaced; canary reached no ledger, artifact, or log — ok"

# 6. The credential is nowhere in any ledger, artifact, or log.
no_leak "$MEMORY_TOKEN" "the memory credential value"
no_leak "not-for-the-child-$NONCE" "the non-allowlisted variable's value"
if grep -q "LEAKED_SECRET" "$WORK/bridge.err"; then fail "a non-allowlisted variable leaked into the bridge log"; fi

echo "e2e-memory-local: PASS"
