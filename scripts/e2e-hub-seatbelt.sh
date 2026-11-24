#!/usr/bin/env bash
# e2e-hub-seatbelt: prove a hub agent runs CONTAINED under the real macOS
# Seatbelt backend, by judgment (not CI). The agent is generic-chat from the
# agents hub, built from a hub checkout with the hub's reproducible recipe. Its
# SIGNED card pins the program's sha256; this script enrolls that card as
# published (trusted_signers = the published curator key), maps the enrolled
# agent to the freshly built binary, and drives a run whose lead spawns it as a
# hash-bound child under sandbox-exec. Asserts:
#   (a) the child serves the fronted contract and makes ONE governed chat call
#       through the model door to a local fake provider; its reply is the
#       child's artifact (the parent sees the provider's reply);
#   (b) the parent's ledger records the host-program hash this script computed
#       itself, and the child's ledger holds exactly one succeeded model_call;
#   (c) a REPOINTED program (other bytes) mapped to the same consent is refused
#       with the binding reason, starts no child and never runs.
#
# Run by judgment, not in CI, like the other real-sandbox tiers.
# Environment: HUB_DIR = a checkout of the agents hub (required; the script
# skips cleanly when unset, off macOS, or without /usr/bin/sandbox-exec). The
# card's pinned darwin/arm64 hash is the hub's authoritative native build; on
# another arch or toolchain the build differs, and the script says so and skips.
# Requires go, curl and python3. Run from the repo root.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ -z "${HUB_DIR:-}" ]; then
	echo "e2e-hub-seatbelt: SKIP — set HUB_DIR to an agents hub checkout"
	exit 0
fi
if [ "$(uname)" != Darwin ] || [ ! -x /usr/bin/sandbox-exec ]; then
	echo "e2e-hub-seatbelt: SKIP — macOS with /usr/bin/sandbox-exec is required"
	exit 0
fi
for tool in go curl python3 pgrep; do
	command -v "$tool" >/dev/null 2>&1 || { echo "e2e-hub-seatbelt: FAIL — $tool is required"; exit 1; }
done
[ -f "$HUB_DIR/scripts/build.sh" ] && [ -f "$HUB_DIR/agents/generic-chat/card.json" ] || { echo "e2e-hub-seatbelt: FAIL — HUB_DIR is not an agents hub checkout"; exit 1; }
HUB_DIR="$(cd "$HUB_DIR" && pwd)"

SOCK_DIR="$(mktemp -d /tmp/hs.XXXXXX)"
SUP_DIR="$(mktemp -d /tmp/hs.XXXXXX)"
SPAWN_ROOT="$(mktemp -d /tmp/hs.XXXXXX)"
WORK="$(mktemp -d /tmp/hs.XXXXXX)"
STORE_ROOT="$WORK/stores"
PID_DIR="$WORK/pids"
PIDS=()
cleanup() {
	for p in ${PIDS[@]+"${PIDS[@]}"}; do
		kill "$p" >/dev/null 2>&1 || true
		wait "$p" >/dev/null 2>&1 || true
	done
	rm -rf "$SOCK_DIR" "$SUP_DIR" "$SPAWN_ROOT" "$WORK"
}
trap cleanup EXIT
fail() {
	echo "e2e-hub-seatbelt: FAIL — $*"
	[ -f "$WORK/refspawn.err" ] && { echo "--- refspawn.err (tail)"; tail -n 40 "$WORK/refspawn.err"; } >&2
	exit 1
}
unset AGENTHOF_TOKEN || true
# shellcheck source=scripts/acceptance-lib.sh
. "$ROOT/scripts/acceptance-lib.sh"   # field, count, bound, out_of
# shellcheck source=scripts/enroll-lib.sh
. "$ROOT/scripts/enroll-lib.sh"       # ran_of

CURATOR_KID=f07e492a38568409cbcb459b1feac8b70e08eec00149ac1981b4f9c053412404
CURATOR_KEY=k2troapQ5SHzGpMeckKzHBUNcI517qZmiX/bw9Bl05o=
sha_of() { printf 'sha256:%s' "$(shasum -a 256 "$1" | awk '{print $1}')"; }

# Build everything BEFORE anything starts.
go build -o "$WORK/agenthof" ./cmd/agenthof
go build -o "$WORK/refexec" ./deploy/refexec
go build -o "$WORK/refspawn" ./deploy/refspawn
go build -o "$WORK/echo-agent" ./examples/echo-agent
BUILT="$("$HUB_DIR/scripts/build.sh" generic-chat darwin arm64 "$WORK/generic-chat")" || fail "the hub build failed"
HASH="$(sha_of "$WORK/generic-chat")"
[ "$BUILT" = "$HASH" ] || fail "the hub build reported $BUILT but the bytes hash to $HASH"
# A repointed program: same source, different bytes (a stripped link).
CGO_ENABLED=0 go -C "$HUB_DIR" build -trimpath -buildvcs=false -ldflags='-s -w' -o "$WORK/generic-chat-variant" ./agents/generic-chat
VARIANT_HASH="$(sha_of "$WORK/generic-chat-variant")"
[ "$HASH" != "$VARIANT_HASH" ] || fail "the variant has the consented bytes, so refusing it would prove nothing"
CARD="$HUB_DIR/agents/generic-chat/card.json"
if ! grep -q "$HASH" "$CARD"; then
	echo "e2e-hub-seatbelt: SKIP — this toolchain does not reproduce the card's pinned darwin/arm64 hash ($HASH)"
	exit 0
fi

# --- the fake model provider the gateway's catalog entry `chat` points at.
PROVIDER_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
NONCE="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
python3 scripts/fake-openai-provider.py --bind "127.0.0.1:$PROVIDER_PORT" --reply "governed:$NONCE" --log "$WORK/provider.jsonl" >/dev/null 2>"$WORK/provider.err" &
PIDS+=($!)
for i in $(seq 1 60); do
	curl -s -o /dev/null "http://127.0.0.1:$PROVIDER_PORT/" && break
	[ "$i" = 60 ] && fail "the fake provider never came up"
	sleep 0.2
done
export AGENTHOF_GATEWAY_KEY="host-side-dummy-key-$NONCE"

# --- refspawn on the seatbelt tier, with generic-chat mapped to the built binary.
(umask 077 && mkdir -p "$STORE_ROOT" "$PID_DIR")
spawn_config() {
	cat <<EOC
confiner: seatbelt
socket: $SUP_DIR/refspawn.sock
spawn_root: $SPAWN_ROOT
store_root: $STORE_ROOT
pid_dir: $PID_DIR
images:
  generic-chat: $WORK/generic-chat
  repointed: $WORK/generic-chat-variant
timeout: 5m
ready_timeout: 60s
limits:
  memory: 256m
  cpus: "1"
  pids: 64
max_compartments: 3
refexec:
  command: [$WORK/refexec]
  timeout: 2m
  limits:
    memory: 256m
    cpus: "1"
    pids: 64
  max_compartments: 2
  env_allow: []
EOC
}
spawn_config >"$WORK/refspawn.yaml"
"$WORK/refspawn" -config "$WORK/refspawn.yaml" 2>>"$WORK/refspawn.err" &
PIDS+=($!)
for i in $(seq 1 60); do
	[ -S "$SUP_DIR/refspawn.sock" ] && break
	[ "$i" = 60 ] && fail "refspawn socket never appeared"
	sleep 0.5
done

# The root run's agent: a host process that spawns the hub agent on request.
mkdir -p "$WORK/lead-ws"
"$WORK/echo-agent" -socket "$SOCK_DIR/agent.sock" -workspace "$WORK/lead-ws" 2>"$WORK/agent.err" &
PIDS+=($!)
for i in $(seq 1 60); do
	[ -S "$SOCK_DIR/agent.sock" ] && break
	[ "$i" = 60 ] && { cat "$WORK/agent.err" >&2; fail "agent socket never appeared"; }
	sleep 0.5
done

# --- the installed configuration: the published curator key is the one trusted
# signer, the catalog's `chat` is the fake provider, the lead role may enroll.
CFG="$WORK/config"
mkdir -p "$CFG/agents" "$CFG/workflows" "$CFG/roles"
cat >"$CFG/gateway.yaml" <<EOC
refbox_socket_dir: $SOCK_DIR
spawn_supervisor: unix://$SUP_DIR/refspawn.sock
spawn:
  max_depth: 2
  max_parallel: 2
  max_total_spawns: 8
step_timeout: 3m
models:
  chat:
    endpoint: http://127.0.0.1:$PROVIDER_PORT
    model: chat
    api_key_env: AGENTHOF_GATEWAY_KEY
defaults:
  model: chat
trusted_signers:
  - {kid: $CURATOR_KID, key: $CURATOR_KEY}
EOC
cat >"$CFG/agents/lead.yaml" <<EOC
name: lead
description: the root run's agent, a host process
model: chat
instruction: Run the script.
output: output
execution: fronted
endpoint: unix://$SOCK_DIR/agent.sock
may_spawn:
EOC
printf 'name: lead-wf\ndescription: lead\nsteps:\n  - name: lead\n    agent: lead\n' >"$CFG/workflows/lead-wf.yaml"
cat >"$CFG/roles/lead.yaml" <<EOC
name: lead
description: Runs the parent workflow and enrolls agents
workflows: [lead-wf]
allowed_groups: ["spawn-users"]
control: [apply, enroll]
EOC
ARGS=(--config "$CFG" --control-log "$WORK/control.jsonl" --as ci --groups spawn-users)
"$WORK/agenthof" apply "${ARGS[@]}" >/dev/null || fail "apply of the base config failed"

# Enroll the hub's signed card exactly as published.
# shellcheck disable=SC2034  # read by enroll_agent in enroll-lib.sh
ENROLL_ARGS=("${ARGS[@]}")
# shellcheck disable=SC2034  # read by enroll_agent in enroll-lib.sh
AGENTHOF="$WORK/agenthof"
enroll_agent "$CARD" generic-chat "$CFG"
printf '%s\n' "$ENROLL_OUT" | grep -q 'seatbelt (program "generic-chat"' || { echo "$ENROLL_OUT"; fail "enroll did not offer the program mapping for the seatbelt tier"; }
grep -q "$HASH" "$CFG/agents/generic-chat.yaml" || fail "the enrolled agent file does not record the consented hash"
# The same consent, enrolled again as an agent the operator maps to other bytes.
enroll_agent "$CARD" repointed "$CFG"
for a in generic-chat repointed; do enroll_allow_spawn "$CFG/agents/lead.yaml" "$a"; done
"$WORK/agenthof" apply "${ARGS[@]}" >"$WORK/apply.out" 2>&1 || { cat "$WORK/apply.out"; fail "apply of the enrolled agents failed"; }

run() { # $1 = input; sets OUT, RUNID, AUDIT
	OUT="$("$WORK/agenthof" run lead lead-wf --input "$1" "${ARGS[@]}" \
		--log-dir "$WORK/logs" --artifact-dir "$WORK/artifacts" 2>>"$WORK/agenthof.err" || true)"
	echo "$OUT"
	RUNID="$(echo "$OUT" | sed -n 's/^run \(r-[a-f0-9]*\) finished.*/\1/p')"
	[ -n "$RUNID" ] || { cat "$WORK/agenthof.err" >&2 || true; fail "no run id"; }
	AUDIT="$("$WORK/agenthof" audit "$RUNID" --log-dir "$WORK/logs" --control-log "$WORK/control.jsonl")"
	echo "$AUDIT"
	echo "$AUDIT" | grep -q "ledger integrity: verified" || fail "ledger not verified"
}
ledger() { echo "$WORK/logs/$1.jsonl"; }
parent_artifact() {
	local sha
	sha="$(field "$(ledger "$1")" step_succeeded artifact_sha | tail -1)"
	[ -n "$sha" ] && [ -s "$WORK/artifacts/$sha" ] || fail "run $1 has no stored step artifact"
	cat "$WORK/artifacts/$sha"
}

# (c) first, so the binding refusal is proven on a provider that has seen nothing:
# the repointed program is refused and never runs.
SUP_AT="$(wc -l <"$WORK/refspawn.err" | tr -d ' ')"
run "spawn:repointed/repointed:x-$NONCE"
tail -n "+$((SUP_AT + 1))" "$WORK/refspawn.err" >"$WORK/sup-tail.err"
[ "$(count "$(ledger "$RUNID")" spawn refused)" = 1 ] || fail "expected the repointed spawn refused"
[ "$(field "$(ledger "$RUNID")" spawn reason refused)" = "spawn artifact refused" ] || fail "the refusal is not the binding reason"
[ -z "$(field "$(ledger "$RUNID")" spawn child_run_id refused)" ] || fail "a binding refusal must start no child run"
grep -qF -- "artifact to run is not a consented one" "$WORK/sup-tail.err" || fail "the supervisor did not record the hash mismatch"
if grep -q "compartment started.*-repointed" "$WORK/sup-tail.err"; then fail "a compartment was started for the repointed program"; fi
if pgrep -f "generic-chat-variant" >/dev/null 2>&1; then fail "the repointed program is running"; fi
[ ! -s "$WORK/provider.jsonl" ] || fail "the repointed refusal still reached the provider"
echo "binding: a repointed hub binary is refused with the binding reason and never ran — ok"

# (a)+(b): the bound child answers through the model door.
run "spawn:generic-chat/generic-chat:hello-$NONCE"
echo "$OUT" | grep -q "finished: succeeded" || fail "the run spawning generic-chat did not succeed"
PARENT="$RUNID"
CHILD="$(field "$(ledger "$PARENT")" spawn child_run_id succeeded)"
if [ -z "$CHILD" ]; then
	for l in "$WORK"/logs/*.jsonl; do [ "$l" = "$(ledger "$PARENT")" ] || { echo "--- child ledger"; cat "$l"; }; done
	fail "the spawn of generic-chat was not recorded as succeeded"
fi
parent_artifact "$PARENT" | grep -q "governed:$NONCE" || fail "the provider's reply did not come back as the child's artifact"
[ "$(count "$(ledger "$CHILD")" model_call succeeded)" = 1 ] || fail "the child did not make exactly one governed model call"
[ "$(field "$(ledger "$PARENT")" spawn child_confiner succeeded)" = seatbelt ] || fail "the spawn does not record the seatbelt tier"
[ "$(ran_of "$(ledger "$PARENT")" generic-chat)" = "host-program $HASH" ] || { ran_of "$(ledger "$PARENT")" generic-chat; fail "the spawn's child_artifact is not the host-program hash computed here ($HASH)"; }
grep -q "compartment started.*child=$CHILD.*compartment=agenthof-spawn-$CHILD-generic-chat" "$WORK/refspawn.err" || fail "generic-chat did not run in a compartment named for the child"
python3 - "$WORK/provider.jsonl" <<'PY' || fail "the provider did not see exactly one governed call"
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
assert len(rows) == 1, len(rows)
assert rows[0]["path"] == "/v1/chat/completions", rows[0]["path"]
assert rows[0]["model"] == "chat", rows[0]["model"]
PY
echo "contained hub agent: bound to $HASH, one governed chat call, provider reply returned — ok"

echo "e2e-hub-seatbelt: PASS"
