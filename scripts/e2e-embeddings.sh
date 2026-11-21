#!/usr/bin/env bash
# e2e-embeddings: prove the embeddings route of the model door against a REAL
# OpenAI-compatible embeddings server — the one tier that sends a governed
# /v1/embeddings call through the agenthof BINARY to an actual provider and
# reads back a real vector, rather than the in-process stub the .txtar journey
# (door_embeddings.txtar) and unit tests use. No external API key and no spend:
# the server is an Ollama container serving the all-minilm model locally.
#
# A direct curl probe first pins down the contract the door relies on (HTTP
# 200, usage.prompt_tokens > 0, a non-empty data[0].embedding). Then a
# governed run proves: the agent embeds through Agenthof, the artifact reports
# the real vector's dimension count, and the ledger holds ONE model_call with
# prompt tokens and no completion tokens, accounted and verifiable. Two
# falsifiable negative controls follow: an agent naming the provider's model
# instead of the logical one is refused, and an agent with no embedding_model
# is refused — each recorded, and neither reaches the server (its request log
# is unchanged across both).
#
# Pinned: the server IMAGE, by digest (the multi-arch index digest, taken from
# the registry), and the model by its tag (all-minilm:22m). NOT pinned: the
# model WEIGHTS, which the server pulls from the Ollama registry at run time
# and which the image digest does not cover. Needs network on first run.
#
# Requires: podman (rootless), go, curl, python3. Run from the repo root. On
# macOS run it inside the Lima VM (deploy/lima), as with the other real-backend
# tiers. EMBED_PORT selects the server's host port (default 11434); KEEP=1 (or
# --keep) keeps the server container, the agents and the work directory for
# inspection. Local-by-judgment only — never CI (a real container backend, like
# the podman combined run).
set -euo pipefail

ME="e2e-embeddings"
IMAGE="docker.io/ollama/ollama:0.12.6@sha256:a61a8fd395dbb931cc8cb1b5da7a2510746575c87113fdc45b647ee59ef7f808"
PROVIDER_MODEL="all-minilm:22m"
CONTAINER="agenthof-embeddings-e2e"
PORT="${EMBED_PORT:-11434}"
ENDPOINT="http://127.0.0.1:$PORT"
OK_ADDR="127.0.0.1:18081"
WRONG_ADDR="127.0.0.1:18082"

KEEP="${KEEP:-0}" # KEEP=1 env, or --keep (as deploy/lima/lima.sh forwards it)
for a in "$@"; do
  case "$a" in
    --keep) KEEP=1 ;;
    *) echo "$ME: unknown argument: $a (want: [--keep])" >&2; exit 2 ;;
  esac
done

fail() { echo "$ME: $*" >&2; exit 1; }

command -v podman >/dev/null 2>&1 || fail "need rootless podman on PATH"

WORK=$(mktemp -d)
AGENT_PIDS=()
cleanup() {
  local rc=$? # must be first: later commands overwrite $?
  if [ "$KEEP" = 1 ]; then
    echo "kept: container '$CONTAINER' up on $ENDPOINT, agents ${AGENT_PIDS[*]-none}, work dir $WORK"
    echo "inspect: podman logs $CONTAINER ; tear down: podman rm -f $CONTAINER ; kill ${AGENT_PIDS[*]-}"
    return 0
  fi
  # On a failure, surface the server's own log before the container and the work
  # dir (with any run ledgers) are destroyed — the only diagnostic left.
  [ "$rc" = 0 ] || podman logs --tail 40 "$CONTAINER" 2>&1 || true
  for p in ${AGENT_PIDS[@]+"${AGENT_PIDS[@]}"}; do kill "$p" >/dev/null 2>&1 || true; done
  podman rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$WORK" || true
}
trap cleanup EXIT

# run <step> <expected exit> <command...>: runs it, echoes output, fails naming
# the step unless the exit matches. Output is left in $OUT for expect.
OUT=""
run() {
  local step=$1 want=$2 code=0
  shift 2
  OUT=$("$@" 2>&1) || code=$?
  printf '%s\n' "$OUT"
  [ "$code" = "$want" ] || fail "$step: exit $code, want $want"
}
# run_nonzero <step> <command...>: like run, but any non-zero exit passes.
run_nonzero() {
  local step=$1 code=0
  shift
  OUT=$("$@" 2>&1) || code=$?
  printf '%s\n' "$OUT"
  [ "$code" != 0 ] || fail "$step: exit 0, want non-zero"
}
# expect <step> <pattern>: $OUT must contain a line matching the ERE pattern.
expect() { grep -Eq -- "$2" <<<"$OUT" || fail "$1: output lacks /$2/"; }

# shellcheck source=scripts/acceptance-lib.sh
source scripts/acceptance-lib.sh

# --- 1. the server: drop any leftover of THIS container (e.g. a KEEP=1 run)
#     before the port check, so our own leftovers never look like a foreign
#     conflict; then refuse a foreign listener on the port. ---
podman rm -f "$CONTAINER" >/dev/null 2>&1 || true
if curl -sS -o /dev/null "$ENDPOINT/" 2>/dev/null; then
  fail "something already listens on $ENDPOINT (a foreign process?); set EMBED_PORT to a free port"
fi
echo "starting the embeddings server (pulling the pinned image on first run may take a while)..."
podman run -d --name "$CONTAINER" -p "127.0.0.1:$PORT:11434" "$IMAGE" >/dev/null
echo "waiting for the server..."
for i in $(seq 1 120); do
  curl -fsS -o /dev/null "$ENDPOINT/api/version" 2>/dev/null && break
  [ "$i" = 120 ] && fail "the embeddings server never became ready on $ENDPOINT"
  sleep 1
done
echo "loading $PROVIDER_MODEL (pulled from the registry at run time; not covered by the image digest)..."
podman exec "$CONTAINER" ollama pull "$PROVIDER_MODEL" >/dev/null 2>&1 || fail "could not pull $PROVIDER_MODEL"
echo "the server is up on $ENDPOINT"

# server_calls: how many /v1/embeddings requests the server has served.
server_calls() { podman logs "$CONTAINER" 2>&1 | grep -c 'POST.*"/v1/embeddings"' || true; }

# --- 2. the direct probe: the contract the door relies on, with no Agenthof. ---
PROBE="$WORK/probe.json"
CODE=$(curl -sS -o "$PROBE" -w '%{http_code}' -X POST "$ENDPOINT/v1/embeddings" \
  -H 'Content-Type: application/json' -d "{\"model\":\"$PROVIDER_MODEL\",\"input\":\"hello\"}") \
  || fail "probe: the embeddings request failed"
[ "$CODE" = 200 ] || fail "probe: HTTP $CODE, want 200"
DIM=$(python3 - "$PROBE" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
tokens = d["usage"]["prompt_tokens"]
assert isinstance(tokens, int) and tokens > 0, "usage.prompt_tokens is not a positive integer"
print(len(d["data"][0]["embedding"]))
PY
) || fail "probe: the reply lacks usage.prompt_tokens > 0 or data[0].embedding"
[ "$DIM" -gt 0 ] 2>/dev/null || fail "probe: the embedding is empty"
echo "probe: 200, prompt_tokens > 0, $DIM dimensions"

# --- 3. build, then the config: three agents, one workflow each. ---
AH="$WORK/agenthof"
MA="$WORK/model-agent"
echo "building agenthof and model-agent..."
go build -o "$AH" ./cmd/agenthof
go build -o "$MA" ./examples/model-agent

CFG="config"
mkdir -p "$WORK/$CFG/agents" "$WORK/$CFG/workflows" "$WORK/$CFG/roles"
cat >"$WORK/$CFG/agents/embedder.yaml" <<EOF
name: embedder
model: embed
embedding_model: embed
instruction: embed text
output: out
execution: fronted
endpoint: http://$OK_ADDR
EOF
cat >"$WORK/$CFG/agents/wrong.yaml" <<EOF
name: wrong
model: embed
embedding_model: embed
instruction: embed text
output: out
execution: fronted
endpoint: http://$WRONG_ADDR
EOF
cat >"$WORK/$CFG/agents/plain.yaml" <<EOF
name: plain
model: embed
instruction: call the model
output: out
execution: fronted
endpoint: http://$OK_ADDR
EOF
for w in embed wrong plain; do
  case "$w" in embed) agent=embedder ;; *) agent=$w ;; esac
  cat >"$WORK/$CFG/workflows/$w-wf.yaml" <<EOF
name: $w-wf
steps:
  - name: call
    agent: $agent
EOF
done
cat >"$WORK/$CFG/roles/se.yaml" <<'EOF'
name: se
workflows: [embed-wf, wrong-wf, plain-wf]
allowed_groups: ["*"]
EOF
cat >"$WORK/$CFG/roles/ops.yaml" <<'EOF'
name: platform-admin
allowed_groups: [platform-eng]
control: [apply]
EOF
cat >"$WORK/$CFG/gateway.yaml" <<EOF
models:
  embed:
    endpoint: $ENDPOINT
    model: $PROVIDER_MODEL
    api_key_env: EMBED_KEY
EOF

CFGDIR="$WORK/$CFG"
CTL="$WORK/control.jsonl"
AS_ADMIN=(--as dana@example.com --groups platform-eng)
export EMBED_KEY=local-placeholder

# The two agent programs: one names the logical model, the other the provider's.
"$MA" -embed -model embed -addr "$OK_ADDR" >"$WORK/agent-ok.log" 2>&1 &
AGENT_PIDS+=("$!")
"$MA" -embed -model "$PROVIDER_MODEL" -addr "$WRONG_ADDR" >"$WORK/agent-wrong.log" 2>&1 &
AGENT_PIDS+=("$!")
for addr in "$OK_ADDR" "$WRONG_ADDR"; do
  for i in $(seq 1 50); do
    curl -sS -o /dev/null "http://$addr/" 2>/dev/null && break
    [ "$i" = 50 ] && fail "model-agent never started on $addr"
    sleep 0.2
  done
done

# --- 4. apply ---
run "apply" 0 "$AH" apply --config "$CFGDIR" --control-log "$CTL" "${AS_ADMIN[@]}"
expect "apply" "registry ok:"

# governed <workflow> <log dir> <want exit>: one run of $2's workflow as the se
# role; its ledger path lands in $L.
governed() {
  local wf=$1 dir=$2 want=$3 step="run $1"
  if [ "$want" = 0 ]; then
    run "$step" 0 "$AH" run se "$wf" --input 'hello world' --as dana@example.com \
      --config "$CFGDIR" --control-log "$CTL" --log-dir "$WORK/$dir" --artifact-dir "$WORK/artifacts"
  else
    run_nonzero "$step" "$AH" run se "$wf" --input 'hello world' --as dana@example.com \
      --config "$CFGDIR" --control-log "$CTL" --log-dir "$WORK/$dir" --artifact-dir "$WORK/artifacts"
  fi
  RUNID=$(sed -E -n 's/^run (r-[0-9a-f]+) (finished|refused).*/\1/p' <<<"$OUT" | head -1)
  [[ "$RUNID" =~ ^r-[0-9a-f]+$ ]] || fail "$step: no run id in the output"
  L="$WORK/$dir/$RUNID.jsonl"
  [ -f "$L" ] || fail "$step: no ledger at $L"
}

# --- 5. the governed embed ---
governed embed-wf logs-ok 0
expect "governed embed" "finished: succeeded"
ARTIFACT=$(field "$L" step_succeeded artifact)
[ "$ARTIFACT" = "embedded: $DIM dimensions" ] \
  || fail "governed embed: the step artifact is '$ARTIFACT', want 'embedded: $DIM dimensions'"
[ "$(count "$L" model_call succeeded)" = 1 ] || fail "governed embed: want exactly one succeeded model_call"
[ "$(count "$L" model_call)" = 1 ] || fail "governed embed: want exactly one model_call event"
[ "$(field "$L" model_call model)" = "embed" ] || fail "governed embed: model_call model is not 'embed'"
TOKENS=$(field "$L" model_call prompt_tokens)
[[ "$TOKENS" =~ ^[0-9]+$ ]] && [ "$TOKENS" -gt 0 ] || fail "governed embed: prompt_tokens '$TOKENS' is not a positive integer"
! grep -q completion_tokens "$L" || fail "governed embed: the ledger records completion_tokens for an embedding"
accounted "$L"
run "governed embed audit" 0 "$AH" audit "$RUNID" --log-dir "$WORK/logs-ok" --control-log "$CTL"
expect "governed embed audit" "model embed — [0-9]+ prompt tokens$"
expect "governed embed audit" "ledger completeness: complete \(1 door call\(s\) accounted\)"
run "governed embed audit verify" 0 "$AH" audit verify "$RUNID" --log-dir "$WORK/logs-ok" --control-log "$CTL"
SERVED=$(server_calls)
[ "$SERVED" -ge 2 ] || fail "governed embed: the server saw $SERVED embeddings requests, want the probe and the run"

# --- 6. the mismatched model: the agent names the provider's model, not the
#     logical one. Refused at the door, recorded, never forwarded. ---
BEFORE=$(server_calls)
governed wrong-wf logs-wrong 1
expect "mismatched model" "finished: failed"
[ "$(count "$L" model_call refused)" = 1 ] || fail "mismatched model: want exactly one refused model_call"
[ "$(field "$L" model_call reason refused)" = "model \"$PROVIDER_MODEL\" is not allowed for this agent" ] \
  || fail "mismatched model: refusal reason is '$(field "$L" model_call reason refused)'"
accounted "$L"
[ "$(server_calls)" = "$BEFORE" ] || fail "mismatched model: the server saw a new embeddings request"

# --- 7. no grant: an agent with no embedding_model is refused. ---
BEFORE=$(server_calls)
governed plain-wf logs-plain 1
[ "$(count "$L" model_call refused)" = 1 ] || fail "no grant: want exactly one refused model_call"
[ "$(count "$L" model_call)" = 1 ] || fail "no grant: want exactly one model_call event"
[ "$(field "$L" model_call reason refused)" = "embeddings not allowed for this agent" ] \
  || fail "no grant: refusal reason is '$(field "$L" model_call reason refused)'"
accounted "$L"
[ "$(server_calls)" = "$BEFORE" ] || fail "no grant: the server saw a new embeddings request"

# --- 8. ---
echo "$ME: PASS ($PROVIDER_MODEL, $DIM dimensions: governed embed recorded prompt-only; wrong model and no grant refused, neither forwarded)"
