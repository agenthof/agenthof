#!/usr/bin/env bash
# e2e-rekor: prove run-receipt anchoring against a REAL Rekor v1 transparency
# log — the one tier that drives the agenthof BINARY (audit anchor / audit
# verify / audit <run-id>) against a real rekor-server, rather than the
# in-process fake the .txtar journeys and unit tests use. The anchor CLIENT is
# proven against a real log by internal/anchor/rekor_live_test.go; this proves
# the whole command path and the sidecar it writes end to end, the way worm is
# proven against real MinIO and OIDC against real dex.
#
# anchor a finished run → the receipt is written beside it → verify under the
# key the log SERVED (not independent) → pin that key and verify INDEPENDENTLY
# (log up, and off-box with --offline) → then three falsifiable negative
# controls: the proof does NOT verify under a WRONG key (unverifiable, exit 7),
# a receipt swapped from another anchored run is rejected (MISMATCH, exit 6),
# and with the pin removed the offline reader reaches no verdict (unverifiable,
# exit 7). The run anchored is a refused run — one complete event, anchorable,
# and needing no model endpoint — so the test stays about anchoring and the log.
#
# The stack (deploy/rekor/docker-compose.yml) is the canonical Sigstore Rekor
# v1 stack (MySQL + Trillian log server + signer + rekor-server), all images
# pulled and pinned, driven with rootless podman to match the project's
# containment toolchain. On macOS run it inside the Lima VM (deploy/lima),
# as with the podman acceptance tier.
#
# Requires: podman with podman-compose (or `podman compose`), go, curl, openssl.
# Run from the repo root. REKOR_PORT selects rekor's host port (default 3000);
# KEEP=1 keeps the stack and the work directory for inspection. Local-by-
# judgment only — never CI (a multi-service real-backend stack, like the
# podman combined acceptance run).
set -euo pipefail

COMPOSE_FILE=deploy/rekor/docker-compose.yml
PROJECT=agenthof-rekor-e2e
PORT="${REKOR_PORT:-3000}"
export REKOR_PORT="$PORT"
ENDPOINT="http://127.0.0.1:$PORT"
CFG="config"

KEEP="${KEEP:-0}" # KEEP=1 env, or --keep (as deploy/lima/lima.sh forwards it)
for a in "$@"; do
  case "$a" in
    --keep) KEEP=1 ;;
    *) echo "e2e-rekor: unknown argument: $a (want: [--keep])" >&2; exit 2 ;;
  esac
done

fail() { echo "e2e-rekor: $*" >&2; exit 1; }

# Prefer the standalone podman-compose; fall back to podman's built-in compose.
if command -v podman-compose >/dev/null 2>&1; then
  COMPOSE=(podman-compose)
elif podman compose version >/dev/null 2>&1; then
  COMPOSE=(podman compose)
else
  fail "need 'podman-compose' or 'podman compose' on PATH (and rootless podman)"
fi
COMPOSE+=(-f "$COMPOSE_FILE" -p "$PROJECT")

WORK=$(mktemp -d)
CTL="$WORK/control.jsonl"
PUB="$WORK/anchor.pub" # anchor.pub lives beside the control ledger
cleanup() {
  local rc=$? # must be first: later commands overwrite $?
  if [ "$KEEP" = 1 ]; then
    echo "kept: stack '$PROJECT' up, work dir $WORK"
    echo "inspect rekor: ${COMPOSE[*]} logs rekor-server ; tear down: ${COMPOSE[*]} down -v"
    return 0
  fi
  # On a failure, surface rekor's own logs to stdout before the stack and the
  # work dir (with any run ledgers) are destroyed — the only diagnostic left.
  [ "$rc" = 0 ] || "${COMPOSE[@]}" logs --tail 40 rekor-server 2>&1 || true
  "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
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
# expect <step> <pattern>: $OUT must contain a line matching the ERE pattern.
expect() { grep -Eq -- "$2" <<<"$OUT" || fail "$1: output lacks /$2/"; }

# Drop any leftover stack from a prior run of THIS project (e.g. a KEEP=1 run)
# before the port check, so our own leftovers never look like a foreign conflict.
"${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
# Any foreign HTTP listener on the port, not just a Rekor-shaped one (a non-Rekor
# service answering 404 would otherwise pass, then rekor-server fails to bind and
# the readiness loop times out with a misleading message).
if curl -sS -o /dev/null "$ENDPOINT/" 2>/dev/null; then
  fail "something already listens on $ENDPOINT (a foreign process?); set REKOR_PORT to a free port"
fi

AH="$WORK/agenthof"
echo "building agenthof..."
go build -o "$AH" ./cmd/agenthof

# --- the config: an agent/workflow, a role that denies the runner (so the run
# is refused — one complete, anchorable event), and the control role that may
# anchor. ---
mkdir -p "$WORK/$CFG/agents" "$WORK/$CFG/workflows" "$WORK/$CFG/roles"
cat >"$WORK/$CFG/agents/planner.yaml" <<'EOF'
name: planner
description: Turns a task into a short plan
model: fast
instruction: plan
output: plan
execution: fronted
endpoint: http://127.0.0.1:9/
EOF
cat >"$WORK/$CFG/workflows/plan-only.yaml" <<'EOF'
name: plan-only
steps:
  - name: plan
    agent: planner
EOF
cat >"$WORK/$CFG/roles/locked.yaml" <<'EOF'
name: locked
workflows: [plan-only]
allowed_groups: [nobody-is-in-this-group]
EOF
cat >"$WORK/$CFG/roles/ops.yaml" <<'EOF'
name: platform-admin
allowed_groups: [platform-eng]
control: [apply, anchor]
EOF
cat >"$WORK/$CFG/gateway.yaml" <<'EOF'
models:
  fast:
    endpoint: https://example.test/v1
    model: m
    api_key_env: AGENTHOF_GATEWAY_KEY
EOF
# integrity.yaml is read from beside the control ledger ($WORK/control.jsonl).
cat >"$WORK/integrity.yaml" <<EOF
anchor: tlog
anchor_backend:
  kind: transparency-log
  url: $ENDPOINT
anchor_runs: on-demand
EOF

CFGDIR="$WORK/$CFG"
LOGS="$WORK/logs"
ART="$WORK/artifacts"
AS_ADMIN=(--as dana@example.com --groups platform-eng)
export AGENTHOF_GATEWAY_KEY=dummy

# --- the stack ---
echo "starting the Rekor v1 stack (pulling pinned images on first run may take a while)..."
"${COMPOSE[@]}" up -d
echo "waiting for rekor (tree creation + Trillian can take a minute)..."
for i in $(seq 1 120); do
  curl -fsS -o /dev/null "$ENDPOINT/api/v1/log/publicKey" 2>/dev/null && break
  [ "$i" = 120 ] && { "${COMPOSE[@]}" logs --tail 60 rekor-server || true; fail "rekor never became ready on $ENDPOINT"; }
  sleep 1
done
echo "rekor is up on $ENDPOINT"

run "apply" 0 "$AH" apply --config "$CFGDIR" --control-log "$CTL" "${AS_ADMIN[@]}"
expect "apply" "registry ok:"

# anchorable_run: a refused run writes one complete event; return its id.
anchorable_run() {
  "$AH" run locked plan-only --input hi --as dana@example.com \
    --config "$CFGDIR" --control-log "$CTL" --log-dir "$LOGS" --artifact-dir "$ART" >/dev/null 2>&1 || true
  # shellcheck disable=SC2012  # run-ledger names are r-<16 hex>: no spaces or globs to mishandle
  basename "$(ls -t "$LOGS"/r-*.jsonl | head -1)" .jsonl
}
RUN1=$(anchorable_run)
[[ "$RUN1" =~ ^r-[0-9a-f]{16}$ ]] || fail "run 1: '$RUN1' is not a run id"
RUN2=$(anchorable_run)
[[ "$RUN2" =~ ^r-[0-9a-f]{16}$ ]] || fail "run 2: '$RUN2' is not a run id"
[ "$RUN1" != "$RUN2" ] || fail "the two runs share an id ($RUN1)"
echo "runs: $RUN1 $RUN2"

# --- before anchoring: not anchored ---
run "verify before anchor" 0 "$AH" audit verify "$RUN1" --log-dir "$LOGS" --control-log "$CTL"
expect "verify before anchor" "ledger anchor: not anchored$"

# --- anchor both runs into the real log ---
run "anchor run 1" 0 "$AH" audit anchor --control-log "$CTL" --run "$RUN1" "${AS_ADMIN[@]}" --log-dir "$LOGS"
expect "anchor run 1" "anchored run $RUN1: events=1 sha256=[0-9a-f]{64}"
expect "anchor run 1" "log: $ENDPOINT  entry: [0-9a-f]{80}  log key: [0-9a-f]{64} \(as served\)"
expect "anchor run 1" "index: [0-9]+  integrated: 20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z  \(as reported by the log\)"
[ -f "$LOGS/$RUN1.anchor" ] || fail "anchor run 1: no $RUN1.anchor sidecar written"
cp "$LOGS/$RUN1.anchor" "$WORK/good1.anchor"
run "anchor run 2" 0 "$AH" audit anchor --control-log "$CTL" --run "$RUN2" "${AS_ADMIN[@]}" --log-dir "$LOGS"
[ -f "$LOGS/$RUN2.anchor" ] || fail "anchor run 2: no $RUN2.anchor sidecar written"

# --- unpinned (no anchor.pub yet): the reader fetches the key the log SERVES and
#     verifies under it — verified, but NOT independent. This exercises the
#     served-key reader path against the real log. ---
run "verify as-served (unpinned)" 0 "$AH" audit verify "$RUN1" --log-dir "$LOGS" --control-log "$CTL"
expect "verify as-served (unpinned)" "ledger anchor: anchored — verified under the log key as served \(not independent; pin the log key in anchor.pub or --anchor-key to verify independently\)"

# --- pin the key the log served, then verify independently (log reachable) ---
curl -fsS "$ENDPOINT/api/v1/log/publicKey" -o "$PUB"
grep -q "BEGIN PUBLIC KEY" "$PUB" || fail "fetched log key is not a PEM public key"
run "verify pinned (online)" 0 "$AH" audit verify "$RUN1" --log-dir "$LOGS" --control-log "$CTL"
expect "verify pinned (online)" "ledger anchor: independently verified \(log key pinned; events [0-9]+ [0-9a-f]{64} → $ENDPOINT entry [0-9a-f]{80}\)"
expect "verify pinned (online)" "independently verified"
grep -Eq -- "offline|MISMATCH" <<<"$OUT" && fail "verify pinned (online): said offline/MISMATCH"

# --- audit <run-id> is offline always: independent under the pin, no log asked ---
run "audit offline (pinned)" 0 "$AH" audit "$RUN1" --log-dir "$LOGS" --control-log "$CTL"
expect "audit offline (pinned)" "ledger anchor: independently verified \(log key pinned; offline: presence not checked;"

# --- off the box: the .jsonl + .anchor + the pin verify with no control ledger
#     and (because --offline) no log at all ---
run "verify off-box (--offline, --anchor-key)" 0 "$AH" audit verify "$RUN1" --log-dir "$LOGS" --anchor-key "$PUB" --offline
expect "verify off-box (--offline, --anchor-key)" "independently verified \(log key pinned; offline: presence not checked;"

# --- falsifiability 1 (crypto): the stored proof does NOT verify under a WRONG
#     key — the real-log checkpoint crypto is key-sensitive, not vacuously
#     accepted. Without this, a verifier that accepted any key would pass. ---
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/wrong.key" 2>/dev/null
openssl ec -in "$WORK/wrong.key" -pubout -out "$WORK/wrong.pub" 2>/dev/null
grep -q "BEGIN PUBLIC KEY" "$WORK/wrong.pub" || fail "could not generate a wrong P-256 key"
run "verify under wrong key" 7 "$AH" audit verify "$RUN1" --log-dir "$LOGS" --anchor-key "$WORK/wrong.pub" --offline
expect "verify under wrong key" "ledger anchor: unverifiable — log key differs from the pinned key"

# --- falsifiability 2: a receipt from another anchored run is rejected ---
cp "$LOGS/$RUN2.anchor" "$LOGS/$RUN1.anchor"
run "verify swapped sidecar" 6 "$AH" audit verify "$RUN1" --log-dir "$LOGS" --control-log "$CTL"
expect "verify swapped sidecar" "ledger anchor: MISMATCH — sidecar record names another run"
cp "$WORK/good1.anchor" "$LOGS/$RUN1.anchor"
run "verify after restoring good sidecar" 0 "$AH" audit verify "$RUN1" --log-dir "$LOGS" --control-log "$CTL"
expect "verify after restoring good sidecar" "independently verified"

# --- falsifiability 3: with the pin gone, the offline reader reaches no verdict ---
rm "$PUB"
run "audit offline, no pin" 7 "$AH" audit "$RUN1" --log-dir "$LOGS" --control-log "$CTL"
expect "audit offline, no pin" "ledger anchor: unverifiable — no key to verify under"

echo "e2e-rekor: PASS"
