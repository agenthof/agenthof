#!/usr/bin/env bash
# demo-every-door: the README "every door" story, end to end, hermetically.
#
# It reuses the hermetic acceptance harness (scripts/e2e-acceptance-local.sh) to
# stand up the stand-ins — no podman, no real model, no secrets — apply a combined
# config, then shows ONE governed run that drives all four doors (model, exec,
# tool, spawn), the merged investigate tree, and the integrity check.
#
# Requires go and a python with examples/langchain-agent/requirements.txt
# installed (PYTHON=... selects it), the same as the hermetic e2e. This proves
# GOVERNANCE and AUDIT, not containment (the compartments here are stand-ins; the
# walls are the podman proof's job — `make acceptance-podman`).
#
# Regenerate the README gif from this with:  vhs docs/assets/every-door-demo.tape
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

# Pre-flight: fail fast and clearly on the common blockers, before the harness.
command -v go >/dev/null 2>&1 || { echo "demo-every-door: go (>= 1.27) is required." >&2; exit 1; }
PY="${PYTHON:-python3}"
"$PY" -c 'import langchain_openai, httpx, mcp' 2>/dev/null || {
	echo "demo-every-door: $PY lacks the demo's dependencies. Install them with:" >&2
	echo "  $PY -m pip install -r examples/langchain-agent/requirements.txt" >&2
	exit 1
}

# Bring up the harness (build the binaries, start the stand-ins, generate and
# apply the combined config) and return here with its environment in scope. Its
# setup chatter goes to a log so the demo below reads clean; if setup aborts, the
# log's CONTENTS are shown (never its path — $TMPDIR can be machine-identifying).
ACCEPTANCE_HARNESS_ONLY=1
SETUP_LOG="${TMPDIR:-/tmp}/demo-every-door-setup.log"
exec 3>&2  # the real terminal, for a setup-failure message even while setup is redirected
trap '[ "$?" = 0 ] || { echo "demo-every-door: harness setup failed —" >&3; cat "$SETUP_LOG" >&3 2>/dev/null; }' EXIT
printf 'setting up the hermetic demo harness (build + stand-ins)…\n'
# shellcheck source=scripts/e2e-acceptance-local.sh
{ source "$HERE/e2e-acceptance-local.sh"; } >"$SETUP_LOG" 2>&1
# Source succeeded: the harness installed its own cleanup EXIT trap (teardown),
# which has replaced ours — exactly what we want for the rest of the run.
rm -f "$SETUP_LOG"

AF="$WORK/agenthof"; CFG="$WORK/config"; LOGS="$WORK/logs"; CTL="$WORK/control.jsonl"; ART="$WORK/artifacts"

# say: print a command the way a session would, then pause briefly so the gif is
# readable. (When run outside the gif the pauses just make it easy to follow.)
PAUSE="${DEMO_PAUSE:-1}"
say() { printf '\n\033[1;36m$ %s\033[0m\n' "$*"; sleep "$PAUSE"; }

say "agenthof apply --config ./config --as dana@example.com --groups acceptance-users"
AGENTHOF_GATEWAY_KEY="$GATEWAY_KEY" "$AF" apply --config "$CFG" --control-log "$CTL" \
	--as dana@example.com --groups acceptance-users

say "agenthof run acceptance-operator acceptance --input 'ship the feature' --token \$TOKEN"
OUT="$(AGENTHOF_GATEWAY_KEY="$GATEWAY_KEY" "$AF" run acceptance-operator acceptance \
	--input "ship the feature" --token "$TOKEN" \
	--config "$CFG" --control-log "$CTL" --log-dir "$LOGS" --artifact-dir "$ART" 2>>"$WORK/agenthof.err" || true)"
echo "$OUT"
RUN="$(sed -E -n 's/^run (r-[a-f0-9]+) .*/\1/p' <<<"$OUT" | head -1)"
grep -q "finished: succeeded" <<<"$OUT" || {
	echo "demo-every-door: the combined run did not succeed:" >&2
	cat "$WORK/agent.err" "$WORK/agenthof.err" 2>/dev/null >&2
	exit 1
}

say "agenthof investigate --run $RUN"
"$AF" investigate --run "$RUN" --log-dir "$LOGS" --control-log "$CTL"

say "agenthof audit verify $RUN"
"$AF" audit verify "$RUN" --log-dir "$LOGS"

printf '\n\033[1;32mEvery door — model, exec, tool, spawn — in one governed run, bound to the human, integrity verified.\033[0m\n'
sleep "$PAUSE"
