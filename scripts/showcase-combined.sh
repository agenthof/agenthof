#!/usr/bin/env bash
# showcase-combined: the combined four-door run with a REAL model deciding —
# the operator's own proof, by hand, never in CI. It reuses the hermetic
# acceptance harness (scripts/e2e-acceptance-local.sh, sourced: the real
# agenthof binary, refexec/refspawn stand-ins running compartments as host
# processes, refbridge over a stdio tool, the stub IdP and per-user upstream,
# a verified human) but points the model route at YOUR OpenAI-compatible
# provider and runs the LangChain agent in its `--driver llm` mode, so the
# model — not a script — chooses which governed doors to open. It then prints
# `agenthof audit <run>` and `agenthof investigate --run <run>`: the model
# rounds, the exec, the on-behalf-of and bridged tool calls, the sub-agent
# children, any refusal, on one timeline, bound to one human, every ledger
# verified. Real models vary: a run may take another path or skip a door; the
# audit shows whatever actually happened, and that is the point. The model is
# offered the doors plus every tool the agent is granted.
# This proves GOVERNANCE and AUDIT. It proves nothing about containment — the
# compartments here are host processes; the podman proofs own the walls.
# The step artifact is the agent's OWN summary of what it did (asserted); the
# ledger events in the audit are the first-hand record.
#
# The provider key: it must reach ONLY the host agenthof process. The
# supervisor stand-in's fake podman starts every child agent with its own
# environment, so a key exported when the stand-ins start would be inherited
# by every "compartment". This script copies the key into a shell variable,
# removes it from the environment before anything starts, checks nothing else
# in the environment still carries it, and hands it to agenthof per command
# only. It never prints the key, and searches every ledger, artifact, log, and
# output for it afterwards.
#
#   SHOWCASE_PROVIDER_BASE_URL=https://api.openai.com \
#   SHOWCASE_PROVIDER_KEY=sk-... \
#   SHOWCASE_PROVIDER_MODEL=gpt-4o-mini \
#   ./scripts/showcase-combined.sh
#
# The base URL is the provider's origin WITHOUT /v1 (the gateway appends
# /v1/chat/completions); the provider must support OpenAI-style tool calling.
# SHOWCASE_STEP_BUDGET is the agent's time budget for the step in whole
# seconds (default 150); it must stay below the harness config's 3-minute
# step timeout, so it must be a whole number from 1 to 179.
# Requires what e2e-acceptance-local.sh requires.
set -euo pipefail

ME="showcase-combined"
usage() {
	echo "$ME: set SHOWCASE_PROVIDER_BASE_URL (the provider's origin, no /v1) and SHOWCASE_PROVIDER_KEY; optionally SHOWCASE_PROVIDER_MODEL (default gpt-4o-mini) and SHOWCASE_STEP_BUDGET seconds (1-179, default 150)" >&2
	exit 1
}
[ -n "${SHOWCASE_PROVIDER_BASE_URL:-}" ] || usage
[ -n "${SHOWCASE_PROVIDER_KEY:-}" ] || usage
# Trailing slashes are stripped first, so the guard sees the value the gateway
# will use (https://host/v1// is /v1 too).
BASE_URL="$SHOWCASE_PROVIDER_BASE_URL"
while [ "${BASE_URL%/}" != "$BASE_URL" ]; do BASE_URL="${BASE_URL%/}"; done
case "$BASE_URL" in
	*/v1)
		echo "$ME: SHOWCASE_PROVIDER_BASE_URL must be the origin without /v1" >&2
		exit 1
		;;
	http://* | https://*) ;;
	*)
		echo "$ME: SHOWCASE_PROVIDER_BASE_URL must start with http:// or https://" >&2
		exit 1
		;;
esac
STEP_BUDGET="${SHOWCASE_STEP_BUDGET:-150}"
case "$STEP_BUDGET" in
	'' | *[!0-9]* | ???*[0-9]) STEP_BUDGET=bad ;;
esac
if [ "$STEP_BUDGET" = bad ] || [ "$STEP_BUDGET" -lt 1 ] || [ "$STEP_BUDGET" -ge 180 ]; then
	echo "$ME: SHOWCASE_STEP_BUDGET must be a whole number of seconds from 1 to 179 (the step times out at 3 minutes)" >&2
	exit 1
fi

# 1. The key leaves the environment before anything starts. unset first, so
#    the variable that holds it can never carry an export attribute the caller
#    gave it.
unset key
key="$SHOWCASE_PROVIDER_KEY"
unset SHOWCASE_PROVIDER_KEY
ENV_DUMP="$(env)" # captured, then searched: never pipe a writer into grep -q under pipefail
if grep -qF -- "$key" <<<"$ENV_DUMP"; then
	echo "$ME: the provider key is still exported under another variable; unset it so no stand-in or child agent can inherit it" >&2
	exit 1
fi
unset ENV_DUMP

# 2. The harness, with the model route at the real provider and the llm driver.
ACCEPTANCE_DRIVER=llm
ACCEPTANCE_AGENT_ARGS="--max-rounds 8 --step-budget $STEP_BUDGET"
ACCEPTANCE_PROVIDER_URL="$BASE_URL"
ACCEPTANCE_PROVIDER_MODEL="${SHOWCASE_PROVIDER_MODEL:-gpt-4o-mini}"
unset ACCEPTANCE_PROVIDER_KEY # drop any export attribute a caller gave this name
ACCEPTANCE_PROVIDER_KEY="$key" # a shell variable: the harness reads it, unsets it, and passes the key to agenthof per command
unset key
ACCEPTANCE_HARNESS_ONLY=1
# shellcheck source-path=SCRIPTDIR
# shellcheck source=e2e-acceptance-local.sh
. "$(cd "$(dirname "$0")" && pwd)/e2e-acceptance-local.sh"
# The harness has installed its cleanup as the EXIT trap.
echo "$ME: harness up — provider $ACCEPTANCE_PROVIDER_URL, model $ACCEPTANCE_PROVIDER_MODEL, the agent in --driver llm"
echo "$ME: this proves governance and audit, not containment (the compartments are host processes); build-mode, by hand"

# 3. The run. run() prints the engine's result and the audit, and fails only
#    when the run has no id or its ledger does not verify — a step the model
#    did not finish is still a governed, recorded run worth reading.
run acceptance
PARENT="$RUNID"
case "$OUT" in
	*"run $PARENT refused"*) echo "$ME: the run was refused before any step ran — the audit above shows the refusal" ;;
	*"finished: succeeded"*) echo "$ME: the model finished the step" ;;
	*) echo "$ME: the model did not finish the step (the failure reason is in the audit above) — the audit shows whatever it did before that" ;;
esac
echo
echo "--- the step artifact (the agent's OWN summary, asserted; the ledger events above are the first-hand record) ---"
# Only a succeeded step has an artifact; parent_artifact would fail the whole
# script on any other run.
HAD_ARTIFACT=
if [ "$(count "$(ledger "$PARENT")" step_succeeded)" = 1 ]; then
	if ! ART="$(parent_artifact "$PARENT")"; then
		echo "$ART"
		fail "the run succeeded but its artifact could not be read"
	fi
	echo "$ART"
	HAD_ARTIFACT=1
else
	echo "(no succeeded step, so no artifact)"
fi
echo
echo "--- investigate --run $PARENT ---"
TREE="$("$WORK/agenthof" investigate --run "$PARENT" --log-dir "$WORK/logs" --control-log "$WORK/control.jsonl")"
OUTS+=("$TREE")
echo "$TREE"
echo

# 4. Every run of the tree verifies on its own: the parent, then every child
#    the model started, whatever came of it.
verify_run "$PARENT" "the combined run"
NCHILD=0
for c in $(field "$(ledger "$PARENT")" spawn child_run_id); do
	verify_run "$c" "a child run"
	NCHILD=$((NCHILD + 1))
done
[ "$NCHILD" -gt 0 ] || echo "no children: the model started no sub-agent runs, so there is no child ledger to verify"

# 5. The key reached no ledger, artifact, log, or output. The positive
#    control is the parent run id — on every ledger event's binding by
#    construction, whatever path the model took — not the step input, which
#    reaches a ledger only if the model happened to echo it.
printf '%s\n' "${OUTS[@]}" >"$WORK/outs.txt"
grep -rqF -- "$PARENT" "$WORK/logs" || fail "the positive control (the run id, bound to every event) is missing, so the search for the key would prove nothing"
# The other places no_leak searches must be populated too, or their absence proves nothing.
[ -s "$WORK/agenthof.err" ] || fail "agenthof's operational log is empty, so searching it for the key would prove nothing"
[ -s "$WORK/control.jsonl" ] || fail "the control log is empty, so searching it for the key would prove nothing"
grep -qF "listening" "$WORK/agent.err" || fail "the agent's log is empty, so searching the process logs for the key would prove nothing"
[ -z "$HAD_ARTIFACT" ] || [ -n "$(ls -A "$WORK/artifacts")" ] || fail "the artifact store is empty, so searching it for the key would prove nothing"
no_leak "$GATEWAY_KEY" "the provider key"
no_leak "$TOKEN" "the subject token"
echo "no leak: the provider key and the subject token are in no ledger, artifact, log, or output — ok"
echo "$ME: done. Read the audit and the tree above with docs/showcase.md."
