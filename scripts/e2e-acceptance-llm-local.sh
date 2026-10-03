#!/usr/bin/env bash
# e2e-acceptance-llm-local: the combined acceptance run driven by a MODEL that
# chooses the doors, hermetically. The same harness as
# scripts/e2e-acceptance-local.sh (sourced: the stand-ins, the config, the
# verified human) with the LangChain agent in its `--driver llm` mode and a
# tool-calling stand-in for the provider that plays a fixed script keyed on
# the request body — never a call counter — so one process serves the
# parent's rounds and the children's plain calls: a round that calls exec, a
# round that calls both granted tools, a round that makes BOTH spawn calls
# together, then a final answer. This proves that an agentic loop — N
# governed model calls plus whatever doors the model chose — is governed
# and audited with no change to the doors. It proves nothing about
# containment (the compartments are host processes), and the stand-in is a
# script, not a real model. Real-model runs are scripts/showcase-combined.sh,
# by hand, never here.
# Asserts: the combined run succeeds under the verified invoker; its ledger
# carries exactly four succeeded model_calls (three tool rounds and the
# answer) and the provider saw four requests offering the tools exec, spawn,
# credential, echo, environment and whoami (the two door tools, then every
# tool the grants allow, sorted) plus two offering none (the children), each
# with the host key injected; one runtime-attested exec whose output is exactly the
# allowlisted variable; one tool_call with auth_mode token_exchange acting as
# the human and one runtime-attested through refbridge; two succeeded spawns
# whose children each have their own linked, verified ledger with one
# model_call, and whose spawn requests were both in flight before either
# returned (they were made in one round and run concurrently); the artifact
# has one line per leg the model took and ends with the answer; investigate
# shows the tree; on a run whose allowlist does not hold the command the
# exec is refused and recorded, the model is told so in the fixed words, goes
# on, and the step SUCCEEDS with the refusal in its artifact — nothing ran;
# likewise both spawns on a run with no may_spawn — no child, nothing
# provisioned; audit verify passes per run; and no secret reaches any
# ledger, artifact, log, or output.
# Requires what e2e-acceptance-local.sh requires. Runs on macOS and Linux.
set -euo pipefail

ME="e2e-acceptance-llm-local"
TOOL_SCRIPT="$(mktemp /tmp/ac-llm.XXXXXX)"
# Until the harness installs its own, a failure before then still removes the file.
trap 'rm -f "$TOOL_SCRIPT"' EXIT
NONCE="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
# The script the stand-in plays, round by round. The echo call carries the
# step input, so the bridged tool's result (and the positive leak control)
# are the same as the scripted gate's.
cat >"$TOOL_SCRIPT" <<EOF
{"rounds": [
  [{"name": "exec", "arguments": {"command": ["env"]}}],
  [{"name": "whoami", "arguments": {}}, {"name": "echo", "arguments": {"text": "drive-$NONCE"}}],
  [{"name": "spawn", "arguments": {"role": "acceptance-worker", "workflow": "acceptance-sub", "input": "drive-$NONCE"}},
   {"name": "spawn", "arguments": {"role": "acceptance-worker", "workflow": "acceptance-sub", "input": "drive-$NONCE"}}]
]}
EOF

ACCEPTANCE_DRIVER=llm
ACCEPTANCE_AGENT_ARGS="--max-rounds 8 --step-budget 150"   # below the harness config's step_timeout: 3m
ACCEPTANCE_PROVIDER_ARGS="--tool-script $TOOL_SCRIPT"
ACCEPTANCE_NONCE="$NONCE"
ACCEPTANCE_HARNESS_ONLY=1
# shellcheck source-path=SCRIPTDIR
# shellcheck source=e2e-acceptance-local.sh
. "$(cd "$(dirname "$0")" && pwd)/e2e-acceptance-local.sh"
# The harness installed cleanup as the EXIT trap; keep it and add our file.
trap 'rm -f "$TOOL_SCRIPT"; cleanup' EXIT

# model_lines ARTIFACT: the artifact's model: lines, in order.
model_lines() { grep '^model: ' <<<"$1" || true; }

# --- 4. The combined run: the model chooses, every door, one human.
run acceptance
grep -q "finished: succeeded" <<<"$OUT" || { cat "$WORK/agent.err"; fail "the combined run did not succeed"; }
PARENT="$RUNID"
L="$(ledger "$PARENT")"
grep -q "invoked by dana@example.com (oidc, issuer $ISSUER)" <<<"$AUDIT" || fail "the run is not attributed to the verified human"
bound "$L" "$PARENT" dana@example.com
[ "$(count "$L" step_succeeded)" = 1 ] || fail "expected exactly one succeeded step"
ART="$(parent_artifact "$PARENT")"
echo "$ART"
# One line per leg the model took: four model lines, the exec, two tools, two
# spawns — and nothing an upstream's text could have added.
[ "$(grep -c '' <<<"$ART")" = 9 ] || fail "the artifact is not exactly nine lines (four model rounds, exec, two tool calls, two spawns)"

# 4a. The model door, N times: one model_call per round the model took — the
#     three tool rounds and the answer — each governed, none refused; the
#     provider saw four requests offering the real tool set and two (the
#     children) offering none, every one with the host key, never the run
#     token, and no X-Agenthof-* header. Checked before the refused runs add
#     calls. The model_call event carries no tool names and no reply body:
#     the model's CHOICES are the exec/tool_call/spawn events below.
[ "$(count "$L" model_call succeeded)" = 4 ] || fail "expected exactly four succeeded model_calls on the parent (three tool rounds and the answer)"
[ "$(count "$L" model_call)" = 4 ] || fail "the parent recorded a model_call that did not succeed"
[ "$(out_of grep -cF "model fast — 3 prompt / 5 completion tokens" <<<"$AUDIT")" = 4 ] || fail "audit did not render four model_calls"
[ "$(model_lines "$ART" | wc -l | tr -d ' ')" = 4 ] || fail "the artifact does not report four model rounds"
[ "$(model_lines "$ART" | sed -n 1p)" = "model: called exec" ] || fail "round 1 did not call exec"
# The line is the MODEL's call order (the tool script's), not the offered order.
[ "$(model_lines "$ART" | sed -n 2p)" = "model: called whoami, echo" ] || fail "round 2 did not call both granted tools"
[ "$(model_lines "$ART" | sed -n 3p)" = "model: called spawn, spawn" ] || fail "round 3 did not make both spawn calls in one round"
[ "$(model_lines "$ART" | sed -n 4p)" = "model: governed:$NONCE" ] || fail "the artifact does not end with the provider's answer"
[ "$(tail -n 1 <<<"$ART")" = "model: governed:$NONCE" ] || fail "the answer is not the artifact's last line"
python3 - "$WORK/provider.jsonl" "$GATEWAY_KEY" <<'PY' || fail "the provider did not see four tool-offering parent rounds and two plain child calls with the host key injected"
import json, sys
lines = [json.loads(l) for l in open(sys.argv[1], encoding="utf-8") if l.strip()]
assert len(lines) == 6, "expected six provider calls (four parent rounds + two children), saw %d" % len(lines)
for r in lines:
    assert r["path"] == "/v1/chat/completions", r["path"]
    assert r["authorization"] == "Bearer " + sys.argv[2], "the provider did not see the host key"
    assert r["model"] == "fast", r["model"]
    assert not [h for h in r["headers"] if h.startswith("x-agenthof")], r["headers"]
parent = [r for r in lines if r["tools"]]
children = [r for r in lines if not r["tools"]]
assert len(parent) == 4 and len(children) == 2, (len(parent), len(children))
for r in parent:
    assert r["tools"] == ["exec", "spawn", "credential", "echo", "environment", "whoami"], "the model was not offered the doors plus the real grant: %r" % r["tools"]
assert sorted(r["tool_rounds"] for r in parent) == [0, 1, 2, 3], [r["tool_rounds"] for r in parent]
assert all(r["tool_rounds"] == 0 for r in children)
print("provider saw: 4 rounds offering [exec, spawn, credential, echo, environment, whoami] + 2 plain child calls, host key injected, model fast, no X-Agenthof-* headers")
PY
MODEL_LINE="$(out_of grep '"type":"model_call"' "$L")"
[ -n "$MODEL_LINE" ] || fail "no model_call line to check, so the absence below would prove nothing"
case "$MODEL_LINE" in *"governed:$NONCE"*) fail "the model reply body reached a model_call event" ;; esac
case "$MODEL_LINE" in *'"whoami"'*) fail "a tool name reached a model_call event (model_call records the model and tokens only)" ;; esac

# 4b. The exec door, first-hand, chosen by the model.
[ "$(count "$L" exec succeeded)" = 1 ] || fail "expected exactly one succeeded exec"
[ "$(count "$L" exec)" = 1 ] || fail "the parent recorded an exec that did not succeed"
[ "$(field "$L" exec mode succeeded)" = runtime ] || fail "the exec is not mode runtime"
EXEC_ATT="$(field "$L" exec runtime_attestation succeeded)"
case "$EXEC_ATT" in *'"runtime": "refexec"'*) ;; *) fail "no refexec attestation on the exec" ;; esac
case "$EXEC_ATT" in *'"command": ["env"]'*) ;; *) fail "the attestation does not name env" ;; esac
grep -Eq "exec env — exit 0 \(runtime\) \[runtime-attested: refexec env pid [0-9]+ spawn 1\]" <<<"$AUDIT" || fail "audit did not render the first-hand exec"
grep -qxF "exec: ACCEPTANCE_E2E_MARKER=1" <<<"$ART" || fail "the exec output is not exactly the allowlisted variable (the compartment's environment was not the allowlist)"
EXEC_LINE="$(out_of grep '"type":"exec"' "$L")"
[ -n "$EXEC_LINE" ] || fail "no exec line in the parent's ledger, so the absence check below would prove nothing"
case "$EXEC_LINE" in *ACCEPTANCE_E2E_MARKER=1*) fail "the exec output body reached the exec event" ;; esac

# 4c. + 4d. The tool door: on behalf of the human, and bridged. The model
#     makes both calls in ONE round, so they run concurrently, and the tool
#     listing that offered them was a session of its own: the gateway is
#     expected to accept concurrent inbound MCP sessions from one run. If a
#     leg here is flaky or fails only when both run at once, that is a
#     finding about the gateway, not something to retry or serialise around.
[ "$(tool_field "$L" whoami status)" = succeeded ] || fail "whoami did not succeed"
[ "$(tool_field "$L" whoami auth_mode)" = token_exchange ] || fail "whoami is not auth_mode token_exchange"
grep -Eq "tool whoami — args [0-9a-f]{8} \(token_exchange\)" <<<"$AUDIT" || fail "audit did not render the token_exchange call"
grep -qxF "tool whoami: acting as: u-dana" <<<"$ART" || fail "the upstream did not see the human's sub"
[ -s "$WORK/issued.jsonl" ] || fail "the issuer logged no exchanged token"
grep -q '"sub":"u-dana"' "$WORK/issued.jsonl" || fail "the issuer exchanged for nobody in particular"
grep -q "\"aud\":\"$UP_AUD\"" "$WORK/issued.jsonl" || fail "the issuer exchanged for no token audienced to the upstream"
[ "$(tool_field "$L" echo status)" = succeeded ] || fail "echo did not succeed"
[ "$(tool_field "$L" echo auth_mode)" = static_env ] || fail "echo is not auth_mode static_env"
ECHO_ATT="$(tool_field "$L" echo runtime_attestation)"
case "$ECHO_ATT" in *'"runtime": "refbridge"'*) ;; *) fail "no refbridge attestation on the bridged call" ;; esac
grep -Eq "tool echo — args [0-9a-f]{8} \(static_env\) \[runtime-attested: refbridge $(ere_escape "$WORK/stdio-tool") -credential-env DEMO_TOKEN pid [0-9]+ spawn 1\]" <<<"$AUDIT" || fail "audit did not render the bridged call's attestation"
grep -qxF "tool echo: drive-$NONCE" <<<"$ART" || fail "the bridged tool did not echo the step input"
[ "$(count "$L" tool_call)" = 2 ] || fail "expected exactly two tool_call events (one per resource)"

# 4e. The spawn door: two children from ONE round, in parallel.
[ "$(count "$L" spawn succeeded)" = 2 ] || fail "expected exactly two succeeded spawns"
[ "$(count "$L" spawn)" = 2 ] || fail "the parent recorded a spawn that did not succeed"
CHILDREN="$(field "$L" spawn child_run_id succeeded)"
[ "$(echo "$CHILDREN" | sort -u | wc -l | tr -d ' ')" = 2 ] || fail "the two spawn events do not name two distinct children"
for c in $CHILDREN; do
	CL="$(ledger "$c")"
	[ -f "$CL" ] || fail "child $c has no ledger of its own"
	bound "$CL" "$c" dana@example.com "$PARENT"
	[ "$(field "$CL" workflow_finished status)" = succeeded ] || fail "child $c did not finish succeeded"
	[ "$(count "$CL" model_call succeeded)" = 1 ] || fail "child $c did not make exactly one governed model call"
	CSHA="$(field "$CL" step_succeeded artifact_sha)"
	[ "$(cat "$WORK/artifacts/$CSHA")" = "governed:$NONCE" ] || fail "child $c's artifact is not the provider's reply"
	grep -qxF "spawn: succeeded $c governed:$NONCE" <<<"$ART" || fail "child $c's preview did not reach the parent's artifact"
	grep -q "spawn acceptance-worker/acceptance-sub → run $c succeeded (depth 1) — artifact ${CSHA:0:8}" <<<"$AUDIT" || fail "audit did not render the spawn of $c"
	grep -q "compartment started.*child=$c.*compartment=agenthof-spawn-$c-acceptance-sub" "$WORK/refspawn.err" || fail "child $c's agent did not run in a compartment the supervisor provisioned"
	CA="$(out_of "$WORK/agenthof" audit "$c" --log-dir "$WORK/logs" --control-log "$WORK/control.jsonl")"
	OUTS+=("$CA")
	grep -q "ledger integrity: verified" <<<"$CA" || fail "child $c's ledger does not verify"
	grep -q "invoked by dana@example.com (oidc, issuer $ISSUER)" <<<"$CA" || fail "child $c is not attributed to the verified human"
	grep -qF "model fast — 3 prompt / 5 completion tokens" <<<"$CA" || fail "child $c's audit shows no model_call"
done
# The supervisor took every set back once the children were over.
for i in $(seq 1 60); do
	[ "$(provisioned_count)" = 2 ] && [ "$(torn_down_count)" = 2 ] && [ -z "$(ls -A "$SPAWN_ROOT")" ] && break
	[ "$i" = 60 ] && fail "the supervisor provisioned $(provisioned_count) sets and tore down $(torn_down_count); something is still there"
	sleep 0.25
done
# The same discriminator as the scripted gate: both "spawn started" lines for
# the parent precede its first "spawn finished" only if the two spawn calls
# the model made in one round were carried concurrently.
[ -f "$WORK/agenthof.err" ] || fail "no agenthof.err, so the parallel order could not be checked"
par_rc=0
awk -v parent="$PARENT" '
	index($0, "spawn started")  && index($0, parent) { started++; if (started == 2) second_start = NR }
	index($0, "spawn finished") && index($0, parent) && !first_finish { first_finish = NR }
	END {
		if (started < 2)   exit 2
		if (!first_finish) exit 3
		exit (second_start < first_finish ? 0 : 1)
	}
' "$WORK/agenthof.err" || par_rc=$?
case "$par_rc" in
	0) echo "parallel: both spawn calls of one model round were in flight before either child returned (agenthof.err) — ok" ;;
	2) fail "the gateway logged fewer than two 'spawn started' lines for the parent run; the parallel order could not be proven" ;;
	3) fail "the gateway logged no 'spawn finished' line for the parent run; the parallel order could not be proven" ;;
	*) fail "a child's spawn finished before the second spawn started: the round's calls ran one after another, not in parallel" ;;
esac
TREE="$("$WORK/agenthof" investigate --run "$PARENT" --log-dir "$WORK/logs" --control-log "$WORK/control.jsonl")"
OUTS+=("$TREE")
echo "$TREE"
grep -q "^[0-9].* run workflow_started — dana@example.com" <<<"$TREE" || fail "investigate --run does not show the parent"
[ "$(out_of grep -c "^  [0-9].* run workflow_started — dana@example.com .*parent=$PARENT" <<<"$TREE")" = 2 ] || fail "investigate --run does not show both children under the parent"
echo "combined llm run: four governed model rounds, first-hand exec, on-behalf-of tool, bridged tool, two parallel children — all the model's own choices — ok"

# --- 5. Refusals the model is told about. Under this driver a refusal does
# not end the step: the door says no, records it, the model gets the fixed
# words and goes on, and the step succeeds WITH the refusal in its ledger.

# 5a. Off-allowlist exec: the model asks for env, this agent's allowlist
#     says true. Refused before the runtime is asked, recorded, and the model
#     goes on to the tool and spawn doors.
BEFORE_EXEC="$(out_of grep -c 'compartment started' "$WORK/refexec.err")"
[ "$BEFORE_EXEC" -ge 1 ] || fail "the exec runtime logged no compartment for the combined run, so the count below would prove nothing"
run acceptance-noexec
grep -q "finished: succeeded" <<<"$OUT" || fail "a refused exec must not fail the llm step; the model is told and goes on"
NOEXEC="$RUNID"
LN="$(ledger "$NOEXEC")"
bound "$LN" "$NOEXEC" dana@example.com
[ "$(count "$LN" exec refused)" = 1 ] || fail "expected exactly one refused exec"
[ "$(count "$LN" exec)" = 1 ] || fail "the refused run recorded an exec that was not the refusal"
[ "$(field "$LN" exec reason refused)" = "command is not on the exec allowlist" ] || fail "the exec refusal is not the allowlist reason"
grep -qF "exec env refused — command is not on the exec allowlist" <<<"$AUDIT" || fail "audit did not render the exec refusal"
if ! NOEXEC_ART="$(parent_artifact "$NOEXEC")"; then
	echo "$NOEXEC_ART"
	fail "no artifact on the off-allowlist run"
fi
grep -qxF "exec: refused by policy" <<<"$NOEXEC_ART" || fail "the model was not told the fixed refusal"
[ "$(count "$LN" tool_call succeeded)" = 2 ] || fail "the model did not go on to the tool door after the refusal"
[ "$(count "$LN" spawn succeeded)" = 2 ] || fail "the model did not go on to the spawn door after the refusal"
[ "$(count "$LN" model_call succeeded)" = 4 ] || fail "the refused run did not take four model rounds"
[ "$(out_of grep -c 'compartment started' "$WORK/refexec.err")" = "$BEFORE_EXEC" ] || fail "the runtime was asked to run an off-allowlist command"
echo "off-allowlist exec: refused, recorded, nothing ran, the model was told in fixed words and finished the task — ok"

# 5b. may_spawn-denied children: the exec and tool legs run and are recorded,
#     both spawns are refused by the door, no child starts, nothing is
#     provisioned, and the model is told and finishes.
BEFORE="$(provisioned_count)"
[ "$BEFORE" -ge 1 ] || fail "the supervisor logged no provisioned set for the earlier runs, so the count below would prove nothing"
run acceptance-nospawn
grep -q "finished: succeeded" <<<"$OUT" || fail "refused spawns must not fail the llm step; the model is told and goes on"
NOSPAWN="$RUNID"
LS="$(ledger "$NOSPAWN")"
bound "$LS" "$NOSPAWN" dana@example.com
[ "$(count "$LS" spawn refused)" = 2 ] || fail "expected exactly two refused spawns"
[ "$(count "$LS" spawn succeeded)" = 0 ] || fail "a child ran although nothing is on may_spawn"
[ "$(field "$LS" spawn reason refused | sort -u)" = "spawn target is not on the agent's may_spawn list" ] || fail "the spawn refusals are not the may_spawn reason"
[ -z "$(field "$LS" spawn child_run_id refused)" ] || fail "a may_spawn refusal must start no child"
[ "$(provisioned_count)" = "$BEFORE" ] || fail "a may_spawn refusal provisioned a set"
if ! NOSPAWN_ART="$(parent_artifact "$NOSPAWN")"; then
	echo "$NOSPAWN_ART"
	fail "no artifact on the may_spawn-denied run"
fi
[ "$(out_of grep -c '^spawn: refused by policy$' <<<"$NOSPAWN_ART")" = 2 ] || fail "the model was not told both fixed refusals"
[ "$(out_of grep -cF "spawn acceptance-worker/acceptance-sub → no child run refused (depth 1) — spawn target is not on the agent's may_spawn list" <<<"$AUDIT")" = 2 ] || fail "audit did not render both spawn refusals"
[ "$(count "$LS" model_call succeeded)" = 4 ] || fail "the no-spawn run did not take four model rounds"
[ "$(count "$LS" exec succeeded)" = 1 ] || fail "the exec leg was not recorded on the no-spawn run"
[ "$(count "$LS" tool_call succeeded)" = 2 ] || fail "the two tool legs were not recorded on the no-spawn run"
echo "may_spawn-denied spawns: both refused and recorded, no child, nothing provisioned, the model was told and finished — ok"

# --- 6. Verify is per run: the parent, each child, and each refused run,
# every one on its own. There is no tree-wide verify, and this proves none
# was assumed. (verify_run is defined with the harness helpers.)
verify_run "$PARENT" "the combined run"
for c in $CHILDREN; do verify_run "$c" "a child run"; done
verify_run "$NOEXEC" "the off-allowlist run"
verify_run "$NOSPAWN" "the no-spawn run"
echo "verify: parent, both children, and both refused runs each verify on their own — ok"

# --- 7. Nothing secret reached anywhere it must not. An absence proves
# something only where the places searched are populated and the same
# search finds what IS there, so positive controls run first through the
# identical grep.
[ "$(find "$WORK/logs" -name '*.jsonl' | wc -l | tr -d ' ')" -ge 7 ] || fail "fewer ledgers than runs (parent, two children, the off-allowlist run and its two children, the no-spawn run), so the leak checks would search an incomplete tree"
[ -n "$(ls -A "$WORK/artifacts")" ] || fail "the artifact store is empty, so the leak checks would search nothing there"
[ -s "$WORK/agenthof.err" ] || fail "the operational log is empty, so the leak checks would search nothing"
grep -q "level=DEBUG" "$WORK/agenthof.err" || fail "the operational log carries no debug records"
[ -s "$WORK/control.jsonl" ] || fail "the control log is empty"
for f in provider idp upstream bridge refexec refspawn agent; do
	[ -f "$WORK/$f.err" ] || fail "$WORK/$f.err is missing, so the leak checks would skip that process"
done
grep -rqF "drive-$NONCE" "$WORK/logs" "$WORK/artifacts" || fail "the positive control (the step input, echoed into a tool_call preview and the artifact) is missing, so the identical search for a secret would prove nothing"
grep -qF "listening" "$WORK/agent.err" || fail "the agent's log is empty, so the search across process logs would prove nothing there"
# Written to a file, not piped: once the captured output outgrows the pipe
# buffer, a grep -q that matches early would SIGPIPE the writer and fail the
# pipeline under pipefail — reporting "no match" exactly when there is one.
printf '%s\n' "${OUTS[@]}" >"$WORK/outs.txt"
grep -qF "spawn acceptance-worker/acceptance-sub" "$WORK/outs.txt" || fail "no captured output names a spawn, so the search below would prove nothing"
no_leak "$TOKEN" "the subject token"
no_leak "$(jwt_payload "$TOKEN")" "the subject token's payload"
no_leak "${TOKEN##*.}" "the subject token's signature"
no_leak "$IDP_SECRET" "the broker's client secret"
no_leak "$TOOL_SECRET" "the bridged tool's credential"
no_leak "$GATEWAY_KEY" "the provider key"
# Tokens are base64url: no whitespace, so word-splitting the output is safe,
# and a plain for loop (not a piped while) runs no_leak in THIS shell, where
# its fail exits the script.
EXCHANGED=0
for exchanged in $(python3 -c 'import json, sys; [print(json.loads(l)["token"]) for l in open(sys.argv[1]) if l.strip()]' "$WORK/issued.jsonl"); do
	no_leak "$exchanged" "an exchanged token"
	no_leak "$(jwt_payload "$exchanged")" "an exchanged token's payload"
	no_leak "${exchanged##*.}" "an exchanged token's signature"
	EXCHANGED=$((EXCHANGED + 1))
done
[ "$EXCHANGED" -ge 1 ] || fail "the issuer's token log named no exchanged token, so the absence check above proved nothing"
echo "no leak: subject token, $EXCHANGED exchanged token(s) (each also by its payload and signature), client secret, tool credential, provider key — in no ledger, artifact, log, or output — ok"
echo "$ME: PASS"
