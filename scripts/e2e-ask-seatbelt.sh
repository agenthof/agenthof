#!/usr/bin/env bash
# e2e-ask-seatbelt: prove `agenthof ask` end to end CONTAINED under the real
# macOS Seatbelt backend, by judgment (not CI). Two agents from the agents hub
# are built from a hub checkout with the hub's reproducible recipe and enrolled
# from their SIGNED cards exactly as published (trusted_signers = the published
# curator key): router-chat, which classifies, and generic-chat, which answers.
# The trusted orchestrator agent may spawn both; the refspawn supervisor maps
# each enrolled agent to its freshly built binary and runs it hash-bound under
# sandbox-exec. `ask`/`run` execute the INSTALLED snapshot under the control-log
# directory, not the working --config directory, so BOTH are denied to every
# compartment: the working config directory via deny_config_read, and the
# control root (which holds installed/, the operator signing key and the run
# ledgers) via deny_read. A local fake provider plays the model for both calls.
# Asserts:
#   (a) ask runs router-chat and then generic-chat, each in a compartment named
#       for its child, each recorded on the orchestrator's ledger with the
#       seatbelt tier and the host-program hash this script computed itself;
#   (b) the answer (the provider's reply to the user's prompt) is the only thing
#       on stdout, and the provider saw exactly the classifier call (the menu
#       names generic-chat) and the answering call (the user's prompt);
#   (c) the receipt on stderr names the seatbelt tier for the leaf, and the
#       ask run's OWN ledger reports completeness (not a gap);
#   (d) a compartment under the same supervisor cannot read the working config
#       directory's gateway.yaml, NOR (d′) the gateway.yaml of the INSTALLED
#       snapshot actually executed under the control root — while an ordinary
#       host file still reads and the unsandboxed control reads both — and
#       nothing leaked;
#   (e) a REPOINTED program (other bytes) mapped to the same consent is refused
#       with the binding reason, starts no child and never runs.
# On (d)/(d′): the hub agents have no way to read a file, so the probe is a plain
# agent run in a child of the same supervisor, whose deny set is the one every
# compartment it starts gets; router-chat's compartment is built from that same
# deny set, not from anything particular to the probe.
#
# Run by judgment, not in CI, like the other real-sandbox tiers.
# Environment: HUB_DIR = a checkout of the agents hub (required; the script
# skips cleanly when unset, off macOS, without /usr/bin/sandbox-exec, or on a
# toolchain that does not reproduce the cards' pinned hashes). The hub pins
# go1.27.4 for its reproducible build; keep the version below in sync with it.
# Requires go, curl and python3. Run from the repo root.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ -z "${HUB_DIR:-}" ]; then
	echo "e2e-ask-seatbelt: SKIP — set HUB_DIR to an agents hub checkout"
	exit 0
fi
if [ "$(uname)" != Darwin ] || [ ! -x /usr/bin/sandbox-exec ]; then
	echo "e2e-ask-seatbelt: SKIP — macOS with /usr/bin/sandbox-exec is required"
	exit 0
fi
for tool in go curl python3 pgrep; do
	command -v "$tool" >/dev/null 2>&1 || { echo "e2e-ask-seatbelt: FAIL — $tool is required"; exit 1; }
done
[ -f "$HUB_DIR/scripts/build.sh" ] && [ -f "$HUB_DIR/agents/generic-chat/card.json" ] && [ -f "$HUB_DIR/agents/router-chat/card.json" ] || { echo "e2e-ask-seatbelt: FAIL — HUB_DIR is not an agents hub checkout"; exit 1; }
HUB_DIR="$(cd "$HUB_DIR" && pwd)"
HUB_GO=go1.27.4   # the hub's pinned build toolchain; keep in sync with its scripts/build.sh
if [ "$(go env GOVERSION)" != "$HUB_GO" ]; then
	echo "e2e-ask-seatbelt: SKIP — the hub's pinned hashes reproduce only on $HUB_GO (found $(go env GOVERSION)); put $HUB_GO first on PATH"
	exit 0
fi

SOCK_DIR="$(mktemp -d /tmp/as.XXXXXX)"
SUP_DIR="$(mktemp -d /tmp/as.XXXXXX)"
SPAWN_ROOT="$(mktemp -d /tmp/as.XXXXXX)"
WORK="$(mktemp -d /tmp/as.XXXXXX)"
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
	echo "e2e-ask-seatbelt: FAIL — $*"
	[ -f "$WORK/refspawn.err" ] && { echo "--- refspawn.err (tail)"; tail -n 40 "$WORK/refspawn.err"; } >&2
	exit 1
}
unset AGENTHOF_TOKEN || true
# shellcheck source=scripts/acceptance-lib.sh
. "$ROOT/scripts/acceptance-lib.sh"   # field, count, bound, out_of
# shellcheck source=scripts/enroll-lib.sh
. "$ROOT/scripts/enroll-lib.sh"       # enroll_agent, ran_of

CURATOR_KID=f07e492a38568409cbcb459b1feac8b70e08eec00149ac1981b4f9c053412404
CURATOR_KEY=k2troapQ5SHzGpMeckKzHBUNcI517qZmiX/bw9Bl05o=
sha_of() { printf 'sha256:%s' "$(shasum -a 256 "$1" | awk '{print $1}')"; }

# Build everything BEFORE anything starts.
go build -o "$WORK/agenthof" ./cmd/agenthof
go build -o "$WORK/refexec" ./deploy/refexec
go build -o "$WORK/refspawn" ./deploy/refspawn
go build -o "$WORK/echo-agent" ./examples/echo-agent
for a in generic-chat router-chat; do
	BUILT="$("$HUB_DIR/scripts/build.sh" "$a" darwin arm64 "$WORK/$a")" || fail "the hub build of $a failed"
	HASH="$(sha_of "$WORK/$a")"
	[ "$BUILT" = "$HASH" ] || fail "the hub build of $a reported $BUILT but the bytes hash to $HASH"
	if ! grep -q "$HASH" "$HUB_DIR/agents/$a/card.json"; then
		echo "e2e-ask-seatbelt: SKIP — this $HUB_GO build does not reproduce $a's pinned darwin/arm64 hash ($HASH)"
		exit 0
	fi
done
GC_HASH="$(sha_of "$WORK/generic-chat")"
RC_HASH="$(sha_of "$WORK/router-chat")"
# A repointed program: same source, different bytes (a stripped link).
CGO_ENABLED=0 go -C "$HUB_DIR" build -trimpath -buildvcs=false -ldflags='-s -w' -o "$WORK/generic-chat-variant" ./agents/generic-chat
VARIANT_HASH="$(sha_of "$WORK/generic-chat-variant")"
[ "$GC_HASH" != "$VARIANT_HASH" ] || fail "the variant has the consented bytes, so refusing it would prove nothing"

# --- the fake model provider both catalog entries point at. The router model
# answers the classifier's numbered menu with "1" (generic-chat is the only
# choice), the chat model answers the user's prompt with a nonce-bearing reply.
PROVIDER_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
NONCE="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
python3 scripts/fake-openai-provider.py --bind "127.0.0.1:$PROVIDER_PORT" --reply "answered:$NONCE" \
	--reply-for "router=1" --log "$WORK/provider.jsonl" >/dev/null 2>"$WORK/provider.err" &
PIDS+=($!)
for i in $(seq 1 60); do
	curl -s -o /dev/null "http://127.0.0.1:$PROVIDER_PORT/" && break
	[ "$i" = 60 ] && fail "the fake provider never came up"
	sleep 0.2
done
export AGENTHOF_GATEWAY_KEY="host-side-dummy-key-$NONCE"

# The working config directory (the --config source) and the control root (the
# control log, the installed snapshot ask/run actually execute, the signing key
# and the run ledgers). Both are denied to compartments; Seatbelt resolves the
# deny to a real path, so each directory must exist before refspawn starts — the
# control root is created empty now and apply fills it below.
CFG="$WORK/config"
mkdir -p "$CFG/agents" "$CFG/workflows" "$CFG/roles"
CFG_REAL="$(cd "$CFG" && pwd -P)"
CTL_DIR="$WORK/control"
mkdir -p "$CTL_DIR"
CTL_REAL="$(cd "$CTL_DIR" && pwd -P)"
printf 'open-%s\n' "$NONCE" >"$WORK/open.txt"

# --- refspawn on the seatbelt tier, every enrolled agent mapped to its built
# binary, the config directory read-denied to every compartment.
(umask 077 && mkdir -p "$STORE_ROOT" "$PID_DIR")
cat >"$WORK/refspawn.yaml" <<EOC
confiner: seatbelt
socket: $SUP_DIR/refspawn.sock
spawn_root: $SPAWN_ROOT
store_root: $STORE_ROOT
pid_dir: $PID_DIR
deny_config_read: $CFG_REAL
deny_read:
  - $CTL_REAL
images:
  generic-chat: $WORK/generic-chat
  router-chat: $WORK/router-chat
  repointed: $WORK/generic-chat-variant
  probe: $WORK/echo-agent
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
"$WORK/refspawn" -config "$WORK/refspawn.yaml" 2>>"$WORK/refspawn.err" &
PIDS+=($!)
for i in $(seq 1 60); do
	[ -S "$SUP_DIR/refspawn.sock" ] && break
	[ "$i" = 60 ] && fail "refspawn socket never appeared"
	sleep 0.5
done

# The lead's agent (used only by the probe and refusal scenarios): a host process.
mkdir -p "$WORK/lead-ws"
"$WORK/echo-agent" -socket "$SOCK_DIR/agent.sock" -workspace "$WORK/lead-ws" 2>"$WORK/agent.err" &
PIDS+=($!)
for i in $(seq 1 60); do
	[ -S "$SOCK_DIR/agent.sock" ] && break
	[ "$i" = 60 ] && { cat "$WORK/agent.err" >&2; fail "agent socket never appeared"; }
	sleep 0.5
done

# --- the installed configuration. Both catalog models point at the provider's
# ORIGIN: the gateway appends /v1/chat/completions itself.
cat >"$CFG/gateway.yaml" <<EOC
refbox_socket_dir: $SOCK_DIR
spawn_supervisor: unix://$SUP_DIR/refspawn.sock
spawn:
  max_depth: 3
  max_parallel: 2
  max_total_spawns: 8
step_timeout: 3m
models:
  router:
    endpoint: http://127.0.0.1:$PROVIDER_PORT
    model: router
    api_key_env: AGENTHOF_GATEWAY_KEY
  chat:
    endpoint: http://127.0.0.1:$PROVIDER_PORT
    model: chat
    api_key_env: AGENTHOF_GATEWAY_KEY
defaults:
  model: chat
trusted_signers:
  - {kid: $CURATOR_KID, key: $CURATOR_KEY}
EOC
# The orchestrator: the trusted agent whose may_spawn is everything ask may
# start — the classifier and the leaf, and nothing else, added once enrolled
# (below). It never runs a step.
cat >"$CFG/agents/orchestrator.yaml" <<EOC
name: orchestrator
description: routes a request to the agent that answers it
model: chat
instruction: Route.
output: output
execution: fronted
endpoint: unix://$SOCK_DIR/agent.sock
may_spawn:
EOC
printf 'name: ask\ndescription: ask\nsteps:\n  - name: ask\n    agent: orchestrator\n' >"$CFG/workflows/ask.yaml"
printf 'name: orchestrator\ndescription: Runs ask\nworkflows: [ask]\nallowed_groups: ["spawn-users"]\n' >"$CFG/roles/orchestrator.yaml"
# The lead and its probe: a plain agent that execs cat, to read the config
# under the same supervisor.
cat >"$CFG/agents/lead.yaml" <<EOC
name: lead
description: the root run's agent, a host process
model: chat
instruction: Run the script.
output: output
execution: fronted
endpoint: unix://$SOCK_DIR/agent.sock
may_spawn:
  - role: probe
    workflow: probe-wf
EOC
cat >"$CFG/agents/probe.yaml" <<EOC
name: probe
description: reads a file inside its compartment
model: chat
instruction: Run the script.
output: output
execution: fronted
endpoint: unix:///run/agenthof/placeholder.sock
exec:
  runtime: refexec
  url: unix:///run/agenthof-exec/placeholder.sock
  timeout: 60s
  allow:
    - exe: cat
EOC
printf 'name: lead-wf\ndescription: lead\nsteps:\n  - name: lead\n    agent: lead\n' >"$CFG/workflows/lead-wf.yaml"
printf 'name: probe-wf\ndescription: probe\nsteps:\n  - name: probe\n    agent: probe\n' >"$CFG/workflows/probe-wf.yaml"
printf 'name: probe\ndescription: Runs the probe\nworkflows: [probe-wf]\nallowed_groups: ["spawn-users"]\n' >"$CFG/roles/probe.yaml"
cat >"$CFG/roles/lead.yaml" <<EOC
name: lead
description: Runs the parent workflow and enrolls agents
workflows: [lead-wf]
allowed_groups: ["spawn-users"]
control: [apply, enroll]
EOC
ARGS=(--config "$CFG" --control-log "$CTL_DIR/control.jsonl" --as ci --groups spawn-users)
"$WORK/agenthof" apply "${ARGS[@]}" >"$WORK/apply.out" 2>&1 || { cat "$WORK/apply.out"; fail "apply of the base config failed"; }

# Enroll both hub cards exactly as published.
# shellcheck disable=SC2034  # read by enroll_agent in enroll-lib.sh
ENROLL_ARGS=("${ARGS[@]}")
# shellcheck disable=SC2034  # read by enroll_agent in enroll-lib.sh
AGENTHOF="$WORK/agenthof"
for a in generic-chat router-chat; do
	enroll_agent "$HUB_DIR/agents/$a/card.json" "$a" "$CFG"
	printf '%s\n' "$ENROLL_OUT" | grep -q "seatbelt (program \"$a\"" || { echo "$ENROLL_OUT"; fail "enroll of $a did not offer the program mapping for the seatbelt tier"; }
done
grep -q "$GC_HASH" "$CFG/agents/generic-chat.yaml" || fail "the enrolled generic-chat does not record the consented hash"
grep -q "$RC_HASH" "$CFG/agents/router-chat.yaml" || fail "the enrolled router-chat does not record the consented hash"
# The same consent, enrolled again as an agent the operator maps to other bytes.
enroll_agent "$HUB_DIR/agents/generic-chat/card.json" repointed "$CFG"
enroll_allow_spawn "$CFG/agents/lead.yaml" repointed
for a in router-chat generic-chat; do enroll_allow_spawn "$CFG/agents/orchestrator.yaml" "$a"; done
"$WORK/agenthof" apply "${ARGS[@]}" >"$WORK/apply.out" 2>&1 || { cat "$WORK/apply.out"; fail "apply of the enrolled agents failed"; }

ledger() { echo "$CTL_DIR/runs/$1.jsonl"; }
run() { # $1 = input; sets OUT, RUNID, AUDIT  (the lead's run, for the probe and refusal scenarios)
	OUT="$("$WORK/agenthof" run lead lead-wf --input "$1" "${ARGS[@]}" \
		--log-dir "$CTL_DIR/runs" --artifact-dir "$CTL_DIR/artifacts" 2>>"$WORK/agenthof.err" || true)"
	echo "$OUT"
	RUNID="$(echo "$OUT" | sed -n 's/^run \(r-[a-f0-9]*\) finished.*/\1/p')"
	[ -n "$RUNID" ] || { cat "$WORK/agenthof.err" >&2 || true; fail "no run id"; }
	AUDIT="$("$WORK/agenthof" audit "$RUNID" --log-dir "$CTL_DIR/runs" --control-log "$CTL_DIR/control.jsonl")"
	echo "$AUDIT"
	echo "$AUDIT" | grep -q "ledger integrity: verified" || fail "ledger not verified"
}

# (e) first, so the binding refusal is proven on a provider that has seen nothing.
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

# (d)+(d′) neither the working config directory NOR the installed snapshot the
# run actually executes is readable from a compartment. The unsandboxed control
# reads both; a sandboxed read of an ordinary host file succeeds, so the denial
# is specific; the sandboxed reads of each gateway.yaml are refused.
INSTALLED_GW="$(find "$CTL_DIR/installed" -name gateway.yaml | head -1)"
[ -n "$INSTALLED_GW" ] || fail "no installed gateway.yaml under the control root; nothing to prove the executed config is denied"
grep -q "^models:" "$CFG/gateway.yaml" || fail "the unsandboxed control cannot read the working gateway.yaml, so a sandboxed refusal proves nothing"
grep -q "refbox_socket_dir" "$INSTALLED_GW" || fail "the unsandboxed control cannot read the installed gateway.yaml, so a sandboxed refusal proves nothing"
run "spawn:probe/probe-wf:exec-run:cat $WORK/open.txt"
CH="$(field "$(ledger "$RUNID")" spawn child_run_id)"
[ -n "$CH" ] || fail "no child run id for the positive read control"
CAUDIT="$("$WORK/agenthof" audit "$CH" --log-dir "$CTL_DIR/runs" --control-log "$CTL_DIR/control.jsonl")"
echo "$CAUDIT" | grep -Eq "exec cat $WORK/open.txt — exit 0 \(runtime\) \[runtime-attested: refexec cat .*; confiner: seatbelt" || { echo "$CAUDIT"; fail "a sandboxed read of an ordinary host file did not succeed, so the denials below could be a deny-everything sandbox"; }
# (d) the working --config directory's gateway.yaml.
run "spawn:probe/probe-wf:exec-run:cat $CFG/gateway.yaml"
CH="$(field "$(ledger "$RUNID")" spawn child_run_id)"
[ -n "$CH" ] || fail "no child run id for the working-config read"
CAUDIT="$("$WORK/agenthof" audit "$CH" --log-dir "$CTL_DIR/runs" --control-log "$CTL_DIR/control.jsonl")"
echo "$CAUDIT" | grep -Eq "exec cat $CFG/gateway.yaml — exit 1 \(runtime\) \[runtime-attested: refexec cat .*; confiner: seatbelt" || { echo "$CAUDIT"; fail "the sandboxed read of the working gateway.yaml was not refused"; }
# (d′) the INSTALLED snapshot's gateway.yaml — the copy ask/run actually run.
run "spawn:probe/probe-wf:exec-run:cat $INSTALLED_GW"
CHI="$(field "$(ledger "$RUNID")" spawn child_run_id)"
[ -n "$CHI" ] || fail "no child run id for the installed-config read"
CIAUDIT="$("$WORK/agenthof" audit "$CHI" --log-dir "$CTL_DIR/runs" --control-log "$CTL_DIR/control.jsonl")"
echo "$CIAUDIT" | grep -Eq "exec cat $INSTALLED_GW — exit 1 \(runtime\) \[runtime-attested: refexec cat .*; confiner: seatbelt" || { echo "$CIAUDIT"; fail "the sandboxed read of the INSTALLED gateway.yaml was not refused — the executed config is reachable next door"; }
if grep -q "AGENTHOF_GATEWAY_KEY" "$(ledger "$CH")" "$(ledger "$CHI")" "$(ledger "$RUNID")"; then fail "the config's content reached a ledger"; fi
for f in "$CTL_DIR"/artifacts/*; do
	if [ -f "$f" ] && grep -q "AGENTHOF_GATEWAY_KEY" "$f"; then fail "the config's content reached an artifact"; fi
done
echo "config isolation: the working AND the installed gateway.yaml are unreadable from a compartment while an ordinary host file reads, nothing leaked — ok"

# (a)+(b)+(c): ask, end to end. Flags go BEFORE the prompt.
: >"$WORK/provider.jsonl"
SUP_AT="$(wc -l <"$WORK/refspawn.err" | tr -d ' ')"
PROMPT="what is a mutex $NONCE"
ASK_OUT="$("$WORK/agenthof" ask --yes "${ARGS[@]}" --log-dir "$CTL_DIR/runs" --artifact-dir "$CTL_DIR/artifacts" "$PROMPT" 2>"$WORK/ask.err")" || { cat "$WORK/ask.err" >&2; fail "ask failed"; }
tail -n "+$((SUP_AT + 1))" "$WORK/refspawn.err" >"$WORK/sup-tail.err"
cat "$WORK/ask.err"
[ "$ASK_OUT" = "answered:$NONCE" ] || { echo "stdout: $ASK_OUT"; fail "stdout is not exactly the provider's answer"; }
ASK_RUN="$(sed -n 's/^ask \(r-[a-f0-9]*\): picked generic-chat\/generic-chat$/\1/p' "$WORK/ask.err")"
[ -n "$ASK_RUN" ] || fail "ask did not report picking generic-chat/generic-chat"
AL="$(ledger "$ASK_RUN")"
[ "$(count "$AL" spawn succeeded)" = 2 ] || fail "expected two succeeded spawns (the classifier, the leaf) on the ask ledger"
[ "$(field "$AL" workflow_finished status)" = succeeded ] || fail "the ask run did not finish succeeded"
for a in router-chat generic-chat; do
	case "$a" in router-chat) want="$RC_HASH" ;; *) want="$GC_HASH" ;; esac
	[ "$(ran_of "$AL" "$a")" = "host-program $want" ] || { ran_of "$AL" "$a"; fail "the spawn's child_artifact for $a is not the host-program hash computed here ($want)"; }
done
[ "$(field "$AL" spawn child_confiner succeeded | sort -u)" = seatbelt ] || fail "a spawn does not record the seatbelt tier"
for c in $(field "$AL" spawn child_run_id succeeded); do
	grep -q "compartment started.*child=$c.*compartment=agenthof-spawn-$c-" "$WORK/sup-tail.err" || fail "child $c did not run in a compartment named for it"
done
grep -q "compartment started.*-router-chat" "$WORK/sup-tail.err" || fail "router-chat did not run in a compartment"
grep -q "compartment started.*-generic-chat" "$WORK/sup-tail.err" || fail "generic-chat did not run in a compartment"
python3 - "$WORK/provider.jsonl" "$NONCE" <<'PY' || fail "the provider did not see exactly one classifier call and one answering call"
import json, sys
# The two rows are told apart by MODEL (router vs chat), not by file order —
# nothing here asserts which call hit the provider first.
rows = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
assert len(rows) == 2, len(rows)
r, c = sorted(rows, key=lambda x: x["model"] != "router")
assert r["model"] == "router" and c["model"] == "chat", (r["model"], c["model"])
for x in rows:
    assert x["path"] == "/v1/chat/completions", x["path"]
rp = json.dumps(r["messages"])
assert "role=generic-chat workflow=generic-chat" in rp and "role=router-chat" not in rp, "menu"
assert sys.argv[2] in json.dumps(c["messages"]), "user prompt"
PY
# The receipt's seatbelt tier is anchored to the LEAF's own line, not a bare
# match anywhere in the receipt; the ask run's own ledger reports completeness.
grep -Eq "generic-chat/generic-chat +run r-[a-f0-9]+: containment tier seatbelt" "$WORK/ask.err" || { cat "$WORK/ask.err"; fail "the receipt does not name the seatbelt tier on the leaf's line"; }
grep -q "^receipt for ask $ASK_RUN" "$WORK/ask.err" || fail "no receipt on stderr"
grep -Eq "ledger $ASK_RUN: chain verified, completeness complete" "$WORK/ask.err" || { cat "$WORK/ask.err"; fail "the ask run's own ledger must report completeness complete in the receipt, not a gap"; }
# The head the receipt prints for the ask run's own ledger is its real current
# head: recorded off the box and replayed through `audit verify --expect-head`
# it must hold (exit 0). This is the round trip the receipt's limits line
# promises — the evidence against a later truncation or rewrite.
ASK_HEAD="$(grep -Eo "ledger $ASK_RUN: chain verified, completeness complete, head [0-9a-f]{64}" "$WORK/ask.err" | grep -Eo '[0-9a-f]{64}' || true)"
[ -n "$ASK_HEAD" ] || { cat "$WORK/ask.err"; fail "the receipt does not print the ask run's ledger head"; }
AV_OUT="$("$WORK/agenthof" audit verify "$ASK_RUN" --log-dir "$CTL_DIR/runs" --control-log "$CTL_DIR/control.jsonl" --expect-head "$ASK_HEAD" 2>&1)" || { echo "$AV_OUT"; fail "audit verify exited nonzero replaying the receipt head"; }
if echo "$AV_OUT" | grep -q "expect-head mismatch"; then echo "$AV_OUT"; fail "the receipt head must replay through audit verify --expect-head, but it mismatched"; fi
# `audit <ask-run>` itself must report the orchestrator ledger complete — the
# acceptance check the completeness fix is for — with both spawns accounted.
AAUDIT="$("$WORK/agenthof" audit "$ASK_RUN" --log-dir "$CTL_DIR/runs" --control-log "$CTL_DIR/control.jsonl")"
echo "$AAUDIT" | grep -q "ledger integrity: verified" || { echo "$AAUDIT"; fail "audit does not verify the ask run's ledger"; }
echo "$AAUDIT" | grep -q "ledger completeness: complete (2 door call(s) accounted)" || { echo "$AAUDIT"; fail "audit <ask-run> does not report completeness complete with two door calls"; }
# Both child runs' own ledgers verify. The seatbelt tier for each child is on
# the PARENT's spawn event (asserted above via child_confiner), not in the
# child's own model-only ledger — only an exec child records the tier on its
# own line, as the (d)/(d′) probes show.
for c in $(field "$AL" spawn child_run_id succeeded); do
	CC="$("$WORK/agenthof" audit "$c" --log-dir "$CTL_DIR/runs" --control-log "$CTL_DIR/control.jsonl")"
	echo "$CC" | grep -q "ledger integrity: verified" || { echo "$CC"; fail "child $c ledger not verified"; }
done
echo "ask: classifier and leaf each ran contained and hash-bound, the answer alone on stdout, audit reports the ask ledger complete, the receipt names the tier — ok"

echo "e2e-ask-seatbelt: PASS"
