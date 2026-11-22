#!/usr/bin/env bash
# e2e-enroll-mcp-local: prove the REAL agenthof binary governs the enrollment
# of a local stdio MCP end to end, with no container runtime. `enroll mcp`
# proposes the MCP into the WORKING configuration and ledgers an enroll_mcp
# event; only `apply` installs it. refbridge then launches the MCP from the
# INSTALLED snapshot's governed slice, and a tool-agent calls it through the
# tool door. Asserts: a disclosure run (no --accept) shows the argv, env names,
# tools and digest and writes and ledgers nothing; a wrong digest writes
# nothing; a fetch-at-spawn command is refused before any write; the accepted
# run edits the working gateway.yaml and the agent file, ledgers an enroll_mcp
# success with no card digest, and installs NOTHING; apply installs; the
# granted tools work and an un-granted tool of the same MCP is refused; a
# pasted inline secret VALUE reaches no written file, no output and no ledger;
# an enroll without apply leaves the installed configuration as it was.
# Requires go and python3. Runs on macOS and Linux.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Short on purpose: Unix socket paths have a small OS length limit. The bridge
# directory is SEPARATE from the gateway socket dir and mode 0700.
SOCK_DIR="$(mktemp -d /tmp/em.XXXXXX)"
BRIDGE_DIR="$(mktemp -d /tmp/emb.XXXXXX)"
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
	echo "e2e-enroll-mcp-local: FAIL — $*"
	exit 1
}
sha() { python3 -c 'import hashlib, sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())' "$1"; }
filesha() { python3 -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$1"; }
# no_leak VALUE WHAT: VALUE appears in no file under the scratch tree (config,
# control ledger, run ledgers, artifacts, captured output). Never prints VALUE.
no_leak() {
	local value="$1"
	shift
	if grep -rqF -- "$value" "$WORK" 2>/dev/null; then
		fail "$* reached a written file, the ledger, or a captured output"
	fi
}
ZERO_DIGEST="sha256:$(printf '0%.0s' $(seq 1 64))"

go build -o "$WORK/agenthof" ./cmd/agenthof
go build -o "$WORK/refbridge" ./deploy/refbridge
go build -o "$WORK/stdio-tool" ./examples/stdio-tool
go build -o "$WORK/tool-agent" ./examples/tool-agent

NONCE="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
CONFIG="$WORK/config"
CTL="$WORK/control.jsonl"
AH=("$WORK/agenthof")
IDENT=(--as ci --groups devs)

export E2E_TOOL_TOKEN="tool-secret-$NONCE"
export AGENTHOF_GATEWAY_KEY="host-side-dummy-key-$NONCE" # the model route is never called; the key only lets it resolve

# --- a hermetic base configuration with NO tool resources: the MCP arrives
# only through `enroll mcp`. The role may apply and enroll; the agent has no
# tool grant until enrollment adds one.
mkdir -p "$CONFIG/agents" "$CONFIG/workflows" "$CONFIG/roles"
cat >"$CONFIG/gateway.yaml" <<EOF
refbox_socket_dir: $SOCK_DIR
models:
  fast:
    endpoint: http://127.0.0.1:9/v1
    model: fast
    api_key_env: AGENTHOF_GATEWAY_KEY
defaults:
  model: fast
EOF
cat >"$CONFIG/agents/tool-user.yaml" <<EOF
name: tool-user
description: Calls an enrolled stdio MCP through the tool door (e2e)
model: fast
instruction: Run the call script.
output: reply
execution: fronted
endpoint: unix://$SOCK_DIR/agent.sock
EOF
cat >"$CONFIG/workflows/enroll-demo.yaml" <<EOF
name: enroll-demo
description: One step through the enrolled stdio MCP
steps:
  - name: call
    agent: tool-user
EOF
cat >"$CONFIG/roles/enroll-operator.yaml" <<EOF
name: enroll-operator
description: Runs the enrollment e2e
workflows: [enroll-demo]
allowed_groups: ["devs"]
control: [apply, enroll]
EOF

"${AH[@]}" apply --config "$CONFIG" --control-log "$CTL" "${IDENT[@]}" >"$WORK/apply0.out" || { cat "$WORK/apply0.out"; fail "the base apply failed"; }
INSTALLED_CURRENT="$WORK/installed/current"
[ -f "$INSTALLED_CURRENT" ] || fail "the base apply installed nothing"
BASE_HASH="$(tr -d '[:space:]' <"$INSTALLED_CURRENT")"

SOCKET="$BRIDGE_DIR/tool.sock"
CMD="$WORK/stdio-tool -credential-env DEMO_TOKEN"
ENROLL=("${AH[@]}" enroll mcp demo-tool --command "$CMD" --socket "$SOCKET" --token-env E2E_TOOL_TOKEN
	--tools "echo,credential" --grant tool-user --config "$CONFIG" --control-log "$CTL" "${IDENT[@]}")

GW_BEFORE="$(filesha "$CONFIG/gateway.yaml")"
AGENT_BEFORE="$(filesha "$CONFIG/agents/tool-user.yaml")"
CTL_BEFORE="$(wc -l <"$CTL" | tr -d ' ')"

# 1. Disclosure run: no --accept. It shows what would be recorded and written,
#    and writes and ledgers nothing.
DISC="$("${ENROLL[@]}")" || fail "the disclosure run failed"
echo "$DISC"
echo "$DISC" | grep -qF "command (recorded verbatim in the ledger): [\"$WORK/stdio-tool\" \"-credential-env\" \"DEMO_TOKEN\"]" || fail "the disclosure did not show the launch argv"
echo "$DISC" | grep -qF "env names (passed through; values are never read or recorded): " || fail "the disclosure did not show the env names line"
echo "$DISC" | grep -qF "read-only tools: echo, credential" || fail "the disclosure did not show the tools"
echo "$DISC" | grep -qF "grant: agent \"tool-user\" gets exactly those tools, read-only" || fail "the disclosure did not show the grant"
DIGEST="$(echo "$DISC" | sed -n 's/^accept-digest: \(sha256:[0-9a-f]\{64\}\)$/\1/p')"
[ -n "$DIGEST" ] || fail "the disclosure did not print an accept-digest"
echo "$DISC" | grep -qF "nothing written" || fail "the disclosure did not say nothing was written"
[ "$(filesha "$CONFIG/gateway.yaml")" = "$GW_BEFORE" ] || fail "the disclosure run changed gateway.yaml"
[ "$(filesha "$CONFIG/agents/tool-user.yaml")" = "$AGENT_BEFORE" ] || fail "the disclosure run changed the agent file"
[ "$(wc -l <"$CTL" | tr -d ' ')" = "$CTL_BEFORE" ] || fail "the disclosure run appended to the control ledger"
if grep -q "enroll_mcp" "$CTL"; then fail "the disclosure run ledgered an enroll_mcp event"; fi
echo "disclosure: argv, env names, tools, digest shown; nothing written or ledgered — ok"

# 2. A wrong accept digest writes nothing.
if "${ENROLL[@]}" --accept "$ZERO_DIGEST" >"$WORK/wrong.out" 2>&1; then
	fail "a wrong accept digest was accepted"
fi
grep -qF "the accepted digest does not match the proposed resource" "$WORK/wrong.out" || { cat "$WORK/wrong.out"; fail "the wrong digest was not refused with the digest error"; }
[ "$(filesha "$CONFIG/gateway.yaml")" = "$GW_BEFORE" ] || fail "a wrong digest changed gateway.yaml"
[ "$(filesha "$CONFIG/agents/tool-user.yaml")" = "$AGENT_BEFORE" ] || fail "a wrong digest changed the agent file"
echo "wrong digest: refused, nothing written — ok"

# 3. A fetch-at-spawn command is refused before any write.
if "${AH[@]}" enroll mcp bad-tool --command "/usr/bin/npx -y x" --socket "$BRIDGE_DIR/bad.sock" --token-env E2E_TOOL_TOKEN \
	--tools echo --config "$CONFIG" --control-log "$CTL" "${IDENT[@]}" --accept "$ZERO_DIGEST" >"$WORK/npx.out" 2>&1; then
	fail "a fetch-at-spawn command was accepted"
fi
grep -qF "not fetch-at-spawn" "$WORK/npx.out" || { cat "$WORK/npx.out"; fail "the fetch-at-spawn command was not refused as such"; }
[ "$(filesha "$CONFIG/gateway.yaml")" = "$GW_BEFORE" ] || fail "the fetch-at-spawn refusal changed gateway.yaml"
echo "fetch-at-spawn: refused before any write — ok"

# 4. Accept run.
ACC="$("${ENROLL[@]}" --accept "$DIGEST")" || { echo "$ACC"; fail "the accepted enrollment failed"; }
echo "$ACC"
echo "$ACC" | grep -qF 'enrolled "demo-tool": 2 file(s) edited' || fail "the accepted run did not report the edits"
grep -qF "demo-tool:" "$CONFIG/gateway.yaml" || fail "the resource is not in the working gateway.yaml"
grep -qF "runtime: refbridge" "$CONFIG/gateway.yaml" || fail "the launch runtime is not in gateway.yaml"
grep -qF "$WORK/stdio-tool" "$CONFIG/gateway.yaml" || fail "the launch command is not in gateway.yaml"
grep -qF "read_only_tools" "$CONFIG/gateway.yaml" || fail "read_only_tools is not in gateway.yaml"
grep -qF "resource: demo-tool" "$CONFIG/agents/tool-user.yaml" || fail "the grant is not in the agent file"
EV="$(grep '"action":"enroll_mcp"' "$CTL" | tail -n 1)"
[ -n "$EV" ] || fail "no enroll_mcp ledger event"
echo "$EV" | grep -qF '"outcome":"success"' || fail "the enroll_mcp event is not a success"
echo "$EV" | grep -qF "$WORK/stdio-tool" || fail "the enroll_mcp event does not carry the launch argv"
if echo "$EV" | grep -q "card_sha256"; then fail "the enroll_mcp event carries a card digest"; fi
# Enroll proposes; apply installs: nothing is installed yet.
[ "$(tr -d '[:space:]' <"$INSTALLED_CURRENT")" = "$BASE_HASH" ] || fail "enroll changed the installed configuration"
if grep -rqF "demo-tool" "$WORK/installed"; then fail "enroll installed the resource before apply"; fi
echo "accepted: working config and agent edited, enroll_mcp ledgered (no card digest), nothing installed — ok"

# 5. Apply installs.
"${AH[@]}" apply --config "$CONFIG" --control-log "$CTL" "${IDENT[@]}" >"$WORK/apply1.out" || { cat "$WORK/apply1.out"; fail "apply of the enrolled configuration failed"; }
HASH="$(tr -d '[:space:]' <"$INSTALLED_CURRENT")"
[ "$HASH" != "$BASE_HASH" ] || fail "apply did not install a new configuration"
INSTALLED_GATEWAY="$WORK/installed/${HASH#sha256:}/gateway.yaml"
[ -f "$INSTALLED_GATEWAY" ] || fail "no installed gateway.yaml at $INSTALLED_GATEWAY"
grep -qF "demo-tool:" "$INSTALLED_GATEWAY" || fail "the installed gateway.yaml lacks the enrolled resource"
echo "apply: enrolled resource installed — ok"

# 6. refbridge launches the MCP from the INSTALLED snapshot's governed slice.
"$WORK/refbridge" -project "$INSTALLED_GATEWAY" -resource demo-tool -credential-env DEMO_TOKEN \
	-materialization env-at-spawn -out "$WORK/slice-demo-tool.yaml" || fail "refbridge could not project the installed slice"
"$WORK/refbridge" -config "$WORK/slice-demo-tool.yaml" 2>"$WORK/bridge.err" &
PIDS+=($!)
"$WORK/tool-agent" -socket "$SOCK_DIR/agent.sock" 2>"$WORK/agent.err" &
PIDS+=($!)
for i in $(seq 1 60); do
	[ -S "$SOCKET" ] && [ -S "$SOCK_DIR/agent.sock" ] && break
	[ "$i" = 60 ] && {
		cat "$WORK/bridge.err" "$WORK/agent.err" || true
		fail "sockets never appeared"
	}
	sleep 0.5
done

# 7. A contained run uses exactly the granted tools.
OUT="$("${AH[@]}" run enroll-operator enroll-demo --input "call echo hello-$NONCE; call credential" "${IDENT[@]}" \
	--config "$CONFIG" --control-log "$CTL" --log-dir "$WORK/logs" --artifact-dir "$WORK/artifacts")" || { echo "$OUT"; fail "the run through the enrolled MCP failed"; }
echo "$OUT"
echo "$OUT" | grep -q "finished: succeeded" || fail "the enrolled-MCP run did not succeed"
RUNID="$(echo "$OUT" | sed -n 's/^run \(r-[a-f0-9]*\) finished.*/\1/p')"
AUDIT="$("${AH[@]}" audit "$RUNID" --log-dir "$WORK/logs" --control-log "$CTL")"
echo "$AUDIT"
echo "$AUDIT" | grep -q "ledger integrity: verified" || fail "ledger not verified"
for tool in echo credential; do
	echo "$AUDIT" | grep -Eq "tool $tool — args [0-9a-f]{8} \(static_env\)" || fail "no succeeded tool_call for $tool"
done
EXPECTED="$(printf 'hello-%s\n%s' "$NONCE" "$(sha "$E2E_TOOL_TOKEN")")"
[ -f "$WORK/artifacts/$(sha "$EXPECTED")" ] || { ls "$WORK/artifacts"; fail "the granted tools did not return the expected output"; }
echo "run: the granted tools echo and credential work through the enrolled MCP — ok"

# 8. An un-granted tool of the SAME MCP is refused by the door.
OUT2="$("${AH[@]}" run enroll-operator enroll-demo --input "call environment" "${IDENT[@]}" \
	--config "$CONFIG" --control-log "$CTL" --log-dir "$WORK/logs2" --artifact-dir "$WORK/artifacts2" 2>&1 || true)"
echo "$OUT2"
if echo "$OUT2" | grep -q "finished: succeeded"; then fail "an un-granted tool call succeeded"; fi
grep -rqF "tool is not available to this run" "$WORK/logs2" "$WORK/artifacts2" || { echo "$OUT2"; fail "the un-granted tool was not refused by the door"; }
if grep -rq '"status":"succeeded"[^}]*"tool":"environment"' "$WORK/logs2"; then fail "an un-granted tool was recorded as a successful call"; fi
echo "un-granted: environment refused by the door — ok"

# 9. A pasted configuration carrying an inline secret VALUE: the value reaches
#    no written file, no output and no ledger.
PASTE_SECRET="inline-secret-$NONCE"
PASTE="{\"mcpServers\":{\"pasted\":{\"command\":\"$WORK/stdio-tool\",\"args\":[\"-credential-env\",\"PASTED_TOKEN\"],\"env\":{\"PASTED_TOKEN\":\"$PASTE_SECRET\"}}}}"
PENROLL=("${AH[@]}" enroll mcp pasted-tool --from-paste --socket "$BRIDGE_DIR/pasted.sock" --token-env E2E_TOOL_TOKEN
	--tools echo --config "$CONFIG" --control-log "$CTL" "${IDENT[@]}")
printf '%s' "$PASTE" | "${PENROLL[@]}" >"$WORK/paste-disclosure.out" 2>&1 || { cat "$WORK/paste-disclosure.out"; fail "the paste disclosure failed"; }
grep -qF "PASTED_TOKEN" "$WORK/paste-disclosure.out" || fail "the paste disclosure did not show the env NAME"
PDIGEST="$(sed -n 's/^accept-digest: \(sha256:[0-9a-f]\{64\}\)$/\1/p' "$WORK/paste-disclosure.out")"
[ -n "$PDIGEST" ] || fail "the paste disclosure did not print an accept-digest"
printf '%s' "$PASTE" | "${PENROLL[@]}" --accept "$PDIGEST" >"$WORK/paste-accept.out" 2>&1 || { cat "$WORK/paste-accept.out"; fail "the pasted enrollment failed"; }
grep -qF "pasted-tool:" "$CONFIG/gateway.yaml" || fail "the pasted resource is not in gateway.yaml"
grep -qF "PASTED_TOKEN" "$CONFIG/gateway.yaml" || fail "the pasted env NAME is not in gateway.yaml"
no_leak "$PASTE_SECRET" "a pasted inline secret value"
no_leak "$E2E_TOOL_TOKEN" "the gateway-side tool token"
echo "paste: inline secret value appears in no file, output or ledger — ok"

# 10. Enroll without apply leaves the installed configuration as it was.
[ "$(tr -d '[:space:]' <"$INSTALLED_CURRENT")" = "$HASH" ] || fail "the pasted enrollment changed the installed configuration"
if grep -rqF "pasted-tool" "$WORK/installed"; then fail "the pasted enrollment was installed without apply"; fi
echo "enroll without apply: nothing installed — ok"

# 11. Every child is torn down after its session.
command -v pgrep >/dev/null 2>&1 || fail "pgrep is required to prove every child is torn down"
for i in $(seq 1 20); do
	pgrep -f "$WORK/stdio-tool" >/dev/null 2>&1 || break
	[ "$i" = 20 ] && { pgrep -fl "$WORK/stdio-tool"; fail "a stdio-tool child outlived its session"; }
	sleep 0.5
done

echo "e2e-enroll-mcp-local: PASS"
