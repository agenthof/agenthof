#!/usr/bin/env bash
# e2e-drive-local: prove the REAL agenthof binary governs a Drive MCP server
# (a FAKE: canned data, no network, no real Google) fronted by refbridge over a
# Unix socket, with no container runtime. A drive-agent (serving its step
# endpoint on a Unix socket) runs small scripts through the tool door as two
# agents: one holding a NAMED read-only grant (search, readGoogleDoc) and one
# with no grant at all. Asserts: a search then a read returns the canned note
# and the ledger carries two refbridge-attested tool_call events whose
# environment NAMES are exactly the allowlist plus the bearer variable; the
# Google credential VALUE reached the child (its startup fingerprint) yet no
# credential value is in any ledger, artifact, or log; downloadFile, absent from
# the named grant, is refused by name with no resource or attestation recorded;
# an agent without the grant is refused the same way; an upstream error result
# is recorded, capped at 200 runes; and the ledger verifies complete.
# Requires go. Runs on macOS and Linux.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Short on purpose: Unix socket paths have a small OS length limit. The bridge
# directory is SEPARATE from the gateway socket dir and mode 0700, as
# refbridge requires.
SOCK_DIR="$(mktemp -d /tmp/dr.XXXXXX)"
BRIDGE_DIR="$(mktemp -d /tmp/drb.XXXXXX)"
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
	echo "e2e-drive-local: FAIL — $*"
	exit 1
}
# no_leak VALUE WHAT...: VALUE must appear in no ledger, artifact, process
# log, or captured agenthof stdout. Never prints VALUE.
no_leak() {
	local value="$1"
	shift
	if grep -rqF -- "$value" "$WORK/logs" "$WORK/artifacts" "$WORK/bridge.err" "$WORK/agent.err" "$WORK/control.jsonl" "$WORK"/run*.err; then
		fail "$* reached the ledger, an artifact, or a process log"
	fi
	if printf '%s\n' "${OUT1:-}" "${AUDIT1:-}" "${OUT2:-}" "${AUDIT2:-}" "${OUT3:-}" "${AUDIT3:-}" "${OUT4:-}" "${AUDIT4:-}" "${OUT5:-}" "${AUDIT5:-}" | grep -qF -- "$value"; then
		fail "$* reached agenthof's output"
	fi
}
# ere_escape: a literal string made safe inside a grep -E pattern.
ere_escape() { printf '%s' "$1" | sed 's/[][\\.*^$+?(){}|]/\\&/g'; }
runid_of() { printf '%s\n' "$1" | sed -n 's/^run \(r-[a-f0-9]*\) finished.*/\1/p'; }
sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		printf '%s' "$1" | sha256sum | cut -d' ' -f1
	else
		printf '%s' "$1" | shasum -a 256 | cut -d' ' -f1
	fi
}

go build -o "$WORK/agenthof" ./cmd/agenthof
go build -o "$WORK/refbridge" ./deploy/refbridge
go build -o "$WORK/fake-drive-mcp" ./examples/fake-drive-mcp
go build -o "$WORK/drive-agent" ./examples/drive-agent

cat >"$WORK/bridge.yaml" <<EOF
socket: $BRIDGE_DIR/drive.sock
command: ["$WORK/fake-drive-mcp"]
credential:
  env: DRIVE_BRIDGE_BEARER
  materialization: env-at-spawn
env_passthrough: [GOOGLE_DRIVE_MCP_REFRESH_TOKEN, GOOGLE_DRIVE_MCP_CLIENT_ID, GOOGLE_DRIVE_MCP_CLIENT_SECRET]
egress:
  allow: []
sessions:
  max: 4
  idle_timeout: 10m
  max_lifetime: 30m
EOF

NONCE="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
REFRESH="refresh-$NONCE"
CLIENT_ID="client-id-$NONCE"
CLIENT_SECRET="client-secret-$NONCE"
BEARER="bearer-$NONCE"
LEAKED="not-for-the-child-$NONCE"
# LEAKED_SECRET is not allowlisted and must never reach the child.
GOOGLE_DRIVE_MCP_REFRESH_TOKEN="$REFRESH" GOOGLE_DRIVE_MCP_CLIENT_ID="$CLIENT_ID" \
	GOOGLE_DRIVE_MCP_CLIENT_SECRET="$CLIENT_SECRET" DRIVE_BRIDGE_BEARER="$BEARER" \
	LEAKED_SECRET="$LEAKED" "$WORK/refbridge" -config "$WORK/bridge.yaml" 2>"$WORK/bridge.err" &
PIDS+=($!)
"$WORK/drive-agent" -socket "$SOCK_DIR/agent.sock" 2>"$WORK/agent.err" &
PIDS+=($!)
for i in $(seq 1 60); do
	[ -S "$BRIDGE_DIR/drive.sock" ] && [ -S "$SOCK_DIR/agent.sock" ] && break
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
  drive:
    kind: mcp
    url: unix://$BRIDGE_DIR/drive.sock
    runtime: refbridge
    credential_source: static_env
    token_env: DRIVE_BRIDGE_BEARER
    read_only_tools: [search, readGoogleDoc]
EOF
cat >"$WORK/config/agents/drive-reader.yaml" <<EOF
name: drive-reader
description: Reads Drive through the tool door with a named read-only grant (e2e)
model: fast
instruction: Run the drive script.
output: reply
execution: fronted
endpoint: unix://$SOCK_DIR/agent.sock
tools:
  - resource: drive
    tools: [search, readGoogleDoc]
    mode: read-only
EOF
cat >"$WORK/config/agents/drive-ungranted.yaml" <<EOF
name: drive-ungranted
description: Runs the drive script with no tool grant at all (e2e)
model: fast
instruction: Run the drive script.
output: reply
execution: fronted
endpoint: unix://$SOCK_DIR/agent.sock
EOF
cat >"$WORK/config/agents/drive-search-only.yaml" <<EOF
name: drive-search-only
description: Reads Drive with a named grant narrower than the read-only set (e2e)
model: fast
instruction: Run the drive script.
output: reply
execution: fronted
endpoint: unix://$SOCK_DIR/agent.sock
tools:
  - resource: drive
    tools: [search]
    mode: read-only
EOF
cat >"$WORK/config/workflows/drive-search-only.yaml" <<EOF
name: drive-search-only
description: One step as the search-only agent
steps:
  - name: call
    agent: drive-search-only
EOF
cat >"$WORK/config/workflows/drive-read.yaml" <<EOF
name: drive-read
description: One step as the granted agent
steps:
  - name: call
    agent: drive-reader
EOF
cat >"$WORK/config/workflows/drive-ungranted.yaml" <<EOF
name: drive-ungranted
description: One step as the agent without a grant
steps:
  - name: call
    agent: drive-ungranted
EOF
cat >"$WORK/config/roles/drive-operator.yaml" <<EOF
name: drive-operator
description: Runs the drive e2e workflows
workflows: [drive-read, drive-ungranted, drive-search-only]
allowed_groups: ["drive-users"]
control: [apply]
EOF

# Credentials live with the HOST agenthof process only.
export DRIVE_BRIDGE_BEARER="$BEARER"
export AGENTHOF_GATEWAY_KEY="host-side-dummy-key-$NONCE" # the model route is never called; the key only lets it resolve

"$WORK/agenthof" apply --config "$WORK/config" --control-log "$WORK/control.jsonl" --as ci --groups drive-users

run() { # $1 = workflow, $2 = step input
	"$WORK/agenthof" run drive-operator "$1" --input "$2" \
		--as ci --groups drive-users --config "$WORK/config" --control-log "$WORK/control.jsonl" \
		--log-dir "$WORK/logs" --artifact-dir "$WORK/artifacts"
}
audit() { "$WORK/agenthof" audit "$1" --log-dir "$WORK/logs" --control-log "$WORK/control.jsonl"; }

# 1. Governed read: search then read in ONE session of the granted agent.
OUT1="$(run drive-read "search meeting; read note-2" 2>"$WORK/run1.err")"
echo "$OUT1"
echo "$OUT1" | grep -q "finished: succeeded" || fail "drive-read did not succeed"
RUNID1="$(runid_of "$OUT1")"
[ -n "$RUNID1" ] || fail "no run id for the read run"
AUDIT1="$(audit "$RUNID1")"
echo "$AUDIT1"
echo "$AUDIT1" | grep -q "ledger integrity: verified" || fail "read run ledger not verified"
echo "$AUDIT1" | grep -q "ledger completeness: complete (" || fail "read run ledger does not account for itself"
LEDGER1="$WORK/logs/$RUNID1.jsonl"
[ "$(grep -c '"runtime_attestation":{"runtime":"refbridge"' "$LEDGER1")" = 2 ] || fail "want two attested tool_call events (search, read)"
[ "$(grep -c '"resources_touched":\["drive"\]' "$LEDGER1")" = 2 ] || fail "want resources_touched [drive] on both tool_call events of the successful run"
ATTESTED="\\[runtime-attested: refbridge $(ere_escape "$WORK/fake-drive-mcp") pid [0-9]+"
[ "$(echo "$AUDIT1" | grep -Ec "tool search — args [0-9a-f]{8} \(static_env\) $ATTESTED")" = 1 ] || fail "audit does not render the attested search call"
[ "$(echo "$AUDIT1" | grep -Ec "tool readGoogleDoc — args [0-9a-f]{8} \(static_env\) $ATTESTED")" = 1 ] || fail "audit does not render the attested readGoogleDoc call"
ART1="$(grep -rlF 'Meeting: agreed to review the audit ledger' "$WORK/artifacts" | head -n1 || true)"
[ -n "$ART1" ] || fail "the artifact does not carry the canned note text"
grep -qF 'note-2 Meeting notes' "$ART1" || fail "the artifact does not carry the search hit"
echo "governed read: canned note returned; two attested tool_call lines — ok"

# 2. Exact environment NAMES: the allowlist plus the bearer, nothing else.
ENV_JSON='"env_names":["DRIVE_BRIDGE_BEARER","GOOGLE_DRIVE_MCP_CLIENT_ID","GOOGLE_DRIVE_MCP_CLIENT_SECRET","GOOGLE_DRIVE_MCP_REFRESH_TOKEN"]'
[ "$(grep -cF "$ENV_JSON" "$LEDGER1")" = 2 ] || fail "want env_names of exactly the allowlist plus the bearer on both tool_call events"
if grep -q "LEAKED_SECRET" "$LEDGER1"; then fail "a non-allowlisted variable was attested in the child's environment"; fi
echo "env names: exactly the allowlist plus the bearer on both events, no stray variable — ok"

# 3. The credential VALUE reached the child (its startup fingerprint matches
#    the hash computed here); the no-leak sweep at the end shows it is nowhere
#    in a ledger, artifact, or log.
FP="$(sha256_of "$REFRESH")"
grep -qF "fingerprint $FP" "$WORK/bridge.err" || fail "the refresh-token value did not reach the child (fingerprint mismatch)"
echo "credential value reached the child (fingerprint matches) — ok"

# 4. A tool outside the named grant is refused by NAME, with no resource or
#    attestation recorded.
if OUT2="$(run drive-read "call downloadFile fileId=x localPath=/tmp/y" 2>"$WORK/run2.err")"; then
	fail "downloadFile was not refused"
fi
echo "$OUT2"
echo "$OUT2" | grep -q "finished: failed" || fail "refused run did not finish failed"
RUNID2="$(runid_of "$OUT2")"
[ -n "$RUNID2" ] || fail "no run id for the refused run"
AUDIT2="$(audit "$RUNID2")"
echo "$AUDIT2"
echo "$AUDIT2" | grep -q "ledger integrity: verified" || fail "refused run ledger not verified"
echo "$AUDIT2" | grep -q "ledger completeness: complete (" || fail "refused run ledger does not account for itself"
echo "$AUDIT2" | grep -q "tool downloadFile refused — tool is not available to this run" || fail "downloadFile was not refused with the grant reason"
if grep -q '"runtime_attestation"' "$WORK/logs/$RUNID2.jsonl"; then fail "the refused call recorded an attested tool_call"; fi
if grep -q '"resources_touched"' "$WORK/logs/$RUNID2.jsonl"; then fail "the refused call recorded a touched resource"; fi
if echo "$AUDIT2" | grep -Eq "tool downloadFile — args"; then fail "the refused downloadFile recorded a tool_call"; fi
echo "named grant: downloadFile refused by name; no resource or attestation — ok"

# 5. An agent with no grant for the resource is refused the same way.
if OUT3="$(run drive-ungranted "search meeting" 2>"$WORK/run3.err")"; then
	fail "the ungranted agent's search was not refused"
fi
echo "$OUT3"
RUNID3="$(runid_of "$OUT3")"
[ -n "$RUNID3" ] || fail "no run id for the ungranted run"
AUDIT3="$(audit "$RUNID3")"
echo "$AUDIT3"
echo "$OUT3" | grep -q "finished: failed" || fail "ungranted run did not finish failed"
echo "$AUDIT3" | grep -q "ledger integrity: verified" || fail "ungranted run ledger not verified"
echo "$AUDIT3" | grep -q "ledger completeness: complete (" || fail "ungranted run ledger does not account for itself"
echo "$AUDIT3" | grep -q "tool search refused — tool is not available to this run" || fail "the ungranted search was not refused"
if grep -q '"runtime_attestation"' "$WORK/logs/$RUNID3.jsonl"; then fail "the ungranted call recorded an attested tool_call"; fi
if grep -q '"resources_touched"' "$WORK/logs/$RUNID3.jsonl"; then fail "the ungranted call recorded a touched resource"; fi
echo "ungranted agent: search refused; nothing attested — ok"

# 5b. A NAMED grant narrows WITHIN the read-only set: [search] is a valid
#     read-only grant, yet readGoogleDoc (also read-only) is refused. A wildcard
#     read-only grant would expose it, so only a named grant explains this.
if OUT5="$(run drive-search-only "read note-1" 2>"$WORK/run5.err")"; then
	fail "the search-only agent's readGoogleDoc was not refused"
fi
echo "$OUT5"
echo "$OUT5" | grep -q "finished: failed" || fail "search-only run did not finish failed"
RUNID5="$(runid_of "$OUT5")"
[ -n "$RUNID5" ] || fail "no run id for the search-only run"
AUDIT5="$(audit "$RUNID5")"
echo "$AUDIT5"
echo "$AUDIT5" | grep -q "ledger integrity: verified" || fail "search-only run ledger not verified"
echo "$AUDIT5" | grep -q "ledger completeness: complete (" || fail "search-only run ledger does not account for itself"
echo "$AUDIT5" | grep -q "tool readGoogleDoc refused — tool is not available to this run" || fail "readGoogleDoc was not refused for the [search] grant"
if grep -q '"runtime_attestation"' "$WORK/logs/$RUNID5.jsonl"; then fail "the refused call recorded an attested tool_call"; fi
if grep -q '"resources_touched"' "$WORK/logs/$RUNID5.jsonl"; then fail "the refused call recorded a touched resource"; fi
echo "named [search] grant: readGoogleDoc refused within the read-only set — ok"

# 6. Error path: an upstream error result is recorded, bounded at 200 runes,
#    and no credential value rides along.
CANARY="CANARY$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
if OUT4="$(run drive-read "read __error__:$CANARY" 2>"$WORK/run4.err")"; then
	fail "the upstream error result did not fail the step"
fi
echo "$OUT4"
RUNID4="$(runid_of "$OUT4")"
[ -n "$RUNID4" ] || fail "no run id for the error run"
AUDIT4="$(audit "$RUNID4")"
echo "$AUDIT4"
echo "$OUT4" | grep -q "finished: failed" || fail "error run did not finish failed"
echo "$AUDIT4" | grep -q "ledger integrity: verified" || fail "error run ledger not verified"
echo "$AUDIT4" | grep -q "ledger completeness: complete (" || fail "error run ledger does not account for itself"
# Extracting a quote-free "reason" value is safe: the canary and padding hold nothing JSON escapes.
REASON="$(grep '"tool":"readGoogleDoc"' "$WORK/logs/$RUNID4.jsonl" | grep -o '"reason":"[^"]*"' | head -n1 | sed 's/^"reason":"//; s/"$//' || true)"
[ -n "$REASON" ] || fail "the failed tool_call recorded no reason"
case "$REASON" in "$CANARY"*) ;; *) fail "the recorded reason does not begin with the upstream error text" ;; esac
[ "$(printf '%s' "$REASON" | wc -m | tr -d ' ')" = 200 ] || fail "the recorded reason is not capped at exactly 200 runes"
echo "error path: upstream text recorded, capped at 200 runes — ok"

# 7. No credential value is anywhere in any ledger, artifact, or log.
no_leak "$REFRESH" "the refresh-token value"
no_leak "$CLIENT_ID" "the client-id value"
no_leak "$CLIENT_SECRET" "the client-secret value"
no_leak "$BEARER" "the bearer value"
no_leak "$LEAKED" "the non-allowlisted variable's value"
if grep -q "LEAKED_SECRET" "$WORK/bridge.err"; then fail "a non-allowlisted variable leaked into the bridge log"; fi
echo "no credential value in any ledger, artifact, or log — ok"

echo "e2e-drive-local: PASS"
