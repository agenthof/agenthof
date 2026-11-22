#!/usr/bin/env bash
# e2e-drive-seatbelt: the native macOS Seatbelt containment leg for the
# governed Drive read. It proves the confiner's walls, not Google: the
# credential here is a PLACEHOLDER, never a real token, and a fake Drive MCP
# (canned data, no network) sits behind refbridge. Seatbelt's baseline allows
# host-wide reads, so a contained agent could read a credential file straight
# off the disk UNLESS its directory is in the confiner deny_read and outside
# every later allow. Asserts: (1) the governed search/read through the tool
# door succeed, attested by refbridge; (2) an unsandboxed control shows the
# placeholder file really holds the placeholder value; (3) an exec-door
# agent's `cat <credential file>` INSIDE the Seatbelt compartment exits 1,
# recorded first-hand by refexec, while a contained read of an ordinary host
# file succeeds (the denial is specific); (4) a contained dial to a Google
# IP:443 (resolved on the HOST) is refused (curl exit 7), after an unsandboxed
# control shows the host can reach it; (5) the governed read still succeeds
# AFTER the refusals; (6) the placeholder value is in no ledger, artifact, or
# log. Requires macOS with sandbox-exec (skips cleanly elsewhere), go, python3
# and curl. Run from the repo root.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ "$(uname)" != Darwin ] || [ ! -x /usr/bin/sandbox-exec ]; then
	echo "e2e-drive-seatbelt: SKIP — macOS with /usr/bin/sandbox-exec is required"
	exit 0
fi
for tool in go python3 curl; do
	command -v "$tool" >/dev/null 2>&1 || { echo "e2e-drive-seatbelt: FAIL — $tool is required"; exit 1; }
done

# Short on purpose: Unix socket paths have a small OS length limit.
SOCK_DIR="$(mktemp -d /tmp/ds.XXXXXX)"    # gateway + agent sockets
BRIDGE_DIR="$(mktemp -d /tmp/dsb.XXXXXX)" # refbridge socket dir (0700, separate)
EXEC_DIR="$(mktemp -d /tmp/dsx.XXXXXX)"   # refexec socket dir (0700, separate)
WORK="$(mktemp -d /tmp/dsw.XXXXXX)"
# The credential directory is the point of the test: it must be OUTSIDE /tmp,
# /private/tmp, store_root and every workspace, so it is made under the host's
# /var/tmp (/private/var/tmp, a different tree from /private/tmp), canonicalised
# so the deny_read path is the real one the sandbox compares against.
CRED_DIR="$(cd -P "$(mktemp -d /var/tmp/dsd.XXXXXX)" && pwd -P)"
chmod 0700 "$BRIDGE_DIR" "$CRED_DIR"
case "$CRED_DIR" in
/tmp/* | /private/tmp/*)
	echo "e2e-drive-seatbelt: FAIL — the credential dir $CRED_DIR is under /tmp"
	rm -rf "$SOCK_DIR" "$BRIDGE_DIR" "$EXEC_DIR" "$CRED_DIR" "$WORK"
	exit 1
	;;
esac
STORE_ROOT="$WORK/stores"
PID_DIR="$WORK/pids"
STORE="e2e-work-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
PIDS=()
cleanup() {
	for p in ${PIDS[@]+"${PIDS[@]}"}; do
		kill "$p" >/dev/null 2>&1 || true
		wait "$p" >/dev/null 2>&1 || true
	done
	rm -rf "$SOCK_DIR" "$BRIDGE_DIR" "$EXEC_DIR" "$CRED_DIR" "$WORK"
}
trap cleanup EXIT
unset AGENTHOF_TOKEN || true

NONCE="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
PLACEHOLDER="placeholder-not-a-real-token-$NONCE"
PH_CLIENT_ID="placeholder-client-id-$NONCE"
PH_CLIENT_SECRET="placeholder-client-secret-$NONCE"
PH_BEARER="placeholder-bearer-$NONCE"

# fail prints the process logs for diagnosis with the placeholder filtered out.
fail() {
	echo "e2e-drive-seatbelt: FAIL — $*"
	for f in refexec.err bridge.err agent.err exec-agent.err; do
		[ -f "$WORK/$f" ] && { echo "--- $f"; grep -vF -e "$PLACEHOLDER" -e "$PH_CLIENT_ID" -e "$PH_CLIENT_SECRET" -e "$PH_BEARER" "$WORK/$f" || true; } >&2
	done
	exit 1
}
mode_of() { python3 -c 'import os, sys; print(oct(os.stat(sys.argv[1]).st_mode & 0o777))' "$1"; }
runid_of() { printf '%s\n' "$1" | sed -n 's/^run \(r-[a-f0-9]*\) finished.*/\1/p'; }
ere_escape() { printf '%s' "$1" | sed 's/[][\\.*^$+?(){}|]/\\&/g'; }

go build -o "$WORK/agenthof" ./cmd/agenthof
go build -o "$WORK/refexec" ./deploy/refexec
go build -o "$WORK/refbridge" ./deploy/refbridge
go build -o "$WORK/fake-drive-mcp" ./examples/fake-drive-mcp
go build -o "$WORK/drive-agent" ./examples/drive-agent
go build -o "$WORK/echo-agent" ./examples/echo-agent

# The placeholder credential file, in a deny_read dir outside every allow.
CRED_FILE="$CRED_DIR/google-credentials.json"
printf '{"refresh_token":"%s"}\n' "$PLACEHOLDER" >"$CRED_FILE"
chmod 0600 "$CRED_FILE"

# A Google IPv4 address, resolved on the HOST: the compartment has no DNS, and
# the dial must be to an address, not a name.
GOOGLE_IP="$(python3 -c 'import socket; print(socket.getaddrinfo("www.googleapis.com", 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0])' 2>/dev/null || true)"

# --- refexec, seatbelt: deny_read names the credential dir, which is outside
# every allow (scratch and workspace are under store_root, nowhere near it).
cat >"$WORK/refexec.yaml" <<EOF
confiner: seatbelt
socket: $EXEC_DIR/refexec.sock
store_root: $STORE_ROOT
pid_dir: $PID_DIR
workspace:
  store: $STORE
deny_read: ["$CRED_DIR"]
limits:
  memory: 256m
  cpus: "1"
  pids: 64
compartments:
  max: 2
env_allow: []
timeout: 2m
EOF
(umask 077 && mkdir -p "$PID_DIR")
REFEXEC_BIN="$WORK/refexec" REFEXEC_CONFIG="$WORK/refexec.yaml" deploy/refexec/refexec-run-seatbelt.sh 2>"$WORK/refexec.err" &
PIDS+=($!)

# --- the governed Drive path: refbridge -> fake-drive-mcp on the HOST, with the
# same env split as the hermetic tier and a PLACEHOLDER bearer.
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
GOOGLE_DRIVE_MCP_REFRESH_TOKEN="$PLACEHOLDER" GOOGLE_DRIVE_MCP_CLIENT_ID="$PH_CLIENT_ID" \
	GOOGLE_DRIVE_MCP_CLIENT_SECRET="$PH_CLIENT_SECRET" DRIVE_BRIDGE_BEARER="$PH_BEARER" \
	"$WORK/refbridge" -config "$WORK/bridge.yaml" 2>"$WORK/bridge.err" &
PIDS+=($!)
"$WORK/drive-agent" -socket "$SOCK_DIR/agent.sock" 2>"$WORK/agent.err" &
PIDS+=($!)
# The exec agent is a host process (no agent compartment on macOS); it works in
# the workspace store of the refexec it is paired with.
"$WORK/echo-agent" -socket "$SOCK_DIR/exec-agent.sock" -workspace "$STORE_ROOT/$STORE" 2>"$WORK/exec-agent.err" &
PIDS+=($!)
for i in $(seq 1 60); do
	[ -S "$BRIDGE_DIR/drive.sock" ] && [ -S "$SOCK_DIR/agent.sock" ] && [ -S "$EXEC_DIR/refexec.sock" ] && [ -S "$SOCK_DIR/exec-agent.sock" ] && break
	[ "$i" = 60 ] && fail "sockets never appeared"
	sleep 0.5
done
[ "$(mode_of "$EXEC_DIR")" = 0o700 ] || fail "refexec socket dir is not 0700"
grep -q "refexec listening.*confiner=seatbelt" "$WORK/refexec.err" || fail "refexec did not report the seatbelt tier at start"

# --- a hermetic Agenthof config, written from scratch.
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
cat >"$WORK/config/agents/seat-exec.yaml" <<EOF
name: seat-exec
description: A host agent whose exec door is first-hand, served by refexec under seatbelt (no drive grant)
model: fast
instruction: Run the command.
output: output
execution: fronted
endpoint: unix://$SOCK_DIR/exec-agent.sock
exec:
  runtime: refexec
  url: unix://$EXEC_DIR/refexec.sock
  timeout: 2m
  allow:
    - exe: cat
    - exe: curl
EOF
for wf in drive-read seat-exec; do
	agent="$wf"
	[ "$wf" != drive-read ] || agent=drive-reader
	cat >"$WORK/config/workflows/$wf.yaml" <<EOF
name: $wf
description: One step through $agent
steps:
  - name: call
    agent: $agent
EOF
done
cat >"$WORK/config/roles/drive-seat-operator.yaml" <<EOF
name: drive-seat-operator
description: Runs the drive seatbelt e2e workflows
workflows: [drive-read, seat-exec]
allowed_groups: ["drive-users"]
control: [apply]
EOF
export DRIVE_BRIDGE_BEARER="$PH_BEARER" # the host agenthof presents it to the bridge
export AGENTHOF_GATEWAY_KEY="host-side-dummy-key-$NONCE" # the model route is never called
"$WORK/agenthof" apply --config "$WORK/config" --control-log "$WORK/control.jsonl" --as ci --groups drive-users

ALL_OUT="" # every run's output and audit, scanned for the placeholder at the end
run() { # $1 workflow, $2 input; sets OUT, RUNID, AUDIT (a refused run is data, not a script failure)
	OUT="$("$WORK/agenthof" run drive-seat-operator "$1" --input "$2" \
		--as ci --groups drive-users --config "$WORK/config" --control-log "$WORK/control.jsonl" \
		--log-dir "$WORK/logs" --artifact-dir "$WORK/artifacts" 2>>"$WORK/run.err" || true)"
	echo "$OUT"
	ALL_OUT="$ALL_OUT$OUT"$'\n'
	RUNID="$(runid_of "$OUT")"
	[ -n "$RUNID" ] || fail "no run id"
	AUDIT="$("$WORK/agenthof" audit "$RUNID" --log-dir "$WORK/logs" --control-log "$WORK/control.jsonl")"
	echo "$AUDIT"
	ALL_OUT="$ALL_OUT$AUDIT"$'\n'
	echo "$AUDIT" | grep -q "ledger integrity: verified" || fail "ledger not verified"
	echo "$AUDIT" | grep -q "ledger completeness: complete (" || fail "ledger does not account for itself"
}
governed_read() { # $1 label; asserts a governed search + read succeed, attested by refbridge
	run drive-read "search meeting; read note-2"
	echo "$OUT" | grep -q "finished: succeeded" || fail "$1: the governed Drive read did not succeed"
	[ "$(grep -c '"runtime_attestation":{"runtime":"refbridge"' "$WORK/logs/$RUNID.jsonl")" = 2 ] || fail "$1: want two attested tool_calls (search, read)"
	local attested
	attested="\\[runtime-attested: refbridge $(ere_escape "$WORK/fake-drive-mcp") pid [0-9]+"
	echo "$AUDIT" | grep -Eq "tool search — args [0-9a-f]{8} \(static_env\) $attested" || fail "$1: audit does not render the attested search"
	echo "$AUDIT" | grep -Eq "tool readGoogleDoc — args [0-9a-f]{8} \(static_env\) $attested" || fail "$1: audit does not render the attested readGoogleDoc"
	grep -rqF 'Meeting: agreed to review the audit ledger' "$WORK/artifacts" || fail "$1: no artifact carries the canned note text"
}

# 1. POSITIVE CONTROL: the governed path works.
governed_read "before the refusals"
echo "positive control: governed search and read returned the canned note, attested — ok"

# 2. UNSANDBOXED CONTROL: the placeholder bytes are really on disk, so a refusal
#    below is a refusal of real content, not of an empty file.
grep -qF "$PLACEHOLDER" "$CRED_FILE" || fail "the unsandboxed control cannot read the placeholder from the credential file, so a sandboxed refusal proves nothing"
echo "unsandboxed control: the placeholder credential is on disk — ok"

# 3. CONTAINED CREDENTIAL READ REFUSED, recorded first-hand. First the positive
#    read control (an ordinary host file reads fine under the same compartment),
#    so the denial is specific to the credential dir.
printf 'open-%s\n' "$NONCE" >"$WORK/open.txt"
run seat-exec "exec-run:cat $WORK/open.txt"
echo "$OUT" | grep -q "finished: succeeded" || fail "a contained read of an ordinary host file failed, so the denial below could be a deny-everything sandbox"
echo "$AUDIT" | grep -Eq "exec cat $(ere_escape "$WORK/open.txt") — exit 0 \(runtime\) \[runtime-attested: refexec cat .*; confiner: seatbelt" || fail "the ordinary read was not recorded first-hand"
run seat-exec "exec-run:cat $CRED_FILE"
echo "$OUT" | grep -q "finished: failed" || fail "a contained cat of the credential file must fail"
echo "$AUDIT" | grep -Eq "exec cat $(ere_escape "$CRED_FILE") — exit 1 \(runtime\) \[runtime-attested: refexec cat .*; confiner: seatbelt" || fail "the contained credential read was not refused and recorded first-hand (exit 1)"
grep -q '"runtime_attestation":{"runtime":"refexec"' "$WORK/logs/$RUNID.jsonl" || fail "no refexec attestation for the refused read"
if grep -q '"runtime_attestation":{"runtime":"refbridge"' "$WORK/logs/$RUNID.jsonl"; then fail "the contained read produced a drive tool_call: it was not out-of-band"; fi
echo "contained cat of the credential file refused (exit 1), recorded first-hand — ok"

# 4. CONTAINED DIAL TO GOOGLE REFUSED: Seatbelt denies network, so curl to the
#    Google IP:443 fails with exit 7 (could not connect) — a refusal, not a
#    timeout. The unsandboxed control comes first: a host with no route (or no
#    DNS) could not attribute a refusal to the sandbox, so then this leg is
#    skipped, not read as enforcement.
NET_RAN=""
if [ -n "$GOOGLE_IP" ] && curl -sk --max-time 5 -o /dev/null --resolve "www.googleapis.com:443:$GOOGLE_IP" https://www.googleapis.com/ 2>/dev/null; then
	DIAL="curl -sSk --max-time 3 -o /dev/null --resolve www.googleapis.com:443:$GOOGLE_IP https://www.googleapis.com/"
	run seat-exec "exec-run:$DIAL"
	echo "$OUT" | grep -q "finished: failed" || fail "a contained dial to Google must fail"
	echo "$AUDIT" | grep -Eq "exec curl .*$(ere_escape "$GOOGLE_IP").* — exit 7 \(runtime\) \[runtime-attested: refexec curl .*; confiner: seatbelt" || fail "the contained dial to $GOOGLE_IP:443 was not refused and recorded first-hand (curl exit 7)"
	echo "contained dial to Google $GOOGLE_IP:443 refused, recorded first-hand — ok"
	NET_RAN=1
else
	# DRIVE_SEATBELT_REQUIRE_NET=1 makes this skip a hard failure, for callers that require the containment proof.
	[ "${DRIVE_SEATBELT_REQUIRE_NET:-}" != 1 ] || fail "DRIVE_SEATBELT_REQUIRE_NET=1 but the unsandboxed control could not reach Google (resolved ip: ${GOOGLE_IP:-none}), so the dial refusal cannot be proven"
	echo "SKIP — the unsandboxed control could not reach Google (resolved ip: ${GOOGLE_IP:-none}), so a sandboxed refusal could not be attributed to the sandbox"
fi

# 5. The governed read still works AFTER the refusals: the walls are specific.
governed_read "after the refusals"
echo "governed read still succeeds after the contained refusals — ok"

# 6. THE PLACEHOLDER VALUES (refresh token, client id, client secret, bearer)
#    are in no ledger, artifact, process log (bridge.err carries refbridge's and
#    the fake MCP's stderr), control log, or captured agenthof output/audit.
LEAKED=""
for value in "$PLACEHOLDER" "$PH_CLIENT_ID" "$PH_CLIENT_SECRET" "$PH_BEARER"; do
	for target in "$WORK/logs" "$WORK/artifacts" "$WORK/control.jsonl" "$WORK/run.err" "$WORK/bridge.err" "$WORK/agent.err" "$WORK/exec-agent.err" "$WORK/refexec.err"; do
		if grep -rqF -- "$value" "$target" 2>/dev/null; then LEAKED="$LEAKED $target"; fi
	done
	if printf '%s' "$ALL_OUT" | grep -qF -- "$value"; then LEAKED="$LEAKED agenthof-output"; fi
done
[ -z "$LEAKED" ] || fail "a placeholder credential value reached:$LEAKED"
echo "all four placeholder values absent from every ledger, artifact, process log, control log, and audit — ok"

# No compartment outlives its command.
[ -z "$(ls "$PID_DIR")" ] || { ls -la "$PID_DIR"; fail "a compartment's PID record was left behind"; }

if [ -n "$NET_RAN" ]; then
	echo "e2e-drive-seatbelt: PASS"
else
	echo "e2e-drive-seatbelt: PASS (the Google-dial leg was SKIPPED: the unsandboxed control could not reach Google)"
fi
