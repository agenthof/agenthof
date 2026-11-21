#!/usr/bin/env bash
# e2e-memory-seatbelt: the native macOS Seatbelt falsifier for the EMBEDDED
# memory store. Seatbelt's baseline allows host-wide reads, so a contained
# agent can read an embedded store file straight off the disk — with no memory
# grant and no tool_call — UNLESS the file's directory is in the confiner
# deny_read and outside every later allow (scratch, /private/tmp under
# shared_host_scratch, workspaces, store_root). This e2e proves that placement
# rule holds with the real sandbox. Asserts: (1) positive control — a
# memory-agent, through the governed tool door, upserts a record carrying a
# sentinel and searches it back (the refbridge runs the store on the HOST);
# (2) unsandboxed control — a plain host cat of the store file shows the
# sentinel bytes are really on disk; (3) an exec-door agent's `cat <store
# file>` INSIDE the Seatbelt compartment exits 1, recorded first-hand by
# refexec, while a contained read of an ordinary host file succeeds (so the
# denial is specific, not a deny-everything sandbox); (4) with
# shared_host_scratch ON the same contained read is STILL refused, the tier
# records the loosening, and the contained read of an ordinary file still
# works; (5) record B's disk-only sentinel (never returned through the door) is
# in no ledger, artifact, or log. Requires macOS with sandbox-exec
# (skips cleanly anywhere else), go and python3. Run from the repo root.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Decided before anything is created, so a skip leaves nothing behind.
if [ "$(uname)" != Darwin ] || [ ! -x /usr/bin/sandbox-exec ]; then
	echo "e2e-memory-seatbelt: SKIP — macOS with /usr/bin/sandbox-exec is required"
	exit 0
fi
for tool in go python3; do
	command -v "$tool" >/dev/null 2>&1 || { echo "e2e-memory-seatbelt: FAIL — $tool is required"; exit 1; }
done

# Short on purpose: Unix socket paths have a small OS length limit.
SOCK_DIR="$(mktemp -d /tmp/ms.XXXXXX)"    # gateway + agent sockets
BRIDGE_DIR="$(mktemp -d /tmp/msb.XXXXXX)" # refbridge socket dir (0700, separate)
EXEC_DIR="$(mktemp -d /tmp/msx.XXXXXX)"   # refexec socket dir (0700, separate)
EXEC2_DIR="$(mktemp -d /tmp/msy.XXXXXX)"  # the shared_host_scratch refexec
WORK="$(mktemp -d /tmp/msw.XXXXXX)"
# The store directory is the point of the test: it must be OUTSIDE /tmp,
# /private/tmp, store_root and every workspace, so it is made under the
# host's /var/tmp (/private/var/tmp, a different tree from /private/tmp), canonicalised so
# the deny_read path is the real one the sandbox compares against.
STORE_DIR="$(cd -P "$(mktemp -d /var/tmp/msd.XXXXXX)" && pwd -P)"
chmod 0700 "$BRIDGE_DIR" "$STORE_DIR"
# The shared_host_scratch refexec's own dirs must ALSO live outside /private/tmp:
# the tier's startup probe refuses that loosening when the workspace or PID dir
# is under the shared scratch it opens (asserted below), so they go beside the
# store dir, not inside it.
WORK2="$(cd -P "$(mktemp -d /var/tmp/msv.XXXXXX)" && pwd -P)"
case "$STORE_DIR" in
/tmp/* | /private/tmp/*)
	echo "e2e-memory-seatbelt: FAIL — the store dir $STORE_DIR is under /tmp"
	rm -rf "$STORE_DIR" "$SOCK_DIR" "$BRIDGE_DIR" "$EXEC_DIR" "$EXEC2_DIR" "$WORK2" "$WORK"
	exit 1
	;;
esac
STORE_ROOT="$WORK/stores"
STORE_ROOT2="$WORK2/stores"
PID_DIR="$WORK/pids"
PID_DIR2="$WORK2/pids"
STORE="e2e-work-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
PIDS=()
cleanup() {
	for p in ${PIDS[@]+"${PIDS[@]}"}; do
		kill "$p" >/dev/null 2>&1 || true
		wait "$p" >/dev/null 2>&1 || true
	done
	rm -rf "$SOCK_DIR" "$BRIDGE_DIR" "$EXEC_DIR" "$EXEC2_DIR" "$STORE_DIR" "$WORK2" "$WORK"
}
trap cleanup EXIT
unset AGENTHOF_TOKEN || true

NONCE="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
SENTINEL_A="sentinel-a-$NONCE" # record A: returned through the governed door
SENTINEL_B="sentinel-b-$NONCE" # record B: never returned; it lives only on disk

# fail prints the process logs for diagnosis with both sentinels filtered out,
# so a detected leak is never itself echoed.
fail() {
	echo "e2e-memory-seatbelt: FAIL — $*"
	for f in refexec.err refexec2.err bridge.err agent.err exec-agent.err; do
		[ -f "$WORK/$f" ] && { echo "--- $f"; grep -vF -e "$SENTINEL_A" -e "$SENTINEL_B" "$WORK/$f" || true; } >&2
	done
	exit 1
}
mode_of() { python3 -c 'import os, sys; print(oct(os.stat(sys.argv[1]).st_mode & 0o777))' "$1"; }
runid_of() { printf '%s\n' "$1" | sed -n 's/^run \(r-[a-f0-9]*\) finished.*/\1/p'; }

go build -o "$WORK/agenthof" ./cmd/agenthof
go build -o "$WORK/refexec" ./deploy/refexec
go build -o "$WORK/refbridge" ./deploy/refbridge
go build -o "$WORK/memory-store" ./examples/memory-store
go build -o "$WORK/memory-agent" ./examples/memory-agent
go build -o "$WORK/echo-agent" ./examples/echo-agent

STORE_FILE="$STORE_DIR/memory.json"

# --- refexec, seatbelt: deny_read names the store dir, which is outside every
# allow (scratch and workspace are under store_root, nowhere near STORE_DIR).
# The second instance adds shared_host_scratch.
exec_config() { # $1 sock dir, $2 store root, $3 pid dir, $4 "shared" to loosen
	cat <<EOF
confiner: seatbelt
socket: $1/refexec.sock
store_root: $2
pid_dir: $3
workspace:
  store: $STORE
deny_read: ["$STORE_DIR"]
limits:
  memory: 256m
  cpus: "1"
  pids: 64
compartments:
  max: 2
env_allow: []
timeout: 2m
EOF
	[ "${4:-}" != shared ] || echo "shared_host_scratch: true"
}
exec_config "$EXEC_DIR" "$STORE_ROOT" "$PID_DIR" >"$WORK/refexec.yaml"
exec_config "$EXEC2_DIR" "$STORE_ROOT2" "$PID_DIR2" shared >"$WORK/refexec2.yaml"
(umask 077 && mkdir -p "$PID_DIR" "$PID_DIR2")

# A refexec property (not the store-dir rule): with shared_host_scratch on, a
# refexec whose OWN store_root/pid_dir are under /private/tmp is refused at
# startup (the sandbox's write probe lands in the scratch it opened), which is
# why the second instance's dirs live under /var/tmp. Bounded: a regression that
# accepted the config would serve forever, so it is killed after 20 s and fails.
mkdir -p "$WORK/badpids" "$WORK/badstores"
exec_config "$EXEC2_DIR" "$WORK/badstores" "$WORK/badpids" shared >"$WORK/refexec-bad.yaml"
"$WORK/refexec" -config "$WORK/refexec-bad.yaml" >/dev/null 2>"$WORK/bad.err" &
BAD_PID=$!
for i in $(seq 1 40); do
	kill -0 "$BAD_PID" 2>/dev/null || break
	sleep 0.5
done
if kill -0 "$BAD_PID" 2>/dev/null; then
	kill "$BAD_PID" >/dev/null 2>&1 || true
	wait "$BAD_PID" >/dev/null 2>&1 || true
	fail "a shared_host_scratch config with its dirs under /private/tmp was accepted (still serving)"
fi
if wait "$BAD_PID"; then
	fail "a shared_host_scratch config with its dirs under /private/tmp exited 0"
fi
grep -q "did not deny a write outside the workspace" "$WORK/bad.err" || { cat "$WORK/bad.err" >&2; fail "the refusal did not come from the tier's probe"; }
REFEXEC_BIN="$WORK/refexec" REFEXEC_CONFIG="$WORK/refexec.yaml" deploy/refexec/refexec-run-seatbelt.sh 2>"$WORK/refexec.err" &
PIDS+=($!)
REFEXEC_BIN="$WORK/refexec" REFEXEC_CONFIG="$WORK/refexec2.yaml" deploy/refexec/refexec-run-seatbelt.sh 2>"$WORK/refexec2.err" &
PIDS+=($!)

# --- the governed memory path: refbridge -> memory-store (embedded) on the HOST.
cat >"$WORK/bridge.yaml" <<EOF
socket: $BRIDGE_DIR/memory.sock
command: ["$WORK/memory-store", "-backend", "embedded", "-store-file", "$STORE_FILE", "-credential-env", "MEMORY_TOKEN"]
credential:
  env: MEMORY_TOKEN
  materialization: env-at-spawn
env_passthrough: []
egress:
  allow: []
sessions:
  max: 4
  idle_timeout: 10m
  max_lifetime: 30m
EOF
export MEMORY_TOKEN="memory-secret-$NONCE"
"$WORK/refbridge" -config "$WORK/bridge.yaml" 2>"$WORK/bridge.err" &
PIDS+=($!)
"$WORK/memory-agent" -socket "$SOCK_DIR/agent.sock" 2>"$WORK/agent.err" &
PIDS+=($!)
# The exec agents are host processes (no agent compartment on macOS); each
# works in the workspace store of the refexec it is paired with.
"$WORK/echo-agent" -socket "$SOCK_DIR/exec-agent.sock" -workspace "$STORE_ROOT/$STORE" 2>"$WORK/exec-agent.err" &
PIDS+=($!)
"$WORK/echo-agent" -socket "$SOCK_DIR/exec-agent2.sock" -workspace "$STORE_ROOT2/$STORE" 2>>"$WORK/exec-agent.err" &
PIDS+=($!)
for i in $(seq 1 60); do
	[ -S "$BRIDGE_DIR/memory.sock" ] && [ -S "$SOCK_DIR/agent.sock" ] && [ -S "$EXEC_DIR/refexec.sock" ] &&
		[ -S "$EXEC2_DIR/refexec.sock" ] && [ -S "$SOCK_DIR/exec-agent.sock" ] && [ -S "$SOCK_DIR/exec-agent2.sock" ] && break
	[ "$i" = 60 ] && fail "sockets never appeared"
	sleep 0.5
done
[ "$(mode_of "$EXEC_DIR")" = 0o700 ] || fail "refexec socket dir is not 0700"
grep -q "refexec listening.*confiner=seatbelt" "$WORK/refexec.err" || fail "refexec did not report the seatbelt tier at start"
grep -q "refexec listening.*confiner=seatbelt opts=\[shared-host-scratch\]" "$WORK/refexec2.err" || fail "the second refexec did not report the seatbelt tier with shared-host-scratch at start"

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
  memory:
    kind: mcp
    url: unix://$BRIDGE_DIR/memory.sock
    runtime: refbridge
    credential_source: static_env
    token_env: MEMORY_TOKEN
    read_only_tools: [memory_search]
EOF
cat >"$WORK/config/agents/memory-writer.yaml" <<EOF
name: memory-writer
description: Upserts and searches memory through the tool door (the governed path)
model: fast
instruction: Run the memory script.
output: reply
execution: fronted
endpoint: unix://$SOCK_DIR/agent.sock
tools:
  - resource: memory
    tools: ["*"]
    mode: read-write
EOF
exec_agent() { # $1 name, $2 agent socket, $3 refexec socket dir
	cat <<EOF
name: $1
description: A host agent whose exec door is first-hand, served by refexec under seatbelt (no memory grant)
model: fast
instruction: Run the command.
output: output
execution: fronted
endpoint: unix://$SOCK_DIR/$2
exec:
  runtime: refexec
  url: unix://$3/refexec.sock
  timeout: 2m
  allow:
    - exe: cat
EOF
}
exec_agent seat-exec exec-agent.sock "$EXEC_DIR" >"$WORK/config/agents/seat-exec.yaml"
exec_agent seat-exec-shared exec-agent2.sock "$EXEC2_DIR" >"$WORK/config/agents/seat-exec-shared.yaml"
for wf in memory-write seat-exec seat-exec-shared; do
	agent="$wf"
	[ "$wf" != memory-write ] || agent=memory-writer
	cat >"$WORK/config/workflows/$wf.yaml" <<EOF
name: $wf
description: One step through $agent
steps:
  - name: call
    agent: $agent
EOF
done
cat >"$WORK/config/roles/seatbelt-operator.yaml" <<EOF
name: seatbelt-operator
description: Runs the memory seatbelt e2e workflows
workflows: [memory-write, seat-exec, seat-exec-shared]
allowed_groups: ["memory-users"]
control: [apply]
EOF
export AGENTHOF_GATEWAY_KEY="host-side-dummy-key-$NONCE" # the model route is never called
"$WORK/agenthof" apply --config "$WORK/config" --control-log "$WORK/control.jsonl" --as ci --groups memory-users

ALL_OUT="" # every run's output and audit, scanned for record B's sentinel at the end
run() { # $1 workflow, $2 input; sets OUT, RUNID, AUDIT (a refused run is data, not a script failure)
	OUT="$("$WORK/agenthof" run seatbelt-operator "$1" --input "$2" \
		--as ci --groups memory-users --config "$WORK/config" --control-log "$WORK/control.jsonl" \
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

# 1. POSITIVE CONTROL: the governed path works. Two records, each carrying its
#    own sentinel in text and metadata: A is returned by a k=1 search whose
#    vector matches only A; B is never returned through the door, so B's bytes
#    exist only on disk.
run memory-write "{\"upserts\":[{\"collection\":\"notes\",\"text\":\"$SENTINEL_A\",\"vector\":[0,1,0],\"metadata\":{\"tag\":\"$SENTINEL_A\"}},{\"collection\":\"notes\",\"text\":\"$SENTINEL_B\",\"vector\":[1,0,0],\"metadata\":{\"tag\":\"$SENTINEL_B\"}}],\"searches\":[{\"collection\":\"notes\",\"vector\":[0,1,0],\"k\":1}]}"
echo "$OUT" | grep -q "finished: succeeded" || fail "the governed memory run did not succeed"
[ "$(grep -c '"runtime_attestation":{"runtime":"refbridge"' "$WORK/logs/$RUNID.jsonl")" = 3 ] || fail "want three attested tool_calls (two upserts, one search): the governed path was not exercised"
# Informational: the memory_search tool_call event as recorded, and whether the
# RETURNED record's (A's) sentinel is in its result preview. B must never be.
echo "--- memory_search tool_call event (record A is the returned record):"
grep '"type":"tool_call"' "$WORK/logs/$RUNID.jsonl" | grep '"memory_search"' || true
if grep '"type":"tool_call"' "$WORK/logs/$RUNID.jsonl" | grep '"memory_search"' | grep -qF "$SENTINEL_A"; then
	echo "info: the returned record's sentinel (A) IS in the memory_search ledger preview"
else
	echo "info: the returned record's sentinel (A) is NOT in the memory_search ledger preview"
fi
[ "$(grep -cE '^hit ' "$(grep -rlE '^hit ' "$WORK/artifacts" | head -n1)")" = 1 ] || fail "the k=1 search did not return exactly one hit"
echo "$AUDIT" | grep -Eq "tool memory_search — args [0-9a-f]{8} \(static_env\) \[runtime-attested: refbridge" || fail "audit does not render the attested memory_search"
ART="$(grep -rlE '^hit [^ ]+ 1\.0000$' "$WORK/artifacts" | head -n1 || true)"
[ -n "$ART" ] || fail "the governed search did not return the upserted record at 1.0000"
echo "positive control: the governed memory_search returned the record — ok"

# 2. UNSANDBOXED CONTROL: the sentinel bytes are really on disk, so a refusal
#    below is a refusal of real content, not of an empty file.
[ -f "$STORE_FILE" ] || fail "the store file was never written"
grep -qF "$SENTINEL_A" "$STORE_FILE" || fail "the unsandboxed control cannot read record A's sentinel from the store file"
grep -qF "$SENTINEL_B" "$STORE_FILE" || fail "the unsandboxed control cannot read record B's sentinel from the store file, so a sandboxed refusal proves nothing"
echo "unsandboxed control: both sentinels, B included, are on disk in the store file — ok"

# 3. CONTAINED OUT-OF-BAND READ REFUSED, recorded first-hand. First the
#    positive read control (an ordinary host file reads fine under the same
#    compartment), so the denial is specific to the store dir.
printf 'open-%s\n' "$NONCE" >"$WORK/open.txt"
run seat-exec "exec-run:cat $WORK/open.txt"
echo "$OUT" | grep -q "finished: succeeded" || fail "a contained read of an ordinary host file failed, so the denial below could be a deny-everything sandbox"
echo "$AUDIT" | grep -Eq "exec cat $WORK/open.txt — exit 0 \(runtime\) \[runtime-attested: refexec cat .*; confiner: seatbelt" || fail "the ordinary read was not recorded first-hand"
run seat-exec "exec-run:cat $STORE_FILE"
echo "$OUT" | grep -q "finished: failed" || fail "a contained cat of the embedded store file must fail"
echo "$AUDIT" | grep -Eq "exec cat $STORE_FILE — exit 1 \(runtime\) \[runtime-attested: refexec cat .*; confiner: seatbelt" || fail "the contained out-of-band read was not refused and recorded first-hand (exit 1)"
grep -q '"runtime_attestation":{"runtime":"refexec"' "$WORK/logs/$RUNID.jsonl" || fail "no refexec attestation for the refused read"
if grep -q '"runtime_attestation":{"runtime":"refbridge"' "$WORK/logs/$RUNID.jsonl"; then fail "the contained read produced a memory tool_call: it was not out-of-band"; fi
echo "contained cat of the store file refused (exit 1), recorded first-hand — ok"

# 4. shared_host_scratch ON: the loosening opens /private/tmp for read and
#    write, not the store dir (which is outside it), so the store read is STILL
#    refused. The audit's loosening marker is the proof the variant really ran
#    with shared scratch (an ordinary file reads under the baseline regardless).
run seat-exec-shared "exec-run:cat $WORK/open.txt"
echo "$OUT" | grep -q "finished: succeeded" || fail "a contained read under the shared-scratch tier failed"
echo "$AUDIT" | grep -q "; shared host scratch\]" || fail "audit did not record the shared-host-scratch loosening"
run seat-exec-shared "exec-run:cat $STORE_FILE"
echo "$OUT" | grep -q "finished: failed" || fail "with shared_host_scratch on, the contained cat of the store file must still fail"
echo "$AUDIT" | grep -Eq "exec cat $STORE_FILE — exit 1 \(runtime\) \[runtime-attested: refexec cat .*; confiner: seatbelt" || fail "the shared-scratch contained read was not refused and recorded first-hand (exit 1)"
echo "$AUDIT" | grep -q "; shared host scratch\]" || fail "the refused shared-scratch run did not record the loosening"
echo "shared_host_scratch on: the store file is still refused (store dir outside /private/tmp) — ok"

# 5. RECORD B'S SENTINEL ABSENT everywhere an out-of-band read could have put
#    it. B was never returned through the door (only A was), so its bytes exist
#    only in the store file: finding them in a ledger, artifact, or log would
#    mean a contained read got through. A is deliberately NOT asserted absent:
#    the governed path may record a bounded result preview of what it returned.
LEAKED=""
for target in "$WORK/logs" "$WORK/artifacts" "$WORK/control.jsonl" "$WORK/run.err" "$WORK/bridge.err" "$WORK/agent.err" "$WORK/exec-agent.err" "$WORK/refexec.err" "$WORK/refexec2.err"; do
	if grep -rqF -- "$SENTINEL_B" "$target" 2>/dev/null; then LEAKED="$LEAKED $target"; fi
done
[ -z "$LEAKED" ] || fail "record B's sentinel (never returned through the door) reached:$LEAKED"
if printf '%s' "$ALL_OUT" | grep -qF -- "$SENTINEL_B"; then fail "record B's sentinel reached agenthof's output or an audit"; fi
echo "record B's sentinel (disk-only) absent from every ledger, artifact, log, and audit — ok"

# No compartment outlives its command.
[ -z "$(ls "$PID_DIR")$(ls "$PID_DIR2")" ] || { ls -la "$PID_DIR" "$PID_DIR2"; fail "a compartment's PID record was left behind"; }

echo "e2e-memory-seatbelt: PASS"
