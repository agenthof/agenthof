#!/usr/bin/env bash
# e2e-refexec-seatbelt: prove first-hand exec end to end with the real macOS
# Seatbelt backend. The sibling of e2e-refexec.sh: there the agent runs in a
# refbox compartment and refexec starts a podman container per command; here
# refexec runs on a macOS host with `confiner: seatbelt` and starts each
# command under /usr/bin/sandbox-exec, with the workspace store — a plain
# directory under store_root — as its working directory. There is no agent
# compartment on macOS: the reference agent runs as an ordinary host process
# whose workspace is that same store directory, and only the exec commands
# are confined. Asserts: the step artifact is the agent's note (the sandboxed
# command saw the agent's file), the ledger records the exec with mode runtime,
# refexec's first-hand attestation and the seatbelt tier, audit renders the
# tier's grade verbatim, the exec event never carries the output body; a
# command that tries the network is refused inside its compartment (direct
# network denied) and recorded first-hand as a failed exec; a command that
# writes outside the store fails and leaves no file (writes scoped); an
# off-allowlist command is refused before refexec is asked; no compartment's
# PID record or scratch dir is left behind; the store outlives the runtime;
# and a refexec config missing a guardrail, or carrying a key the backend does
# not consume, is refused before anything starts. Requires macOS with
# sandbox-exec (skips cleanly anywhere else), go, curl and python3. Run from
# the repo root.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Decided before anything is created, so a skip leaves nothing behind. This
# e2e proves the Seatbelt tier with the real sandbox and has no meaning
# without it; the backend-neutral governance e2e is e2e-refexec-local.sh.
if [ "$(uname)" != Darwin ] || [ ! -x /usr/bin/sandbox-exec ]; then
	echo "e2e-refexec-seatbelt: SKIP — macOS with /usr/bin/sandbox-exec is required"
	exit 0
fi
# On a macOS host the e2e applies, so a missing build tool is a broken
# environment, not a reason to skip.
for tool in go curl python3; do
	command -v "$tool" >/dev/null 2>&1 || { echo "e2e-refexec-seatbelt: FAIL — $tool is required"; exit 1; }
done

# Short on purpose: Unix socket paths have a small OS length limit, and
# refexec checks that a socket under <store_root>/.scratch/ would fit too.
# refexec's socket dir is SEPARATE from the gateway socket dir and mode 0700
# (mktemp makes it so), as refexec and Agenthof both require.
SOCK_DIR="$(mktemp -d /tmp/rx.XXXXXX)"     # the gateway + agent socket dir
EXEC_DIR="$(mktemp -d /tmp/rx.XXXXXX)"     # refexec's socket dir; the agent is never told about it
WORK="$(mktemp -d /tmp/rx.XXXXXX)"
STORE_ROOT="$WORK/stores"                  # every workspace store is <store_root>/<name>
PID_DIR="$WORK/pids"                       # one record per live compartment; must exist before refexec starts
# The long-lived workspace store; it must stay off the refexec- prefix that
# refexec's startup reap removes (refexec -check refuses such a store).
STORE="e2e-work-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
STORE_PATH="$STORE_ROOT/$STORE"
PIDS=()
cleanup() {
	for p in ${PIDS[@]+"${PIDS[@]}"}; do
		kill "$p" >/dev/null 2>&1 || true
		wait "$p" >/dev/null 2>&1 || true
	done
	rm -rf "$SOCK_DIR" "$EXEC_DIR" "$WORK"
}
trap cleanup EXIT
fail() {
	echo "e2e-refexec-seatbelt: FAIL — $*"
	[ -f "$WORK/refexec.err" ] && { echo "--- refexec.err"; cat "$WORK/refexec.err"; } >&2
	exit 1
}
sha_stdin() { python3 -c 'import hashlib, sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())'; }
mode_of() { python3 -c 'import os, sys; print(oct(os.stat(sys.argv[1]).st_mode & 0o777))' "$1"; }
unset AGENTHOF_TOKEN || true

# Build everything BEFORE anything starts: the compartments' wall clocks must
# not pay for a cold build. No image is involved: the sandbox runs the host's
# own programs.
go build -o "$WORK/agenthof" ./cmd/agenthof
go build -o "$WORK/refexec" ./deploy/refexec
go build -o "$WORK/echo-agent" ./examples/echo-agent

# --- refexec's config: the seatbelt backend on this run's private dirs.
exec_config() { # $1 = "no-timeout" to omit the timeout, "image" to add a podman-only key
	cat <<EOF
confiner: seatbelt
socket: $EXEC_DIR/refexec.sock
store_root: $STORE_ROOT
pid_dir: $PID_DIR
workspace:
  store: $STORE
limits:
  memory: 256m
  cpus: "1"
  pids: 64
compartments:
  max: 2
env_allow: []
EOF
	[ "${1:-}" = no-timeout ] || echo "timeout: 2m"
	[ "${1:-}" != image ] || echo "image: docker.io/library/busybox:1.36.1"
}
exec_config >"$WORK/refexec.yaml"

# Config is law before anything starts: a config without a timeout, and a
# seatbelt config carrying a podman-only key, are each refused by the same
# binary that would serve them.
exec_config no-timeout >"$WORK/refexec-bad.yaml"
if "$WORK/refexec" -config "$WORK/refexec-bad.yaml" -check >/dev/null 2>"$WORK/check.err"; then
	fail "a refexec config without a timeout was accepted"
fi
grep -q "timeout is required" "$WORK/check.err" || { cat "$WORK/check.err" >&2; fail "the refusal did not name timeout"; }
exec_config image >"$WORK/refexec-image.yaml"
if "$WORK/refexec" -config "$WORK/refexec-image.yaml" -check >/dev/null 2>"$WORK/check.err"; then
	fail "a seatbelt config carrying image: was accepted"
fi
grep -q "does not consume podman keys: image" "$WORK/check.err" || { cat "$WORK/check.err" >&2; fail "the refusal did not name the unconsumed key"; }

# refexec on the host, through its launcher (which reads -check, prepares the
# 0700 socket dir and creates the store directory). The PID dir is the
# operator's to provide; the launcher does not create it.
(umask 077 && mkdir -p "$PID_DIR")
REFEXEC_BIN="$WORK/refexec" REFEXEC_CONFIG="$WORK/refexec.yaml" deploy/refexec/refexec-run-seatbelt.sh 2>"$WORK/refexec.err" &
PIDS+=($!)
for i in $(seq 1 60); do
	[ -S "$EXEC_DIR/refexec.sock" ] && break
	[ "$i" = 60 ] && fail "refexec socket never appeared"
	sleep 0.5
done
[ "$(mode_of "$EXEC_DIR/refexec.sock")" = 0o600 ] || fail "refexec socket is not mode 0600"
[ "$(mode_of "$EXEC_DIR")" = 0o700 ] || fail "refexec socket dir is not 0700"
[ -d "$STORE_PATH" ] || fail "the launcher did not create the workspace store directory"
[ "$(mode_of "$STORE_PATH")" = 0o700 ] || fail "the workspace store directory is not 0700"
grep -q "limits not enforced on this tier" "$WORK/refexec.err" || fail "refexec did not say that limits are not enforced under seatbelt"
grep -q "refexec listening.*confiner=seatbelt" "$WORK/refexec.err" || fail "refexec did not report the seatbelt tier at start"

# The agent: a host process on macOS (there is no agent compartment on this
# tier), with the store directory as its workspace, so what it writes is
# what a sandboxed command finds in its working directory.
"$WORK/echo-agent" -socket "$SOCK_DIR/agent.sock" -workspace "$STORE_PATH" 2>"$WORK/agent.err" &
PIDS+=($!)
for i in $(seq 1 60); do
	[ -S "$SOCK_DIR/agent.sock" ] && break
	[ "$i" = 60 ] && { cat "$WORK/agent.err" >&2; fail "agent socket never appeared"; }
	sleep 0.5
done

# --- a hermetic Agenthof config, written from scratch. The allowlist is the
# commands the scenarios need and nothing else.
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
EOF
cat >"$WORK/config/agents/seatbelt-exec.yaml" <<EOF
name: seatbelt-exec
description: The reference agent on a macOS host whose exec door is first-hand, served by refexec under seatbelt
model: fast
instruction: Write a note on the workspace, then run the command.
output: output
execution: fronted
endpoint: unix://$SOCK_DIR/agent.sock
exec:
  runtime: refexec
  url: unix://$EXEC_DIR/refexec.sock
  timeout: 2m
  allow:
    - exe: cat
    - exe: curl
    - exe: cp
EOF
cat >"$WORK/config/workflows/seatbelt-exec.yaml" <<EOF
name: seatbelt-exec
description: One step through the reference agent; its command runs first-hand in a seatbelt compartment
steps:
  - name: run
    agent: seatbelt-exec
EOF
cat >"$WORK/config/roles/seatbelt-exec-operator.yaml" <<EOF
name: seatbelt-exec-operator
description: Runs the first-hand exec workflow
workflows: [seatbelt-exec]
allowed_groups: ["exec-users"]
control: [apply]
EOF

NONCE="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
export AGENTHOF_GATEWAY_KEY="host-side-dummy-key-$NONCE"   # the model route is never called; the key only lets it resolve

"$WORK/agenthof" apply --config "$WORK/config" --control-log "$WORK/control.jsonl" --as ci --groups exec-users

run() { # $1 = input; sets OUT, RUNID, AUDIT
	OUT="$("$WORK/agenthof" run seatbelt-exec-operator seatbelt-exec --input "$1" \
		--as ci --groups exec-users --config "$WORK/config" --control-log "$WORK/control.jsonl" \
		--log-dir "$WORK/logs" --artifact-dir "$WORK/artifacts" || true)"
	echo "$OUT"
	RUNID="$(echo "$OUT" | sed -n 's/^run \(r-[a-f0-9]*\) finished.*/\1/p')"
	[ -n "$RUNID" ] || { cat "$WORK/agent.err" >&2 || true; fail "no run id"; }
	AUDIT="$("$WORK/agenthof" audit "$RUNID" --log-dir "$WORK/logs" --control-log "$WORK/control.jsonl")"
	echo "$AUDIT"
	echo "$AUDIT" | grep -q "ledger integrity: verified" || fail "ledger not verified"
	echo "$AUDIT" | grep -q "ledger completeness: complete (" || fail "ledger does not account for itself"
}
# The tier's grade, as audit words it (internal/audit/audit.go). The closing
# bracket pins that no loosening (shared host scratch) was recorded.
GRADE="; confiner: seatbelt — shared-kernel OS-sandbox tier (macOS Seatbelt): same trust basis as podman — shared kernel, below any VM/microVM tier; direct network denied; writes scoped; host-readable; no resource caps; process teardown best-effort]"

# 1. The agent writes on the store; the sandboxed command reads it from its
#    working directory first-hand; the ledger carries refexec's account, the
#    seatbelt tier, and never the output (the step's artifact preview is the
#    output by design).
run "write:hello-$NONCE; exec-run:cat agent-note.txt"
echo "$OUT" | grep -q "finished: succeeded" || fail "run did not succeed"
echo "$AUDIT" | grep -Eq "exec cat agent-note.txt — exit 0 \(runtime\) \[runtime-attested: refexec cat agent-note.txt pid [0-9]+ spawn 1; confiner: seatbelt" || fail "no first-hand exec line rendered"
echo "$AUDIT" | grep -qF "$GRADE" || fail "audit did not render the seatbelt tier's grade verbatim"
grep -q '"mode":"runtime"' "$WORK/logs/$RUNID.jsonl" || fail "exec event is not mode runtime"
grep -q '"runtime_attestation":{"runtime":"refexec","session":"refexec-' "$WORK/logs/$RUNID.jsonl" || fail "no refexec attestation in the ledger"
grep -q '"confiner":"seatbelt"' "$WORK/logs/$RUNID.jsonl" || fail "the ledger does not record the seatbelt tier"
grep -q '"credential_env":"","env_names":\["TMPDIR"\],"materialization":"","confiner":"seatbelt"' "$WORK/logs/$RUNID.jsonl" || fail "the attestation must be credential-less naming only the scratch TMPDIR (env_allow is empty) and the seatbelt tier"
grep -q '"type":"exec"' "$WORK/logs/$RUNID.jsonl" || fail "no exec event in the ledger"
if grep '"type":"exec"' "$WORK/logs/$RUNID.jsonl" | grep -q "hello-$NONCE"; then fail "the output body reached the exec event"; fi
ART="$WORK/artifacts/$(printf 'hello-%s\n' "$NONCE" | sha_stdin)"
grep -q "\"output_sha\":\"$(basename "$ART")\"" "$WORK/logs/$RUNID.jsonl" || fail "the exec event's output_sha is not the artifact's hash"
[ -f "$ART" ] || { ls "$WORK/artifacts"; fail "no artifact equal to the note: the compartment did not see the agent's file"; }
[ "$(cat "$STORE_PATH/agent-note.txt")" = "hello-$NONCE" ] || fail "the note is not in the workspace store"
grep -q "compartment started" "$WORK/refexec.err" || fail "refexec did not log the compartment start"
grep -q "compartment finished" "$WORK/refexec.err" || fail "refexec did not log the compartment finish"
echo "first-hand run on the workspace store: artifact, attestation, seatbelt tier graded, no output in the exec event — ok"

# 2. Direct network denied: curl through the door fails inside the sandbox
#    with exit 7 (could not connect) — a refusal, not a timeout (28) — and the
#    ledger records that first-hand as a failed exec. The unsandboxed control
#    comes first: a host with no route fails at once too, so a refusal could
#    not be attributed to the sandbox and this scenario is skipped, not read
#    as enforcement.
STARTS=1   # the compartments refexec has been asked for so far: cat
if curl -sS --max-time 3 -o /dev/null http://1.1.1.1/ 2>/dev/null; then
	run "exec-run:curl -sS --max-time 3 http://1.1.1.1/"
	echo "$OUT" | grep -q "finished: failed" || fail "a command that needs the network must fail"
	echo "$AUDIT" | grep -Eq "exec curl -sS --max-time 3 http://1.1.1.1/ — exit 7 \(runtime\) \[runtime-attested: refexec curl .*; confiner: seatbelt" || fail "the network refusal was not recorded first-hand with curl's could-not-connect exit"
	echo "direct network denied inside the compartment, recorded first-hand — ok"
	STARTS=$((STARTS + 1))
else
	echo "SKIP — the unsandboxed curl could not reach 1.1.1.1, so a sandboxed refusal could not be attributed to the sandbox"
fi

# 3. Writes scoped: a command that copies the note outside the store fails
#    inside the sandbox and leaves no file; the ledger records it first-hand.
run "exec-run:cp agent-note.txt $WORK/leak"
echo "$OUT" | grep -q "finished: failed" || fail "a write outside the store must fail"
echo "$AUDIT" | grep -Eq "exec cp agent-note.txt $WORK/leak — exit [1-9][0-9]* \(runtime\) \[runtime-attested: refexec cp .*; confiner: seatbelt" || fail "the denied write was not recorded first-hand"
[ ! -e "$WORK/leak" ] || fail "a sandboxed command wrote outside the store"
echo "write outside the store denied, no file left — ok"
STARTS=$((STARTS + 1))

# 4. An off-allowlist command is refused before refexec is asked.
run "exec-run:sh -c id"
echo "$OUT" | grep -q "finished: failed" || fail "an off-allowlist command must fail the step"
echo "$AUDIT" | grep -q "exec sh -c id refused — command is not on the exec allowlist" || fail "refusal not rendered"
[ "$(grep -c 'compartment started' "$WORK/refexec.err")" = "$STARTS" ] || fail "refexec was asked to run something it should not have been (want $STARTS starts)"

# 5. No compartment outlives its command: every PID record and scratch dir is
#    gone while refexec is still up. The store outlives the runtime but not
#    the recipe.
[ -z "$(ls "$PID_DIR")" ] || { ls -la "$PID_DIR"; fail "a compartment's PID record was left behind"; }
[ -z "$(ls "$STORE_ROOT/.scratch" 2>/dev/null)" ] || { ls -la "$STORE_ROOT/.scratch"; fail "a compartment's scratch dir was left behind"; }
kill "${PIDS[0]}" >/dev/null 2>&1 || true
wait "${PIDS[0]}" >/dev/null 2>&1 || true
if [ -S "$EXEC_DIR/refexec.sock" ]; then fail "refexec left its socket behind"; fi
[ "$(cat "$STORE_PATH/agent-note.txt")" = "hello-$NONCE" ] || fail "the note must survive the runtime (the store is recipe-scoped)"

echo "e2e-refexec-seatbelt: PASS"
