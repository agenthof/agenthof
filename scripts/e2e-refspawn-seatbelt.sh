#!/usr/bin/env bash
# e2e-refspawn-seatbelt: prove per-child isolation end to end with the real
# macOS Seatbelt backend. The sibling of e2e-refspawn.sh: there refspawn
# provisions a podman volume and one container per agent; here refspawn runs
# on a macOS host with `confiner: seatbelt`, so a child's workspace store is a
# plain directory under store_root, every agent compartment of the child is a
# process started by /usr/bin/sandbox-exec with that directory as its working
# directory, and the child's refexec — a host process refspawn forks — starts
# each exec command under sandbox-exec too. The root run's agent is an
# ordinary host process (there is no agent compartment on macOS). Asserts: a
# two-agent child shares its one workspace (the writer's note is what the
# reader reads — on the file path through the agents, and on the exec path
# through the child's own refexec); the ledger records the exec first-hand
# with the seatbelt tier, the child's audit renders the tier's grade verbatim
# and the parent's audit renders it on the spawn line; a command that tries
# the network is refused inside its compartment, a command that writes
# outside the store fails and leaves no file, and a command that reads a
# deny_read subtree is refused; while a child is alive, the refexec config
# refspawn rendered carries the seatbelt keys (store_root, pid_dir and a
# deny_read naming the operator's subtree and spawn_root) and no podman
# image, the child's agent compartments hold PID records naming its store,
# and its refexec runs on the host; after the parent finishes no store, PID
# record, scratch dir, directory or refexec process the supervisor made is
# left and the supervisor logged no store it could not remove (its
# non-forced RemoveStore succeeded, so nothing held the store); and when a
# child's refexec dies with an exec command still running, the store is
# in use, so the supervisor's non-forced removal is refused and the store
# survives instead of being pulled out from under the command. A refspawn
# config carrying a podman-only key, or missing store_root, is refused before
# anything starts. Requires macOS with sandbox-exec (skips cleanly anywhere
# else), go, curl and python3. Run from the repo root.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Decided before anything is created, so a skip leaves nothing behind. This
# e2e proves the Seatbelt tier with the real sandbox and has no meaning
# without it; the backend-neutral governance e2e is e2e-refspawn-local.sh.
if [ "$(uname)" != Darwin ] || [ ! -x /usr/bin/sandbox-exec ]; then
	echo "e2e-refspawn-seatbelt: SKIP — macOS with /usr/bin/sandbox-exec is required"
	exit 0
fi
# On a macOS host the e2e applies, so a missing build tool is a broken
# environment, not a reason to skip.
for tool in go curl python3 pgrep; do
	command -v "$tool" >/dev/null 2>&1 || { echo "e2e-refspawn-seatbelt: FAIL — $tool is required"; exit 1; }
done

# Short on purpose: Unix socket paths have a small OS length limit. The
# gateway/agent socket dir, refspawn's socket dir and the spawn root are
# SEPARATE and mode 0700, as refspawn and Agenthof both require (mktemp makes
# them so). Nothing the compartments must read lives under store_root,
# pid_dir or spawn_root: the profile read-denies those subtrees.
SOCK_DIR="$(mktemp -d /tmp/sp.XXXXXX)"     # the root run's gateway + agent socket dir
SUP_DIR="$(mktemp -d /tmp/sp.XXXXXX)"      # refspawn's socket dir; never given to a compartment
SPAWN_ROOT="$(mktemp -d /tmp/sp.XXXXXX)"   # per-child dirs: <id> (agent sockets), <id>-exec (refexec socket + config)
WORK="$(mktemp -d /tmp/sp.XXXXXX)"
STORE_ROOT="$WORK/stores"                  # every workspace store is <store_root>/<name>
PID_DIR="$WORK/pids"                       # one record per live compartment; must exist before refspawn starts
DENIED="$WORK/denied"                      # an operator deny_read subtree
PIDS=()
ALIVE=""
cleanup() {
	if [ -n "$ALIVE" ]; then
		kill "$ALIVE" >/dev/null 2>&1 || true
		wait "$ALIVE" >/dev/null 2>&1 || true
	fi
	# A command a killed refexec left running is named by its PID record.
	for pid in $(record_pids 2>/dev/null || true); do
		kill -9 "$pid" >/dev/null 2>&1 || true
	done
	for p in ${PIDS[@]+"${PIDS[@]}"}; do
		kill "$p" >/dev/null 2>&1 || true
		wait "$p" >/dev/null 2>&1 || true
	done
	rm -rf "$SOCK_DIR" "$SUP_DIR" "$SPAWN_ROOT" "$WORK"
}
trap cleanup EXIT
fail() {
	echo "e2e-refspawn-seatbelt: FAIL — $*"
	[ -f "$WORK/refspawn.err" ] && { echo "--- refspawn.err (tail)"; tail -n 40 "$WORK/refspawn.err"; } >&2
	exit 1
}
# record_pids: the pid of every compartment a PID record names.
record_pids() {
	python3 - "$PID_DIR" <<'PY'
import glob, json, sys
for path in sorted(glob.glob(sys.argv[1] + "/*.pid")):
    try:
        pid = json.load(open(path)).get("pid", 0)
    except Exception:
        continue
    if pid > 0:
        print(pid)
PY
}
mode_of() { python3 -c 'import os, sys; print(oct(os.stat(sys.argv[1]).st_mode & 0o777))' "$1"; }
unset AGENTHOF_TOKEN || true
# shellcheck source=scripts/acceptance-lib.sh
. "$ROOT/scripts/acceptance-lib.sh"   # field, count, bound, out_of

# Build everything BEFORE anything starts: the compartments' wall clocks must
# not pay for a cold build. No image is involved: the sandbox runs the host's
# own programs, named by absolute path.
go build -o "$WORK/agenthof" ./cmd/agenthof
go build -o "$WORK/refexec" ./deploy/refexec
go build -o "$WORK/refspawn" ./deploy/refspawn
go build -o "$WORK/echo-agent" ./examples/echo-agent

# --- refspawn's config: the seatbelt backend on this run's private dirs.
# The child agents run the echo-agent by absolute path; refexec.image is
# podman's key and is absent.
spawn_config() { # $1 = "image" to add a podman-only key, "no-store-root" to omit store_root
	cat <<EOF
confiner: seatbelt
socket: $SUP_DIR/refspawn.sock
spawn_root: $SPAWN_ROOT
EOF
	[ "${1:-}" = no-store-root ] || echo "store_root: $STORE_ROOT"
	cat <<EOF
pid_dir: $PID_DIR
deny_read: ["$DENIED"]
images:
  writer: $WORK/echo-agent
  reader: $WORK/echo-agent
timeout: 5m
ready_timeout: 60s
limits:
  memory: 256m
  cpus: "1"
  pids: 64
max_compartments: 3
refexec:
  command: [$WORK/refexec]
EOF
	[ "${1:-}" != image ] || echo "  image: docker.io/library/busybox:1.36.1"
	cat <<EOF
  timeout: 2m
  limits:
    memory: 256m
    cpus: "1"
    pids: 64
  max_compartments: 2
  env_allow: []
EOF
}
(umask 077 && mkdir -p "$STORE_ROOT" "$PID_DIR" "$DENIED")
printf 'denied-%s\n' "$$" >"$DENIED/secret"
spawn_config >"$WORK/refspawn.yaml"

# Config is law before anything starts: a seatbelt config carrying a
# podman-only key, and one without store_root, are each refused by the same
# binary that would serve them; the good config passes and names its socket
# and spawn root.
spawn_config image >"$WORK/refspawn-image.yaml"
if "$WORK/refspawn" -config "$WORK/refspawn-image.yaml" -check >/dev/null 2>"$WORK/check.err"; then
	fail "a seatbelt config carrying image: was accepted"
fi
grep -q "does not consume podman keys: image" "$WORK/check.err" || { cat "$WORK/check.err" >&2; fail "the refusal did not name the unconsumed key"; }
spawn_config no-store-root >"$WORK/refspawn-bad.yaml"
if "$WORK/refspawn" -config "$WORK/refspawn-bad.yaml" -check >/dev/null 2>"$WORK/check.err"; then
	fail "a seatbelt config without store_root was accepted"
fi
grep -q "store_root must be an absolute path" "$WORK/check.err" || { cat "$WORK/check.err" >&2; fail "the refusal did not name store_root"; }
CHECK="$("$WORK/refspawn" -config "$WORK/refspawn.yaml" -check)"
[ "$CHECK" = "$(printf 'socket=%s\nspawn_root=%s' "$SUP_DIR/refspawn.sock" "$SPAWN_ROOT")" ] || { echo "$CHECK"; fail "-check did not report the socket and spawn root"; }

# refspawn on the host. Its socket dir is the access gate: 0700, made by
# mktemp above.
start_refspawn() {
	"$WORK/refspawn" -config "$WORK/refspawn.yaml" 2>>"$WORK/refspawn.err" &
	PIDS+=($!)
	for i in $(seq 1 60); do
		[ -S "$SUP_DIR/refspawn.sock" ] && return 0
		sleep 0.5
	done
	fail "refspawn socket never appeared"
}
start_refspawn
[ "$(mode_of "$SUP_DIR/refspawn.sock")" = 0o600 ] || fail "refspawn socket is not mode 0600"
[ "$(mode_of "$SUP_DIR")" = 0o700 ] || fail "refspawn socket dir is not 0700"
grep -q "limits not enforced on this tier" "$WORK/refspawn.err" || fail "refspawn did not say that limits are not enforced under seatbelt"
grep -q "refspawn listening" "$WORK/refspawn.err" || fail "refspawn did not report that it was listening"

# The root run's agent: a host process (there is no agent compartment on this
# tier). Its workspace is its own directory, never a child's.
mkdir -p "$WORK/lead-ws"
"$WORK/echo-agent" -socket "$SOCK_DIR/agent.sock" -workspace "$WORK/lead-ws" 2>"$WORK/agent.err" &
PIDS+=($!)
for i in $(seq 1 60); do
	[ -S "$SOCK_DIR/agent.sock" ] && break
	[ "$i" = 60 ] && { cat "$WORK/agent.err" >&2; fail "agent socket never appeared"; }
	sleep 0.5
done

# --- a hermetic Agenthof config, written from scratch. The lead may spawn the
# pair and the single workflows; child agents' endpoint and exec.url are
# placeholders (under spawn the supervisor's sockets win); the workflow step
# names are the agents' so `only:` scripts read naturally. The allowlist is
# the commands the scenarios need and nothing else.
mkdir -p "$WORK/config/agents" "$WORK/config/workflows" "$WORK/config/roles"
cat >"$WORK/config/gateway.yaml" <<EOF
refbox_socket_dir: $SOCK_DIR
spawn_supervisor: unix://$SUP_DIR/refspawn.sock
spawn:
  max_depth: 2
  max_parallel: 2
  max_total_spawns: 8
step_timeout: 3m
models:
  fast:
    endpoint: http://127.0.0.1:9/v1
    model: fast
    api_key_env: AGENTHOF_GATEWAY_KEY
defaults:
  model: fast
EOF
cat >"$WORK/config/agents/lead.yaml" <<EOF
name: lead
description: the root run's agent, a host process
model: fast
instruction: Run the script.
output: output
execution: fronted
endpoint: unix://$SOCK_DIR/agent.sock
may_spawn:
  - role: worker
    workflow: pair-wf
  - role: worker
    workflow: one-wf
EOF
for a in writer reader; do
	cat >"$WORK/config/agents/$a.yaml" <<EOF
name: $a
description: a child agent, in its child's seatbelt compartment
model: fast
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
    - exe: cp
    - exe: curl
    - exe: sleep
EOF
done
wf() { # $1 = workflow, $2.. = agents
	local name="$1"
	shift
	{
		printf 'name: %s\ndescription: through %s\nsteps:\n' "$name" "$*"
		for a in "$@"; do printf '  - name: %s\n    agent: %s\n' "$a" "$a"; done
	} >"$WORK/config/workflows/$name.yaml"
}
wf lead-wf lead
wf pair-wf writer reader
wf one-wf writer
cat >"$WORK/config/roles/lead.yaml" <<EOF
name: lead
description: Runs the parent workflow
workflows: [lead-wf]
allowed_groups: ["spawn-users"]
control: [apply]
EOF
cat >"$WORK/config/roles/worker.yaml" <<EOF
name: worker
description: Runs child workflows
workflows: [pair-wf, one-wf]
allowed_groups: ["spawn-users"]
EOF
NONCE="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
# Credentials go in the environment, never in argv: argv is world-readable
# in the process table. The model route is never called; the key only lets
# it resolve.
export AGENTHOF_GATEWAY_KEY="host-side-dummy-key-$NONCE"

"$WORK/agenthof" apply --config "$WORK/config" --control-log "$WORK/control.jsonl" --as ci --groups spawn-users

run() { # $1 = input; sets OUT, RUNID, AUDIT
	OUT="$("$WORK/agenthof" run lead lead-wf --input "$1" \
		--as ci --groups spawn-users --config "$WORK/config" --control-log "$WORK/control.jsonl" \
		--log-dir "$WORK/logs" --artifact-dir "$WORK/artifacts" 2>>"$WORK/agenthof.err" || true)"
	echo "$OUT"
	RUNID="$(echo "$OUT" | sed -n 's/^run \(r-[a-f0-9]*\) finished.*/\1/p')"
	[ -n "$RUNID" ] || { cat "$WORK/agent.err" >&2 || true; fail "no run id"; }
	AUDIT="$("$WORK/agenthof" audit "$RUNID" --log-dir "$WORK/logs" --control-log "$WORK/control.jsonl")"
	echo "$AUDIT"
	echo "$AUDIT" | grep -q "ledger integrity: verified" || fail "ledger not verified"
	echo "$AUDIT" | grep -q "ledger completeness: complete (" || fail "ledger does not account for itself"
}
ledger() { echo "$WORK/logs/$1.jsonl"; }
child_audit() { # $1 = child run id; sets CAUDIT
	CAUDIT="$("$WORK/agenthof" audit "$1" --log-dir "$WORK/logs" --control-log "$WORK/control.jsonl")"
	echo "$CAUDIT"
	echo "$CAUDIT" | grep -q "ledger integrity: verified" || fail "child $1: ledger not verified"
	echo "$CAUDIT" | grep -q "ledger completeness: complete (" || fail "child $1: ledger does not account for itself"
}
parent_artifact() { # $1 = run id
	local sha
	sha="$(field "$(ledger "$1")" step_succeeded artifact_sha | tail -1)"
	[ -n "$sha" ] || fail "run $1 has no step_succeeded artifact"
	[ -s "$WORK/artifacts/$sha" ] || fail "run $1 names artifact $sha, but the store holds no such body"
	cat "$WORK/artifacts/$sha"
}
# The tier's grade, as audit words it (internal/audit/audit.go). The closing
# bracket pins that no loosening (shared host scratch) was recorded.
GRADE_TEXT="seatbelt — shared-kernel OS-sandbox tier (macOS Seatbelt): same trust basis as podman — shared kernel, below any VM/microVM tier; direct network denied; writes scoped; host-readable; no resource caps; process teardown best-effort"
# Teardown is asynchronous from the parent's side by design: the held request
# closes and the parent's run ends, while the supervisor removes the set it
# made in order afterwards. So the check waits for the whole set to be gone,
# bounded at 30 s, and only then says what is left.
set_left() { # prints what is left of any child's set, nothing when it is all gone
	ls "$STORE_ROOT" | grep '^agenthof-spawn-' || true
	ls "$PID_DIR" | grep '\.pid$' || true
	ls -A "$STORE_ROOT/.scratch" 2>/dev/null || true
	ls -A "$SPAWN_ROOT" || true
	pgrep -f "refexec -config $SPAWN_ROOT" || true
}
nothing_left() {
	local i
	for i in $(seq 1 60); do
		[ -z "$(set_left)" ] && return 0
		sleep 0.5
	done
	set_left
	fail "$1: a store, PID record, scratch dir, directory or refexec process outlived the run (listed above)"
}
no_store_leftover_warning() {
	grep -q "workspace store not removed" "$WORK/refspawn.err" && fail "$1: the supervisor could not remove a store, so its non-forced RemoveStore was refused"
	return 0
}

# 1. A two-agent child: the writer writes the store on the FILE path, the
#    reader (a different agent, the same child store) reads it back. The
#    child's preview is the note. Then the same pair on the EXEC path: the
#    writer's exec copies the note inside the store, the reader's exec reads
#    the copy — both through the child's own refexec, under sandbox-exec.
run "spawn:worker/pair-wf:only:writer:write:shared-$NONCE | only:reader:read:"
echo "$OUT" | grep -q "finished: succeeded" || fail "the pair run did not succeed"
PAIR="$(field "$(ledger "$RUNID")" spawn child_run_id succeeded)"
[ -n "$PAIR" ] || fail "no child run id"
[ "$(count "$(ledger "$PAIR")" step_succeeded)" = 2 ] || fail "the pair child did not run both steps"
parent_artifact "$RUNID" | grep -q "spawn succeeded $PAIR shared-$NONCE" || fail "the reader did not see the writer's note: the child's two agents do not share one store"
[ "$(field "$(ledger "$RUNID")" spawn child_confiner succeeded)" = seatbelt ] || fail "the parent's spawn event does not record the seatbelt tier"
echo "$AUDIT" | grep -qF " [child-confiner: $GRADE_TEXT]" || fail "the parent's audit did not render the child's seatbelt tier verbatim"
bound "$(ledger "$PAIR")" "$PAIR" ci "$RUNID"
grep -q "compartment started.*child=$PAIR.*compartment=agenthof-spawn-$PAIR-writer" "$WORK/refspawn.err" || fail "no writer compartment"
grep -q "compartment started.*child=$PAIR.*compartment=agenthof-spawn-$PAIR-reader" "$WORK/refspawn.err" || fail "no reader compartment"
nothing_left "after the pair run"
echo "multi-agent child: two agents, one shared store, the tier recorded on the spawn — ok"

run "spawn:worker/pair-wf:only:writer:write:exec-$NONCE | only:writer:exec-run:cp agent-note.txt copy.txt | only:reader:exec-run:cat copy.txt"
echo "$OUT" | grep -q "finished: succeeded" || fail "the exec pair run did not succeed"
PAIR="$(field "$(ledger "$RUNID")" spawn child_run_id succeeded)"
[ -n "$PAIR" ] || fail "no child run id"
parent_artifact "$RUNID" | grep -q "spawn succeeded $PAIR exec-$NONCE" || fail "the reader's exec did not see the writer's exec's copy"
CL="$(ledger "$PAIR")"
[ "$(count "$CL" exec succeeded)" = 2 ] || fail "expected two first-hand execs on the child"
child_audit "$PAIR"
echo "$CAUDIT" | grep -Eq "exec cp agent-note.txt copy.txt — exit 0 \(runtime\) \[runtime-attested: refexec cp agent-note.txt copy.txt pid [0-9]+ spawn 1; confiner: seatbelt" || fail "no first-hand cp line rendered"
echo "$CAUDIT" | grep -qF "; confiner: $GRADE_TEXT]" || fail "the child's audit did not render the seatbelt tier's grade verbatim"
grep -q '"mode":"runtime"' "$CL" || fail "the child's exec is not mode runtime"
grep -q '"runtime_attestation":{"runtime":"refexec","session":"refexec-' "$CL" || fail "no refexec attestation in the child's ledger"
grep -q '"credential_env":"","env_names":\["TMPDIR"\],"materialization":"","confiner":"seatbelt"' "$CL" || fail "the attestation must be credential-less naming only the scratch TMPDIR (env_allow is empty) and the seatbelt tier"
if grep '"type":"exec"' "$CL" | grep -q "exec-$NONCE"; then fail "the output body reached an exec event"; fi
nothing_left "after the exec pair run"
echo "exec path: a child's first-hand exec works on the child's store under sandbox-exec, tier recorded and graded — ok"

# 2. Containment through the child's refexec: direct network denied (curl
#    exit 7 — a refusal, not a timeout — after an unsandboxed control), a
#    write outside the store denied with no file left, and a read of the
#    operator's deny_read subtree denied. Each is recorded first-hand as a
#    failed exec.
if curl -sS --max-time 3 -o /dev/null http://1.1.1.1/ 2>/dev/null; then
	run "spawn:worker/one-wf:exec-run:curl -sS --max-time 3 http://1.1.1.1/"
	CH="$(field "$(ledger "$RUNID")" spawn child_run_id)"
	[ -n "$CH" ] || fail "no child run id for the network scenario"
	child_audit "$CH"
	echo "$CAUDIT" | grep -Eq "exec curl -sS --max-time 3 http://1.1.1.1/ — exit 7 \(runtime\) \[runtime-attested: refexec curl .*; confiner: seatbelt" || fail "the network refusal was not recorded first-hand with curl's could-not-connect exit"
	echo "direct network denied inside the compartment, recorded first-hand — ok"
else
	echo "SKIP — the unsandboxed curl could not reach 1.1.1.1, so a sandboxed refusal could not be attributed to the sandbox"
fi
run "spawn:worker/one-wf:write:leak-$NONCE | exec-run:cp agent-note.txt $WORK/leak"
CH="$(field "$(ledger "$RUNID")" spawn child_run_id)"
[ -n "$CH" ] || fail "no child run id for the write scenario"
child_audit "$CH"
echo "$CAUDIT" | grep -Eq "exec cp agent-note.txt $WORK/leak — exit [1-9][0-9]* \(runtime\) \[runtime-attested: refexec cp .*; confiner: seatbelt" || fail "the denied write was not recorded first-hand"
[ ! -e "$WORK/leak" ] || fail "a sandboxed command wrote outside the store"
echo "write outside the store denied, no file left — ok"
[ "$(cat "$DENIED/secret")" = "denied-$$" ] || fail "the unsandboxed control cannot read the deny_read file, so a sandboxed refusal proves nothing"
run "spawn:worker/one-wf:exec-run:cat $DENIED/secret"
CH="$(field "$(ledger "$RUNID")" spawn child_run_id)"
[ -n "$CH" ] || fail "no child run id for the read scenario"
child_audit "$CH"
echo "$CAUDIT" | grep -Eq "exec cat $DENIED/secret — exit [1-9][0-9]* \(runtime\) \[runtime-attested: refexec cat .*; confiner: seatbelt" || fail "the denied read was not recorded first-hand"
if grep -q "denied-$$" "$(ledger "$CH")" "$(ledger "$RUNID")"; then fail "the deny_read file's content reached a ledger"; fi
for f in "$WORK"/artifacts/*; do
	if grep -q "denied-$$" "$f"; then fail "the deny_read file's content reached an artifact"; fi
done
echo "read of a deny_read subtree denied, nothing leaked — ok"
nothing_left "after the containment runs"

# 3. The set, inspected while a child is alive: the refexec config refspawn
#    rendered for the child, the PID records of its agent compartments naming
#    its store, its refexec on the host, and its store directory. After the
#    run the store is gone by the non-forced removal.
"$WORK/agenthof" run lead lead-wf --input "spawn:worker/pair-wf:only:reader:sleep:20" --as ci --groups spawn-users --config "$WORK/config" --control-log "$WORK/control.jsonl" --log-dir "$WORK/logs" --artifact-dir "$WORK/artifacts" >"$WORK/alive.out" 2>>"$WORK/agenthof.err" &
ALIVE=$!
READER_REC=""
for i in $(seq 1 60); do
	READER_REC="$(ls "$PID_DIR" 2>/dev/null | grep -E '^agenthof-spawn-.*-reader\.pid$' | head -1 || true)"
	[ -n "$READER_REC" ] && break
	[ "$i" = 60 ] && fail "no reader compartment appeared"
	sleep 0.5
done
CHILD_ID="${READER_REC#agenthof-spawn-}"; CHILD_ID="${CHILD_ID%-reader.pid}"
CSTORE="agenthof-spawn-$CHILD_ID-work"
RXCFG="$SPAWN_ROOT/$CHILD_ID-exec/refexec.yaml"
for i in $(seq 1 60); do
	[ -s "$PID_DIR/agenthof-spawn-$CHILD_ID-writer.pid" ] && [ -s "$RXCFG" ] && pgrep -f "refexec -config $SPAWN_ROOT/$CHILD_ID-exec" >/dev/null && break
	[ "$i" = 60 ] && fail "the child's set did not come up whole"
	sleep 0.5
done
grep -qx "confiner: seatbelt" "$RXCFG" || { cat "$RXCFG"; fail "the rendered refexec config does not name the seatbelt backend"; }
grep -qx "store_root: $STORE_ROOT" "$RXCFG" || { cat "$RXCFG"; fail "the rendered refexec config does not carry store_root"; }
grep -qx "pid_dir: $PID_DIR" "$RXCFG" || { cat "$RXCFG"; fail "the rendered refexec config does not carry pid_dir"; }
grep -qx "deny_read: \[\"$DENIED\", \"$SPAWN_ROOT\"\]" "$RXCFG" || { cat "$RXCFG"; fail "the rendered refexec config's deny_read is not the operator's subtree plus spawn_root"; }
grep -qx "  store: $CSTORE" "$RXCFG" || { cat "$RXCFG"; fail "the rendered refexec config does not name the child's store"; }
if grep -q "image:" "$RXCFG"; then cat "$RXCFG"; fail "a seatbelt child's refexec config carries a podman image"; fi
[ "$(mode_of "$RXCFG")" = 0o600 ] || fail "the rendered refexec config is not mode 0600"
[ -d "$STORE_ROOT/$CSTORE" ] || fail "the child's store directory does not exist"
[ "$(mode_of "$STORE_ROOT/$CSTORE")" = 0o700 ] || fail "the child's store directory is not 0700"
for a in writer reader; do
	python3 - "$PID_DIR/agenthof-spawn-$CHILD_ID-$a.pid" "$CSTORE" <<'PY' || fail "the $a compartment's PID record does not name the child's store with a live pid"
import json, sys
rec = json.load(open(sys.argv[1]))
assert rec["store"] == sys.argv[2], rec
assert rec["pid"] > 0 and rec["start_unix_micro"] > 0, rec
PY
done
READER_PID="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["pid"])' "$PID_DIR/$READER_REC")"
ps -o command= -p "$READER_PID" | grep -q "echo-agent -socket $SPAWN_ROOT/$CHILD_ID/reader.sock" || fail "the reader compartment's process is not the echo-agent on the child's socket"
grep -q "refexec listening.*$SPAWN_ROOT/$CHILD_ID-exec/refexec.sock confiner=seatbelt" "$WORK/refspawn.err" || fail "the child's refexec did not report the seatbelt tier at start"
wait "$ALIVE" || true
ALIVE=""
grep -q "finished: succeeded" "$WORK/alive.out" || { cat "$WORK/alive.out"; fail "the inspected run did not succeed"; }
nothing_left "after the inspected run"
[ ! -e "$STORE_ROOT/$CSTORE" ] || fail "the child's store survived a teardown that nothing held up"
grep -q "set torn down.*child=$CHILD_ID" "$WORK/refspawn.err" || grep -q "child=$CHILD_ID.*set torn down" "$WORK/refspawn.err" || fail "the supervisor did not log the child's teardown"
no_store_leftover_warning "after the inspected run"
echo "set: rendered refexec config, PID records on the store, host refexec, store removed by the non-forced path — ok"

# 4. In-use teardown: a child's refexec dies while an exec command is still
#    running. The supervisor tears the set down in order — but the command
#    outlived its refexec, so a live PID record still names the store, and
#    its non-forced RemoveStore is refused (ErrStoreInUse) instead of pulling
#    the store out from under the running command. The store survives.
"$WORK/agenthof" run lead lead-wf --input "spawn:worker/one-wf:exec-run:sleep 60" --as ci --groups spawn-users --config "$WORK/config" --control-log "$WORK/control.jsonl" --log-dir "$WORK/logs" --artifact-dir "$WORK/artifacts" >"$WORK/inuse.out" 2>>"$WORK/agenthof.err" &
ALIVE=$!
EXEC_REC=""
for i in $(seq 1 60); do
	EXEC_REC="$(python3 - "$PID_DIR" <<'PY' || true
import glob, json, os, sys
for path in sorted(glob.glob(sys.argv[1] + "/refexec-*.pid")):
    try:
        rec = json.load(open(path))
    except Exception:
        continue
    if rec.get("pid", 0) > 0 and rec.get("store", "").startswith("agenthof-spawn-"):
        print(os.path.basename(path), rec["pid"], rec["store"])
        break
PY
)"
	[ -n "$EXEC_REC" ] && break
	[ "$i" = 60 ] && fail "no exec compartment appeared on a child's store"
	sleep 0.5
done
read -r _ SLEEP_PID USTORE <<<"$EXEC_REC"
[ -d "$STORE_ROOT/$USTORE" ] || fail "the child's store directory does not exist"
RXPID="$(pgrep -f "refexec -config $SPAWN_ROOT/" | head -1 || true)"
[ -n "$RXPID" ] || fail "the child's refexec is not running"
ps -o command= -p "$SLEEP_PID" | grep -Eq "(^|/)sleep 60$" || fail "the exec compartment's process is not the sleep command"
kill -9 "$RXPID"
for i in $(seq 1 90); do
	grep -q "workspace store not removed" "$WORK/refspawn.err" && break
	[ "$i" = 90 ] && fail "the supervisor never reported a store it could not remove"
	sleep 0.5
done
grep -q "refexec exited; tearing the set down" "$WORK/refspawn.err" || fail "the supervisor did not tear the set down when the refexec died"
grep "workspace store not removed" "$WORK/refspawn.err" | grep -q "store is in use" || fail "the store removal was not refused as in use"
grep "workspace store not removed" "$WORK/refspawn.err" | grep -qF "$USTORE" || fail "the in-use refusal does not name the child's store"
[ -d "$STORE_ROOT/$USTORE" ] || fail "the store was removed from under a running command"
kill -0 "$SLEEP_PID" 2>/dev/null || fail "the running command did not survive the refused removal"
wait "$ALIVE" || true
ALIVE=""
# The orphaned command is the operator's to end; the next start's reap does
# not touch it (its record is the refexec's, not the supervisor's).
kill -9 "$SLEEP_PID" >/dev/null 2>&1 || true
[ -z "$(ls -A "$SPAWN_ROOT")" ] || { ls -la "$SPAWN_ROOT"; fail "the spawn root is not empty after the in-use teardown"; }
echo "in-use teardown: the store survived a refused non-forced removal while a command still ran on it — ok"

# 5. The supervisor shuts down cleanly and the lead's workspace never saw a
#    child's files.
kill "${PIDS[0]}" >/dev/null 2>&1 || true
wait "${PIDS[0]}" >/dev/null 2>&1 || true
[ ! -S "$SUP_DIR/refspawn.sock" ] || fail "refspawn left its socket behind"
[ ! -e "$WORK/lead-ws/agent-note.txt" ] || fail "a child's note reached the lead's workspace"

echo "e2e-refspawn-seatbelt: PASS"
