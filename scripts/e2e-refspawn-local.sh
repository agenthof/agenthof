#!/usr/bin/env bash
# e2e-refspawn-local: prove the REAL agenthof binary runs governed sub-agent
# runs through the spawn door, hermetically, with no container runtime. The
# compartment supervisor is a stand-in built from refspawn's own test tree:
# the real refspawn program with a fake podman in place of podman, so each
# child "compartment" is the reference agent (examples/echo-agent) run
# directly on the host, each child "volume" a directory, and each child's
# refexec the refexec stand-in — the door, the supervisor protocol, the
# ledger and audit are real. One host echo-agent over TCP serves the root
# run; every child agent is provisioned by the supervisor.
# Asserts: a parent spawns a child that reports back (the child's preview
# lands in the parent's artifact; the parent's ledger carries one spawn
# event linking child_run_id; the child's own ledger carries parent_run_id,
# depth and the SAME invoker); parallel children overlap in time and the
# parallel cap refuses the surplus atomically; the total cap refuses the
# surplus across a run; nesting stops at max_depth with a recorded refusal;
# a target off may_spawn and a role RBAC denies are refused and recorded
# (the latter with its own child ledger); a child fronting an on-behalf-of
# resource under a --as invoker is refused before its engine starts with the
# fixed reason and provisions nothing; investigate --run shows the tree and
# audit renders the spawn lines; a cyclic may_spawn graph is rejected at
# apply when reject_cycles is set, a missing cap and a missing supervisor
# are rejected whenever may_spawn is declared; a parent step's timeout
# tears an in-flight child down with bounded latency and the supervisor
# removes its set; a supervisor that is absent, behind a directory anyone
# could reach, or answering nonsense refuses every spawn fail-closed with
# the fixed reason and burns no total; an agent the supervisor has no image
# for is refused the same way; a multi-agent child's agents share the
# child's one volume while each child gets a fresh one; and nothing the
# supervisor made outlives the run.
#
# Seven failure modes the design treats differently — off may_spawn, an
# RBAC denial, each cap, a pre-run on-behalf-of refusal, a child torn down
# with its parent, and a child with no compartments — are told apart by the
# FIXED reason each records, never by a shared wrapper line. The four ways
# a child can end up with no compartments share ONE ledger reason on
# purpose (an agent learns nothing about the operator's runtime from it), so
# they are told apart by the distinct record each leaves in the operator's
# log, over only the lines the run in question wrote. Every absence check is
# preceded by a positive assertion over the same file, so no grep can
# succeed on an empty one. Requires go and python3. Runs on macOS and Linux.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Short on purpose: Unix socket paths have a small OS length limit. The
# supervisor's socket dir and the spawn root are SEPARATE and mode 0700, as
# refspawn and Agenthof both require (mktemp makes them so).
WORK="$(mktemp -d /tmp/sp.XXXXXX)"
SUP_DIR="$(mktemp -d /tmp/sp.XXXXXX)"
SPAWN_ROOT="$(mktemp -d /tmp/sp.XXXXXX)"
VOLROOT="$(mktemp -d /tmp/sp.XXXXXX)"
DEAD_DIR="$(mktemp -d /tmp/sp.XXXXXX)"   # private, but nothing listens in it
OPEN_DIR="$(mktemp -d /tmp/sp.XXXXXX)"   # made world-readable below: the client must refuse to dial here
BAD_DIR="$(mktemp -d /tmp/sp.XXXXXX)"    # private, and something that is not a supervisor listens in it
chmod 755 "$OPEN_DIR"
PIDS=()
cleanup() {
	for p in ${PIDS[@]+"${PIDS[@]}"}; do
		kill "$p" >/dev/null 2>&1 || true
		wait "$p" >/dev/null 2>&1 || true
	done
	rm -rf "$WORK" "$SUP_DIR" "$SPAWN_ROOT" "$VOLROOT" "$DEAD_DIR" "$OPEN_DIR" "$BAD_DIR"
}
trap cleanup EXIT
unset AGENTHOF_TOKEN || true

fail() {
	echo "e2e-refspawn-local: FAIL — $*"
	exit 1
}
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'; }
wait_port() { # $1 = port, $2 = what
	for i in $(seq 1 60); do
		python3 -c "import socket; socket.create_connection(('127.0.0.1', $1), 1).close()" >/dev/null 2>&1 && return 0
		[ "$i" = 60 ] && { cat "$WORK"/*.err || true; fail "$2 never listened"; }
		sleep 0.2
	done
}
wait_socket() { # $1 = socket path, $2 = what, $3 = log to show on failure
	for i in $(seq 1 60); do
		[ -S "$1" ] && return 0
		[ "$i" = 60 ] && { cat "$3" >&2 || true; fail "$2 never appeared"; }
		sleep 0.2
	done
}
mode_of() { python3 -c 'import os, sys; print(oct(os.stat(sys.argv[1]).st_mode & 0o777))' "$1"; }
# field FILE TYPE KEY [STATUS]: print KEY of every TYPE event (optionally only
# those with STATUS) in a ledger, one per line.
field() {
	python3 - "$1" "$2" "$3" "${4:-}" <<'PY'
import json, sys
path, typ, key, status = sys.argv[1:5]
for line in open(path):
    if not line.strip():
        continue
    e = json.loads(line)
    if e.get("type") != typ or (status and e.get("status") != status):
        continue
    v = e.get(key, "")
    print(v if not isinstance(v, dict) else json.dumps(v))
PY
}
# count FILE TYPE [STATUS]: how many such events.
count() { field "$1" "$2" type "${3:-}" | wc -l | tr -d ' '; }
# reasons FILE: every non-empty reason a ledger records, one per line,
# DECODED, so a fixed reason carrying quotes is matched exactly.
reasons() {
	python3 - "$1" <<'PY'
import json, sys
for line in open(sys.argv[1]):
    if not line.strip():
        continue
    r = json.loads(line).get("reason", "")
    if r:
        print(r)
PY
}
# Output is captured into a variable before it is grepped, never piped
# straight in: under `set -o pipefail` a `grep -q` that matches early kills
# the writer with SIGPIPE and fails the pipeline — inverting a negative
# assertion, the one thing this script must never do.
out_of() { "$@" || true; }
has_line() { # $1 = text, $2 = exact line
	printf '%s\n' "$1" | grep -qxF -- "$2"
}
# has_event FILE TYPE: the ledger exists, is non-empty, and carries a TYPE
# event. Every absence check below runs this first.
has_event() {
	[ -s "$1" ] || fail "$1 is empty, so an absence check over it would prove nothing"
	grep -q "\"type\":\"$2\"" "$1" || fail "$1 carries no $2 event, so an absence check over it would prove nothing"
}

go build -o "$WORK/agenthof" ./cmd/agenthof
go build -o "$WORK/echo-agent" ./examples/echo-agent
go test -c -o "$WORK/refexec-stub" ./deploy/refexec
go test -c -o "$WORK/refspawn-stub" ./deploy/refspawn

NONCE="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
AGENT_PORT="$(free_port)"
IDP_PORT="$(free_port)"   # nothing ever listens here: the OBO child is refused before any exchange
mkdir -p "$WORK/ws"
"$WORK/echo-agent" -addr "127.0.0.1:$AGENT_PORT" -workspace "$WORK/ws" 2>"$WORK/agent.err" &
PIDS+=($!)
wait_port "$AGENT_PORT" "echo-agent"

# --- the supervisor stand-in: real refspawn, fake podman. Its "images" are
# the host echo-agent; its refexec is the refexec stand-in. Config is law
# here too: a config missing a key is refused before anything starts.
spawn_config() { # $1 = socket path, $2 = "no-images" to omit the images block, $3 = max_compartments
	cat <<EOF
socket: $1
spawn_root: $SPAWN_ROOT
EOF
	[ "${2:-}" = no-images ] || cat <<EOF
images:
  child: $WORK/echo-agent
  writer: $WORK/echo-agent
  reader: $WORK/echo-agent
EOF
	cat <<EOF
timeout: 10m
ready_timeout: 30s
limits:
  memory: 256m
  cpus: "1"
  pids: 64
max_compartments: ${3:-4}
refexec:
  command: [$WORK/refexec-stub, -refexec-test-stub]
  image: example.test/exec:1
  timeout: 30s
  limits:
    memory: 256m
    cpus: "1"
    pids: 64
  max_compartments: 2
  env_allow: []
EOF
}
spawn_config "$SUP_DIR/refspawn.sock" >"$WORK/refspawn.yaml"
spawn_config "$SUP_DIR/bad.sock" no-images >"$WORK/refspawn-bad.yaml"
if REFSPAWN_TEST_VOLROOT="$VOLROOT" "$WORK/refspawn-stub" -refspawn-test-stub -config "$WORK/refspawn-bad.yaml" >/dev/null 2>"$WORK/check.err"; then
	fail "a refspawn config without images was accepted"
fi
grep -q "images is required" "$WORK/check.err" || { cat "$WORK/check.err"; fail "the refusal did not name images"; }
REFSPAWN_TEST_VOLROOT="$VOLROOT" "$WORK/refspawn-stub" -refspawn-test-stub -config "$WORK/refspawn.yaml" 2>"$WORK/refspawn.err" &
PIDS+=($!)
wait_socket "$SUP_DIR/refspawn.sock" "the supervisor socket" "$WORK/refspawn.err"
[ "$(mode_of "$SUP_DIR/refspawn.sock")" = "0o600" ] || fail "supervisor socket is not mode 0600"

# Something that is not a supervisor, in a private directory of its own: it
# answers 200 and then a line that is not the pinned shape, so the client
# must refuse the answer instead of handing an agent whatever it names.
cat >"$WORK/badline.py" <<'PY'
import os, socket, sys
path = sys.argv[1]
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(path)
os.chmod(path, 0o600)
srv.listen(8)
held = []
while True:
    conn, _ = srv.accept()
    conn.recv(65536)
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\n\r\nnot-a-provision-line\n")
    held.append(conn)  # held open, the way a real lease would be
PY
python3 "$WORK/badline.py" "$BAD_DIR/refspawn.sock" 2>"$WORK/badline.err" &
PIDS+=($!)
wait_socket "$BAD_DIR/refspawn.sock" "the nonsense supervisor's socket" "$WORK/badline.err"

# The seven fixed reasons the door, the engine, the pre-run gate and the
# Spawner record, mirroring the Go constants. Each names ONE refusal mode;
# sole_reason below holds every refusal ledger to exactly its own.
R_NOT_ALLOWED="spawn target is not on the agent's may_spawn list"
R_DEPTH="spawn would exceed max_depth"
R_PARALLEL="spawn would exceed max_parallel"
R_TOTAL="spawn would exceed max_total_spawns"
R_OBO="obo requires a verified invoker token"
R_RBAC="role \"locked\" requires membership in one of its allowed groups (nobody); the invoker's groups don't qualify"
R_UNAVAILABLE="spawn compartment unavailable"
REASONS=("$R_NOT_ALLOWED" "$R_DEPTH" "$R_PARALLEL" "$R_TOTAL" "$R_OBO" "$R_RBAC" "$R_UNAVAILABLE")
for i in $(seq 0 6); do
	for j in $(seq 0 6); do
		if [ "$i" -lt "$j" ] && [ "${REASONS[$i]}" = "${REASONS[$j]}" ]; then
			fail "two refusal modes share one reason (${REASONS[$i]}), so no assertion below could tell them apart"
		fi
	done
done
# A child torn down with its parent refused nothing, so the door records
# either no reason or its own "did not complete" — never one of the seven.
R_INCOMPLETE="spawn did not complete"
for r in "${REASONS[@]}"; do
	[ "$r" != "$R_INCOMPLETE" ] || fail "a torn-down child and a refused one share one reason, so §8 could not tell them apart"
done
# sole_reason FILE WANT: the ledger records WANT, and no OTHER mode's reason.
sole_reason() {
	local got other
	got="$(reasons "$1")"
	[ -n "$got" ] || fail "$1 records no reason at all, so naming one proves nothing"
	if ! has_line "$got" "$2"; then
		printf '%s\n' "$got"
		fail "$1 does not record the fixed reason: $2"
	fi
	for other in "${REASONS[@]}"; do
		if [ "$other" != "$2" ] && has_line "$got" "$other"; then
			fail "$1 records another mode's reason ($other) beside its own ($2)"
		fi
	done
}
# no_reason FILE: the ledger records none of the fixed refusal reasons.
no_reason() {
	local got other
	got="$(reasons "$1")"
	for other in "${REASONS[@]}"; do
		if has_line "$got" "$other"; then
			fail "$1 records the refusal reason $other, but nothing there was refused"
		fi
	done
}

# The four distinct records the supervisor's client writes for the ONE fixed
# ledger reason above: the socket's directory is not private, the supervisor
# cannot be reached, it refused, or its answer is not the pinned shape. The
# ledger reason is deliberately the same for all four, so the operator's log
# is where they are told apart — and each is matched by substring, so none
# may contain another.
L_NOTPRIVATE="refspawn socket dir rejected"
L_UNREACHABLE="refspawn provision failed"
L_REFUSED="refspawn provision refused"
L_MALFORMED="refspawn answer malformed"
LOGLINES=("$L_NOTPRIVATE" "$L_UNREACHABLE" "$L_REFUSED" "$L_MALFORMED")
for i in $(seq 0 3); do
	for j in $(seq 0 3); do
		if [ "$i" != "$j" ] && [ "${LOGLINES[$i]#*"${LOGLINES[$j]}"}" != "${LOGLINES[$i]}" ]; then
			fail "one failure class's record (${LOGLINES[$j]}) is part of another's (${LOGLINES[$i]}), so no assertion below could tell them apart"
		fi
	done
done
# sole_log FILE WANT: FILE records WANT's failure class and none of the
# other three. FILE is one run's slice of the operational log (err_tail), so
# a class another run produced cannot be mistaken for this one's.
sole_log() {
	local other
	[ -s "$1" ] || fail "$1 is empty, so naming a failure class in it would prove nothing"
	grep -qF -- "$2" "$1" || { cat "$1"; fail "$1 does not record the failure class: $2"; }
	for other in "${LOGLINES[@]}"; do
		if [ "$other" != "$2" ] && grep -qF -- "$other" "$1"; then
			cat "$1"
			fail "$1 records another failure class ($other) beside its own ($2)"
		fi
	done
}
# One operational log carries every run, so err_mark remembers where it ends
# now and err_tail leaves just what the run since then wrote.
ERR_AT=0
err_mark() {
	[ -f "$WORK/agenthof.err" ] || : >"$WORK/agenthof.err"
	ERR_AT="$(wc -l <"$WORK/agenthof.err" | tr -d ' ')"
}
err_tail() { tail -n "+$((ERR_AT + 1))" "$WORK/agenthof.err" >"$WORK/tail.err"; }

# --- a hermetic Agenthof config, written from scratch. Child agents keep the
# host echo-agent's TCP endpoint in their YAML: under spawn it is ignored,
# the supervisor's sockets win — and that is asserted below.
write_config() { # $1 = dir, $2 = extra gateway.yaml lines, $3 = child may_spawn block ("" for none), $4 = supervisor url (default: the live one)
	local dir="$1" sup="${4:-unix://$SUP_DIR/refspawn.sock}"
	rm -rf "$dir"
	mkdir -p "$dir/agents" "$dir/workflows" "$dir/roles"
	cat >"$dir/gateway.yaml" <<EOF
models:
  fast:
    endpoint: http://127.0.0.1:9/v1
    model: fast
    api_key_env: AGENTHOF_GATEWAY_KEY
defaults:
  model: fast
tools:
  obo-tool:
    kind: mcp
    url: http://127.0.0.1:$IDP_PORT/
    credential_source: static_env
    grant_type: token_exchange
    client_auth: client_secret_basic
    token_endpoint: http://127.0.0.1:$IDP_PORT/token
    audience: https://obo-upstream.example
    client_id_env: OBO_CLIENT_ID
    client_secret_env: OBO_CLIENT_SECRET
spawn_supervisor: $sup
$2
EOF
	agent() { # $1 = name, $2 = extra agent lines
		cat >"$dir/agents/$1.yaml" <<EOF
name: $1
description: e2e agent $1
model: fast
instruction: Run the script.
output: output
execution: fronted
endpoint: http://127.0.0.1:$AGENT_PORT/
$2
EOF
	}
	agent lead "may_spawn:
  - role: worker
    workflow: child-wf
  - role: worker
    workflow: obo-wf
  - role: worker
    workflow: pair-wf
  - role: worker
    workflow: ghost-wf
  - role: locked
    workflow: locked-wf"
	agent child "$3"
	agent writer ""
	agent reader ""
	agent ghost ""
	agent obo-child "tools:
  - resource: obo-tool
    mode: all"
	wf() { # $1 = workflow, $2.. = agents, one step each
		local name="$1"
		shift
		{
			printf 'name: %s\ndescription: through %s\nsteps:\n' "$name" "$*"
			for a in "$@"; do printf '  - name: %s\n    agent: %s\n' "$a" "$a"; done
		} >"$dir/workflows/$name.yaml"
	}
	wf lead-wf lead
	wf child-wf child
	wf obo-wf obo-child
	wf locked-wf child
	wf pair-wf writer reader
	wf ghost-wf ghost
	cat >"$dir/roles/lead.yaml" <<EOF
name: lead
description: Runs the parent workflow
workflows: [lead-wf]
allowed_groups: ["devs"]
EOF
	cat >"$dir/roles/worker.yaml" <<EOF
name: worker
description: Runs child workflows
workflows: [child-wf, obo-wf, pair-wf, ghost-wf]
allowed_groups: ["devs"]
EOF
	cat >"$dir/roles/locked.yaml" <<EOF
name: locked
description: Nobody is in this group
workflows: [locked-wf]
allowed_groups: ["nobody"]
EOF
}
CAPS="spawn:
  max_depth: 2
  max_parallel: 2
  max_total_spawns: 3"
CHILD_RESPAWNS="may_spawn:
  - role: worker
    workflow: child-wf"
write_config "$WORK/config" "$CAPS" "$CHILD_RESPAWNS"
# Credentials go in the environment, never in argv: argv is world-readable
# in the process table.
export AGENTHOF_GATEWAY_KEY="host-side-dummy-key-$NONCE"
export OBO_CLIENT_ID=agenthof-broker
export OBO_CLIENT_SECRET="never-used-$NONCE"

"$WORK/agenthof" apply --config "$WORK/config" --control-log "$WORK/control.jsonl" --as ci --groups devs

# Config is law at apply: a cycle is rejected once reject_cycles is on, an
# acyclic graph passes, may_spawn with no caps is rejected, and may_spawn
# with no supervisor is rejected — with and without a gateway.yaml.
reject_apply() { # $1 = config dir, $2 = expected message fragment
	if "$WORK/agenthof" apply --config "$1" --control-log "$WORK/control.jsonl" --as ci --groups devs >"$WORK/apply-bad.out" 2>&1; then
		fail "apply accepted: $2"
	fi
	[ -s "$WORK/apply-bad.out" ] || fail "apply rejected $1 but said nothing"
	grep -q "$2" "$WORK/apply-bad.out" || { cat "$WORK/apply-bad.out"; fail "apply did not say: $2"; }
}
write_config "$WORK/cfg-cycle" "$CAPS
  reject_cycles: true" "$CHILD_RESPAWNS"
reject_apply "$WORK/cfg-cycle" "may_spawn graph has a cycle: child -> child"
write_config "$WORK/cfg-acyclic" "$CAPS
  reject_cycles: true" ""
"$WORK/agenthof" apply --config "$WORK/cfg-acyclic" --control-log "$WORK/control.jsonl" --as ci --groups devs >/dev/null || fail "an acyclic may_spawn graph must pass with reject_cycles on"
write_config "$WORK/cfg-nocaps" "" "$CHILD_RESPAWNS"
reject_apply "$WORK/cfg-nocaps" "must set spawn.max_depth"
write_config "$WORK/cfg-nosup" "$CAPS" "$CHILD_RESPAWNS"
sed -i.bak '/^spawn_supervisor:/d' "$WORK/cfg-nosup/gateway.yaml" && rm -f "$WORK/cfg-nosup/gateway.yaml.bak"
reject_apply "$WORK/cfg-nosup" "must set spawn_supervisor"
write_config "$WORK/cfg-nogw" "" "$CHILD_RESPAWNS"
rm "$WORK/cfg-nogw/gateway.yaml"
reject_apply "$WORK/cfg-nogw" "must set spawn.max_depth"
reject_apply "$WORK/cfg-nogw" "must set spawn_supervisor"
echo "apply: cycle rejected, acyclic accepted, missing caps and missing supervisor rejected — ok"

OUTS=()
run() { # $1 = config dir, $2 = role, $3 = workflow, $4 = input; sets OUT, RUNID, AUDIT
	OUT="$("$WORK/agenthof" run "$2" "$3" --input "$4" --as dana@example.com --groups devs \
		--config "$1" --log-dir "$WORK/logs" --artifact-dir "$WORK/artifacts" \
		--log-level debug 2>>"$WORK/agenthof.err" || true)"
	OUTS+=("$OUT")
	echo "$OUT"
	RUNID="$(echo "$OUT" | sed -E -n 's/^run (r-[a-f0-9]+) (finished|refused).*/\1/p')"
	[ -n "$RUNID" ] || fail "no run id in the output of $3"
	AUDIT="$("$WORK/agenthof" audit "$RUNID" --log-dir "$WORK/logs" --control-log "$WORK/control.jsonl" || true)"
	OUTS+=("$AUDIT")
	echo "$AUDIT"
	echo "$AUDIT" | grep -q "ledger integrity: verified" || fail "$3: ledger not verified"
}
ledger() { echo "$WORK/logs/$1.jsonl"; }
parent_artifact() { # $1 = run id: the full step artifact body
	local sha
	sha="$(field "$(ledger "$1")" step_succeeded artifact_sha | tail -1)"
	[ -n "$sha" ] || fail "run $1 has no step_succeeded artifact"
	[ -s "$WORK/artifacts/$sha" ] || fail "run $1 names artifact $sha, but the store holds no such body"
	cat "$WORK/artifacts/$sha"
}
# provisioned_count: how many sets the supervisor has provisioned so far,
# from its log; torn_down likewise. Together they prove nothing leaks.
provisioned_count() { out_of grep -c "set provisioned" "$WORK/refspawn.err"; }
torn_down_count() { out_of grep -c "set torn down" "$WORK/refspawn.err"; }
leftover_volumes() { find "$VOLROOT" -maxdepth 1 -name 'agenthof-spawn-*' -print; }
# nothing_left: no volume directory, no child directory and no set the
# supervisor has not taken back. The supervisor removes a set in its own
# process once the gateway hangs up, so this waits for that to land instead
# of racing it — and fails if it never does.
nothing_left() {
	for i in $(seq 1 60); do
		if [ -z "$(ls -A "$SPAWN_ROOT")" ] && [ -z "$(leftover_volumes)" ] &&
			[ "$(provisioned_count)" = "$(torn_down_count)" ]; then
			return 0
		fi
		[ "$i" = 60 ] && break
		sleep 0.25
	done
	ls -la "$SPAWN_ROOT" "$VOLROOT"
	fail "$1: the supervisor provisioned $(provisioned_count) sets and tore down $(torn_down_count), and something it made is still there"
}

# 1. A parent spawns a child that reports back. The child is a full governed
#    run of its own, linked both ways, under the same human — and it ran in
#    the compartment the supervisor provisioned, not at its configured
#    endpoint: the supervisor's log names the child's run id.
run "$WORK/config" lead lead-wf "spawn:worker/child-wf:hello-$NONCE"
echo "$OUT" | grep -q "finished: succeeded" || fail "the spawning run did not succeed"
PARENT="$RUNID"
[ "$(count "$(ledger "$PARENT")" spawn)" = 1 ] || fail "expected exactly one spawn event on the parent"
CHILD="$(field "$(ledger "$PARENT")" spawn child_run_id succeeded)"
[ -n "$CHILD" ] || fail "the parent's spawn event carries no child_run_id"
[ -f "$(ledger "$CHILD")" ] || fail "the child has no ledger of its own"
has_event "$(ledger "$CHILD")" workflow_started
grep -q "\"parent_run_id\":\"$PARENT\"" "$(ledger "$CHILD")" || fail "the child's binding does not name its parent"
grep -q '"depth":1' "$(ledger "$CHILD")" || fail "the child's binding is not at depth 1"
[ "$(field "$(ledger "$CHILD")" workflow_finished status)" = succeeded ] || fail "the child did not finish succeeded"
grep -q '"subject":"dana@example.com"' "$(ledger "$CHILD")" || fail "the child is not attributed to the same human"
has_event "$(ledger "$PARENT")" workflow_started
if grep -q "parent_run_id" "$(ledger "$PARENT")"; then fail "a root run's events must carry no parent_run_id"; fi
PARENT_ART="$(parent_artifact "$PARENT")"
echo "$PARENT_ART" | grep -q "spawn succeeded $CHILD hello-$NONCE" || fail "the child's preview did not reach the parent's artifact"
CHILD_SHA="$(field "$(ledger "$CHILD")" step_succeeded artifact_sha)"
[ -n "$CHILD_SHA" ] || fail "the child wrote no artifact"
[ "$(field "$(ledger "$PARENT")" spawn output_sha succeeded)" = "$CHILD_SHA" ] || fail "the spawn event's output_sha is not the child's artifact hash"
SPAWN_LINE="$(out_of grep '"type":"spawn"' "$(ledger "$PARENT")")"
echo "$SPAWN_LINE" | grep -q "$CHILD_SHA" || fail "the parent's spawn event does not carry the child's artifact hash"
if echo "$SPAWN_LINE" | grep -q "hello-$NONCE"; then fail "the child's artifact body reached the parent's spawn event"; fi
no_reason "$(ledger "$PARENT")"
grep -q "child=$CHILD" "$WORK/refspawn.err" || fail "the supervisor never provisioned a set under the child's run id"
grep -q "compartment started.*child=$CHILD.*compartment=agenthof-spawn-$CHILD-child" "$WORK/refspawn.err" || fail "the child's agent did not run in a compartment named for the child"
echo "$AUDIT" | grep -q "spawn worker/child-wf → run $CHILD succeeded (depth 1) — artifact ${CHILD_SHA:0:8}" || fail "audit did not render the spawn line"
CHILD_AUDIT="$(out_of "$WORK/agenthof" audit "$CHILD" --log-dir "$WORK/logs" --control-log "$WORK/control.jsonl")"
echo "$CHILD_AUDIT" | grep -q "ledger integrity: verified" || fail "the child's ledger does not verify"
TREE="$("$WORK/agenthof" investigate --run "$PARENT" --log-dir "$WORK/logs" --control-log "$WORK/control.jsonl")"
echo "$TREE" | grep -q "^[0-9].* run workflow_started — dana@example.com" || fail "investigate --run does not show the parent"
echo "$TREE" | grep -q "^  [0-9].* run workflow_started — dana@example.com .*parent=$PARENT" || fail "investigate --run does not show the child indented under its parent"
TREE_JSON="$("$WORK/agenthof" investigate --run "$PARENT" --json --log-dir "$WORK/logs" --control-log "$WORK/control.jsonl")"
echo "$TREE_JSON" | grep -q "\"parent_run_id\": \"$PARENT\"" || fail "the investigate JSON carries no parent_run_id"
nothing_left "after the first spawn"
echo "spawn: child ran in its compartment, reported back, linked both ways, same invoker, tree shown, set torn down — ok"

# 2. Parallel: three children at once under max_parallel 2. Two run
#    concurrently (their ledgers overlap in time), the third is refused
#    while they are in flight — and refusals do not count toward the total.
run "$WORK/config" lead lead-wf "spawn-parallel:3:worker/child-wf:sleep:2"
echo "$OUT" | grep -q "finished: succeeded" || fail "the parallel run did not succeed"
[ "$(count "$(ledger "$RUNID")" spawn succeeded)" = 2 ] || fail "expected 2 succeeded spawns"
[ "$(count "$(ledger "$RUNID")" spawn refused)" = 1 ] || fail "expected 1 refused spawn"
[ "$(field "$(ledger "$RUNID")" spawn reason refused)" = "$R_PARALLEL" ] || fail "the refusal is not the parallel cap"
sole_reason "$(ledger "$RUNID")" "$R_PARALLEL"
# shellcheck disable=SC2046  # run ids are hex and space-free: word-splitting them into two argv slots is the point
python3 - "$WORK/logs" $(field "$(ledger "$RUNID")" spawn child_run_id succeeded) <<'PY' || fail "the two children did not overlap in time (they ran one after another)"
import json, sys
from datetime import datetime
logs, a, b = sys.argv[1:4]
def parse(ts):
    # Go writes RFC3339 with up to nine fractional digits; parse by hand so
    # a Python older than 3.11 (macOS's bundled one) accepts it.
    base, _, frac = ts.rstrip("Z").partition(".")
    t = datetime.strptime(base, "%Y-%m-%dT%H:%M:%S")
    return t.replace(microsecond=int((frac + "000000")[:6]))
def span(run):
    ts = [parse(json.loads(l)["time"]) for l in open(f"{logs}/{run}.jsonl") if l.strip()]
    return min(ts), max(ts)
(a0, a1), (b0, b1) = span(a), span(b)
sys.exit(0 if a0 < b1 and b0 < a1 else 1)
PY
nothing_left "after the parallel run"
echo "parallel: two children overlapped in their own compartments, the third was refused atomically — ok"

# 3. The total cap: four sequential children under max_total_spawns 3.
run "$WORK/config" lead lead-wf "spawn:worker/child-wf:a; spawn:worker/child-wf:b; spawn:worker/child-wf:c; spawn:worker/child-wf:d"
[ "$(count "$(ledger "$RUNID")" spawn succeeded)" = 3 ] || fail "expected 3 succeeded spawns"
[ "$(field "$(ledger "$RUNID")" spawn reason refused)" = "$R_TOTAL" ] || fail "the fourth spawn was not refused by the total cap"
sole_reason "$(ledger "$RUNID")" "$R_TOTAL"
TOTAL_ART="$(parent_artifact "$RUNID")"
echo "$TOTAL_ART" | grep -qF "spawn refused - $R_TOTAL" || fail "the refusal did not reach the agent"
echo "total cap: 3 ran, the 4th refused — ok"

# 4. Nesting stops at max_depth 2: root(0) -> child(1) -> grandchild(2),
#    whose own spawn (depth 3) is refused and recorded on ITS ledger. The
#    grandchild was asked for through the child's gateway, which listens in
#    the child's own socket directory.
run "$WORK/config" lead lead-wf "spawn:worker/child-wf:spawn:worker/child-wf:spawn:worker/child-wf:deep-$NONCE"
echo "$OUT" | grep -q "finished: succeeded" || fail "the nested run did not succeed"
DEEP_ROOT="$RUNID"
C1="$(field "$(ledger "$DEEP_ROOT")" spawn child_run_id succeeded)"
[ -n "$C1" ] || fail "the nested chain did not reach depth 1"
C2="$(field "$(ledger "$C1")" spawn child_run_id succeeded)"
[ -n "$C2" ] || fail "the nested chain did not reach depth 2"
grep -q "\"parent_run_id\":\"$C1\"" "$(ledger "$C2")" || fail "the grandchild does not name the child as its parent"
grep -q '"depth":2' "$(ledger "$C2")" || fail "the grandchild is not at depth 2"
[ "$(count "$(ledger "$C2")" spawn refused)" = 1 ] || fail "the grandchild recorded no refused spawn"
[ "$(field "$(ledger "$C2")" spawn reason refused)" = "$R_DEPTH" ] || fail "the depth-3 spawn was not refused by the depth cap"
sole_reason "$(ledger "$C2")" "$R_DEPTH"
[ -z "$(field "$(ledger "$C2")" spawn child_run_id refused)" ] || fail "a depth refusal must start no child"
no_reason "$(ledger "$DEEP_ROOT")"
no_reason "$(ledger "$C1")"
grep -q "gateway listener started.*run=$C1.*network=unix" "$WORK/agenthof.err" || fail "the child's gateway did not listen on a Unix socket in its compartment's directory"
echo "$AUDIT" | grep -q "spawn worker/child-wf → run $C1 succeeded (depth 1)" || fail "audit did not render the nested spawn"
C2_AUDIT="$(out_of "$WORK/agenthof" audit "$C2" --log-dir "$WORK/logs" --control-log "$WORK/control.jsonl")"
echo "$C2_AUDIT" | grep -qF "spawn worker/child-wf → no child run refused (depth 3) — $R_DEPTH" || fail "the grandchild's audit did not render the depth refusal"
DEEP_TREE="$("$WORK/agenthof" investigate --run "$DEEP_ROOT" --log-dir "$WORK/logs" --control-log "$WORK/control.jsonl")"
echo "$DEEP_TREE" | grep -q "^    [0-9].* run workflow_started .*parent=$C1" || fail "investigate does not show the grandchild at depth 2"
nothing_left "after the nested run"
echo "nesting: depth 1 and 2 ran, depth 3 refused and recorded — ok"

# 5. Off may_spawn: refused by the door, nothing started, no child run id,
#    nothing provisioned.
BEFORE="$(provisioned_count)"
run "$WORK/config" lead lead-wf "spawn:lead/lead-wf:x"
OFFLIST="$RUNID"
[ "$(count "$(ledger "$OFFLIST")" spawn refused)" = 1 ] || fail "an off-list target was not refused"
[ "$(field "$(ledger "$OFFLIST")" spawn reason refused)" = "$R_NOT_ALLOWED" ] || fail "the off-list refusal is not the may_spawn one"
sole_reason "$(ledger "$OFFLIST")" "$R_NOT_ALLOWED"
[ -z "$(field "$(ledger "$OFFLIST")" spawn child_run_id refused)" ] || fail "an off-list refusal must start no child"
[ "$(provisioned_count)" = "$BEFORE" ] || fail "an off-list refusal provisioned a set"
echo "$AUDIT" | grep -qF "spawn lead/lead-wf → no child run refused (depth 1) — $R_NOT_ALLOWED" || fail "audit did not render the may_spawn refusal"

# 6. RBAC denies the child role: the door let the target through, the set
#    WAS provisioned (the engine refuses after the child has somewhere to
#    run), the ENGINE refused it, and the child has its own run_refused
#    ledger linked to the parent. The set is torn down like any other.
BEFORE="$(provisioned_count)"
run "$WORK/config" lead lead-wf "spawn:locked/locked-wf:x"
RBACRUN="$RUNID"
LOCKED="$(field "$(ledger "$RBACRUN")" spawn child_run_id refused)"
[ -n "$LOCKED" ] || fail "an RBAC-refused child must have its own run id"
[ "$(count "$(ledger "$LOCKED")" run_refused)" = 1 ] || fail "the refused child has no run_refused event"
grep -q "\"parent_run_id\":\"$RBACRUN\"" "$(ledger "$LOCKED")" || fail "the refused child does not name its parent"
[ "$(field "$(ledger "$LOCKED")" run_refused reason)" = "$R_RBAC" ] || fail "the child's refusal is not the engine's RBAC one"
sole_reason "$(ledger "$LOCKED")" "$R_RBAC"
sole_reason "$(ledger "$RBACRUN")" "$R_RBAC"
[ "$(provisioned_count)" = $((BEFORE + 1)) ] || fail "an RBAC-refused child is refused AFTER provisioning; its set must have been provisioned once"
nothing_left "after the RBAC refusal"
echo "$AUDIT" | grep -q "spawn locked/locked-wf → run $LOCKED refused (depth 1) — role \"locked\" requires membership" || fail "audit did not render the RBAC refusal"

# 7. A child fronting an on-behalf-of resource under a --as invoker is
#    refused BEFORE its engine starts, with the fixed reason; the exchange
#    endpoint (which nothing listens on) is never contacted, and nothing is
#    provisioned.
if python3 -c "import socket; socket.create_connection(('127.0.0.1', $IDP_PORT), 1).close()" >/dev/null 2>&1; then
	fail "something is listening on the OBO token endpoint's port, so \"never contacted\" would prove nothing"
fi
BEFORE="$(provisioned_count)"
run "$WORK/config" lead lead-wf "spawn:worker/obo-wf:x"
OBORUN="$RUNID"
OBO="$(field "$(ledger "$OBORUN")" spawn child_run_id refused)"
[ -n "$OBO" ] || fail "the OBO child must have its own run id"
[ "$(count "$(ledger "$OBO")" run_refused)" = 1 ] || fail "the OBO child has no run_refused event"
[ "$(field "$(ledger "$OBO")" run_refused reason)" = "$R_OBO" ] || fail "the OBO child's refusal is not the fixed pre-run reason"
sole_reason "$(ledger "$OBO")" "$R_OBO"
sole_reason "$(ledger "$OBORUN")" "$R_OBO"
# The run_refused event asserted above is what makes this absence a real
# absence: the ledger is populated, and what is missing from it is the
# workflow.
if grep -q '"type":"workflow_started"\|"type":"step_' "$(ledger "$OBO")"; then fail "a pre-run refusal must start no workflow and no step"; fi
grep -q "\"parent_run_id\":\"$OBORUN\"" "$(ledger "$OBO")" || fail "the OBO child does not name its parent"
[ "$(provisioned_count)" = "$BEFORE" ] || fail "a pre-run refusal must provision nothing"
echo "refusals: off-list, RBAC (after provisioning), and OBO pre-run (before it) — each recorded under its own reason — ok"

# The four refusal ledgers, side by side: each carries its own fixed reason
# and none of the others, so a reader can tell which door said no.
[ "$(reasons "$(ledger "$OFFLIST")" | sort -u | wc -l | tr -d ' ')" = 1 ] || fail "the off-list run records more than one reason"
[ "$(reasons "$(ledger "$LOCKED")" | sort -u | wc -l | tr -d ' ')" = 1 ] || fail "the RBAC-refused child records more than one reason"
[ "$(reasons "$(ledger "$OBO")" | sort -u | wc -l | tr -d ' ')" = 1 ] || fail "the OBO-refused child records more than one reason"
[ "$(reasons "$(ledger "$C2")" | sort -u | wc -l | tr -d ' ')" = 1 ] || fail "the depth-refused grandchild records more than one reason"

# 8. Parent-linked teardown: a 2s step timeout on the parent tears down a
#    child that would sleep 60s, with bounded latency; the supervisor sees
#    the lease close and removes the set. The child refused nothing — it
#    was killed — so neither ledger names any of the refusal reasons.
write_config "$WORK/cfg-fast" "$CAPS
step_timeout: 2s" "$CHILD_RESPAWNS"
START="$(date +%s)"
run "$WORK/cfg-fast" lead lead-wf "spawn:worker/child-wf:sleep:60"
ELAPSED=$(( $(date +%s) - START ))
echo "$OUT" | grep -q "finished: failed" || fail "a parent step past its deadline must fail"
[ "$ELAPSED" -le 20 ] || fail "teardown took ${ELAPSED}s; the child must die with its parent step, not sleep on"
SLOW="$(field "$(ledger "$RUNID")" spawn child_run_id failed)"
[ -n "$SLOW" ] || fail "the torn-down child was not recorded on the parent"
[ "$(count "$(ledger "$SLOW")" workflow_finished)" = 1 ] || fail "the torn-down child has no workflow_finished (its ledger was left open)"
[ "$(field "$(ledger "$SLOW")" workflow_finished status)" != succeeded ] || fail "a torn-down child must not succeed"
no_reason "$(ledger "$RUNID")"
no_reason "$(ledger "$SLOW")"
# The one thing a torn-down child's spawn event may say besides nothing.
TORN_REASON="$(field "$(ledger "$RUNID")" spawn reason failed)"
case "$TORN_REASON" in
	"" | "$R_INCOMPLETE") ;;
	*) fail "a child torn down with its parent recorded the refusal reason: $TORN_REASON" ;;
esac
for i in $(seq 1 40); do
	grep -q "set torn down.*child=$SLOW" "$WORK/refspawn.err" && break
	[ "$i" = 40 ] && fail "the supervisor never tore down the torn-down child's set"
	sleep 0.5
done
nothing_left "after the teardown"
echo "teardown: parent step timeout tore the child down in ${ELAPSED}s and the supervisor removed its set — ok"

# 9. Fail-closed: four ways a child can end up with no compartments. Every
#    spawn is refused with the ONE fixed compartment reason, no child
#    exists, and the total is NOT burned — four attempts under
#    max_total_spawns 3 all record the compartment reason, never the total
#    cap. Which of the four it was is in the operator's log, not the
#    ledger: the run's own slice of that log names its class and no other.
unavailable_run() { # $1 = config dir, $2 = the failure class expected in the operational log
	local before
	err_mark
	before="$(provisioned_count)"
	run "$1" lead lead-wf "spawn:worker/child-wf:a; spawn:worker/child-wf:b; spawn:worker/child-wf:c; spawn:worker/child-wf:d"
	err_tail
	echo "$OUT" | grep -q "finished: succeeded" || fail "the parent step reports the refusals and still finishes"
	[ "$(count "$(ledger "$RUNID")" spawn refused)" = 4 ] || fail "expected 4 refused spawns with no usable supervisor"
	[ "$(count "$(ledger "$RUNID")" spawn succeeded)" = 0 ] || fail "a child ran with no usable supervisor"
	sole_reason "$(ledger "$RUNID")" "$R_UNAVAILABLE"
	[ -z "$(field "$(ledger "$RUNID")" spawn child_run_id refused)" ] || fail "a fail-closed refusal must start no child"
	[ "$(provisioned_count)" = "$before" ] || fail "the live supervisor was asked although the config names another"
	sole_log "$WORK/tail.err" "$2"
	echo "$AUDIT" | grep -qF "spawn worker/child-wf → no child run refused (depth 1) — $R_UNAVAILABLE" || fail "audit did not render the fail-closed refusal"
}
write_config "$WORK/cfg-dead" "$CAPS" "$CHILD_RESPAWNS" "unix://$DEAD_DIR/nobody.sock"
"$WORK/agenthof" apply --config "$WORK/cfg-dead" --control-log "$WORK/control.jsonl" --as ci --groups devs >/dev/null || fail "apply rejected a config naming a socket that is not there; whether the supervisor answers is a run-time fact"
[ ! -e "$DEAD_DIR/nobody.sock" ] || fail "something is listening where nothing should, so \"unreachable\" would prove nothing"
unavailable_run "$WORK/cfg-dead" "$L_UNREACHABLE"
write_config "$WORK/cfg-open" "$CAPS" "$CHILD_RESPAWNS" "unix://$OPEN_DIR/refspawn.sock"
"$WORK/agenthof" apply --config "$WORK/cfg-open" --control-log "$WORK/control.jsonl" --as ci --groups devs >/dev/null || fail "apply rejected a config naming a world-readable directory; its mode is measured when it is dialled"
[ "$(mode_of "$OPEN_DIR")" = "0o755" ] || fail "the open directory is not 0755, so refusing to dial in it would prove nothing"
unavailable_run "$WORK/cfg-open" "$L_NOTPRIVATE"
write_config "$WORK/cfg-badline" "$CAPS" "$CHILD_RESPAWNS" "unix://$BAD_DIR/refspawn.sock"
"$WORK/agenthof" apply --config "$WORK/cfg-badline" --control-log "$WORK/control.jsonl" --as ci --groups devs >/dev/null || fail "apply rejected a config naming a supervisor it has not dialled"
[ -S "$BAD_DIR/refspawn.sock" ] || fail "nothing is listening in the private directory, so a malformed ANSWER would prove nothing"
unavailable_run "$WORK/cfg-badline" "$L_MALFORMED"
echo "fail-closed: an absent, a world-readable and a nonsense supervisor each refuse every spawn with the one fixed reason, start no child and burn no total — ok"

# 10. An agent the supervisor has no image for: refused at provision time by
#     the supervisor itself (the fourth failure class), nothing started,
#     total not burned (the three later spawns still fit).
BEFORE="$(provisioned_count)"
err_mark
run "$WORK/config" lead lead-wf "spawn:worker/ghost-wf:x; spawn:worker/child-wf:a; spawn:worker/child-wf:b; spawn:worker/child-wf:c"
err_tail
[ "$(count "$(ledger "$RUNID")" spawn refused)" = 1 ] || fail "expected the ghost spawn refused"
[ "$(field "$(ledger "$RUNID")" spawn reason refused)" = "$R_UNAVAILABLE" ] || fail "the no-image refusal is not the compartment reason"
[ "$(count "$(ledger "$RUNID")" spawn succeeded)" = 3 ] || fail "the three later children must all fit under max_total_spawns 3: the ghost refusal must not count"
sole_reason "$(ledger "$RUNID")" "$R_UNAVAILABLE"
sole_log "$WORK/tail.err" "$L_REFUSED"
[ "$(provisioned_count)" = $((BEFORE + 3)) ] || fail "the ghost must not have been provisioned"
grep -q "provision refused.*reason=\"no image for agent\".*agent=ghost" "$WORK/refspawn.err" || fail "the supervisor did not log the no-image refusal"
nothing_left "after the ghost refusal"
echo "no image: the supervisor refused fail-closed before anything started, total not burned — ok"

# 11. Isolation, hermetically: a multi-agent child's two agents share the
#     child's one workspace (the writer's note is what the reader reads),
#     a second child gets a fresh one (it reads absent), and neither note
#     reached the parent's own workspace.
run "$WORK/config" lead lead-wf "spawn:worker/pair-wf:only:writer:write:shared-$NONCE | only:reader:read:"
echo "$OUT" | grep -q "finished: succeeded" || fail "the pair run did not succeed"
PAIR="$(field "$(ledger "$RUNID")" spawn child_run_id succeeded)"
[ "$(count "$(ledger "$PAIR")" step_succeeded)" = 2 ] || fail "the pair child did not run both steps"
PAIR_ART="$(parent_artifact "$RUNID")"
echo "$PAIR_ART" | grep -q "spawn succeeded $PAIR shared-$NONCE" || fail "the reader did not see the writer's note: the child's agents do not share its workspace"
grep -q "compartment started.*child=$PAIR.*compartment=agenthof-spawn-$PAIR-writer" "$WORK/refspawn.err" || fail "no writer compartment for the pair child"
grep -q "compartment started.*child=$PAIR.*compartment=agenthof-spawn-$PAIR-reader" "$WORK/refspawn.err" || fail "no reader compartment for the pair child"
run "$WORK/config" lead lead-wf "spawn:worker/child-wf:read:"
FRESH_ART="$(parent_artifact "$RUNID")"
echo "$FRESH_ART" | grep -q "spawn succeeded r-[0-9a-f]* absent" || fail "a new child must start on a fresh workspace"
[ ! -e "$WORK/ws/agent-note.txt" ] || fail "a child's note reached the parent's workspace"
# The same workspace, written and listed through the same host agent: a note
# of the parent's own lands at exactly the path checked above, which is what
# makes that absence an empty workspace and not an unreachable directory.
run "$WORK/config" lead lead-wf "write:probe-$NONCE; ls:"
PROBE_ART="$(parent_artifact "$RUNID")"
echo "$PROBE_ART" | grep -qx "agent-note.txt" || { echo "$PROBE_ART"; fail "the parent's own write does not show in its own listing"; }
[ -e "$WORK/ws/agent-note.txt" ] || fail "the parent's note is not at the path the absence above searched, so that absence proved nothing"
nothing_left "after the isolation runs"
echo "isolation: one workspace per child, shared by that child's agents, fresh per child, invisible to the parent — ok"

# 12. Nothing that must not leak did. An absence proves something only where
#     the places searched are populated and the same search finds what IS
#     there, so a positive control runs through the identical grep first.
[ "$(find "$WORK/logs" -name '*.jsonl' | wc -l | tr -d ' ')" -ge 25 ] || fail "fewer ledgers than runs, so the leak checks would search an incomplete tree"
[ -s "$WORK/agenthof.err" ] || fail "the operational log is empty, so the leak checks would search nothing"
grep -q "level=DEBUG" "$WORK/agenthof.err" || fail "the operational log carries no debug records"
grep -rqF "hello-$NONCE" "$WORK/logs" "$WORK/artifacts" "$WORK/agenthof.err" || fail "the positive control is missing, so the identical search for the secret would prove nothing"
if grep -rqF "never-used-$NONCE" "$WORK/logs" "$WORK/artifacts" "$WORK/agenthof.err" "$WORK/refspawn.err"; then fail "the client secret reached a ledger, artifact or log"; fi
# Written to a file, not piped: once the captured output outgrows the pipe
# buffer, a grep -q that matches early would SIGPIPE the writer and fail the
# pipeline under pipefail — reporting "no match" exactly when there is one.
printf '%s\n' "${OUTS[@]}" >"$WORK/outs.txt"
[ -s "$WORK/outs.txt" ] || fail "nothing agenthof printed was captured, so the search below would prove nothing"
grep -qF "spawn worker/child-wf" "$WORK/outs.txt" || fail "no captured output names a spawn, so the search below would prove nothing"
if grep -qF "never-used-$NONCE" "$WORK/outs.txt"; then fail "the client secret reached agenthof's output"; fi
echo "e2e-refspawn-local: PASS"
