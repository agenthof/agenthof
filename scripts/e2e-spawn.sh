#!/usr/bin/env bash
# e2e-spawn: prove per-child isolation end to end with real rootless podman.
# The root run's agent runs in a refbox compartment; refspawn runs on the
# host and, per spawned child, creates one workspace volume, one refbox
# compartment per agent in the child's workflow (both mounting that volume
# at /work) and one refexec bound to it. Asserts: a two-agent child shares
# its one workspace (the writer's note is what the reader reads — on the
# file path through the agents, and on the exec path through the child's
# own refexec); two parallel sibling children each see only their own file
# in /work, through the agents and through exec; a child's note never
# reaches the parent's workspace; each compartment runs the image the
# supervisor maps its agent to; a child compartment mounts exactly the
# child's volume and the child's socket directory, cannot reach the child's
# refexec socket, and has no network; an agent with no image is refused
# before anything starts; the supervisor's compartment cap refuses a set
# that will not fit; and after the parent finishes no container, volume,
# directory or refexec process the supervisor made is left. The two ways a
# set is refused share one ledger reason on purpose, so they are told apart
# by the distinct record the supervisor writes for each, over only the lines
# that run produced. Requires rootless podman, go and python3. Run from the
# repo root (or through deploy/lima/lima.sh e2e spawn).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
	echo "e2e-spawn: FAIL — $*"
	exit 1
}
# Checked before anything is created, so there is nothing to clean up: this
# e2e is about the real runtime's isolation and has no meaning without it.
command -v podman >/dev/null || fail "podman is not installed; this e2e proves isolation with the real runtime. Run it on a Linux host with rootless podman (CI does), or through 'deploy/lima/lima.sh e2e spawn' on macOS. The hermetic governance e2e is scripts/e2e-spawn-local.sh."

IMAGE="${REFBOX_IMAGE:-refbox-echo:test}"
IMAGE_B="refbox-echo-b:test"
LEAD="refbox-lead"
EXEC_IMAGE="${REFEXEC_IMAGE:-docker.io/library/busybox:1.36.1}"

SOCK_DIR="$(mktemp -d)"                    # the ROOT run's gateway + agent socket dir, mounted into the lead's refbox
export AGENTHOF_REFBOX_SOCKET_DIR="$SOCK_DIR"
SUP_DIR="$(mktemp -d /tmp/sp.XXXXXX)"      # refspawn's socket dir (0700); never mounted anywhere
SPAWN_ROOT="$(mktemp -d /tmp/sp.XXXXXX)"   # per-child dirs; <id> is mounted into that child only, <id>-exec never
WORK="$(mktemp -d)"
REFSPAWN_PID=""
ALIVE=""
cleanup() {
	if [ -n "$ALIVE" ]; then
		kill "$ALIVE" >/dev/null 2>&1 || true
		wait "$ALIVE" >/dev/null 2>&1 || true
	fi
	podman rm -f "$LEAD" >/dev/null 2>&1 || true
	if [ -n "$REFSPAWN_PID" ]; then
		kill "$REFSPAWN_PID" >/dev/null 2>&1 || true
		wait "$REFSPAWN_PID" >/dev/null 2>&1 || true
	fi
	podman ps -aq --filter 'name=^agenthof-spawn-' | xargs -r podman rm -f >/dev/null 2>&1 || true
	podman ps -aq --filter 'name=^refexec-' | xargs -r podman rm -f >/dev/null 2>&1 || true
	podman volume ls -q --filter 'name=^agenthof-spawn-' | xargs -r podman volume rm -f >/dev/null 2>&1 || true
	rm -rf "$SOCK_DIR" "$SUP_DIR" "$SPAWN_ROOT" "$WORK"
}
trap cleanup EXIT
unset AGENTHOF_TOKEN || true

# Build and pull everything BEFORE anything starts: the compartments' wall
# clocks must not pay for a cold build or a pull. refspawn and refexec run
# podman with --pull=never, so every image is fetched here, by the operator.
# The second agent image is the same recipe under a second tag with a label:
# what it proves is that refspawn runs each agent in the image its map
# names, which the ImageName of each compartment shows below.
go build -o "$WORK/agenthof" ./cmd/agenthof
go build -o "$WORK/refexec" ./deploy/refexec
go build -o "$WORK/refspawn" ./deploy/refspawn
podman build -f deploy/refbox/Containerfile -t "$IMAGE" .
podman build -f deploy/refbox/Containerfile --label agenthof.e2e.agent=reader -t "$IMAGE_B" .
podman pull "$EXEC_IMAGE" >/dev/null

# refspawn's config: the two agent images, a compartment cap of 3 (a pair
# plus one), and the refexec template.
cat >"$WORK/refspawn.yaml" <<EOF
socket: $SUP_DIR/refspawn.sock
spawn_root: $SPAWN_ROOT
images:
  writer: $IMAGE
  reader: $IMAGE_B
timeout: 5m
ready_timeout: 60s
limits:
  memory: 256m
  cpus: "1"
  pids: 64
max_compartments: 3
refexec:
  command: [$WORK/refexec]
  image: $EXEC_IMAGE
  timeout: 60s
  limits:
    memory: 256m
    cpus: "1"
    pids: 64
  max_compartments: 2
  env_allow: []
EOF
"$WORK/refspawn" -config "$WORK/refspawn.yaml" -check >/dev/null || fail "refspawn rejected its config"
"$WORK/refspawn" -config "$WORK/refspawn.yaml" 2>"$WORK/refspawn.err" &
REFSPAWN_PID=$!
for i in $(seq 1 30); do
	[ -S "$SUP_DIR/refspawn.sock" ] && break
	[ "$i" = 30 ] && { cat "$WORK/refspawn.err" >&2; fail "refspawn socket never appeared"; }
	sleep 0.5
done
[ "$(stat -c %a "$SUP_DIR/refspawn.sock")" = 600 ] || fail "refspawn socket is not mode 0600"
[ "$(stat -c %a "$SUP_DIR")" = 700 ] || fail "refspawn socket dir is not 0700"

# The root run's agent, in its own refbox (an ephemeral tmpfs workspace).
REFBOX_DETACH=1 REFBOX_IMAGE="$IMAGE" REFBOX_NAME="$LEAD" REFBOX_TIMEOUT=1500 deploy/refbox/refbox-run.sh >/dev/null
for i in $(seq 1 30); do
	[ -S "$SOCK_DIR/refbox-echo.sock" ] && break
	[ "$i" = 30 ] && { podman logs "$LEAD" || true; fail "lead agent socket never appeared"; }
	sleep 1
done

# The Agenthof config: the lead may spawn the pair, the single and the
# ghost workflows; child agents' endpoint and exec.url are placeholders
# (under spawn the supervisor's sockets win); the workflow step names are
# the agents' so `only:` scripts read naturally.
mkdir -p "$WORK/config/agents" "$WORK/config/workflows" "$WORK/config/roles"
cat >"$WORK/config/gateway.yaml" <<EOF
refbox_socket_dir: $SOCK_DIR
spawn_supervisor: unix://$SUP_DIR/refspawn.sock
spawn:
  max_depth: 2
  max_parallel: 2
  max_total_spawns: 6
step_timeout: 3m
models:
  fast:
    endpoint: http://localhost:4000
    model: fast
    api_key_env: AGENTHOF_GATEWAY_KEY
defaults:
  model: fast
EOF
cat >"$WORK/config/agents/lead.yaml" <<EOF
name: lead
description: the root run's agent, in a refbox
model: fast
instruction: Run the script.
output: output
execution: fronted
endpoint: unix://$SOCK_DIR/refbox-echo.sock
may_spawn:
  - role: worker
    workflow: pair-wf
  - role: worker
    workflow: one-wf
  - role: worker
    workflow: ghost-wf
EOF
for a in writer reader; do
	cat >"$WORK/config/agents/$a.yaml" <<EOF
name: $a
description: a child agent, in its child's compartment
model: fast
instruction: Run the script.
output: output
execution: fronted
endpoint: unix:///run/agenthof/placeholder.sock
exec:
  mode: runtime
  runtime: refexec
  url: unix:///run/agenthof-exec/placeholder.sock
  timeout: 60s
  allow:
    - exe: cat
    - exe: cp
    - exe: ls
EOF
done
cat >"$WORK/config/agents/ghost.yaml" <<EOF
name: ghost
description: an agent the supervisor has no image for
model: fast
instruction: Never runs.
output: output
execution: fronted
endpoint: unix:///run/agenthof/placeholder.sock
EOF
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
wf ghost-wf ghost
cat >"$WORK/config/roles/lead.yaml" <<EOF
name: lead
description: Runs the parent workflow
workflows: [lead-wf]
allowed_groups: ["refbox-users"]
EOF
cat >"$WORK/config/roles/worker.yaml" <<EOF
name: worker
description: Runs child workflows
workflows: [pair-wf, one-wf, ghost-wf]
allowed_groups: ["refbox-users"]
EOF
NONCE="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
# Credentials go in the environment, never in argv: argv is world-readable
# in the process table. The model route is never called; the key only lets
# it resolve.
export AGENTHOF_GATEWAY_KEY="host-side-dummy-key-$NONCE"
R_UNAVAILABLE="spawn compartment unavailable"
# The two refusals below share that one ledger reason — an agent learns
# nothing about the operator's runtime from it — so the supervisor's own
# record is what tells them apart, and neither text may contain the other.
S_NO_IMAGE="no image for agent"
S_CAP="compartment cap reached"
case "$S_NO_IMAGE" in *"$S_CAP"*) fail "the two provision refusals share a record, so no assertion below could tell them apart" ;; esac
case "$S_CAP" in *"$S_NO_IMAGE"*) fail "the two provision refusals share a record, so no assertion below could tell them apart" ;; esac

"$WORK/agenthof" apply --config "$WORK/config" --control-log "$WORK/control.jsonl" --as ci --groups refbox-users

run() { # $1 = input; sets OUT, RUNID, AUDIT
	OUT="$("$WORK/agenthof" run lead lead-wf --input "$1" \
		--as ci --groups refbox-users --config "$WORK/config" \
		--log-dir "$WORK/logs" --artifact-dir "$WORK/artifacts" --log-level debug 2>>"$WORK/agenthof.err" || true)"
	echo "$OUT"
	RUNID="$(echo "$OUT" | sed -n 's/^run \(r-[a-f0-9]*\) finished.*/\1/p')"
	[ -n "$RUNID" ] || { podman logs "$LEAD" || true; cat "$WORK/refspawn.err" || true; fail "no run id"; }
	AUDIT="$("$WORK/agenthof" audit "$RUNID" --log-dir "$WORK/logs" --control-log "$WORK/control.jsonl")"
	echo "$AUDIT"
	echo "$AUDIT" | grep -q "ledger integrity: verified" || fail "ledger not verified"
}
ledger() { echo "$WORK/logs/$1.jsonl"; }
field() { # FILE TYPE KEY [STATUS]
	python3 - "$1" "$2" "$3" "${4:-}" <<'PY'
import json, sys
path, typ, key, status = sys.argv[1:5]
for line in open(path):
    if not line.strip():
        continue
    e = json.loads(line)
    if e.get("type") != typ or (status and e.get("status") != status):
        continue
    print(e.get(key, ""))
PY
}
count() { field "$1" "$2" type "${3:-}" | wc -l | tr -d ' '; }
parent_artifact() { # $1 = run id
	local sha
	sha="$(field "$(ledger "$1")" step_succeeded artifact_sha | tail -1)"
	[ -n "$sha" ] || fail "run $1 has no step_succeeded artifact"
	[ -s "$WORK/artifacts/$sha" ] || fail "run $1 names artifact $sha, but the store holds no such body"
	cat "$WORK/artifacts/$sha"
}
# One supervisor log carries every run, so sup_mark remembers where it ends
# now and sup_tail leaves just what the run since then wrote — the only way
# one provision refusal can be told from another's in the same file.
SUP_AT=0
sup_mark() { SUP_AT="$(wc -l <"$WORK/refspawn.err" | tr -d ' ')"; }
sup_tail() { tail -n "+$((SUP_AT + 1))" "$WORK/refspawn.err" >"$WORK/sup-tail.err"; }
# sole_refusal WANT OTHER: the records that run produced name WANT's
# refusal and not OTHER's.
sole_refusal() {
	[ -s "$WORK/sup-tail.err" ] || fail "the supervisor recorded nothing for that run, so naming its refusal would prove nothing"
	grep -qF -- "provision refused" "$WORK/sup-tail.err" || { cat "$WORK/sup-tail.err"; fail "the supervisor recorded no provision refusal"; }
	grep -qF -- "$1" "$WORK/sup-tail.err" || { cat "$WORK/sup-tail.err"; fail "the supervisor did not record: $1"; }
	if grep -qF -- "$2" "$WORK/sup-tail.err"; then
		cat "$WORK/sup-tail.err"
		fail "the supervisor recorded the other refusal ($2) beside its own ($1)"
	fi
}
# Teardown is asynchronous from the parent's side by design: the held request
# closes and the parent's run ends, while the supervisor removes the set it
# made in order afterwards. So the check waits for the whole set to be gone,
# bounded at 30 s, and only then says what is left.
nothing_left() {
	local i
	for i in $(seq 1 60); do
		if [ -z "$(podman ps -aq --filter 'name=^agenthof-spawn-')" ] &&
			[ -z "$(podman ps -aq --filter 'name=^refexec-')" ] &&
			[ -z "$(podman volume ls -q --filter 'name=^agenthof-spawn-')" ] &&
			[ -z "$(ls -A "$SPAWN_ROOT")" ] &&
			! pgrep -f "refexec -config $SPAWN_ROOT" >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.5
	done
	[ -z "$(podman ps -aq --filter 'name=^agenthof-spawn-')" ] || { podman ps -a --filter 'name=^agenthof-spawn-'; fail "$1: a child compartment outlived the run"; }
	[ -z "$(podman ps -aq --filter 'name=^refexec-')" ] || { podman ps -a --filter 'name=^refexec-'; fail "$1: an exec compartment outlived the run"; }
	[ -z "$(podman volume ls -q --filter 'name=^agenthof-spawn-')" ] || { podman volume ls --filter 'name=^agenthof-spawn-'; fail "$1: a child volume outlived the run"; }
	[ -z "$(ls -A "$SPAWN_ROOT")" ] || { ls -la "$SPAWN_ROOT"; fail "$1: the spawn root is not empty"; }
	if pgrep -f "refexec -config $SPAWN_ROOT" >/dev/null 2>&1; then pgrep -fl "refexec -config $SPAWN_ROOT"; fail "$1: a child's refexec outlived the run"; fi
}

# 1. A two-agent child: the writer writes /work on the FILE path, the
#    reader (a different agent, a different image, the same child volume)
#    reads it back. The child's preview is the note.
run "spawn:worker/pair-wf:only:writer:write:shared-$NONCE | only:reader:read:"
echo "$OUT" | grep -q "finished: succeeded" || { cat "$WORK/refspawn.err"; fail "the pair run did not succeed"; }
PAIR="$(field "$(ledger "$RUNID")" spawn child_run_id succeeded)"
[ -n "$PAIR" ] || fail "no child run id"
[ "$(count "$(ledger "$PAIR")" step_succeeded)" = 2 ] || fail "the pair child did not run both steps"
PAIR_ART="$(parent_artifact "$RUNID")"
echo "$PAIR_ART" | grep -q "spawn succeeded $PAIR shared-$NONCE" || fail "the reader did not see the writer's note: the child's two agents do not share one workspace"
grep -q "\"parent_run_id\":\"$RUNID\"" "$(ledger "$PAIR")" || fail "the child does not name its parent"
if grep -q "\"parent_run_id\":\"$PAIR\"" "$(ledger "$PAIR")"; then fail "a child's own binding must name its PARENT, not itself"; fi
grep -q "compartment started.*child=$PAIR.*compartment=agenthof-spawn-$PAIR-writer" "$WORK/refspawn.err" || fail "no writer compartment"
grep -q "compartment started.*child=$PAIR.*compartment=agenthof-spawn-$PAIR-reader" "$WORK/refspawn.err" || fail "no reader compartment"
nothing_left "after the pair run"
echo "multi-agent child: two agents, two images, one shared workspace — ok"

# 2. Two parallel siblings: each creates a file named for its own run in
#    /work, waits so both are alive at once, and lists /work. Each sees
#    exactly its own file: the volumes are distinct. Also on the EXEC path:
#    the child's refexec lists the child's volume.
run "spawn-parallel:2:worker/one-wf:touch-run: | sleep:3 | ls:"
echo "$OUT" | grep -q "finished: succeeded" || fail "the parallel run did not succeed"
[ "$(count "$(ledger "$RUNID")" spawn succeeded)" = 2 ] || fail "expected two succeeded siblings"
ART="$(parent_artifact "$RUNID")"
for c in $(field "$(ledger "$RUNID")" spawn child_run_id succeeded); do
	echo "$ART" | grep -qx "spawn succeeded $c $c.txt" || { echo "$ART"; fail "sibling $c saw more than its own file in /work (file path)"; }
done
# The supervisor's slots are freed only when that run's set is gone, and the
# cap is 3: without this the next pair of siblings could be refused for want
# of a compartment the run above has not finished releasing.
nothing_left "after the sibling file-path run"
run "spawn-parallel:2:worker/one-wf:touch-run: | sleep:3 | exec-run:ls /work"
echo "$OUT" | grep -q "finished: succeeded" || fail "the parallel exec run did not succeed"
ART="$(parent_artifact "$RUNID")"
for c in $(field "$(ledger "$RUNID")" spawn child_run_id succeeded); do
	echo "$ART" | grep -qx "spawn succeeded $c $c.txt" || { echo "$ART"; fail "sibling $c's refexec saw more than its own file in /work (exec path)"; }
	grep -q '"mode":"runtime"' "$(ledger "$c")" || fail "sibling $c's exec was not first-hand"
	grep -q '"runtime_attestation":{"runtime":"refexec"' "$(ledger "$c")" || fail "sibling $c's exec carries no refexec attestation"
done
nothing_left "after the sibling runs"
echo "siblings: own volume each, on the file path and the exec path — ok"

# 3. The exec path within a child: the writer's exec copies the note on the
#    child's volume, the reader's exec reads the copy — both through the
#    child's own refexec. Then the parent's own workspace never saw any of it.
run "spawn:worker/pair-wf:only:writer:write:exec-$NONCE | only:writer:exec-run:cp /work/agent-note.txt /work/copy.txt | only:reader:exec-run:cat /work/copy.txt"
echo "$OUT" | grep -q "finished: succeeded" || fail "the exec pair run did not succeed"
PAIR="$(field "$(ledger "$RUNID")" spawn child_run_id succeeded)"
EXEC_ART="$(parent_artifact "$RUNID")"
echo "$EXEC_ART" | grep -q "spawn succeeded $PAIR exec-$NONCE" || fail "the reader's exec did not see the writer's exec's copy"
[ "$(count "$(ledger "$PAIR")" exec succeeded)" = 2 ] || fail "expected two first-hand execs on the child"
run "ls:"
LISTING="$(parent_artifact "$RUNID")"
echo "$LISTING" | grep -qx "empty" || { echo "$LISTING"; fail "a child's files reached the parent's workspace"; }
# The same directive, through the same agent, names a file when there is
# one: what makes the listing above an empty workspace and not a broken ls.
run "write:probe-$NONCE; ls:"
LISTING="$(parent_artifact "$RUNID")"
echo "$LISTING" | grep -qx "agent-note.txt" || { echo "$LISTING"; fail "the parent's own ls sees nothing it wrote, so the empty listing above proved nothing"; }
nothing_left "after the exec run"
echo "exec path: a child's first-hand exec works on the child's volume, invisible to the parent — ok"

# 4. Containment of a child compartment, inspected while a child is alive:
#    the image its agent maps to, exactly two mounts (the child's volume at
#    /work and the child's socket dir), never the exec dir, no network, and
#    no way to reach the child's refexec socket.
"$WORK/agenthof" run lead lead-wf --input "spawn:worker/pair-wf:only:reader:sleep:20" --as ci --groups refbox-users --config "$WORK/config" --log-dir "$WORK/logs" --artifact-dir "$WORK/artifacts" >"$WORK/alive.out" 2>>"$WORK/agenthof.err" &
ALIVE=$!
for i in $(seq 1 60); do
	READER="$(podman ps --format '{{.Names}}' --filter 'name=^agenthof-spawn-.*-reader$' | head -1)"
	[ -n "$READER" ] && break
	[ "$i" = 60 ] && fail "no reader compartment appeared"
	sleep 0.5
done
CHILD_ID="${READER#agenthof-spawn-}"; CHILD_ID="${CHILD_ID%-reader}"
WRITER="agenthof-spawn-$CHILD_ID-writer"
[ "$(podman inspect "$READER" --format '{{.ImageName}}')" = "localhost/$IMAGE_B" ] || fail "the reader runs $(podman inspect "$READER" --format '{{.ImageName}}'), not the image its agent maps to"
[ "$(podman inspect "$WRITER" --format '{{.ImageName}}')" = "localhost/$IMAGE" ] || fail "the writer runs $(podman inspect "$WRITER" --format '{{.ImageName}}'), not the image its agent maps to"
MOUNTS="$(podman inspect "$READER" --format '{{range .Mounts}}{{.Type}} {{.Source}} {{.Destination}}{{"\n"}}{{end}}')"
# A named volume's Source is the backing host path, so its identity is in
# .Name: the volume at /work is THIS child's, not a sibling's, and it is the
# only one. The bind assertions below stay on paths, which is what they claim.
VOLUMES="$(podman inspect "$READER" --format '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}} {{.Destination}}{{"\n"}}{{end}}{{end}}')"
echo "$VOLUMES" | grep -qx "agenthof-spawn-$CHILD_ID-work /work" || fail "the child's own volume is not the one at /work: $VOLUMES"
[ "$(echo "$VOLUMES" | grep -c . || true)" = 1 ] || fail "unexpected volumes: $VOLUMES"
echo "$MOUNTS" | grep -q "^bind $SPAWN_ROOT/$CHILD_ID $SPAWN_ROOT/$CHILD_ID$" || fail "the child's socket dir is not mounted at its own path: $MOUNTS"
[ "$(echo "$MOUNTS" | grep -c '^bind ' || true)" = 1 ] || fail "unexpected binds: $MOUNTS"
if echo "$MOUNTS" | grep -q -- "-exec"; then fail "the child's exec dir is mounted into its compartment: $MOUNTS"; fi
if echo "$MOUNTS" | grep -q "$SOCK_DIR"; then fail "the ROOT's socket dir is mounted into a child compartment: $MOUNTS"; fi
# /probe must run and succeed once before anything is asked of it that must
# fail: a missing or renamed probe would answer every negative below with the
# same non-zero exit, for the wrong reason.
podman exec "$READER" /probe -touch /work/probe-ok || fail "/probe cannot write the child's own workspace, so the negatives below would prove nothing"
if podman exec "$READER" /probe -touch "$SPAWN_ROOT/$CHILD_ID-exec/probe-was-here"; then fail "a child compartment can reach its refexec's directory"; fi
if podman exec "$READER" /probe -dial 1.1.1.1:443; then fail "a child compartment reached the internet"; fi
if podman inspect "$READER" --format '{{range .Config.Env}}{{println .}}{{end}}' | grep -Ei 'TOKEN|SECRET|PASSWORD|API_KEY|AGENTHOF_' >/dev/null; then fail "a child compartment has credential-like environment"; fi
pgrep -f "refexec -config $SPAWN_ROOT/$CHILD_ID-exec" >/dev/null || fail "the child's refexec is not running on the host"
# Measure — not assert — what a child's compartments cost.
podman stats --no-stream --format 'compartment {{.Name}}: mem {{.MemUsage}} pids {{.PIDs}}' "$READER" "$WRITER" || true
wait "$ALIVE" || true
ALIVE=""
grep -q "finished: succeeded" "$WORK/alive.out" || { cat "$WORK/alive.out"; fail "the inspected run did not succeed"; }
nothing_left "after the inspected run"
echo "containment: mapped image, two mounts, no exec dir, no network, refexec on the host — ok"

# 5. Fail-closed at provision time: an agent with no image is refused with
#    the fixed reason before any compartment starts; the compartment cap
#    refuses a second pair that will not fit beside the first. One ledger
#    reason, two distinct records in the supervisor's log.
sup_mark
run "spawn:worker/ghost-wf:x"
sup_tail
[ "$(field "$(ledger "$RUNID")" spawn reason refused)" = "$R_UNAVAILABLE" ] || fail "the ghost spawn was not refused with the compartment reason"
[ -z "$(field "$(ledger "$RUNID")" spawn child_run_id refused)" ] || fail "a no-image refusal must start no child"
sole_refusal "$S_NO_IMAGE" "$S_CAP"
grep -q "agent=ghost" "$WORK/sup-tail.err" || fail "the supervisor's refusal does not name the agent it has no image for"
sup_mark
run "spawn-parallel:2:worker/pair-wf:sleep:3"
sup_tail
[ "$(count "$(ledger "$RUNID")" spawn succeeded)" = 1 ] || fail "under max_compartments 3 exactly one pair fits"
[ "$(field "$(ledger "$RUNID")" spawn reason refused)" = "$R_UNAVAILABLE" ] || fail "the second pair was not refused with the compartment reason"
sole_refusal "$S_CAP" "$S_NO_IMAGE"
nothing_left "after the refusals"
echo "fail-closed: no image and the compartment cap both refuse before anything starts, each under its own record — ok"

# The root compartment is unchanged by all of this: its own mounts only.
ROOT_MOUNTS="$(podman inspect "$LEAD" --format '{{range .Mounts}}{{.Type}} {{.Source}} {{.Destination}}{{"\n"}}{{end}}')"
echo "$ROOT_MOUNTS" | grep -q "bind $SOCK_DIR $SOCK_DIR" || fail "root socket dir not mounted"
if echo "$ROOT_MOUNTS" | grep -q "$SPAWN_ROOT\|$SUP_DIR"; then fail "a spawn directory is mounted into the root compartment: $ROOT_MOUNTS"; fi
podman exec "$LEAD" /probe -touch /work/probe-ok || fail "/probe cannot write the root compartment's own workspace, so the negative below would prove nothing"
if podman exec "$LEAD" /probe -touch "$SUP_DIR/probe-was-here"; then fail "the root compartment can reach refspawn's directory"; fi

echo "e2e-spawn: PASS"
