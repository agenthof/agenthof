#!/usr/bin/env bash
# e2e-reap-two-instance: prove the confiner's owner-stamped reap end to end
# with the real backend of the host — Seatbelt (real /usr/bin/sandbox-exec) on
# macOS, rootless podman on Linux. Every compartment is stamped with the
# process that launched it (the refexec instance), and an instance's startup
# reap removes only LEFTOVERS — compartments whose owner is gone — never a
# compartment a still-running sibling is using. Until now that was proven by
# unit tests only; this runs real refexec binaries against the real backend.
#
# Three refexec instances, A, B and C, run against the same compartment
# namespace (Seatbelt: one shared store_root and pid_dir; podman: the one
# engine). The reap is driven through refexec's own HTTP contract (POST /run on
# its socket), not through agenthof: the reap does not involve the gateway, so
# this script stays about the reap.
#   1. C and A start on a clean namespace and each puts a long command in
#      flight (A's is the live sibling). Then C is killed with SIGKILL: a
#      crashed instance, its compartment (process or container, PID record,
#      scratch dir) left behind with an owner that is gone — a real orphan.
#      A leftover store under the reap prefix and a decoy store off it are
#      added.
#   2. B starts. Its startup (probe, REAP, listen) runs while both are
#      present, so ONE sweep must tell them apart: A's compartment — the
#      running process, its PID record, its scratch dir, its store — is
#      untouched, and still finishes with its OWN exit (not a killed one),
#      while C's orphan is removed, record, scratch dir and leftover store
#      included, and the decoy stays. The "A was spared" assertions can fail:
#      the same sweep demonstrably reaps what it should.
#   3. B runs its own command on its own store; after A and B stop, nothing
#      is left behind.
# Podman has no store_root or pid_dir: the engine is the shared namespace, the
# compartment is a container stamped with an owner label, and a store is a
# volume. Requires macOS with sandbox-exec, or Linux with rootless podman (and
# the busybox image, which is pulled here); skips cleanly anywhere else. Also
# needs go, curl and python3. Run from the repo root.
set -euo pipefail

ME="e2e-reap-two-instance"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Decided before anything is created, so a skip leaves nothing behind.
BACKEND=""
case "$(uname)" in
Darwin)
	[ -x /usr/bin/sandbox-exec ] && BACKEND=seatbelt
	;;
Linux)
	if command -v podman >/dev/null 2>&1 && [ "$(podman info --format '{{.Host.Security.Rootless}} {{.Host.ServiceIsRemote}}' 2>/dev/null || true)" = "true false" ]; then
		BACKEND=podman
	fi
	;;
esac
if [ -z "$BACKEND" ]; then
	echo "$ME: SKIP — needs macOS with /usr/bin/sandbox-exec, or Linux with a local rootless podman"
	exit 0
fi
# On a host with a backend the e2e applies, so a missing build tool is a
# broken environment, not a reason to skip.
for tool in go curl python3; do
	command -v "$tool" >/dev/null 2>&1 || { echo "$ME: FAIL — $tool is required"; exit 1; }
done

IMAGE="${REFEXEC_IMAGE:-docker.io/library/busybox:1.36.1}"
WORK="$(mktemp -d /tmp/rx.XXXXXX)"
STORE_ROOT="$WORK/stores"   # seatbelt: every store is <store_root>/<name>
PID_DIR="$WORK/pids"        # seatbelt: one record per live compartment; shared by the instances
HEX="$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
# Each instance's long-lived store stays off the refexec- prefix that the
# startup reap removes (refexec -check refuses such a store).
STORE_A="e2e-a-$HEX"
STORE_B="e2e-b-$HEX"
STORE_C="e2e-c-$HEX"
# A leftover store a crashed instance's reap target (under the reap prefix),
# and a decoy off it that no reap may touch.
ORPHAN_STORE="refexec-orphan-$HEX"
# A store UNDER the reap prefix but stamped with a LIVE instance's owner
# (podman): the reap must spare it, as it spares that instance's compartment.
LIVE_STORE="refexec-live-$HEX"
DECOY_STORE="e2e-decoy-$HEX"
PIDS=()        # the refexec instances still to stop
SLEEP_PIDS=()  # compartment processes recorded for cleanup (seatbelt)
EXEC_DIRS=()
cleanup() {
	for p in ${PIDS[@]+"${PIDS[@]}"}; do
		kill "$p" >/dev/null 2>&1 || true
		wait "$p" >/dev/null 2>&1 || true
	done
	# A compartment is setsid'd: a failure part-way would leave its process
	# running. Signal it only while it is still the sleep it was.
	for p in ${SLEEP_PIDS[@]+"${SLEEP_PIDS[@]}"}; do
		if [ "$(comm_of "$p")" = sleep ]; then kill -9 "$p" >/dev/null 2>&1 || true; fi
	done
	if [ "$BACKEND" = podman ]; then
		podman ps -aq --filter 'name=^refexec-' | xargs -r podman rm -f >/dev/null 2>&1 || true
		for v in "$STORE_A" "$STORE_B" "$STORE_C" "$ORPHAN_STORE" "$LIVE_STORE" "$DECOY_STORE"; do
			podman volume rm -f "$v" >/dev/null 2>&1 || true
		done
	fi
	for d in ${EXEC_DIRS[@]+"${EXEC_DIRS[@]}"}; do rm -rf "$d"; done
	rm -rf "$WORK"
}
trap cleanup EXIT
fail() {
	echo "$ME: FAIL — $*"
	for f in "$WORK"/refexec-*.err; do
		[ -f "$f" ] && { echo "--- $f"; cat "$f"; } >&2
	done
	exit 1
}
# shellcheck source=scripts/acceptance-lib.sh
. "$ROOT/scripts/acceptance-lib.sh"
mode_of() { python3 -c 'import os, sys; print(oct(os.stat(sys.argv[1]).st_mode & 0o777))' "$1"; }
comm_of() { local c; c="$(ps -p "$1" -o comm= 2>/dev/null || true)"; basename "${c:-none}"; }
unset AGENTHOF_TOKEN || true

# Build everything BEFORE anything starts: no compartment's clock may pay for
# a cold build or a pull. refexec runs podman with --pull=never, so the exec
# image is fetched here, by the operator.
go build -o "$WORK/refexec" ./deploy/refexec
if [ "$BACKEND" = podman ]; then
	podman pull "$IMAGE" >/dev/null
fi

# --- backend-specific observation. Everything after these functions is shared.
# A compartment is named by its session (refexec-<hex>), taken from refexec's
# own "compartment started" log line.
pidrec() { echo "$PID_DIR/$1.pid"; }
scratch_of() { echo "$STORE_ROOT/.scratch/$1"; }
rec_field() { python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$(pidrec "$1")" "$2"; }
# compartment_present SESSION: its record (seatbelt) / its container (podman).
compartment_present() {
	if [ "$BACKEND" = seatbelt ]; then
		[ -f "$(pidrec "$1")" ]
	else
		[ -n "$(podman ps -aq --filter "name=^$1\$")" ]
	fi
}
# compartment_running SESSION: its command is running right now.
compartment_running() {
	if [ "$BACKEND" = seatbelt ]; then
		compartment_present "$1" && [ "$(comm_of "$(rec_field "$1" pid)")" = sleep ]
	else
		[ "$(podman inspect --format '{{.State.Running}}' "$1" 2>/dev/null || true)" = true ]
	fi
}
# compartment_owner SESSION: the owner pid the compartment is stamped with.
compartment_owner() {
	if [ "$BACKEND" = seatbelt ]; then
		rec_field "$1" owner_pid
	else
		local l; l="$(podman inspect --format '{{index .Config.Labels "agenthof.owner"}}' "$1")"
		echo "${l%%-*}"
	fi
}
store_present() {
	if [ "$BACKEND" = seatbelt ]; then
		[ -d "$STORE_ROOT/$1" ]
	else
		podman volume inspect "$1" >/dev/null 2>&1
	fi
}
make_store() {
	if [ "$BACKEND" = seatbelt ]; then
		(umask 077 && mkdir -p "$STORE_ROOT/$1")
	else
		podman volume create "$1" >/dev/null
	fi
}
inst_config() { # $1 = exec socket dir, $2 = workspace store
	if [ "$BACKEND" = seatbelt ]; then
		cat <<EOF
confiner: seatbelt
socket: $1/refexec.sock
store_root: $STORE_ROOT
pid_dir: $PID_DIR
workspace:
  store: $2
limits:
  memory: 256m
  cpus: "1"
  pids: 64
compartments:
  max: 2
env_allow: []
timeout: 2m
EOF
	else
		cat <<EOF
confiner: podman
socket: $1/refexec.sock
image: $IMAGE
workspace:
  store: $2
  path: /work
limits:
  memory: 256m
  cpus: "1"
  pids: 64
compartments:
  max: 2
env_allow: []
timeout: 2m
EOF
	fi
}

# start_instance TAG STORE: a refexec through its launcher, on its own socket
# dir and workspace store, logging to $WORK/refexec-TAG.err. Waits for the
# socket — refexec opens it only after its startup reap has finished. Sets
# INST_PID (the launcher exec's refexec, so it IS refexec's pid) and
# INST_DIR; the instance is added to PIDS.
start_instance() {
	local tag="$1" store="$2" i
	INST_DIR="$(mktemp -d /tmp/rx.XXXXXX)"   # 0700; SEPARATE per instance; short for the socket-path limit
	EXEC_DIRS+=("$INST_DIR")
	inst_config "$INST_DIR" "$store" >"$WORK/refexec-$tag.yaml"
	if [ "$BACKEND" = seatbelt ]; then
		REFEXEC_BIN="$WORK/refexec" REFEXEC_CONFIG="$WORK/refexec-$tag.yaml" deploy/refexec/refexec-run-seatbelt.sh 2>"$WORK/refexec-$tag.err" &
	else
		REFEXEC_BIN="$WORK/refexec" REFEXEC_CONFIG="$WORK/refexec-$tag.yaml" deploy/refexec/refexec-run.sh 2>"$WORK/refexec-$tag.err" &
	fi
	INST_PID=$!
	PIDS+=("$INST_PID")
	for i in $(seq 1 60); do
		[ -S "$INST_DIR/refexec.sock" ] && break
		kill -0 "$INST_PID" 2>/dev/null || fail "instance $tag exited during startup"
		[ "$i" = 60 ] && fail "instance $tag: socket never appeared"
		sleep 0.5
	done
	[ "$(mode_of "$INST_DIR/refexec.sock")" = 0o600 ] || fail "instance $tag: socket is not mode 0600"
	grep -q "refexec listening.*confiner=$BACKEND" "$WORK/refexec-$tag.err" || fail "instance $tag did not report the $BACKEND tier at start"
	store_present "$store" || fail "instance $tag: the launcher did not create its store"
}
# run_cmd SOCKDIR ARGV_JSON: POST /run to a refexec; prints the response.
run_cmd() {
	curl -sS --max-time 120 --unix-socket "$1/refexec.sock" -X POST -d "{\"command\":$2}" http://refexec/run
}
# wait_started TAG: waits for the instance's compartment to be in flight (its
# own "compartment started" log line) and sets SESSION and CPID (the pid
# refexec logged for it). Seatbelt's is the sandbox-exec process, which
# becomes the program; podman's is the client.
wait_started() {
	local tag="$1" line i
	for i in $(seq 1 60); do
		line="$(sed -n '/msg="compartment started"/{p;q;}' "$WORK/refexec-$tag.err")"
		[ -n "$line" ] && break
		[ "$i" = 60 ] && fail "instance $tag: no compartment started"
		sleep 0.5
	done
	SESSION="$(sed -n 's/.* session=\(refexec-[0-9a-f]*\) .*/\1/p' <<<"$line")"
	CPID="$(sed -n 's/.* pid=\([0-9]*\).*/\1/p' <<<"$line")"
	[ -n "$SESSION" ] && [ -n "$CPID" ] || fail "instance $tag: could not read the compartment from: $line"
	compartment_present "$SESSION" || fail "instance $tag: compartment $SESSION has no record/container once started"
	SLEEP_PIDS+=("$CPID")
}

# --- 1. C and A start on a clean namespace (their own startup reaps find
# nothing), each with a command in flight. A is the live sibling; C will crash.
if [ "$BACKEND" = seatbelt ]; then
	(umask 077 && mkdir -p "$PID_DIR")
fi
start_instance C "$STORE_C"
C_PID="$INST_PID"; C_DIR="$INST_DIR"
start_instance A "$STORE_A"
A_PID="$INST_PID"; A_DIR="$INST_DIR"
# Stores a crashed instance leaves under the reap prefix, and a decoy off it
# that no reap may touch. Created after both instances' startup reaps, so only
# the next instance's reap can see them.
make_store "$ORPHAN_STORE"
make_store "$DECOY_STORE"

run_cmd "$C_DIR" '["sleep","300"]' >"$WORK/c.resp" 2>/dev/null &
C_CURL=$!
wait_started C
C_SESSION="$SESSION"; C_CPID="$CPID"
run_cmd "$A_DIR" '["sleep","25"]' >"$WORK/a.resp" &
A_CURL=$!
wait_started A
A_SESSION="$SESSION"; A_CPID="$CPID"
[ "$A_SESSION" != "$C_SESSION" ] || fail "A and C share a compartment name"
for t in A C; do
	s="${t}_SESSION"; o="${t}_PID"
	compartment_running "${!s}" || fail "$t's compartment is not running"
	[ "$(compartment_owner "${!s}")" = "${!o}" ] || fail "$t's compartment is not stamped with $t's pid (${!o})"
	if [ "$BACKEND" = seatbelt ]; then
		[ -d "$(scratch_of "${!s}")" ] || fail "$t's compartment has no scratch dir"
	fi
done
store_present "$STORE_A" || fail "A's store is missing before B starts"
echo "A has $A_SESSION and C has $C_SESSION in flight, each stamped with its owner's pid — ok"

# A store under the reap prefix stamped with A's LIVE owner label (podman only):
# B's reap must spare it exactly as it spares A's compartment — otherwise
# `podman volume rm -f` would stop and remove the container holding it, ending
# A's run. (Seatbelt spares a live store through its compartment's PID record,
# covered by A's own store above; podman has no such record, hence the label.)
if [ "$BACKEND" = podman ]; then
	A_OWNER_LABEL="$(podman inspect --format '{{index .Config.Labels "agenthof.owner"}}' "$A_SESSION")"
	[ -n "$A_OWNER_LABEL" ] || fail "could not read A's owner label from its compartment"
	podman volume create --label "agenthof.owner=$A_OWNER_LABEL" "$LIVE_STORE" >/dev/null
fi

# --- 2. C crashes: its owner is gone, its compartment is left behind.
kill -9 "$C_PID"
wait "$C_PID" >/dev/null 2>&1 || true
PIDS=("$A_PID")
if wait "$C_CURL"; then fail "C's request succeeded though its instance was killed"; fi
# The orphan must outlive its owner, or there is no leftover for the reap to
# tell from a live sibling's compartment. (kill -0 would also match a zombie,
# hence the process table.)
[ -z "$(ps -p "$C_PID" -o pid= 2>/dev/null || true)" ] || fail "C is still running after SIGKILL"
compartment_running "$C_SESSION" || fail "C's compartment did not outlive its killed owner, so there is no leftover to reap"
if [ "$BACKEND" = seatbelt ]; then
	[ -d "$(scratch_of "$C_SESSION")" ] || fail "C's orphan has no scratch dir"
fi
compartment_running "$A_SESSION" || fail "A's compartment is not running after C's crash"
echo "C crashed with $C_SESSION still running, its owner $C_PID gone — ok"

# --- 3. B starts. Its socket appears only after its startup reap has run, with
# A's compartment live and C's an orphan in the same namespace.
start_instance B "$STORE_B"
B_PID="$INST_PID"; B_DIR="$INST_DIR"
B_ERR="$WORK/refexec-B.err"

# The live sibling is spared: compartment, record, scratch dir, store.
compartment_running "$A_SESSION" || fail "B's startup reap ended A's running compartment"
[ "$(compartment_owner "$A_SESSION")" = "$A_PID" ] || fail "A's compartment lost its owner stamp"
if [ "$BACKEND" = seatbelt ]; then
	[ -d "$(scratch_of "$A_SESSION")" ] || fail "B's startup reap removed A's scratch dir"
	[ "$(comm_of "$A_CPID")" = sleep ] || fail "A's command (pid $A_CPID) is no longer running"
fi
store_present "$STORE_A" || fail "B's startup reap removed A's store"
grep -Eq "msg=\"leaving a compartment another running instance owns\" compartment=$A_SESSION owner_pid=$A_PID" "$B_ERR" || fail "B did not log leaving A's compartment"
OUT_B="$(cat "$B_ERR")"
if grep -Eq "reaping leftover compartment\" compartment=$A_SESSION" <<<"$OUT_B"; then fail "B logged reaping A's live compartment"; fi

# The dead owner's leftovers are reaped: the same sweep that spared A.
if compartment_present "$C_SESSION"; then fail "B did not reap C's orphaned compartment (owner $C_PID is gone)"; fi
for i in $(seq 1 20); do
	[ "$(comm_of "$C_CPID")" != sleep ] && break
	[ "$i" = 20 ] && fail "C's orphaned command (pid $C_CPID) is still running after the reap"
	sleep 0.5
done
if [ "$BACKEND" = seatbelt ]; then
	[ ! -e "$(scratch_of "$C_SESSION")" ] || fail "B did not reap C's scratch dir"
fi
if store_present "$ORPHAN_STORE"; then fail "B did not reap the leftover store under the reap prefix"; fi
store_present "$DECOY_STORE" || fail "B's reap removed a store off the reap prefix"
if [ "$BACKEND" = podman ]; then
	store_present "$LIVE_STORE" || fail "B's reap removed a store under the prefix that a live instance (A, $A_PID) owns"
	grep -Eq "msg=\"leaving a store another running instance owns\" store=$LIVE_STORE owner_pid=$A_PID" "$B_ERR" || fail "B did not log leaving the live-owner store $LIVE_STORE"
fi
grep -Eq "msg=\"reaping leftover compartment\" compartment=$C_SESSION" "$B_ERR" || fail "B did not log reaping C's compartment"
echo "B's startup reap spared A's live $A_SESSION and reaped C's orphaned $C_SESSION — ok"

# B runs its own command, on its own store, while A's is still in flight.
RESP="$(run_cmd "$B_DIR" "[\"echo\",\"b-$HEX\"]")" || fail "B's own command failed to run"
[ "$(python3 -c 'import json, sys; r = json.load(sys.stdin); print(r["exit_code"], r["output"].strip())' <<<"$RESP")" = "0 b-$HEX" ] || fail "B's command did not run with exit 0 and its own output: $RESP"
grep -q "\"confiner\":\"$BACKEND\"" <<<"$RESP" || fail "B's attestation does not carry the $BACKEND tier: $RESP"
compartment_running "$A_SESSION" || fail "A's compartment ended while B ran its own"
echo "B ran its own command on its own store: exit 0, $BACKEND tier — ok"

# --- 4. A's command finishes with its OWN exit — a reap would have ended it
# with a kill — and nothing is left behind once the instances stop.
A_RC=0
wait "$A_CURL" || A_RC=$?
[ "$A_RC" = 0 ] || fail "A's request failed (curl exit $A_RC): $(cat "$WORK/a.resp")"
[ "$(python3 -c 'import json, sys; print(json.load(sys.stdin)["exit_code"])' <"$WORK/a.resp")" = 0 ] || fail "A's command did not finish with its own exit 0: $(cat "$WORK/a.resp")"
grep -q "\"session\":\"$A_SESSION\"" "$WORK/a.resp" || fail "A's response is not the attestation of $A_SESSION"
echo "A's command finished with its own exit 0 after B's reap — ok"

if compartment_present "$A_SESSION"; then fail "A's compartment was left behind after it finished"; fi
for p in "$A_PID" "$B_PID"; do
	kill "$p" >/dev/null 2>&1 || true
	wait "$p" >/dev/null 2>&1 || true
done
PIDS=()
for d in "$A_DIR" "$B_DIR"; do
	if [ -S "$d/refexec.sock" ]; then fail "an instance left its socket behind"; fi
done
if [ "$BACKEND" = seatbelt ]; then
	[ -z "$(ls "$PID_DIR")" ] || { ls -la "$PID_DIR"; fail "a PID record was left behind"; }
	[ -z "$(ls "$STORE_ROOT/.scratch" 2>/dev/null)" ] || { ls -la "$STORE_ROOT/.scratch"; fail "a scratch dir was left behind"; }
else
	[ -z "$(podman ps -aq --filter 'name=^refexec-')" ] || { podman ps -a --filter 'name=^refexec-'; fail "a compartment was left behind"; }
fi

echo "$ME: PASS ($BACKEND)"
