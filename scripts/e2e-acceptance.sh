#!/usr/bin/env bash
# e2e-acceptance: the combined acceptance run on REAL rootless podman — the
# containment tier. The same scenario as scripts/e2e-acceptance-local.sh (one
# LangChain agent, in ONE governed run of the real agenthof binary, drives
# every door: a model call, a first-hand exec, an on-behalf-of HTTP tool
# call, a stdio tool call fronted by refbridge, and two parallel sub-agent
# runs), but every compartment is real: the agent runs from the langchain
# image in a refbox (--network none), refexec runs each command in a
# compartment of its own, refbridge fronts the stdio tool from its own
# compartment, and refspawn provisions a refbox + refexec per child. The
# model provider is a host stand-in bound on the HOST's address, not
# loopback — so a compartment's failed dial to it proves something:
# 127.0.0.1 inside --network none is the compartment's OWN loopback, and the
# only way out of any compartment is the gateway socket bind-mounted into
# it. The other two stand-ins stay on loopback, each for a reason that is
# not this harness's to override: the stub issuer mints a token for whoever
# asks and so refuses any non-loopback -addr (examples/obo-idp), and a tool
# resource's url must be https, loopback http or a unix:// socket, so a
# gateway pointed at the upstream on the host address would be refused at
# apply. Neither is ever dialed from inside a compartment anyway — the
# host-side gateway does both. What this tier proves is containment AS
# CONFIGURED: every compartment runs --network none under the operator's
# podman, and it is podman that does the containing — Agenthof relies on it
# and does not itself enforce it. The hermetic run proves governance and
# audit on every push.
# Asserts, beyond the hermetic run's governance and audit facts (adapted:
# the exec output carries the allowlisted variable AND NOT a canary from
# refexec's own environment; refbridge attests /stdio-tool from its image):
# credential starvation — no credential-like name in the environment of the
# root, the bridge or any child compartment, and no runtime socket mounted;
# no egress — the root and the bridge cannot dial the provider at the host
# address the gateway reaches it on, nor anything off the machine (the
# issuer and the upstream are loopback-only, see above, and a compartment's
# 127.0.0.1 is its own, so dialing them from inside would prove nothing;
# refexec's one-shot compartments are too short-lived to probe here, and
# their no-network is scripts/e2e-refexec.sh's proof); mount scoping — each
# child, inspected while alive, mounts exactly its own volume and its own
# socket directory, never the exec dir, never the root's socket dir, and
# cannot reach its refexec's socket; four runtimes coexist with disjoint
# 0700 socket directories and nothing cross-mounted; and after every run
# nothing the runtimes made is left. Requires rootless podman, go, python3
# (standard library only — the fake provider needs nothing else) and
# iproute2, on a Linux host; on macOS run it through
# deploy/lima/lima.sh e2e acceptance, or `make acceptance-podman` on
# either. `--keep` leaves the compartments, the volumes and the scratch
# directory for inspection. Knobs:
#   REFBOX_LANGCHAIN_IMAGE  the agent image tag   (refbox-langchain:test)
#   REFBRIDGE_IMAGE         the bridge image tag  (refbridge:test)
#   REFEXEC_IMAGE           the exec image        (docker.io/library/busybox:1.36.1)
#   ACCEPTANCE_DELAY        seconds the provider holds each answer, so a child is alive to inspect (15)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
ME="e2e-acceptance"
KEEP=0
for a in "$@"; do
	case "$a" in
		--keep) KEEP=1 ;;
		*) echo "$ME: unknown argument: $a (want: [--keep])" >&2; exit 2 ;;
	esac
done
fail() {
	echo "$ME: FAIL — $*"
	exit 1
}
# Checked before anything is created, so there is nothing to clean up.
command -v podman >/dev/null || fail "podman is not installed; this run proves containment with the real runtime. Run it on a Linux host with rootless podman, through 'deploy/lima/lima.sh e2e acceptance' on macOS, or 'make acceptance-podman' on either. The hermetic governance gate is scripts/e2e-acceptance-local.sh."
command -v ip >/dev/null || fail "ip (iproute2) is not installed; it finds the host address the stand-ins bind"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=acceptance-lib.sh
. "$ROOT/scripts/acceptance-lib.sh"

LC_IMAGE="${REFBOX_LANGCHAIN_IMAGE:-refbox-langchain:test}"
BRIDGE_IMAGE="${REFBRIDGE_IMAGE:-refbridge:test}"
EXEC_IMAGE="${REFEXEC_IMAGE:-docker.io/library/busybox:1.36.1}"
ROOT_NAME="refbox-acceptance"
BRIDGE_NAME="refbridge-acceptance"
# The socket file name the langchain image's ENTRYPOINT carries
# (deploy/refbox/Containerfile.python). The compartment is pointed at it and
# the config names the same file: the hermetic harness's lc.sock is its own.
AGENT_SOCK="refbox-langchain.sock"
# Timing, in one place. The provider holds every answer DELAY seconds, so a
# child's compartment is alive — and inspectable — for at least that long
# after its agent is ready. The step must outlast: the parent's held model
# call + exec + two tool calls + a child's cold start (a distroless Python
# importing langchain; ready_timeout below) + the child's held call. The
# supervisor's compartment timeout must cover the step; the root's covers
# the three runs and every inspection. (The agent's own clients allow far
# more: REQUEST_TIMEOUT, 240 s, on the model, exec and spawn doors, and
# DOOR_TIMEOUT, 300 s to read, on the MCP tool doors — both in
# examples/langchain-agent/agent.py. A held spawn — a child's cold start
# plus its held answer — fits well inside 240 s.)
DELAY="${ACCEPTANCE_DELAY:-15}"
STEP_TIMEOUT=5m
READY_TIMEOUT=120s
ROOT_TIMEOUT=1500

# Short on purpose: Unix socket paths have a small OS length limit. Every
# socket directory is separate and 0700 (mktemp makes them so), and none may
# sit inside another: the gateway's (mounted into the root refbox only), the
# bridge's (into the bridge only), refexec's and the supervisor's (never
# mounted), and the spawn root (each child's own dir into that child only).
SOCK_DIR="$(mktemp -d /tmp/ac.XXXXXX)"
export AGENTHOF_REFBOX_SOCKET_DIR="$SOCK_DIR"
BRIDGE_DIR="$(mktemp -d /tmp/ac.XXXXXX)"
EXEC_DIR="$(mktemp -d /tmp/ac.XXXXXX)"
SUP_DIR="$(mktemp -d /tmp/ac.XXXXXX)"
SPAWN_ROOT="$(mktemp -d /tmp/ac.XXXXXX)"
WORK="$(mktemp -d /tmp/ac.XXXXXX)"
NONCE="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
VOLUME="acceptance-work-$NONCE"
PIDS=()
OUTS=()
RUN_PID=""
# sweep: remove what this script names — the root and bridge compartments,
# any child or exec compartment, the child volumes and every acceptance-work
# volume. Run at START too: a previous --keep run leaves exactly these.
sweep() {
	podman rm -f "$ROOT_NAME" "$BRIDGE_NAME" >/dev/null 2>&1 || true
	podman ps -aq --filter 'name=^agenthof-spawn-' | xargs -r podman rm -f >/dev/null 2>&1 || true
	podman ps -aq --filter 'name=^refexec-' | xargs -r podman rm -f >/dev/null 2>&1 || true
	podman volume ls -q --filter 'name=^agenthof-spawn-' | xargs -r podman volume rm -f >/dev/null 2>&1 || true
	podman volume ls -q --filter 'name=^acceptance-work-' | xargs -r podman volume rm -f >/dev/null 2>&1 || true
}
# capture_logs: the compartments' own stderr, into the scratch dir where the
# leak search reads every *.err — taken before teardown, kept by --keep.
capture_logs() {
	podman logs "$ROOT_NAME" >"$WORK/root.err" 2>&1 || true
	podman logs "$BRIDGE_NAME" >"$WORK/bridge.err" 2>&1 || true
}
cleanup() {
	if [ -n "$RUN_PID" ]; then kill "$RUN_PID" >/dev/null 2>&1 || true; wait "$RUN_PID" >/dev/null 2>&1 || true; fi
	capture_logs
	# Host processes always go (refspawn tears its live sets down; refexec
	# removes its compartments; the stand-ins hold nothing worth keeping) —
	# --keep is for what can be inspected: the root and bridge compartments,
	# the volumes, the socket dirs and the scratch dir.
	for p in ${PIDS[@]+"${PIDS[@]}"}; do
		kill "$p" >/dev/null 2>&1 || true
		wait "$p" >/dev/null 2>&1 || true
	done
	if [ "$KEEP" = 1 ]; then
		echo "$ME: --keep — compartments $ROOT_NAME and $BRIDGE_NAME are left running (host processes stopped; any child set was torn down by the supervisor); volumes kept; scratch: $WORK (config, logs, artifacts, *.err incl. root.err/bridge.err); sockets: $SOCK_DIR $BRIDGE_DIR $EXEC_DIR $SUP_DIR $SPAWN_ROOT"
		return 0
	fi
	sweep
	rm -rf "$SOCK_DIR" "$BRIDGE_DIR" "$EXEC_DIR" "$SUP_DIR" "$SPAWN_ROOT" "$WORK"
}
trap cleanup EXIT
unset AGENTHOF_TOKEN || true
sweep

# The host address the stand-ins bind. 127.0.0.1 inside --network none is the
# compartment's OWN loopback, so a failed dial to it would prove nothing; a
# failed dial to this address does. Not one pipeline: under pipefail a
# failing `ip` would be swallowed by awk's success, and a run that dialled an
# empty host would report no egress without ever having tried.
host_ip() {
	local route
	route="$(ip -4 route get 1.1.1.1 2>/dev/null)" || return 1
	awk '{for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit }}' <<<"$route"
}
HOST_IP="$(host_ip)" || fail "no host address: 'ip -4 route get 1.1.1.1' failed. The stand-ins must bind an address a compartment could try to reach; without one the no-egress probes would be vacuous"
[ -n "$HOST_IP" ] || fail "no host address: 'ip -4 route get 1.1.1.1' named no source address. The stand-ins must bind an address a compartment could try to reach; without one the no-egress probes would be vacuous"
host_port() { # $1 = host (default $HOST_IP): a free port on that address
	python3 -c "import socket; s=socket.socket(); s.bind(('${1:-$HOST_IP}', 0)); print(s.getsockname()[1]); s.close()"
}
wait_host_port() { # $1 = port, $2 = what, $3 = host (default $HOST_IP)
	local host="${3:-$HOST_IP}"
	for i in $(seq 1 60); do
		python3 -c "import socket; socket.create_connection(('$host', $1), 1).close()" >/dev/null 2>&1 && return 0
		[ "$i" = 60 ] && { cat "$WORK"/*.err 2>/dev/null || true; fail "$2 never listened on $host:$1"; }
		sleep 0.2
	done
}
wait_socket() { # $1 = socket path, $2 = what, $3 = seconds, $4 = log to show on failure (a file or a compartment name)
	for i in $(seq 1 "$3"); do
		[ -S "$1" ] && return 0
		[ "$i" = "$3" ] && { { cat "$4" 2>/dev/null || podman logs "$4" 2>&1; } | tail -40 || true; fail "$2 never appeared"; }
		sleep 1
	done
}

# Build and pull everything BEFORE anything starts: the compartments' wall
# clocks must not pay for a cold build or a pull, and refexec/refspawn run
# podman with --pull=never. The images are built on EVERY run (cached when
# unchanged): Containerfile.python copies agent.py at build time, so a run
# that skipped the build could silently test stale code.
go build -o "$WORK/agenthof" ./cmd/agenthof
go build -o "$WORK/obo-idp" ./examples/obo-idp
go build -o "$WORK/obo-upstream" ./examples/obo-upstream
go build -o "$WORK/refexec" ./deploy/refexec
go build -o "$WORK/refspawn" ./deploy/refspawn
podman build -f deploy/refbox/Containerfile.python -t "$LC_IMAGE" .
podman build -f deploy/refbridge/Containerfile -t "$BRIDGE_IMAGE" .
podman pull "$EXEC_IMAGE" >/dev/null

PROVIDER_PORT="$(host_port)"
# Loopback, both of them, and not by this harness's choice: the stub issuer
# refuses any non-loopback -addr (it mints a token for whoever asks), and a
# tool resource's url must be https, loopback http or unix://, so a gateway
# that reached the upstream at the host address would be refused at apply.
# Only the host-side gateway talks to either, so nothing is lost but the
# no-egress target they would have been — the provider is that target.
IDP_PORT="$(host_port 127.0.0.1)"
UP_PORT="$(host_port 127.0.0.1)"
ISSUER="http://127.0.0.1:$IDP_PORT"
UP_AUD="https://obo-upstream.example"
unset GATEWAY_KEY IDP_SECRET TOOL_SECRET
IDP_SECRET="idp-side-secret-$NONCE"
TOOL_SECRET="tool-secret-$NONCE"
GATEWAY_KEY="host-side-dummy-key-$NONCE"
export OBO_CLIENT_ID=agenthof-broker   # an id, not a secret: the broker reads it by name

# --- 1. The stand-ins and the host-side runtimes, BEFORE any secret is
# exported: refspawn hands its own environment to every child's refexec, and
# a podman client passes nothing into a compartment without -e — the
# .Config.Env inspection below is the proof of that; starting them first is
# what makes the proof unsurprising. The IdP's secret is a per-command
# variable on its own line.
python3 scripts/fake-openai-provider.py --bind "$HOST_IP:$PROVIDER_PORT" --reply "governed:$NONCE" --log "$WORK/provider.jsonl" --delay "$DELAY" >/dev/null 2>"$WORK/provider.err" &
PIDS+=($!)
PROVIDER_URL="http://$HOST_IP:$PROVIDER_PORT"
OBO_IDP_CLIENT_SECRET="$IDP_SECRET" "$WORK/obo-idp" -addr "127.0.0.1:$IDP_PORT" -client-id "$OBO_CLIENT_ID" -client-secret-env OBO_IDP_CLIENT_SECRET \
	-audiences "$UP_AUD" -subject-token-type urn:ietf:params:oauth:token-type:id_token \
	-token-log "$WORK/issued.jsonl" 2>"$WORK/idp.err" &
PIDS+=($!)
wait_host_port "$IDP_PORT" "obo-idp" 127.0.0.1
"$WORK/obo-upstream" -addr "127.0.0.1:$UP_PORT" -jwks-url "$ISSUER/keys" -audience "$UP_AUD" 2>"$WORK/upstream.err" &
PIDS+=($!)

# The exec runtime, on the host, through its launcher (which creates the
# workspace volume the root refbox shares and prepares the 0700 socket dir).
# Its environment carries the allowlisted marker AND a canary that is NOT on
# env_allow: the compartment must see the first and never the second.
cat >"$WORK/refexec.yaml" <<EOF
socket: $EXEC_DIR/refexec.sock
image: $EXEC_IMAGE
workspace:
  volume: $VOLUME
  path: /work
timeout: 30s
limits:
  memory: 256m
  cpus: "1"
  pids: 64
compartments:
  max: 2
env_allow: ["ACCEPTANCE_E2E_MARKER"]
EOF
ACCEPTANCE_E2E_MARKER=1 ACCEPTANCE_E2E_CANARY="canary-$NONCE" REFEXEC_BIN="$WORK/refexec" REFEXEC_CONFIG="$WORK/refexec.yaml" deploy/refexec/refexec-run.sh 2>"$WORK/refexec.err" &
PIDS+=($!)
wait_socket "$EXEC_DIR/refexec.sock" "the exec runtime socket" 30 "$WORK/refexec.err"
[ "$(stat -c %a "$EXEC_DIR")" = 700 ] || fail "refexec's socket dir is not 0700"
podman volume inspect "$VOLUME" >/dev/null || fail "the refexec launcher did not create the workspace volume"

# The bridge, in its own compartment, fronting the stdio tool from its image
# over a Unix socket in the bridge's own 0700 dir (mounted at the same path
# inside and out). The credential it materializes comes from the gateway per
# session, never from this environment; env_passthrough is empty because a
# compartment inherits nothing to pass through.
mkdir -p "$WORK/bridge-config"
cat >"$WORK/bridge-config/refbridge.yaml" <<EOF
socket: $BRIDGE_DIR/stdio-tool.sock
command: ["/stdio-tool", "-credential-env", "DEMO_TOKEN"]
credential:
  env: DEMO_TOKEN
  materialization: env-at-spawn
env_passthrough: []
egress:
  allow: []
sessions:
  max: 4
  idle_timeout: 10m
  max_lifetime: 30m
EOF
REFBRIDGE_DETACH=1 REFBRIDGE_IMAGE="$BRIDGE_IMAGE" REFBRIDGE_NAME="$BRIDGE_NAME" REFBRIDGE_SOCKET_DIR="$BRIDGE_DIR" REFBRIDGE_CONFIG_DIR="$WORK/bridge-config" deploy/refbridge/refbridge-run.sh >/dev/null
wait_socket "$BRIDGE_DIR/stdio-tool.sock" "the bridge socket" 30 "$BRIDGE_NAME"
[ "$(stat -c %a "$BRIDGE_DIR/stdio-tool.sock")" = 600 ] || fail "the bridge socket is not mode 0600"

# The supervisor, on the host: per child, one volume, one refbox from the
# image its agent maps to (the same langchain image, in its default one-
# model-call driver — refspawn appends only -socket), one refexec bound to
# that volume. Its compartment timeout covers the step; ready_timeout covers
# a cold distroless Python importing langchain.
cat >"$WORK/refspawn.yaml" <<EOF
socket: $SUP_DIR/refspawn.sock
spawn_root: $SPAWN_ROOT
images:
  acceptance-sub: $LC_IMAGE
timeout: 10m
ready_timeout: $READY_TIMEOUT
limits:
  memory: 256m
  cpus: "1"
  pids: 64
max_compartments: 2
refexec:
  command: [$WORK/refexec]
  image: $EXEC_IMAGE
  timeout: 30s
  limits:
    memory: 256m
    cpus: "1"
    pids: 64
  max_compartments: 2
  env_allow: []
EOF
"$WORK/refspawn" -config "$WORK/refspawn.yaml" -check >/dev/null || fail "refspawn rejected its config"
"$WORK/refspawn" -config "$WORK/refspawn.yaml" 2>"$WORK/refspawn.err" &
PIDS+=($!)
wait_socket "$SUP_DIR/refspawn.sock" "the supervisor socket" 30 "$WORK/refspawn.err"
[ "$(stat -c %a "$SUP_DIR")" = 700 ] || fail "refspawn's socket dir is not 0700"

# The root agent: the langchain image in a real refbox on that workspace,
# with the scripted driver through the recipe's REFBOX_ARGS knob. Its
# defaults are the scenario's legs (env, whoami, echo, two acceptance-sub
# children), so the driver is all it needs to be told.
REFBOX_DETACH=1 REFBOX_IMAGE="$LC_IMAGE" REFBOX_NAME="$ROOT_NAME" REFBOX_SOCKET="$AGENT_SOCK" REFBOX_WORKSPACE_VOLUME="$VOLUME" \
	REFBOX_TIMEOUT="$ROOT_TIMEOUT" REFBOX_ARGS="--driver scripted" deploy/refbox/refbox-run.sh >/dev/null
wait_socket "$SOCK_DIR/$AGENT_SOCK" "the agent socket" 90 "$ROOT_NAME"
# Captured, then searched: a `podman logs | grep -q` that matched early would
# SIGPIPE podman and fail the pipeline under pipefail.
ROOT_LOG="$(out_of podman logs "$ROOT_NAME" 2>&1)"
grep -q "driver scripted" <<<"$ROOT_LOG" || { tail -20 <<<"$ROOT_LOG"; fail "the root agent did not start with the scripted driver"; }

wait_host_port "$UP_PORT" "obo-upstream" 127.0.0.1
wait_host_port "$PROVIDER_PORT" "the provider stand-in"

TOKEN="$(mint u-dana agenthof acceptance-users)"
[ -n "$TOKEN" ] || fail "the issuer minted no token"

# --- 2. The combined config, from the shared generator: the same scenario as
# the hermetic run, listening where this run's runtimes listen.
AC_SOCK_DIR="$SOCK_DIR"
AC_AGENT_SOCK="$AGENT_SOCK"
AC_PROVIDER_URL="$PROVIDER_URL"
AC_UP_URL="http://127.0.0.1:$UP_PORT/"
AC_ISSUER="$ISSUER"
AC_UP_AUD="$UP_AUD"
AC_BRIDGE_URL="unix://$BRIDGE_DIR/stdio-tool.sock"
AC_EXEC_URL="unix://$EXEC_DIR/refexec.sock"
AC_SUP_URL="unix://$SUP_DIR/refspawn.sock"
AC_STEP_TIMEOUT="$STEP_TIMEOUT"
acceptance_config "$WORK/config"

# --- 3. Secrets, only now: everything host-side that could inherit them is
# running, and no compartment ever sees this environment. The provider key
# rides each agenthof command line; it is never exported.
export OBO_CLIENT_SECRET="$IDP_SECRET"
export E2E_TOOL_TOKEN="$TOOL_SECRET"
export AGENTHOF_OIDC_ISSUER="$ISSUER"
export AGENTHOF_OIDC_CLIENT_ID=agenthof
export AGENTHOF_OIDC_SUBJECT_TOKEN_TYPE=urn:ietf:params:oauth:token-type:id_token

AGENTHOF_GATEWAY_KEY="$GATEWAY_KEY" "$WORK/agenthof" apply --config "$WORK/config" --control-log "$WORK/control.jsonl" --as ci --groups acceptance-users
echo "apply: the combined config is valid — ok"

# start_run WORKFLOW: the run, in the background, its output to $WORK/WORKFLOW.out;
# sets RUN_PID. finish_run WORKFLOW waits for it and sets OUT, RUNID, AUDIT.
# The combined run is started this way so the children can be inspected
# while they are alive; the refused runs use run (= both, synchronously).
# Identity is the verified token, never --as: an on-behalf-of workflow under
# --as is refused before the engine, and the children inherit the token's invoker.
start_run() {
	AGENTHOF_GATEWAY_KEY="$GATEWAY_KEY" "$WORK/agenthof" run acceptance-operator "$1" --input "drive-$NONCE" --token "$TOKEN" \
		--config "$WORK/config" --log-dir "$WORK/logs" --artifact-dir "$WORK/artifacts" \
		--log-level debug >"$WORK/$1.out" 2>>"$WORK/agenthof.err" &
	RUN_PID=$!
}
finish_run() {
	wait "$RUN_PID" || true
	RUN_PID=""
	OUT="$(cat "$WORK/$1.out")"
	OUTS+=("$OUT")
	echo "$OUT"
	RUNID="$(echo "$OUT" | sed -E -n 's/^run (r-[a-f0-9]+) (finished|refused).*/\1/p')"
	[ -n "$RUNID" ] || { out_of podman logs "$ROOT_NAME" 2>&1 | tail -20; fail "no run id in the output of $1"; }
	AUDIT="$(out_of "$WORK/agenthof" audit "$RUNID" --log-dir "$WORK/logs" --control-log "$WORK/control.jsonl")"
	OUTS+=("$AUDIT")
	echo "$AUDIT"
	grep -q "ledger integrity: verified" <<<"$AUDIT" || fail "$1: ledger not verified"
}
run() { start_run "$1"; finish_run "$1"; }
ledger() { echo "$WORK/logs/$1.jsonl"; }
parent_artifact() { # $1 = run id: the full step artifact body
	local sha
	sha="$(field "$(ledger "$1")" step_succeeded artifact_sha | tail -1)"
	[ -n "$sha" ] || fail "run $1 has no step_succeeded artifact"
	[ -s "$WORK/artifacts/$sha" ] || fail "run $1 names artifact $sha, but the store holds no such body"
	cat "$WORK/artifacts/$sha"
}
provisioned_count() { out_of grep -c "set provisioned" "$WORK/refspawn.err"; }
# wait_live_children: block until BOTH sub-agent compartments of the run in
# flight are up; sets LIVE to their two names (sorted). Fewer than two in
# time is a failure of this harness's timing (raise DELAY or READY_TIMEOUT),
# never a reason to skip the inspection.
wait_live_children() {
	local i
	for i in $(seq 1 300); do
		LIVE="$(podman ps --format '{{.Names}}' --filter 'name=^agenthof-spawn-.*-acceptance-sub$' | sort)"
		[ "$(out_of grep -c . <<<"$LIVE")" = 2 ] && return 0
		kill -0 "$RUN_PID" 2>/dev/null || { cat "$WORK/acceptance.out"; fail "the combined run ended before two child compartments were seen alive at once (saw: ${LIVE:-none}); raise DELAY ($DELAY s) so a child outlives the poll"; }
		sleep 0.5
	done
	fail "two child compartments never appeared together within 150 s (saw: ${LIVE:-none}); the children's cold start is slower than READY_TIMEOUT ($READY_TIMEOUT) allows, or DELAY ($DELAY s) is too short"
}

# --- 4. The combined run: every door, one step, one human — with both
# children inspected while alive (section 4g, below).
start_run acceptance
wait_live_children
echo "live children: $LIVE"
finish_run acceptance
if ! grep -q "finished: succeeded" <<<"$OUT"; then
	out_of podman logs "$ROOT_NAME" 2>&1 | tail -40
	fail "the combined run did not succeed"
fi
echo "combined run: succeeded — ok"
echo "$ME: PASS"
