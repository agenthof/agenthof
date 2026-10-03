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

# --- containment helpers. A failing probe is a REAL gap in a ref* runtime:
# print the evidence (mounts, environment NAMES — never values — and the
# compartment's log), then fail. Never retried, never relaxed.
containment_fail() { # $1 = compartment, $2.. = message
	echo "$ME: containment gap in $1 — mounts:"
	podman inspect "$1" --format '{{range .Mounts}}{{.Type}} {{.Source}} {{.Destination}}{{"\n"}}{{end}}' 2>&1 || true
	echo "$ME: environment names:"
	podman inspect "$1" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | cut -d= -f1 || true
	echo "$ME: log:"
	podman logs "$1" 2>&1 | tail -40 || true
	fail "${*:2}"
}
# no_credential_env COMPARTMENT: credential starvation — nothing credential-
# like in the compartment's environment, no runtime socket mounted. The
# hermetic run cannot make this check: its "compartments" inherit the host's
# environment. Here the environment is what podman gave the image, and the
# recipes pass no -e. Each inspection is captured, then searched: a
# `podman inspect | grep` that matched early would SIGPIPE the inspect and
# fail the pipeline under pipefail — turning a found credential name into a
# passing check, which is the one thing this must never do. An empty
# inspection is a failure too, for the same reason.
no_credential_env() {
	local names mounts
	names="$(out_of podman inspect "$1" --format '{{range .Config.Env}}{{println .}}{{end}}')"
	[ -n "$names" ] || fail "podman named no environment at all for $1, so the credential search would prove nothing"
	if grep -Eqi 'TOKEN|SECRET|PASSWORD|API_KEY|AGENTHOF_' <<<"$names"; then
		containment_fail "$1" "$1 has a credential-like name in its environment"
	fi
	mounts="$(out_of podman inspect "$1" --format '{{json .Mounts}}')"
	[ -n "$mounts" ] || fail "podman named no mounts at all for $1, so the runtime-socket search would prove nothing"
	if grep -Eq 'docker\.sock|podman\.sock' <<<"$mounts"; then
		containment_fail "$1" "$1 can see a container-runtime socket"
	fi
}
# no_egress COMPARTMENT: the probe runs (a positive control on the probe
# itself), then cannot reach the provider at the host address the gateway
# reaches it on, nor the internet. That address is live — the gateway's
# governed calls reached it (provider.jsonl) — so a failed dial is the wall,
# not a wrong address. The IdP and the upstream are deliberately not dialed:
# nothing of theirs listens on the host address (the stub issuer refuses a
# non-loopback -addr, and a tool resource's url must be loopback — see the
# header), so a failed dial to one would prove nothing.
no_egress() {
	podman exec "$1" /probe -touch /work/probe-ok || containment_fail "$1" "/probe cannot run in $1, so the negatives below would prove nothing"
	local addr
	for addr in "$HOST_IP:$PROVIDER_PORT" 1.1.1.1:443; do
		if podman exec "$1" /probe -dial "$addr"; then containment_fail "$1" "$1 reached $addr directly; the gateway socket must be its only way out"; fi
	done
}
# inspect_child NAME: a live child compartment mounts exactly its own volume
# (agenthof-spawn-<id>-work at /work) and its own socket directory, never the
# exec dir, never the root's socket dir, never the bridge's or the
# supervisor's; runs the image its agent maps to; is credential-starved;
# cannot reach its refexec's directory; has no route out; and its refexec
# is a host process. A real containment fact needing no agent cooperation.
inspect_child() {
	local name="$1" id image vols mounts
	id="${name#agenthof-spawn-}"; id="${id%-acceptance-sub}"
	# Not a bare inspection: a child that is already gone must say so, since
	# every assertion below reads the same live compartment.
	image="$(podman inspect "$name" --format '{{.ImageName}}')" || fail "podman cannot inspect child compartment $name; it was alive when the poll saw it ($LIVE) and is gone now, so raise DELAY ($DELAY s) to keep a child alive through its inspection"
	[ "$image" = "localhost/$LC_IMAGE" ] || containment_fail "$name" "child $id runs $image, not the image its agent maps to"
	vols="$(podman inspect "$name" --format '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}} {{.Destination}}{{"\n"}}{{end}}{{end}}')"
	grep -qx "agenthof-spawn-$id-work /work" <<<"$vols" || containment_fail "$name" "child $id's own volume is not the one at /work: $vols"
	[ "$(out_of grep -c . <<<"$vols")" = 1 ] || containment_fail "$name" "child $id mounts more than its own volume: $vols"
	mounts="$(podman inspect "$name" --format '{{range .Mounts}}{{.Type}} {{.Source}} {{.Destination}}{{"\n"}}{{end}}')"
	grep -q "^bind $SPAWN_ROOT/$id $SPAWN_ROOT/$id$" <<<"$mounts" || containment_fail "$name" "child $id's socket dir is not mounted at its own path: $mounts"
	[ "$(out_of grep -c '^bind ' <<<"$mounts")" = 1 ] || containment_fail "$name" "child $id has binds beyond its socket dir: $mounts"
	case "$mounts" in *-exec*) containment_fail "$name" "child $id's exec dir is mounted into its compartment: $mounts" ;; esac
	case "$mounts" in *"$SOCK_DIR"*) containment_fail "$name" "the ROOT's socket dir is mounted into child $id: $mounts" ;; esac
	case "$mounts" in *"$BRIDGE_DIR"*|*"$SUP_DIR"*|*"$EXEC_DIR"*) containment_fail "$name" "another runtime's socket dir is mounted into child $id: $mounts" ;; esac
	no_credential_env "$name"
	if podman exec "$name" /probe -touch "$SPAWN_ROOT/$id-exec/probe-was-here"; then containment_fail "$name" "child $id can reach its refexec's directory"; fi
	no_egress "$name"
	pgrep -f "refexec -config $SPAWN_ROOT/$id-exec" >/dev/null || fail "child $id's refexec is not running on the host"
	podman stats --no-stream --format 'compartment {{.Name}}: mem {{.MemUsage}} pids {{.PIDs}}' "$name" || true
	echo "child $id: own volume, own socket dir, mapped image, no exec dir, no credential, no route out — ok"
}
# nothing_left WHAT: teardown is asynchronous from the parent's side — the
# held request closes and the run ends while the supervisor removes the set
# in order afterwards — so wait, bounded, for everything the runtimes made
# to be gone, and only then say what is left.
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

# --- 4. The combined run: every door, one step, one human — with both
# children inspected while alive (section 4g, below).
start_run acceptance
wait_live_children
echo "live children: $LIVE"
# 4g. Both children, inspected while they are alive (the provider is holding
#     each one's model call): the mount scoping only a live compartment can
#     show. Their names are checked against the ledger's child ids in 4e.
for name in $LIVE; do inspect_child "$name"; done
finish_run acceptance
if ! grep -q "finished: succeeded" <<<"$OUT"; then
	out_of podman logs "$ROOT_NAME" 2>&1 | tail -40
	fail "the combined run did not succeed"
fi
PARENT="$RUNID"
L="$(ledger "$PARENT")"
grep -q "invoked by dana@example.com (oidc, issuer $ISSUER)" <<<"$AUDIT" || fail "the run is not attributed to the verified human"
bound "$L" "$PARENT" dana@example.com
[ "$(count "$L" step_succeeded)" = 1 ] || fail "expected exactly one succeeded step"
ART="$(parent_artifact "$PARENT")"
echo "$ART"
# One line per leg: model, exec, two tools, two spawns — and nothing an
# upstream's text could have added (the agent collapses each leg's output to
# one line, which is why a real `env` output is one line below).
[ "$(grep -c '' <<<"$ART")" = 6 ] || fail "the artifact is not exactly six lines (model, exec, two tool calls, two spawns)"

# 4a. The model door: one model_call, the provider's nonce'd reply in the
#     artifact — and what reached the provider: three calls so far (the
#     parent's and each child's), each with the HOST key injected (never the
#     run token), the logical model, the chat-completions route, and no
#     X-Agenthof-* header. Checked here, before the refused runs add calls.
[ "$(count "$L" model_call succeeded)" = 1 ] || fail "expected exactly one succeeded model_call on the parent"
[ "$(count "$L" model_call)" = 1 ] || fail "the parent recorded a model_call that did not succeed"
grep -qF "model fast — 3 prompt / 5 completion tokens" <<<"$AUDIT" || fail "audit did not render the model_call"
grep -qxF "model: governed:$NONCE" <<<"$ART" || fail "the artifact does not carry the provider's reply"
python3 - "$WORK/provider.jsonl" "$GATEWAY_KEY" <<'PY' || fail "the provider did not see exactly three governed calls with the host key injected"
import json, sys
lines = [json.loads(l) for l in open(sys.argv[1], encoding="utf-8") if l.strip()]
assert len(lines) == 3, "expected three provider calls (parent + two children), saw %d" % len(lines)
for r in lines:
    assert r["path"] == "/v1/chat/completions", r["path"]
    assert r["authorization"] == "Bearer " + sys.argv[2], "the provider did not see the host key"
    assert r["model"] == "fast", r["model"]
    assert not [h for h in r["headers"] if h.startswith("x-agenthof")], r["headers"]
print("provider saw: 3 calls, host key injected, model fast, /v1/chat/completions, no X-Agenthof-* headers")
PY
MODEL_LINE="$(out_of grep '"type":"model_call"' "$L")"
[ -n "$MODEL_LINE" ] || fail "no model_call line to check, so the absence below would prove nothing"
case "$MODEL_LINE" in *"governed:$NONCE"*) fail "the model reply body reached the model_call event" ;; esac

# 4b. The exec door, first-hand in a real compartment: mode runtime, refexec's
#     attestation names env and exactly the allowlisted variable as injected,
#     and the output — one artifact line, since real podman also sets PATH,
#     HOSTNAME and HOME — carries the allowlisted marker AND NOT the canary
#     that sat in refexec's own environment: the compartment's environment
#     was the allowlist, not refexec's.
[ "$(count "$L" exec succeeded)" = 1 ] || fail "expected exactly one succeeded exec"
[ "$(count "$L" exec)" = 1 ] || fail "the parent recorded an exec that did not succeed"
[ "$(field "$L" exec mode succeeded)" = runtime ] || fail "the exec is not mode runtime"
EXEC_ATT="$(field "$L" exec runtime_attestation succeeded)"
case "$EXEC_ATT" in *'"runtime": "refexec"'*) ;; *) fail "no refexec attestation on the exec" ;; esac
case "$EXEC_ATT" in *'"command": ["env"]'*) ;; *) fail "the attestation does not name env" ;; esac
case "$EXEC_ATT" in *'"env_names": ["ACCEPTANCE_E2E_MARKER"]'*) ;; *) fail "the attestation does not name exactly the allowlisted variable as injected: $EXEC_ATT" ;; esac
grep -Eq "exec env — exit 0 \(runtime\) \[runtime-attested: refexec env pid [0-9]+ spawn 1\]" <<<"$AUDIT" || fail "audit did not render the first-hand exec"
EXEC_ART_LINE="$(out_of grep '^exec: ' <<<"$ART")"
[ -n "$EXEC_ART_LINE" ] || fail "the artifact has no exec line"
grep -Eq "(^| )ACCEPTANCE_E2E_MARKER=1( |$)" <<<"$EXEC_ART_LINE" || fail "the allowlisted variable did not reach the compartment: $EXEC_ART_LINE"
case "$EXEC_ART_LINE" in *ACCEPTANCE_E2E_CANARY=*) fail "a variable NOT on env_allow reached the exec compartment from refexec's environment: $EXEC_ART_LINE" ;; esac
EXEC_LINE="$(out_of grep '"type":"exec"' "$L")"
[ -n "$EXEC_LINE" ] || fail "no exec line in the parent's ledger, so the absence check below would prove nothing"
case "$EXEC_LINE" in *ACCEPTANCE_E2E_MARKER=1*) fail "the exec output body reached the exec event" ;; esac
grep -q "compartment started" "$WORK/refexec.err" || fail "refexec logged no compartment"
echo "exec: allowlisted marker present, canary absent, attested env_names exactly the allowlist — ok"

# 4c. The tool door, on behalf of the human: the upstream answered with her
#     sub, which is in the artifact and (by design) in the tool_call preview;
#     the issuer's log shows the exchange for her, audienced to the upstream.
[ "$(tool_field "$L" whoami status)" = succeeded ] || fail "whoami did not succeed"
[ "$(tool_field "$L" whoami auth_mode)" = token_exchange ] || fail "whoami is not auth_mode token_exchange"
grep -Eq "tool whoami — args [0-9a-f]{8} \(token_exchange\)" <<<"$AUDIT" || fail "audit did not render the token_exchange call"
grep -qxF "tool whoami: acting as: u-dana" <<<"$ART" || fail "the upstream did not see the human's sub"
[ -s "$WORK/issued.jsonl" ] || fail "the issuer logged no exchanged token"
grep -q '"sub":"u-dana"' "$WORK/issued.jsonl" || fail "the issuer exchanged for nobody in particular"
grep -q "\"aud\":\"$UP_AUD\"" "$WORK/issued.jsonl" || fail "the issuer exchanged for no token audienced to the upstream"

# 4d. The tool door, bridged: refbridge's first-hand attestation names the
#     tool as it is in the bridge's image, /stdio-tool.
[ "$(tool_field "$L" echo status)" = succeeded ] || fail "echo did not succeed"
[ "$(tool_field "$L" echo auth_mode)" = static_env ] || fail "echo is not auth_mode static_env"
ECHO_ATT="$(tool_field "$L" echo runtime_attestation)"
case "$ECHO_ATT" in *'"runtime": "refbridge"'*) ;; *) fail "no refbridge attestation on the bridged call" ;; esac
grep -Eq "tool echo — args [0-9a-f]{8} \(static_env\) \[runtime-attested: refbridge /stdio-tool -credential-env DEMO_TOKEN pid [0-9]+ spawn 1\]" <<<"$AUDIT" || fail "audit did not render the bridged call's attestation"
grep -qxF "tool echo: drive-$NONCE" <<<"$ART" || fail "the bridged tool did not echo the step input"
[ "$(count "$L" tool_call)" = 2 ] || fail "expected exactly two tool_call events (one per resource)"

# 4e. The spawn door: two succeeded spawns, two children, each a governed
#     run of its own under the same human, each with its own model_call,
#     each in a compartment the supervisor provisioned — the two compartments
#     inspected alive above — overlapping in time.
[ "$(count "$L" spawn succeeded)" = 2 ] || fail "expected exactly two succeeded spawns"
[ "$(count "$L" spawn)" = 2 ] || fail "the parent recorded a spawn that did not succeed"
CHILDREN="$(field "$L" spawn child_run_id succeeded)"
[ "$(echo "$CHILDREN" | sort -u | wc -l | tr -d ' ')" = 2 ] || fail "the two spawn events do not name two distinct children"
for c in $CHILDREN; do
	CL="$(ledger "$c")"
	[ -f "$CL" ] || fail "child $c has no ledger of its own"
	bound "$CL" "$c" dana@example.com "$PARENT"
	[ "$(field "$CL" workflow_finished status)" = succeeded ] || fail "child $c did not finish succeeded"
	[ "$(count "$CL" model_call succeeded)" = 1 ] || fail "child $c did not make exactly one governed model call"
	CSHA="$(field "$CL" step_succeeded artifact_sha)"
	[ "$(cat "$WORK/artifacts/$CSHA")" = "governed:$NONCE" ] || fail "child $c's artifact is not the provider's reply"
	grep -qxF "spawn: succeeded $c governed:$NONCE" <<<"$ART" || fail "child $c's preview did not reach the parent's artifact"
	grep -q "spawn acceptance-worker/acceptance-sub → run $c succeeded (depth 1) — artifact ${CSHA:0:8}" <<<"$AUDIT" || fail "audit did not render the spawn of $c"
	grep -q "compartment started.*child=$c.*compartment=agenthof-spawn-$c-acceptance-sub" "$WORK/refspawn.err" || fail "child $c's agent did not run in a compartment the supervisor provisioned"
	grep -qx "agenthof-spawn-$c-acceptance-sub" <<<"$LIVE" || fail "child $c's compartment is not one of the two inspected alive ($LIVE)"
	CA="$(out_of "$WORK/agenthof" audit "$c" --log-dir "$WORK/logs" --control-log "$WORK/control.jsonl")"
	OUTS+=("$CA")
	grep -q "ledger integrity: verified" <<<"$CA" || fail "child $c's ledger does not verify"
	grep -q "invoked by dana@example.com (oidc, issuer $ISSUER)" <<<"$CA" || fail "child $c is not attributed to the verified human"
	grep -qF "model fast — 3 prompt / 5 completion tokens" <<<"$CA" || fail "child $c's audit shows no model_call"
done
# Parallel, by the gateway's own serialized order: both of the parent's
# "spawn started" lines precede the FIRST "spawn finished" only if the two
# children overlapped (one process, serialized by slog; match the message
# text + the raw parent run-id so this holds for --log-format text or json).
[ -f "$WORK/agenthof.err" ] || fail "no agenthof.err, so the parallel order could not be checked"
par_rc=0
awk -v parent="$PARENT" '
	index($0, "spawn started")  && index($0, parent) { started++; if (started == 2) second_start = NR }
	index($0, "spawn finished") && index($0, parent) && !first_finish { first_finish = NR }
	END {
		if (started < 2)   exit 2
		if (!first_finish) exit 3
		exit (second_start < first_finish ? 0 : 1)
	}
' "$WORK/agenthof.err" || par_rc=$?
case "$par_rc" in
	0) echo "parallel: both of the parent's spawn requests were in flight before either child returned (agenthof.err) — ok" ;;
	2) fail "the gateway logged fewer than two 'spawn started' lines for the parent run; the parallel order could not be proven" ;;
	3) fail "the gateway logged no 'spawn finished' line for the parent run; the parallel order could not be proven" ;;
	*) fail "a child's spawn finished before the second spawn started: the children ran one after another, not in parallel" ;;
esac

# 4f. The tree, merged: investigate shows the parent and both children under it.
TREE="$("$WORK/agenthof" investigate --run "$PARENT" --log-dir "$WORK/logs" --control-log "$WORK/control.jsonl")"
OUTS+=("$TREE")
echo "$TREE"
grep -q "^[0-9].* run workflow_started — dana@example.com" <<<"$TREE" || fail "investigate --run does not show the parent"
[ "$(out_of grep -c "^  [0-9].* run workflow_started — dana@example.com .*parent=$PARENT" <<<"$TREE")" = 2 ] || fail "investigate --run does not show both children under the parent"
echo "combined run: model, first-hand exec, on-behalf-of tool, bridged tool, two parallel children — one timeline, one human — ok"

# 4h. The root and the bridge, after the run: credential-starved, no route
#     out, each with exactly its own mounts — four runtimes in one run, five
#     disjoint 0700 socket directories (the gateway's, the bridge's,
#     refexec's, the supervisor's and the spawn root), nothing cross-mounted.
#     refexec's one-shot compartments are too short-lived to probe here;
#     their no-network is scripts/e2e-refexec.sh's proof.
no_credential_env "$ROOT_NAME"
no_credential_env "$BRIDGE_NAME"
ROOT_MOUNTS="$(podman inspect "$ROOT_NAME" --format '{{range .Mounts}}{{.Type}} {{.Source}} {{.Destination}}{{"\n"}}{{end}}')"
grep -q "^bind $SOCK_DIR $SOCK_DIR$" <<<"$ROOT_MOUNTS" || containment_fail "$ROOT_NAME" "the gateway socket dir is not mounted into the root at its own path: $ROOT_MOUNTS"
[ "$(out_of grep -c '^bind ' <<<"$ROOT_MOUNTS")" = 1 ] || containment_fail "$ROOT_NAME" "the root has binds beyond the socket dir: $ROOT_MOUNTS"
ROOT_VOLS="$(podman inspect "$ROOT_NAME" --format '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}} {{.Destination}}{{"\n"}}{{end}}{{end}}')"
[ "$ROOT_VOLS" = "$VOLUME /work" ] || containment_fail "$ROOT_NAME" "the root's volumes are not exactly its workspace at /work: $ROOT_VOLS"
case "$ROOT_MOUNTS" in *"$EXEC_DIR"*|*"$SUP_DIR"*|*"$SPAWN_ROOT"*|*"$BRIDGE_DIR"*) containment_fail "$ROOT_NAME" "another runtime's directory is mounted into the root: $ROOT_MOUNTS" ;; esac
if podman exec "$ROOT_NAME" /probe -touch "$SUP_DIR/probe-was-here"; then containment_fail "$ROOT_NAME" "the root can reach refspawn's directory"; fi
if podman exec "$ROOT_NAME" /probe -touch "$EXEC_DIR/probe-was-here"; then containment_fail "$ROOT_NAME" "the root can reach refexec's directory"; fi
no_egress "$ROOT_NAME"
BRIDGE_MOUNTS="$(podman inspect "$BRIDGE_NAME" --format '{{range .Mounts}}{{.Type}} {{.Source}} {{.Destination}}{{"\n"}}{{end}}')"
grep -q "^bind $BRIDGE_DIR $BRIDGE_DIR$" <<<"$BRIDGE_MOUNTS" || containment_fail "$BRIDGE_NAME" "the bridge socket dir is not mounted at its own path: $BRIDGE_MOUNTS"
grep -q "^bind $WORK/bridge-config /config$" <<<"$BRIDGE_MOUNTS" || containment_fail "$BRIDGE_NAME" "the bridge config is not mounted: $BRIDGE_MOUNTS"
[ "$(out_of grep -c '^bind ' <<<"$BRIDGE_MOUNTS")" = 2 ] || containment_fail "$BRIDGE_NAME" "the bridge has binds beyond its socket dir and config: $BRIDGE_MOUNTS"
case "$BRIDGE_MOUNTS" in *"$SOCK_DIR"*|*"$EXEC_DIR"*|*"$SUP_DIR"*|*"$SPAWN_ROOT"*) containment_fail "$BRIDGE_NAME" "another runtime's directory is mounted into the bridge: $BRIDGE_MOUNTS" ;; esac
no_egress "$BRIDGE_NAME"
for d in "$SOCK_DIR" "$BRIDGE_DIR" "$EXEC_DIR" "$SUP_DIR" "$SPAWN_ROOT"; do
	[ "$(stat -c %a "$d")" = 700 ] || fail "socket directory $d is not 0700"
done
# Measure — not assert — what the two long-lived compartments cost against
# the recipes' limits (--memory=256m, --pids-limit=64).
podman stats --no-stream --format 'compartment {{.Name}}: mem {{.MemUsage}} pids {{.PIDs}}' "$ROOT_NAME" "$BRIDGE_NAME" || true
nothing_left "after the combined run"
echo "containment: root and bridge credential-starved, no route to the provider at $HOST_IP or the internet, each with exactly its own mounts, five disjoint 0700 socket dirs, nothing left — ok"

# --- 5. The recorded refusals, each on a run of its own so the combined
# run above stays a pure positive. The driver is the same; the config is
# what says no.

# 5a. Off-allowlist exec: the driver asks for env, this agent's allowlist
#     says true. Refused before the runtime is asked, recorded, and the
#     driver stops there with its fixed reason — no tool call, no spawn.
BEFORE_EXEC="$(out_of grep -c 'compartment started' "$WORK/refexec.err")"
[ "$BEFORE_EXEC" -ge 1 ] || fail "the exec runtime logged no compartment for the combined run, so the count below would prove nothing"
run acceptance-noexec
grep -q "finished: failed" <<<"$OUT" || fail "an off-allowlist exec must fail the step"
NOEXEC="$RUNID"
LN="$(ledger "$NOEXEC")"
bound "$LN" "$NOEXEC" dana@example.com
[ "$(count "$LN" model_call succeeded)" = 1 ] || fail "the model leg before the refusal was not recorded"
[ "$(count "$LN" exec refused)" = 1 ] || fail "expected exactly one refused exec"
[ "$(count "$LN" exec)" = 1 ] || fail "the refused run recorded an exec that was not the refusal"
[ "$(field "$LN" exec reason refused)" = "command is not on the exec allowlist" ] || fail "the exec refusal is not the allowlist reason"
grep -qF "exec env refused — command is not on the exec allowlist" <<<"$AUDIT" || fail "audit did not render the exec refusal"
grep -qF "step drive (agent acceptance-noexec) failed — exec call failed" <<<"$AUDIT" || fail "the agent did not report the exec leg's fixed reason"
[ "$(count "$LN" tool_call)" = 0 ] || fail "the driver went on to the tool door after a refused exec"
[ "$(count "$LN" spawn)" = 0 ] || fail "the driver went on to the spawn door after a refused exec"
[ "$(out_of grep -c 'compartment started' "$WORK/refexec.err")" = "$BEFORE_EXEC" ] || fail "the runtime was asked to run an off-allowlist command"
echo "off-allowlist exec: refused, recorded, nothing ran, the step failed with the fixed reason — ok"

# 5b. may_spawn-denied children: the four other legs run and are recorded,
#     both spawns are refused by the door, no child starts, nothing is
#     provisioned, and the step fails with the spawn leg's fixed reason.
BEFORE="$(provisioned_count)"
[ "$BEFORE" -ge 1 ] || fail "the supervisor logged no provisioned set for the combined run, so the count below would prove nothing"
run acceptance-nospawn
grep -q "finished: failed" <<<"$OUT" || fail "a may_spawn-denied spawn must fail the step"
NOSPAWN="$RUNID"
LS="$(ledger "$NOSPAWN")"
bound "$LS" "$NOSPAWN" dana@example.com
[ "$(count "$LS" model_call succeeded)" = 1 ] || fail "the model leg was not recorded on the no-spawn run"
[ "$(count "$LS" exec succeeded)" = 1 ] || fail "the exec leg was not recorded on the no-spawn run"
[ "$(count "$LS" tool_call succeeded)" = 2 ] || fail "the two tool legs were not recorded on the no-spawn run"
[ "$(count "$LS" spawn refused)" = 2 ] || fail "expected exactly two refused spawns"
[ "$(count "$LS" spawn succeeded)" = 0 ] || fail "a child ran although nothing is on may_spawn"
[ "$(field "$LS" spawn reason refused | sort -u)" = "spawn target is not on the agent's may_spawn list" ] || fail "the spawn refusals are not the may_spawn reason"
[ -z "$(field "$LS" spawn child_run_id refused)" ] || fail "a may_spawn refusal must start no child"
[ "$(provisioned_count)" = "$BEFORE" ] || fail "a may_spawn refusal provisioned a set"
[ "$(out_of grep -cF "spawn acceptance-worker/acceptance-sub → no child run refused (depth 1) — spawn target is not on the agent's may_spawn list" <<<"$AUDIT")" = 2 ] || fail "audit did not render both spawn refusals"
grep -qF "step drive (agent acceptance-nospawn) failed — spawn call failed" <<<"$AUDIT" || fail "the agent did not report the spawn leg's fixed reason"
echo "may_spawn-denied spawns: both refused and recorded, no child, nothing provisioned, the step failed with the fixed reason — ok"
nothing_left "after the refused runs"

# --- 6. Verify is per run: the parent, each child, and each refused run,
# every one on its own. (verify_run is in scripts/acceptance-lib.sh.)
verify_run "$PARENT" "the combined run"
for c in $CHILDREN; do verify_run "$c" "a child run"; done
verify_run "$NOEXEC" "the off-allowlist run"
verify_run "$NOSPAWN" "the no-spawn run"
echo "verify: parent, both children, and both refused runs each verify on their own — ok"

# --- 7. Nothing secret reached anywhere it must not — including the
# compartments' own logs, captured here. An absence proves something only
# where the places searched are populated and the same search finds what IS
# there, so positive controls run first through the identical grep.
capture_logs
[ "$(find "$WORK/logs" -name '*.jsonl' | wc -l | tr -d ' ')" -ge 5 ] || fail "fewer ledgers than runs (parent, two children, two refusals), so the leak checks would search an incomplete tree"
[ -n "$(ls -A "$WORK/artifacts")" ] || fail "the artifact store is empty, so the leak checks would search nothing there"
[ -s "$WORK/agenthof.err" ] || fail "the operational log is empty, so the leak checks would search nothing"
grep -q "level=DEBUG" "$WORK/agenthof.err" || fail "the operational log carries no debug records"
[ -s "$WORK/control.jsonl" ] || fail "the control log is empty"
for f in provider idp upstream refexec refspawn root bridge; do
	[ -f "$WORK/$f.err" ] || fail "$WORK/$f.err is missing, so the leak checks would skip that process"
done
grep -rqF "drive-$NONCE" "$WORK/logs" "$WORK/artifacts" || fail "the positive control (the step input, echoed into a tool_call preview and the artifact) is missing, so the identical search for a secret would prove nothing"
grep -qF "listening" "$WORK/root.err" || fail "the root compartment's log is empty, so the search across compartment logs would prove nothing there"
grep -qF "session ended; child torn down" "$WORK/bridge.err" || fail "the bridge's log records no session, so the search across compartment logs would prove nothing there"
printf '%s\n' "${OUTS[@]}" >"$WORK/outs.txt"
grep -qF "spawn acceptance-worker/acceptance-sub" "$WORK/outs.txt" || fail "no captured output names a spawn, so the search below would prove nothing"
no_leak "$TOKEN" "the subject token"
no_leak "$(jwt_payload "$TOKEN")" "the subject token's payload"
no_leak "${TOKEN##*.}" "the subject token's signature"
no_leak "$IDP_SECRET" "the broker's client secret"
no_leak "$TOOL_SECRET" "the bridged tool's credential"
no_leak "$GATEWAY_KEY" "the provider key"
no_leak "canary-$NONCE" "refexec's canary variable"
EXCHANGED=0
for exchanged in $(python3 -c 'import json, sys; [print(json.loads(l)["token"]) for l in open(sys.argv[1]) if l.strip()]' "$WORK/issued.jsonl"); do
	no_leak "$exchanged" "an exchanged token"
	no_leak "$(jwt_payload "$exchanged")" "an exchanged token's payload"
	no_leak "${exchanged##*.}" "an exchanged token's signature"
	EXCHANGED=$((EXCHANGED + 1))
done
[ "$EXCHANGED" -ge 1 ] || fail "the issuer's token log named no exchanged token, so the absence check above proved nothing"
echo "no leak: subject token, $EXCHANGED exchanged token(s) (each also by its payload and signature), client secret, tool credential, provider key, exec canary — in no ledger, artifact, log, compartment log, or output — ok"
echo "$ME: PASS"
