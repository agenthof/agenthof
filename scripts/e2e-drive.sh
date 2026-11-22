#!/usr/bin/env bash
# e2e-drive: prove the governed Drive read against REAL Google — the one tier
# that runs the pinned @piotr-agier/google-drive-mcp (fronted by refbridge,
# governed by the agenthof BINARY through the tool door) with a real Google
# credential. Everything runs on one Linux host (inside the Lima VM on macOS):
#   - the AGENT runs CONTAINED: a refbox compartment (--network none) from a
#     drive-agent image with /probe. It holds no credential and has no route
#     to Google; its only way out is the gateway socket;
#   - the BRIDGE and the real MCP run as host processes that hold the Google
#     credential (three variables passed through refbridge's allowlist) and
#     talk to real Google.
# Asserts, in order:
#   0. (before anything starts) the three GOOGLE_* variables and the fixture
#      are all set — an absent credential or fixture FAILS, never skips;
#   1. the minted token's granted scopes, read from Google's tokeninfo, are all
#      read-only;
#   2. the contained agent's search then read returns the fixture note's text;
#      the ledger carries two refbridge-attested tool_call events, verifies,
#      and accounts for itself;
#   3. the attested environment NAMES are exactly the bearer variable plus the
#      three passthrough variables (a variable refbridge silently dropped
#      would make the MCP fall back to its browser OAuth flow);
#   4. containment: /probe works in the compartment (positive control), a dial
#      to Google's address (an IP resolved on the HOST, never a hostname) hits
#      the wall while the host itself reaches it, and no GOOGLE_* name is in
#      the compartment's environment;
#   5. downloadFile, absent from the named read-only grant, is refused by name
#      with no resource or attestation recorded;
#   6. a real upstream error (an id that does not exist) and a real OAuth
#      failure (a bogus refresh token) fail their runs, and none of the three
#      passthrough values, the placeholder bearer, the bogus token or any
#      `access_token` is in any ledger, artifact, control log, process log, the
#      full result the agent received, or the scope check's output.
# BY JUDGMENT, local only — never CI (real credentials, real Google, real
# podman). Needs rootless podman, go, python3, curl, node and npm.
#
# Required environment (unset -> exit 1 with a message, before any work):
#   GOOGLE_DRIVE_MCP_REFRESH_TOKEN  GOOGLE_DRIVE_MCP_CLIENT_ID
#   GOOGLE_DRIVE_MCP_CLIENT_SECRET  the real, read-only Google credential
#   DRIVE_E2E_NOTE_ID               id of the fixture Google Doc
#   DRIVE_E2E_NOTE_NAME             its title (the search query; no ';')
#   DRIVE_E2E_EXPECTED_TEXT         a substring its text must contain
# Optional:
#   DRIVE_MCP_INDEX   absolute path of an installed dist/index.js of the pinned
#                     MCP (e.g. /opt/google-drive-mcp/dist/index.js); unset, the
#                     pinned version is installed into the scratch directory
#                     with --ignore-scripts. Always launched as `node <abs>`,
#                     never through npx.
# On macOS run it inside the Lima VM (deploy/lima). --keep (or KEEP=1) keeps the
# compartment and the scratch directories.
set -euo pipefail

ME="e2e-drive"
MCP_PKG="@piotr-agier/google-drive-mcp@2.13.0"
IMAGE="localhost/agenthof-drive-agent:e2e"
CNAME="refbox-drive-e2e"

KEEP="${KEEP:-0}"
for a in "$@"; do
	case "$a" in
	--keep) KEEP=1 ;;
	*)
		echo "$ME: unknown argument: $a (want: [--keep])" >&2
		exit 2
		;;
	esac
done

fail() {
	echo "$ME: FAIL — $*" >&2
	exit 1
}

# --- 0. preflight: fail clearly, never skip. Checked before anything is created.
missing=()
for v in GOOGLE_DRIVE_MCP_REFRESH_TOKEN GOOGLE_DRIVE_MCP_CLIENT_ID GOOGLE_DRIVE_MCP_CLIENT_SECRET \
	DRIVE_E2E_NOTE_ID DRIVE_E2E_NOTE_NAME DRIVE_E2E_EXPECTED_TEXT; do
	[ -n "${!v:-}" ] || missing+=("$v")
done
if [ "${#missing[@]}" -gt 0 ]; then
	echo "$ME: FAIL — this real-backend run needs a real Google credential and a fixture note; unset: ${missing[*]}." >&2
	echo "$ME: it never skips: an absent credential or fixture is a failure. See the header of scripts/e2e-drive.sh." >&2
	exit 1
fi
case "$DRIVE_E2E_NOTE_NAME" in
*";"*) fail "DRIVE_E2E_NOTE_NAME must not contain ';' (it is the agent script's search query)" ;;
esac
for tool in podman go python3 curl node npm; do
	command -v "$tool" >/dev/null 2>&1 || fail "$tool is required (rootless podman; run inside the Lima VM on macOS)"
done
[ "$(uname)" = Linux ] || fail "run on Linux (inside the Lima VM on macOS): the agent is a real podman compartment"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=acceptance-lib.sh
. "$ROOT/scripts/acceptance-lib.sh"

# Short on purpose: Unix socket paths have a small OS length limit.
SOCK_DIR="$(mktemp -d /tmp/dv.XXXXXX)"    # gateway + agent sockets (mounted into the compartment)
BRIDGE_DIR="$(mktemp -d /tmp/dvb.XXXXXX)" # refbridge sockets (0700, never mounted)
WORK="$(mktemp -d /tmp/dvw.XXXXXX)"
chmod 0700 "$BRIDGE_DIR"
PIDS=()
OUTS=()
cleanup() {
	local rc=$?
	if [ "$KEEP" = 1 ]; then
		echo "kept: compartment '$CNAME', dirs $SOCK_DIR $BRIDGE_DIR $WORK, pids ${PIDS[*]-none}"
		return 0
	fi
	for p in ${PIDS[@]+"${PIDS[@]}"}; do
		kill "$p" >/dev/null 2>&1 || true
		wait "$p" >/dev/null 2>&1 || true
	done
	podman rm -f "$CNAME" >/dev/null 2>&1 || true
	rm -rf "$SOCK_DIR" "$BRIDGE_DIR" "$WORK" || true
	return "$rc"
}
trap cleanup EXIT
unset AGENTHOF_TOKEN || true

runid_of() { printf '%s\n' "$1" | sed -n 's/^run \(r-[a-f0-9]*\) finished.*/\1/p'; }

NODE_BIN="$(command -v node)"
case "$NODE_BIN" in /*) ;; *) fail "node did not resolve to an absolute path: $NODE_BIN" ;; esac

# --- the pinned MCP, launched as an absolute `node <abs>/dist/index.js`.
if [ -n "${DRIVE_MCP_INDEX:-}" ]; then
	MCP_INDEX="$DRIVE_MCP_INDEX"
else
	echo "installing $MCP_PKG (no lifecycle scripts)..."
	mkdir -p "$WORK/mcp"
	(cd "$WORK/mcp" && npm init -y >/dev/null && npm install --ignore-scripts --no-audit --no-fund "$MCP_PKG" >"$WORK/npm.out" 2>&1) \
		|| {
			cat "$WORK/npm.out" >&2 || true
			fail "could not install $MCP_PKG"
		}
	MCP_INDEX="$WORK/mcp/node_modules/@piotr-agier/google-drive-mcp/dist/index.js"
fi
case "$MCP_INDEX" in /*) ;; *) fail "the MCP entry point must be an absolute path: $MCP_INDEX" ;; esac
[ -f "$MCP_INDEX" ] || fail "the MCP entry point does not exist: $MCP_INDEX"

# --- binaries and the contained agent image.
echo "building agenthof, refbridge, drive-agent and the compartment image..."
go build -o "$WORK/agenthof" ./cmd/agenthof
go build -o "$WORK/refbridge" ./deploy/refbridge
cat >"$WORK/Containerfile" <<'EOF'
FROM docker.io/library/golang:1.27.2 AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY examples/drive-agent ./examples/drive-agent
COPY deploy/refbox/probe ./deploy/refbox/probe
RUN CGO_ENABLED=0 go build -o /out/drive-agent ./examples/drive-agent \
	&& CGO_ENABLED=0 go build -o /out/probe ./deploy/refbox/probe

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/drive-agent /drive-agent
COPY --from=build /out/probe /probe
ENTRYPOINT ["/drive-agent", "-socket", "/run/agenthof/agent.sock"]
EOF
podman build -q -t "$IMAGE" -f "$WORK/Containerfile" "$ROOT" >/dev/null || fail "could not build the compartment image"

NONCE="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
BEARER="placeholder-bearer-$NONCE"      # the tool resource's own bearer: not the Google credential
BAD_REFRESH="bogus-refresh-token-$NONCE" # for the OAuth-failure path only
export DRIVE_BRIDGE_BEARER="$BEARER" # the tool resource resolves its bearer from agenthof's own environment
export AGENTHOF_GATEWAY_KEY="host-side-dummy-key-$NONCE" # the model route is never called; the key only lets it resolve
REFRESH="$GOOGLE_DRIVE_MCP_REFRESH_TOKEN"
CLIENT_ID="$GOOGLE_DRIVE_MCP_CLIENT_ID"
CLIENT_SECRET="$GOOGLE_DRIVE_MCP_CLIENT_SECRET"

# --- 1. scope check: the minted token's granted scopes must all be
# read-only. The token itself is never written anywhere: only the scope names
# are, and that file is a leak-scan target at the end.
echo "checking the minted token's scopes with Google's tokeninfo..."
GOOGLE_DRIVE_MCP_REFRESH_TOKEN="$REFRESH" GOOGLE_DRIVE_MCP_CLIENT_ID="$CLIENT_ID" GOOGLE_DRIVE_MCP_CLIENT_SECRET="$CLIENT_SECRET" \
	python3 - "$WORK/scope-check.out" <<'PY' || fail "the scope check failed (see above): the credential must mint a token whose scopes are all read-only"
import json, os, sys, urllib.parse, urllib.request

def post(url, fields):
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)

tok = post("https://oauth2.googleapis.com/token", {
    "grant_type": "refresh_token",
    "refresh_token": os.environ["GOOGLE_DRIVE_MCP_REFRESH_TOKEN"],
    "client_id": os.environ["GOOGLE_DRIVE_MCP_CLIENT_ID"],
    "client_secret": os.environ["GOOGLE_DRIVE_MCP_CLIENT_SECRET"],
})
info = post("https://oauth2.googleapis.com/tokeninfo", {"access_token": tok["access_token"]})
scopes = info.get("scope", "").split()
with open(sys.argv[1], "w") as f:
    for s in scopes:
        f.write(s + "\n")
if not scopes:
    print("tokeninfo reported no scopes")
    sys.exit(1)
bad = [s for s in scopes if not s.endswith(".readonly")]
if bad:
    print("scopes that are not read-only: " + " ".join(bad))
    sys.exit(1)
print("granted scopes (all read-only): " + " ".join(scopes))
PY
echo "scopes: every granted scope is read-only — ok"

# --- the real MCP behind a refbridge (host processes holding the credential).
# start_bridge NAME REFRESH: the bridge for resource NAME, the MCP's refresh
# token being REFRESH (the real one, or the bogus one for the OAuth-failure path).
start_bridge() {
	local name="$1" refresh="$2"
	cat >"$WORK/bridge-$name.yaml" <<EOF
socket: $BRIDGE_DIR/$name.sock
command: ["$NODE_BIN", "$MCP_INDEX"]
credential:
  env: DRIVE_BRIDGE_BEARER
  materialization: env-at-spawn
env_passthrough: [GOOGLE_DRIVE_MCP_REFRESH_TOKEN, GOOGLE_DRIVE_MCP_CLIENT_ID, GOOGLE_DRIVE_MCP_CLIENT_SECRET]
egress:
  allow: [www.googleapis.com:443, oauth2.googleapis.com:443]
sessions:
  max: 4
  idle_timeout: 10m
  max_lifetime: 30m
EOF
	GOOGLE_DRIVE_MCP_REFRESH_TOKEN="$refresh" GOOGLE_DRIVE_MCP_CLIENT_ID="$CLIENT_ID" \
		GOOGLE_DRIVE_MCP_CLIENT_SECRET="$CLIENT_SECRET" DRIVE_BRIDGE_BEARER="$BEARER" \
		"$WORK/refbridge" -config "$WORK/bridge-$name.yaml" 2>"$WORK/bridge-$name.err" &
	PIDS+=($!)
	local i
	for i in $(seq 1 60); do
		[ -S "$BRIDGE_DIR/$name.sock" ] && return 0
		sleep 0.5
	done
	cat "$WORK/bridge-$name.err" >&2 || true
	fail "the $name bridge socket never appeared"
}
start_bridge drive "$REFRESH"
start_bridge driveauth "$BAD_REFRESH"

# --- the contained agent: a refbox compartment, --network none, no credential.
AGENTHOF_REFBOX_SOCKET_DIR="$SOCK_DIR" REFBOX_IMAGE="$IMAGE" REFBOX_NAME="$CNAME" REFBOX_SOCKET=agent.sock \
	REFBOX_DETACH=1 REFBOX_TIMEOUT=1800 deploy/refbox/refbox-run.sh >/dev/null || fail "the compartment did not start"
for i in $(seq 1 60); do
	[ -S "$SOCK_DIR/agent.sock" ] && break
	[ "$i" = 60 ] && {
		podman logs "$CNAME" >&2 || true
		fail "the agent socket never appeared"
	}
	sleep 0.5
done

# --- the Agenthof config (written from scratch).
mkdir -p "$WORK/config/agents" "$WORK/config/workflows" "$WORK/config/roles" "$WORK/logs" "$WORK/artifacts"
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
  driveauth:
    kind: mcp
    url: unix://$BRIDGE_DIR/driveauth.sock
    runtime: refbridge
    credential_source: static_env
    token_env: DRIVE_BRIDGE_BEARER
    read_only_tools: [search, readGoogleDoc]
EOF
for r in drive driveauth; do
	cat >"$WORK/config/agents/$r-reader.yaml" <<EOF
name: $r-reader
description: Reads Drive through the tool door with a named read-only grant (real-backend e2e)
model: fast
instruction: Run the drive script.
output: reply
execution: fronted
endpoint: unix://$SOCK_DIR/agent.sock
tools:
  - resource: $r
    tools: [search, readGoogleDoc]
    mode: read-only
EOF
	cat >"$WORK/config/workflows/$r-read.yaml" <<EOF
name: $r-read
description: One step as the $r reader
steps:
  - name: call
    agent: $r-reader
EOF
done
cat >"$WORK/config/roles/drive-operator.yaml" <<EOF
name: drive-operator
description: Runs the drive real-backend e2e workflows
workflows: [drive-read, driveauth-read]
allowed_groups: ["drive-users"]
control: [apply]
EOF
"$WORK/agenthof" apply --config "$WORK/config" --control-log "$WORK/control.jsonl" --as ci --groups drive-users >/dev/null

run() { # $1 = workflow, $2 = step input
	"$WORK/agenthof" run drive-operator "$1" --input "$2" \
		--as ci --groups drive-users --config "$WORK/config" --control-log "$WORK/control.jsonl" \
		--log-dir "$WORK/logs" --artifact-dir "$WORK/artifacts"
}
audit() { "$WORK/agenthof" audit "$1" --log-dir "$WORK/logs" --control-log "$WORK/control.jsonl"; }
check_audit() { # $1 = run id, $2 = what; sets AUDIT_OUT
	AUDIT_OUT="$(audit "$1")"
	echo "$AUDIT_OUT"
	OUTS+=("$AUDIT_OUT")
	grep -q "ledger integrity: verified" <<<"$AUDIT_OUT" || fail "$2 ledger not verified"
	grep -q "ledger completeness: complete (" <<<"$AUDIT_OUT" || fail "$2 ledger does not account for itself"
}

# --- 2. governed read: the CONTAINED agent searches then reads the fixture note.
OUT1="$(run drive-read "search $DRIVE_E2E_NOTE_NAME; read $DRIVE_E2E_NOTE_ID" 2>"$WORK/run1.err")" || {
	cat "$WORK/run1.err" "$WORK/bridge-drive.err" >&2 || true
	fail "the governed read run failed"
}
echo "$OUT1"
OUTS+=("$OUT1")
grep -q "finished: succeeded" <<<"$OUT1" || fail "the governed read did not succeed"
RUNID1="$(runid_of "$OUT1")"
[ -n "$RUNID1" ] || fail "no run id for the governed read"
check_audit "$RUNID1" "governed read"
LEDGER1="$WORK/logs/$RUNID1.jsonl"
accounted "$LEDGER1"
[ "$(grep -c '"runtime_attestation":{"runtime":"refbridge"' "$LEDGER1")" = 2 ] || fail "want two attested tool_call events (search, read)"
ATTESTED="\\[runtime-attested: refbridge $(ere_escape "$NODE_BIN") "
[ "$(grep -Ec "tool search — args [0-9a-f]{8} \(static_env\) $ATTESTED" <<<"$AUDIT_OUT")" = 1 ] || fail "audit does not render the attested search call"
[ "$(grep -Ec "tool readGoogleDoc — args [0-9a-f]{8} \(static_env\) $ATTESTED" <<<"$AUDIT_OUT")" = 1 ] || fail "audit does not render the attested readGoogleDoc call"
ART1="$(grep -rlF -- "$DRIVE_E2E_EXPECTED_TEXT" "$WORK/artifacts" | head -n1 || true)"
[ -n "$ART1" ] || fail "the artifact does not carry the fixture note's expected text"
grep -qF -- "$DRIVE_E2E_NOTE_ID" "$ART1" || fail "the search result does not carry the fixture note's id"
echo "governed read: the contained agent read the fixture note; two attested tool_call events — ok"

# --- 3. env names: the bearer plus the three passthrough variables, exactly.
ENV_JSON='"env_names":["DRIVE_BRIDGE_BEARER","GOOGLE_DRIVE_MCP_CLIENT_ID","GOOGLE_DRIVE_MCP_CLIENT_SECRET","GOOGLE_DRIVE_MCP_REFRESH_TOKEN"]'
[ "$(grep -cF "$ENV_JSON" "$LEDGER1")" = 2 ] || fail "want env_names of exactly the bearer plus the three Google variables on both tool_call events (a dropped variable would send the MCP to a browser OAuth flow)"
echo "env names: the three Google variables and the bearer are attested on both events — ok"

# --- 4. containment: no route from the compartment to Google, no credential in it.
GOOGLE_IP="$(python3 -c 'import socket; print(socket.getaddrinfo("www.googleapis.com", 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0])' 2>/dev/null || true)"
[ -n "$GOOGLE_IP" ] || fail "could not resolve www.googleapis.com on the host, so the dial below would name nothing"
# The host reaches that address: so a refused dial from the compartment is the wall, not a dead address.
python3 - "$GOOGLE_IP" <<'PY' || fail "the host itself cannot reach $GOOGLE_IP:443, so a refused dial from the compartment would prove nothing"
import socket, sys
socket.create_connection((sys.argv[1], 443), timeout=5).close()
PY
# Positive control on the probe itself, then the wall. rc 1 = the probe ran and was refused;
# rc 0 = it got through; anything else = the compartment is gone (never read as "contained").
podman exec "$CNAME" /probe -touch /work/probe-ok || fail "/probe cannot run in the compartment, so the dial below would prove nothing"
rc=0
podman exec "$CNAME" /probe -dial "$GOOGLE_IP:443" || rc=$?
case "$rc" in
0) fail "the contained agent reached Google at $GOOGLE_IP:443 directly; the gateway socket must be its only way out" ;;
1) ;;
*) fail "the compartment vanished mid-inspection (podman exec rc=$rc)" ;;
esac
cenv="$(out_of podman inspect "$CNAME" --format '{{range .Config.Env}}{{println .}}{{end}}')"
[ -n "$cenv" ] || fail "podman named no environment at all for the compartment, so the credential search would prove nothing"
if grep -Eqi 'GOOGLE|TOKEN|SECRET|PASSWORD|API_KEY|AGENTHOF_|DRIVE_BRIDGE' <<<"$cenv"; then
	fail "the compartment has a credential-like name in its environment"
fi
cmounts="$(out_of podman inspect "$CNAME" --format '{{json .Mounts}}')"
[ -n "$cmounts" ] || fail "podman named no mounts at all for the compartment, so the bridge-directory search would prove nothing"
case "$cmounts" in *"$BRIDGE_DIR"*) fail "the bridge's socket directory is mounted into the compartment" ;; esac
echo "containment: /probe ran; the dial to $GOOGLE_IP:443 hit the wall; no credential name in the compartment — ok"

# --- 5. downloadFile is absent from the named grant: refused by name.
if OUT2="$(run drive-read "call downloadFile fileId=$DRIVE_E2E_NOTE_ID localPath=/tmp/y" 2>"$WORK/run2.err")"; then
	fail "downloadFile was not refused"
fi
echo "$OUT2"
OUTS+=("$OUT2")
grep -q "finished: failed" <<<"$OUT2" || fail "the refused run did not finish failed"
RUNID2="$(runid_of "$OUT2")"
[ -n "$RUNID2" ] || fail "no run id for the refused run"
check_audit "$RUNID2" "refused run"
grep -q "tool downloadFile refused — tool is not available to this run" <<<"$AUDIT_OUT" || fail "downloadFile was not refused with the grant reason"
if grep -q '"runtime_attestation"' "$WORK/logs/$RUNID2.jsonl"; then fail "the refused call recorded an attested tool_call"; fi
if grep -q '"resources_touched"' "$WORK/logs/$RUNID2.jsonl"; then fail "the refused call recorded a touched resource"; fi
echo "named grant: downloadFile refused by name; no resource or attestation — ok"

# --- 6. real failures: an upstream error (a document id that does not exist)
# and an OAuth failure (a bogus refresh token) must each fail the run and leak nothing.
if OUT3="$(run drive-read "read no-such-document-$NONCE" 2>"$WORK/run3.err")"; then
	fail "a read of a nonexistent document did not fail the step"
fi
echo "$OUT3"
OUTS+=("$OUT3")
RUNID3="$(runid_of "$OUT3")"
[ -n "$RUNID3" ] || fail "no run id for the bad-id run"
grep -q "finished: failed" <<<"$OUT3" || fail "the bad-id run did not finish failed"
check_audit "$RUNID3" "bad-id run"
# The failure must come from the real upstream: a failed, attested readGoogleDoc
# call with a recorded reason, not any other way a run can fail.
python3 - "$WORK/logs/$RUNID3.jsonl" <<'PY' || fail "the bad-id run has no failed, attested readGoogleDoc tool_call with a reason: the failure did not come from the MCP"
import json, sys
for line in open(sys.argv[1]):
    if not line.strip():
        continue
    e = json.loads(line)
    if e.get("type") == "tool_call" and e.get("tool") == "readGoogleDoc" and e.get("status") != "ok" \
            and e.get("reason") and (e.get("runtime_attestation") or {}).get("runtime") == "refbridge":
        sys.exit(0)
sys.exit(1)
PY
podman logs "$CNAME" >"$WORK/agent.err" 2>&1 || true
[ "$(grep -c 'drive-agent: tool call failed' "$WORK/agent.err")" = 2 ] || fail "want two failed-call lines in the agent's log after the refused and bad-id runs"
echo "upstream error: a real Google error failed the run, ledger verified — ok"

T0=$SECONDS
if OUT4="$(run driveauth-read "read $DRIVE_E2E_NOTE_ID" 2>"$WORK/run4.err")"; then
	fail "a read with a bogus refresh token did not fail the step"
fi
echo "$OUT4"
OUTS+=("$OUT4")
RUNID4="$(runid_of "$OUT4")"
[ -n "$RUNID4" ] || fail "no run id for the OAuth-failure run"
check_audit "$RUNID4" "OAuth-failure run"
# The MCP must have REJECTED the credential, not hung: its child was started,
# the run ended well inside the agent's 240s budget, and the agent's failure
# is not a timeout.
grep -q "child spawned" "$WORK/bridge-driveauth.err" || fail "the driveauth child never started, so the failure did not come from the MCP"
[ $((SECONDS - T0)) -lt 200 ] || fail "the OAuth-failure run took $((SECONDS - T0))s: the MCP hung rather than rejecting the credential"
podman logs "$CNAME" >"$WORK/agent.err" 2>&1 || true
[ "$(grep -c 'drive-agent: tool call failed' "$WORK/agent.err")" = 3 ] || fail "want three failed-call lines in the agent's log after the OAuth-failure run"
if grep 'drive-agent: tool call failed' "$WORK/agent.err" | tail -n1 | grep -Eqi 'deadline exceeded|timed out|timeout'; then
	fail "the OAuth-failure run ended on a timeout: the MCP hung rather than rejecting the credential"
fi
echo "OAuth failure: a real OAuth rejection failed the run, ledger verified — ok"

# --- 7. leak scan. The agent's log is captured from the
# compartment first; the artifacts hold the full result the agent received.
[ -s "$WORK/agent.err" ] || fail "the agent's log is empty, so scanning the error results it received would prove nothing"
printf '%s\n' "${OUTS[@]}" >"$WORK/outs.txt"
leak() { # $1 = value, $2 = what
	no_leak "$1" "$2"
	if grep -qF -- "$1" "$WORK/scope-check.out"; then fail "$2 reached the scope check's output"; fi
}
leak "$REFRESH" "the refresh-token value"
leak "$CLIENT_ID" "the client-id value"
leak "$CLIENT_SECRET" "the client-secret value"
leak "$BEARER" "the placeholder bearer"
leak "$BAD_REFRESH" "the bogus refresh-token value"
if grep -rqi -- "access_token" "$WORK/logs" "$WORK/artifacts" "$WORK/control.jsonl" "$WORK"/*.err "$WORK/scope-check.out" "$WORK/outs.txt"; then
	fail "an access_token reached a ledger, an artifact, the control log, a process log, an output, or the scope check's output"
fi
echo "no credential value, placeholder bearer, or access_token in any ledger, artifact, log, agent result, or the scope check — ok"

echo "$ME: PASS (real Google: a contained agent read the fixture note through the governed tool door; the credential stayed outside the compartment)"
