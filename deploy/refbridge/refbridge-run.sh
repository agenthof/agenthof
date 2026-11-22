#!/usr/bin/env bash
# refbridge-run: run the reference stdio→HTTP MCP bridge in a locked-down
# rootless-podman compartment. The bridge's socket directory is bind-mounted
# at the same path on both sides so the bridge config's `socket:` is valid
# for the bridge and for Agenthof; it must NOT be Agenthof's refbox socket
# dir (that one is mounted into agent compartments). The bridge's own config
# validates before anything starts (-check) and reports the egress allowlist:
# an empty one runs with no network at all; a non-empty one requires
# REFBRIDGE_NETWORK to name a podman network the operator restricts to those
# hosts — this recipe cannot filter egress by host itself (rootless podman,
# no CAP_NET_ADMIN). No credential is passed in: the bridge receives the tool
# credential per call from Agenthof. Requires podman and a Linux host.
set -euo pipefail

SOCK_DIR="${REFBRIDGE_SOCKET_DIR:-${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/agenthof-bridge}"
CONFIG_DIR="${REFBRIDGE_CONFIG_DIR:-$(cd "$(dirname "$0")" && pwd)/bridge-config}"   # the bridge's own config; config/ beside it is the Agenthof demo config
IMAGE="${REFBRIDGE_IMAGE:-refbridge:test}"
NAME="${REFBRIDGE_NAME:-refbridge}"

# Two ways to supply the bridge's config:
#   - a side-file directory (REFBRIDGE_CONFIG_DIR, the default), mounted whole;
#   - the governed resource spec: REFBRIDGE_GATEWAY_CONFIG (the installed
#     gateway.yaml) + REFBRIDGE_RESOURCE (the tool resource id). A host-side
#     `refbridge -project` run (REFBRIDGE_BIN) writes a slice holding only that
#     resource's launch spec, and ONLY that one file is mounted into the
#     compartment. The gateway.yaml itself is never mounted: the MCP process
#     shares the bridge's filesystem, so it must not be able to read the rest
#     of the configuration. The slice is rebuilt from the installed file on
#     every launch, at a stable per-resource path in its own 0700 directory
#     (never the socket directory), so nothing is removed from under a
#     running or detached bridge. The socket comes from the resource's
#     unix:// url; REFBRIDGE_CREDENTIAL_ENV names the variable the bridge sets
#     on the MCP process (not the resource's token_env).
if [ -n "${REFBRIDGE_GATEWAY_CONFIG:-}" ] || [ -n "${REFBRIDGE_RESOURCE:-}" ]; then
	: "${REFBRIDGE_GATEWAY_CONFIG:?refbridge-run: REFBRIDGE_GATEWAY_CONFIG and REFBRIDGE_RESOURCE must be set together}"
	: "${REFBRIDGE_RESOURCE:?refbridge-run: REFBRIDGE_GATEWAY_CONFIG and REFBRIDGE_RESOURCE must be set together}"
	if [ -n "${REFBRIDGE_CONFIG_DIR:-}" ]; then
		echo "refbridge-run: REFBRIDGE_CONFIG_DIR cannot be combined with REFBRIDGE_GATEWAY_CONFIG/REFBRIDGE_RESOURCE" >&2
		exit 1
	fi
	case "$REFBRIDGE_RESOURCE" in
		*/* | . | ..) echo "refbridge-run: REFBRIDGE_RESOURCE must be a plain resource id" >&2; exit 1 ;;
	esac
	SLICE_DIR="${REFBRIDGE_SLICE_DIR:-${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/agenthof-bridge-slice}"
	if [ "$SLICE_DIR" = "$SOCK_DIR" ]; then
		echo "refbridge-run: REFBRIDGE_SLICE_DIR must differ from the socket directory" >&2
		exit 1
	fi
	mkdir -p "$SLICE_DIR"
	chmod 0700 "$SLICE_DIR"
	SLICE="$SLICE_DIR/$REFBRIDGE_RESOURCE.yaml"
	"${REFBRIDGE_BIN:-refbridge}" -project "$REFBRIDGE_GATEWAY_CONFIG" -resource "$REFBRIDGE_RESOURCE" \
		-credential-env "${REFBRIDGE_CREDENTIAL_ENV:-DEMO_TOKEN}" -out "$SLICE"
	config_mount=(-v "$SLICE:/config/refbridge.yaml:ro")
else
	config_mount=(-v "$CONFIG_DIR:/config:ro")
fi

# 0700: the directory is the access gate the bridge insists on. With
# --userns=keep-id --user, the bridge runs as this host user, so the
# directory it checks is owned by the uid it runs as.
mkdir -p "$SOCK_DIR"
chmod 0700 "$SOCK_DIR"

# keep-id + --user: without them the image's nonroot uid maps to a subuid that
# cannot read a 0700 config directory. The image ENTRYPOINT already carries
# `-config /config/refbridge.yaml`; arguments after the image append to it.
EGRESS="$(podman run --rm --network none --userns=keep-id --user "$(id -u):$(id -g)" "${config_mount[@]}" "$IMAGE" -check)"
case "$EGRESS" in
	egress=none) network=(--network none) ;;
	egress=*)
		if [ -z "${REFBRIDGE_NETWORK:-}" ]; then
			echo "refbridge-run: $EGRESS — set REFBRIDGE_NETWORK to a podman network you restrict to exactly those hosts" >&2
			exit 1
		fi
		network=(--network "$REFBRIDGE_NETWORK") ;;
	*) echo "refbridge-run: unexpected -check output: $EGRESS" >&2; exit 1 ;;
esac

common=(
	--name "$NAME"
	"${network[@]}"
	--read-only
	--tmpfs /work
	--cap-drop=ALL
	--security-opt no-new-privileges
	--userns=keep-id
	--user "$(id -u):$(id -g)"
	--memory=256m
	--cpus=1
	--pids-limit=64
	-v "$SOCK_DIR:$SOCK_DIR"
	"${config_mount[@]}"
)

if [ "${REFBRIDGE_DETACH:-}" = 1 ]; then
	podman run -d "${common[@]}" "$IMAGE"
else
	exec podman run --rm "${common[@]}" "$IMAGE"
fi
