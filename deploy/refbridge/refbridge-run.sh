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

# 0700: the directory is the access gate the bridge insists on. With
# --userns=keep-id --user, the bridge runs as this host user, so the
# directory it checks is owned by the uid it runs as.
mkdir -p "$SOCK_DIR"
chmod 0700 "$SOCK_DIR"

# keep-id + --user: without them the image's nonroot uid maps to a subuid that
# cannot read a 0700 config directory. The image ENTRYPOINT already carries
# `-config /config/refbridge.yaml`; arguments after the image append to it.
EGRESS="$(podman run --rm --network none --userns=keep-id --user "$(id -u):$(id -g)" -v "$CONFIG_DIR:/config:ro" "$IMAGE" -check)"
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
	-v "$CONFIG_DIR:/config:ro"
)

if [ "${REFBRIDGE_DETACH:-}" = 1 ]; then
	podman run -d "${common[@]}" "$IMAGE"
else
	exec podman run --rm "${common[@]}" "$IMAGE"
fi
