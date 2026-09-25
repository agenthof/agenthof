#!/usr/bin/env bash
# refbox-run: run the reference agent in a locked-down rootless-podman
# compartment. No network. No credential environment. An ephemeral tmpfs at
# /work. Agenthof is reached only through the bind-mounted socket directory.
# Requires podman and a Linux host. The CI job runs this script.
set -euo pipefail

SOCK_DIR="${AGENTHOF_REFBOX_SOCKET_DIR:-/run/agenthof}" # must match gateway.refbox_socket_dir
IMAGE="${REFBOX_IMAGE:-refbox-echo:test}"
NAME="${REFBOX_NAME:-refbox-echo}"

mkdir -p "$SOCK_DIR"
# Stale gateway sockets from a killed run are orphans; the next run mints a
# new nonce. The compartment recreates the agent socket.
rm -f "$SOCK_DIR"/gw-*.sock "$SOCK_DIR/refbox-echo.sock"

# --user is the host uid: --userns=keep-id maps that uid into the container,
# and the distroless image's own nonroot user cannot create a socket in a
# directory owned by the host user. The cgroup flags and --timeout bound a
# runaway compartment. No -e credentials are passed.
common=(
	--name "$NAME"
	--network none
	--read-only
	--tmpfs /work
	--cap-drop=ALL
	--security-opt no-new-privileges
	--userns=keep-id
	--user "$(id -u):$(id -g)"
	--memory=256m
	--cpus=1
	--pids-limit=64
	--timeout=300
	-v "$SOCK_DIR:$SOCK_DIR"
)

# Args after the image append to the entrypoint. The last -socket wins, so a
# socket directory other than /run/agenthof still matches the mount.
if [ "${REFBOX_DETACH:-}" = 1 ]; then
	podman run -d "${common[@]}" "$IMAGE" -socket "$SOCK_DIR/refbox-echo.sock"
else
	exec podman run --rm "${common[@]}" "$IMAGE" -socket "$SOCK_DIR/refbox-echo.sock"
fi
