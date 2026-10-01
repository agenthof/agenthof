#!/usr/bin/env bash
# refbox-run: run the reference agent in a locked-down rootless-podman
# compartment. No network. No credential environment. An ephemeral tmpfs at
# /work — or, with REFBOX_WORKSPACE_VOLUME set, a named podman volume there,
# the workspace a first-hand exec runtime (deploy/refexec) shares with this
# compartment for the recipe's lifetime. Agenthof is reached only through the
# bind-mounted socket directory. Requires podman and a Linux host. The CI job
# runs this script.
set -euo pipefail

# $XDG_RUNTIME_DIR (/run/user/<uid>) is user-owned. /run itself is root-owned,
# so a rootless mkdir of /run/agenthof fails. This default must equal
# gateway.refbox_socket_dir.
SOCK_DIR="${AGENTHOF_REFBOX_SOCKET_DIR:-${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/agenthof}"
IMAGE="${REFBOX_IMAGE:-refbox-echo:test}"
NAME="${REFBOX_NAME:-refbox-echo}"
# The agent's socket file name inside SOCK_DIR. The echo image is the default;
# another runtime's image (deploy/refbox/Containerfile.python) names its own.
SOCKET="${REFBOX_SOCKET:-refbox-echo.sock}"
# REFBOX_TIMEOUT: podman --timeout in seconds for the compartment (default 300).

mkdir -p "$SOCK_DIR"
# The socket directory must be exclusive to this one compartment. The default
# above is per-user, so this sweep does not unlink a concurrent run's live
# socket in a shared directory. A shared directory would. Stale gateway
# sockets from a killed run are orphans; the next run mints a new nonce.
# The compartment recreates the agent socket.
rm -f "$SOCK_DIR"/gw-*.sock "$SOCK_DIR/$SOCKET"

# /work is an ephemeral tmpfs unless REFBOX_WORKSPACE_VOLUME names a podman
# volume, which is then mounted there instead (created by the refexec
# launcher; removed when the recipe is torn down). Unset, nothing changes.
if [ -n "${REFBOX_WORKSPACE_VOLUME:-}" ]; then
	workspace=(-v "$REFBOX_WORKSPACE_VOLUME:/work")
else
	workspace=(--tmpfs /work)
fi

# --user is the host uid: --userns=keep-id maps that uid into the container,
# and the distroless image's own nonroot user cannot create a socket in a
# directory owned by the host user. The cgroup flags and --timeout bound a
# runaway compartment. No -e credentials are passed.
common=(
	--name "$NAME"
	--network none
	--read-only
	"${workspace[@]}"
	--cap-drop=ALL
	--security-opt no-new-privileges
	--userns=keep-id
	--user "$(id -u):$(id -g)"
	--memory=256m
	--cpus=1
	--pids-limit=64
	--timeout="${REFBOX_TIMEOUT:-300}"
	-v "$SOCK_DIR:$SOCK_DIR"
)

# Args after the image append to the entrypoint. The last -socket wins, so
# SOCK_DIR overrides the image's /run/agenthof path and matches the mount.
if [ "${REFBOX_DETACH:-}" = 1 ]; then
	podman run -d "${common[@]}" "$IMAGE" -socket "$SOCK_DIR/$SOCKET"
else
	exec podman run --rm "${common[@]}" "$IMAGE" -socket "$SOCK_DIR/$SOCKET"
fi
