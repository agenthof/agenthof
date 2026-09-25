#!/usr/bin/env bash
# e2e-refbox: prove the reference agent finishes a run inside a compartment
# that has no network, no injected credentials, and an ephemeral workspace.
# Requires rootless podman and go. Run from the repo root.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Hermetic override. The recipe default is $XDG_RUNTIME_DIR/agenthof, which a
# systemd host provides as a user-owned tmpfs. This job does not prove that
# default is writable; it points the recipe and a rewritten copy of the demo
# config at a private directory.
SOCK_DIR="$(mktemp -d)"
export AGENTHOF_REFBOX_SOCKET_DIR="$SOCK_DIR"
WORK="$(mktemp -d)"
NAME="${REFBOX_NAME:-refbox-echo}"
HOST_PID=""
cleanup() {
	podman rm -f "$NAME" >/dev/null 2>&1 || true
	if [ -n "$HOST_PID" ]; then
		kill "$HOST_PID" >/dev/null 2>&1 || true
	fi
	rm -rf "$SOCK_DIR" "$WORK"
}
trap cleanup EXIT

unset AGENTHOF_TOKEN || true

podman build -f deploy/refbox/Containerfile -t refbox-echo:test .

# A port that is open on the host. A compartment with a route to the host
# would complete this connect; --network none must not.
HOST_IP="$(ip -4 route get 1.1.1.1 | awk '{for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit }}')"
[ -n "$HOST_IP" ] || {
	echo "no host address"
	exit 1
}
HOST_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("0.0.0.0", 0)); print(s.getsockname()[1]); s.close()')"
python3 -m http.server "$HOST_PORT" --bind "$HOST_IP" >/dev/null 2>&1 &
HOST_PID=$!
for i in $(seq 1 20); do
	python3 -c "import socket; s=socket.create_connection(('$HOST_IP', $HOST_PORT), 1); s.close()" >/dev/null 2>&1 && break
	[ "$i" = 20 ] && {
		echo "host probe port never listened"
		exit 1
	}
	sleep 0.2
done

REFBOX_DETACH=1 REFBOX_IMAGE=refbox-echo:test deploy/refbox/refbox-run.sh >/dev/null

for i in $(seq 1 30); do
	[ -S "$SOCK_DIR/refbox-echo.sock" ] && break
	[ "$i" = 30 ] && {
		echo "agent socket never appeared"
		podman logs "$NAME" || true
		exit 1
	}
	sleep 1
done

mkdir -p "$WORK/config"
cp -R deploy/refbox/config/. "$WORK/config/"
sed -i "s|/run/agenthof|$SOCK_DIR|g" \
	"$WORK/config/gateway.yaml" \
	"$WORK/config/agents/refbox-echo.yaml"

go build -o "$WORK/agenthof" ./cmd/agenthof
"$WORK/agenthof" apply --config "$WORK/config" --as ci --groups refbox-users
OUT="$("$WORK/agenthof" run refbox-operator refbox-smoke --input hi \
	--as ci --groups refbox-users --config "$WORK/config" \
	--log-dir "$WORK/logs" --artifact-dir "$WORK/artifacts")"
echo "$OUT"
echo "$OUT" | grep -q "finished: succeeded"

if podman exec "$NAME" /probe -dial 1.1.1.1:443; then
	echo "compartment reached the internet"
	exit 1
fi
if podman exec "$NAME" /probe -dial "$HOST_IP:$HOST_PORT"; then
	echo "compartment reached a host port"
	exit 1
fi

if podman inspect "$NAME" --format '{{range .Config.Env}}{{println .}}{{end}}' |
	grep -Ei 'TOKEN|SECRET|PASSWORD|API_KEY|AGENTHOF_' >/dev/null; then
	echo "compartment has credential-like environment"
	podman inspect "$NAME" --format '{{range .Config.Env}}{{println .}}{{end}}'
	exit 1
fi
if podman inspect "$NAME" --format '{{json .Mounts}}' | grep -Eq 'docker\.sock|podman\.sock'; then
	echo "compartment can see a runtime socket"
	exit 1
fi

MOUNTS="$(podman inspect "$NAME" --format '{{range .Mounts}}{{.Type}} {{.Source}} {{.Destination}}{{"\n"}}{{end}}')"
echo "$MOUNTS" | grep -q "bind $SOCK_DIR $SOCK_DIR"
BIND_COUNT="$(echo "$MOUNTS" | grep -c '^bind ' || true)"
[ "$BIND_COUNT" = 1 ] || {
	echo "unexpected binds: $MOUNTS"
	exit 1
}
podman inspect "$NAME" --format '{{json .HostConfig.Tmpfs}}' | grep -q '/work'

# A file on the tmpfs must not appear on the host, and must be gone once the
# compartment is removed (a new container gets a new tmpfs).
podman exec "$NAME" /probe -touch /work/marker
podman rm -f "$NAME" >/dev/null
if find "$SOCK_DIR" -name marker | grep -q .; then
	echo "workspace file leaked onto the host"
	exit 1
fi

echo "e2e-refbox: PASS"
