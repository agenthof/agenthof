#!/usr/bin/env bash
# lima.sh — drive the Agenthof local test harness (a headless Ubuntu 24.04
# rootless-podman VM) on macOS. See deploy/lima/README.md.
#
#   lima.sh up                 create (first run) or start the VM
#   lima.sh shell              open a shell in the VM at the repo (/agenthof)
#   lima.sh build              compile agenthof and build the compartment images
#   lima.sh e2e [name] [--keep] run e2e(s): refbox | refbridge | all (default all)
#   lima.sh clean [--all]      prune compartment leftovers; --all drops cached images
#   lima.sh down               stop the VM (keeps it for next time)
#   lima.sh destroy            delete the VM entirely
set -euo pipefail

VM="agenthof"
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"   # deploy/lima -> repo root
YAML="$HERE/agenthof.yaml"
MOUNT="/agenthof"                    # where REPO is mounted inside the VM

die() { echo "lima.sh: $*" >&2; exit 1; }
have_vm() { limactl list -q 2>/dev/null | grep -qx "$VM"; }
require_vm() { have_vm || die "no VM named '$VM' — run 'lima.sh up' first"; }
# Run a command inside the VM at the repo, as a login shell (so /etc/profile.d/go.sh
# is on PATH). --workdir lands in the mount and avoids Lima's host-cwd mirroring.
vm() { limactl shell --workdir "$MOUNT" "$VM" -- bash -lc "$1"; }

cmd_up() {
	command -v limactl >/dev/null || die "limactl not found — install Lima (e.g. 'brew install lima')"
	if have_vm; then
		echo "starting existing VM '$VM'…"
		limactl start "$VM"
	else
		echo "creating VM '$VM' (Ubuntu 24.04, rootless podman, Go — first run provisions, several minutes)…"
		# --set injects the real repo path so agenthof.yaml stays machine-independent.
		# Foreground on purpose: backgrounding limactl start reaps the host agent.
		limactl start --name="$VM" --set ".mounts[0].location = \"$REPO\"" --tty=false "$YAML"
	fi
	# shellcheck disable=SC2016  # $(...) must expand in the guest shell, not here
	vm 'podman info >/dev/null && echo "ready: rootless podman $(podman --version | awk "{print \$3}"), $(go version 2>/dev/null || /usr/local/go/bin/go version)"'
}

cmd_shell() {
	require_vm
	# Land in the repo; a login shell picks up Go on PATH.
	exec limactl shell --workdir "$MOUNT" "$VM" -- bash -l
}

cmd_build() {
	require_vm
	echo "building agenthof + compartment images inside the VM…"
	vm "go build -o \$HOME/agenthof ./cmd/agenthof && echo 'built ~/agenthof' \
		&& podman build -f deploy/refbridge/Containerfile -t refbridge:test . \
		&& podman build -f deploy/refbox/Containerfile -t refbox-echo:test ."
	echo "done — in 'lima.sh shell', ~/agenthof is the binary; images refbridge:test and refbox-echo:test are built."
}

cmd_e2e() {
	require_vm
	local name="all" keep=0
	for a in "$@"; do
		case "$a" in
			refbox|refbridge|all) name="$a" ;;
			--keep) keep=1 ;;
			*) die "unknown e2e argument: $a (want refbox | refbridge | all [--keep])" ;;
		esac
	done
	local scripts=()
	case "$name" in
		refbox) scripts=("scripts/e2e-refbox.sh") ;;
		refbridge) scripts=("scripts/e2e-refbridge.sh") ;;
		all) scripts=("scripts/e2e-refbox.sh" "scripts/e2e-refbridge.sh") ;;
	esac
	local rc=0
	for s in "${scripts[@]}"; do
		echo "== $s =="
		vm "bash $s" || { rc=1; break; }
	done
	# Self-clean so rebuild leftovers do not pile up unnoticed (--keep opts out).
	if [ "$keep" = 1 ]; then
		echo "(--keep: skipping cleanup)"
	else
		cmd_clean
	fi
	return "$rc"
}

cmd_clean() {
	require_vm
	local all=0
	[ "${1:-}" = "--all" ] && all=1
	vm '
		echo "=== disk before ==="; podman system df
		podman container prune -f >/dev/null
		if [ '"$all"' = 1 ]; then podman image prune -af >/dev/null; else podman image prune -f >/dev/null; fi
		echo "=== disk after ==="; podman system df
	'
}

cmd_down() { require_vm; limactl stop "$VM"; }
cmd_destroy() { have_vm || { echo "no VM '$VM' to delete"; return 0; }; limactl delete -f "$VM"; }

main() {
	local sub="${1:-}"; shift || true
	case "$sub" in
		up) cmd_up "$@" ;;
		shell) cmd_shell "$@" ;;
		build) cmd_build "$@" ;;
		e2e) cmd_e2e "$@" ;;
		clean) cmd_clean "$@" ;;
		down) cmd_down "$@" ;;
		destroy) cmd_destroy "$@" ;;
		""|-h|--help|help)
			# Print the leading comment block (from line 2 to the first non-comment).
			awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "$0"
			;;
		*) die "unknown command: $sub (see 'lima.sh --help')" ;;
	esac
}
main "$@"
