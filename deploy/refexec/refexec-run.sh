#!/usr/bin/env bash
# refexec-run: start the reference first-hand exec runtime on the HOST. It is
# not a container: refexec invokes rootless podman itself, one compartment per
# command (--network none, --read-only, the shared workspace volume rw at the
# workspace path and nothing else), so it runs beside agenthof as the same
# user. The config validates before anything starts (-check) and reports the
# socket path and the workspace volume; this script prepares the 0700 socket
# directory and creates the volume, then hands over to refexec. Start the
# agent's refbox compartment with REFBOX_WORKSPACE_VOLUME set to the same
# volume so the command sees the agent's files. One refexec per refbox: the
# socket is never shared across compartments. Requires podman and a Linux
# host. No credential is passed in: refexec is credential-less.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${REFEXEC_BIN:-refexec}"
CONFIG="${REFEXEC_CONFIG:-$HERE/exec-config/refexec.yaml}"   # refexec's own config; config/ beside it is the Agenthof demo config

CHECK="$("$BIN" -config "$CONFIG" -check)"
socket=""; volume=""
while IFS= read -r line; do
	case "$line" in
		socket=*) socket="${line#socket=}" ;;
		workspace=*) volume="${line#workspace=}"; volume="${volume%%:*}" ;;
		*) echo "refexec-run: unexpected -check output: $line" >&2; exit 1 ;;
	esac
done <<<"$CHECK"
[ -n "$socket" ] && [ -n "$volume" ] || { echo "refexec-run: -check did not report socket and workspace" >&2; exit 1; }

# 0700: the directory is the access gate refexec insists on.
mkdir -p "$(dirname "$socket")"
chmod 0700 "$(dirname "$socket")"

# The workspace volume lives as long as the recipe: create it once, keep it
# across runs, remove it when the recipe is torn down (podman volume rm).
podman volume create --ignore "$volume" >/dev/null

exec "$BIN" -config "$CONFIG"
