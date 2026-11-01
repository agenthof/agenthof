#!/usr/bin/env bash
# refexec-run-seatbelt: start the reference first-hand exec runtime on a macOS
# HOST, confined by the Seatbelt backend (confiner: seatbelt). The sibling of
# refexec-run.sh: where that one creates a podman volume, this one creates the
# workspace store as a plain directory, because Seatbelt shares the host
# filesystem rather than mounting a volume. The config validates before
# anything starts (-check) and reports the socket path, the store name and the
# store's host directory; this script prepares the 0700 socket directory and
# the 0700 store directory, then hands over to refexec. No credential is passed
# in: refexec is credential-less.
set -euo pipefail

BIN="${REFEXEC_BIN:-refexec}"
CONFIG="${REFEXEC_CONFIG:?set REFEXEC_CONFIG to a refexec config with confiner: seatbelt}"

CHECK="$("$BIN" -config "$CONFIG" -check)"
socket=""; store_path=""
while IFS= read -r line; do
	case "$line" in
		socket=*) socket="${line#socket=}" ;;
		workspace=*) ;;   # the store name; the directory to create is store_path
		store_path=*) store_path="${line#store_path=}" ;;
		*) echo "refexec-run-seatbelt: unexpected -check output: $line" >&2; exit 1 ;;
	esac
done <<<"$CHECK"
[ -n "$socket" ] && [ -n "$store_path" ] || { echo "refexec-run-seatbelt: -check did not report socket and store_path" >&2; exit 1; }

# 0700: the directory is the access gate refexec insists on.
mkdir -p -m 0700 "$(dirname "$socket")"

# The workspace store lives as long as the recipe: create it once, keep it
# across runs, remove the directory when the recipe is torn down.
mkdir -p -m 0700 "$store_path"

exec "$BIN" -config "$CONFIG"
