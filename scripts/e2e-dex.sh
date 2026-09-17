#!/usr/bin/env bash
# e2e-dex: prove the OIDC journey against a real dex.
# Requires: docker, curl, jq, go. Run from the repo root.
set -euo pipefail

cleanup() { docker compose -f deploy/docker-compose.yml rm -sf dex >/dev/null 2>&1 || true; }
trap cleanup EXIT
# Cleanup only stops/removes the dex container; a running litellm stack is left untouched.

# docker-compose.yml requires LITELLM_MASTER_KEY for interpolation even when
# only the dex service is targeted; this tier doesn't touch litellm, so a
# placeholder is enough.
export LITELLM_MASTER_KEY="${LITELLM_MASTER_KEY:-unused-in-dex-e2e}"

docker compose -f deploy/docker-compose.yml up -d dex

echo "waiting for dex discovery..."
for i in $(seq 1 30); do
  curl -fsS http://localhost:5556/dex/.well-known/openid-configuration >/dev/null 2>&1 && break
  [ "$i" = 30 ] && { echo "dex never became ready"; exit 1; }
  sleep 1
done

TOKEN=$(curl -fsS -X POST http://localhost:5556/dex/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "username=dana@example.com" \
  -d "password=demo1234" \
  -d "client_id=agenthof" \
  -d "scope=openid email profile" | jq -r '.id_token')
[ -n "$TOKEN" ] && [ "$TOKEN" != "null" ] || { echo "no id_token from dex"; exit 1; }

export AGENTHOF_OIDC_ISSUER=http://localhost:5556/dex
export AGENTHOF_OIDC_CLIENT_ID=agenthof

WORK=$(mktemp -d)
go run ./cmd/agenthof apply --config examples/config
OUT=$(go run ./cmd/agenthof run software-engineer fix-bug \
  --input "e2e oidc smoke" --token "$TOKEN" --executor echo \
  --config examples/config --log-dir "$WORK/logs" \
  --artifact-dir "$WORK/artifacts" --workspace "$WORK/ws")
echo "$OUT"
echo "$OUT" | grep -q "finished: succeeded"

RUNID=$(echo "$OUT" | sed -n 's/^run \(r-[a-f0-9]*\) finished.*/\1/p')
AUDIT=$(go run ./cmd/agenthof audit "$RUNID" --log-dir "$WORK/logs")
echo "$AUDIT"
echo "$AUDIT" | grep -q "invoked by dana@example.com (oidc, issuer http://localhost:5556/dex)"
echo "$AUDIT" | grep -q "ledger integrity: verified"
echo "e2e-dex: PASS"
