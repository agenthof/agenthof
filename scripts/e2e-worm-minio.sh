#!/usr/bin/env bash
# e2e-worm-minio: prove `sink: worm` against a real MinIO with S3 Object Lock —
# the one tier that exercises the SigV4 client and the compliance lock against
# a real implementation rather than the in-process fake.
#
# seal → verify (0) → delete the local segment → verify (1: missing locally)
# → restore → verify (0) → an admin delete of the locked version REFUSED by
# compliance → verify (0) → seal until three segments exist → delete every
# sealed file and the manifest → rebuild from the sink → verify (0) → every
# rebuilt file byte-identical to what was sealed, the manifest included.
#
# MinIO's community edition is distributed as source only (no published
# container images), so both the server and the mc client are built with
# `go install` at a pinned release tag; the Go module proxy resolves each tag
# to an immutable pseudo-version, which is the pin.
#
# Requires: go, jq, curl, sha256sum. Run from the repo root. WORM_PORT selects
# the port MinIO listens on (default 9000); KEEP=1 keeps the work directory.
set -euo pipefail

MINIO_VERSION=RELEASE.2025-10-15T17-29-55Z
MC_VERSION=RELEASE.2025-08-13T08-35-41Z

PORT="${WORM_PORT:-9000}"
ENDPOINT="http://127.0.0.1:$PORT"
BUCKET=agenthof-worm
PREFIX=agenthof
SINK_URL="$ENDPOINT/$BUCKET/$PREFIX"
CFG=examples/config
AS=(--as dana@example.com --groups platform-eng)

WORK=$(mktemp -d)
MINIO_PID=""
cleanup() {
  if [ -n "$MINIO_PID" ]; then
    kill "$MINIO_PID" >/dev/null 2>&1 || true
    wait "$MINIO_PID" 2>/dev/null || true # let it finish writing before its directory goes
  fi
  [ "${KEEP:-0}" = 1 ] && { echo "kept: $WORK"; return 0; }
  rm -rf "$WORK" || true
}
trap cleanup EXIT

fail() { echo "e2e-worm-minio: $*"; exit 1; }

# run <step> <expected exit> <command...>: runs the command, echoes its
# output, and fails naming the step unless it exited as expected. The output
# is left in $OUT for the caller's own checks.
OUT=""
run() {
  local step=$1 want=$2 code=0
  shift 2
  OUT=$("$@" 2>&1) || code=$?
  printf '%s\n' "$OUT"
  [ "$code" = "$want" ] || fail "$step: exit $code, want $want"
}
# expect <step> <pattern>: $OUT must contain a line matching the pattern.
expect() {
  grep -Eq -- "$2" <<<"$OUT" || fail "$1: output lacks /$2/"
}

if curl -fsS -o /dev/null "$ENDPOINT/minio/health/ready" 2>/dev/null; then
  fail "something already listens on $ENDPOINT; set WORM_PORT to a free port"
fi

# --- the binaries ---
export GOBIN="$WORK/bin"
echo "building minio $MINIO_VERSION and mc $MC_VERSION..."
go install "github.com/minio/minio@$MINIO_VERSION"
go install "github.com/minio/mc@$MC_VERSION"
go build -o "$WORK/agenthof" ./cmd/agenthof
AH="$WORK/agenthof"
MC=("$GOBIN/mc" --quiet --no-color)
export MC_CONFIG_DIR="$WORK/mc"

# --- the server, with the root credential ---
export MINIO_ROOT_USER=minioadmin MINIO_ROOT_PASSWORD=minioadmin MINIO_BROWSER=off
"$GOBIN/minio" server "$WORK/data" --address "127.0.0.1:$PORT" >"$WORK/minio.log" 2>&1 &
MINIO_PID=$!
echo "waiting for minio..."
for i in $(seq 1 30); do
  # ready, not live: live answers before IAM is initialised, and the user
  # and policy setup below needs IAM.
  curl -fsS -o /dev/null "$ENDPOINT/minio/health/ready" 2>/dev/null && break
  [ "$i" = 30 ] && { cat "$WORK/minio.log"; fail "minio never became ready"; }
  sleep 1
done

# A bucket with Object Lock, and a key pair scoped to what the seal needs:
# write (a PUT that carries the lock headers also needs PutObjectRetention),
# read back, list versions, read the lock, read the bucket's lock
# configuration. Nothing that deletes.
"${MC[@]}" alias set local "$ENDPOINT" minioadmin minioadmin
"${MC[@]}" mb --with-lock "local/$BUCKET"
"${MC[@]}" admin user add local worm-seal worm-seal-secret-12345
cat >"$WORK/worm-seal-policy.json" <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "s3:PutObject",
      "s3:PutObjectRetention",
      "s3:GetObject",
      "s3:ListBucketVersions",
      "s3:GetObjectRetention",
      "s3:GetBucketObjectLockConfiguration"
    ],
    "Resource": ["arn:aws:s3:::$BUCKET", "arn:aws:s3:::$BUCKET/*"]
  }]
}
EOF
"${MC[@]}" admin policy create local worm-seal-policy "$WORK/worm-seal-policy.json"
"${MC[@]}" admin policy attach local worm-seal-policy --user worm-seal

# --- the posture, beside the ledger ---
CTL="$WORK/control.jsonl"
cat >"$WORK/integrity.yaml" <<EOF
sink: worm
sink_backend:
  kind: s3-object-lock
  url: $SINK_URL
  region: us-east-1
  mode: compliance
  retention: 1d
  credential:
    credential_source: static_env
    client_auth: sigv4
    client_id_env: AGENTHOF_WORM_ACCESS_KEY_ID
    client_secret_env: AGENTHOF_WORM_SECRET_ACCESS_KEY
EOF
export AGENTHOF_WORM_ACCESS_KEY_ID=worm-seal AGENTHOF_WORM_SECRET_ACCESS_KEY=worm-seal-secret-12345

# --- seal, verify, lose the local segment, verify, restore, verify ---
run "apply" 0 "$AH" apply --config "$CFG" --control-log "$CTL" "${AS[@]}"
# The ledger's identity is minted on the genesis, which the first seal moves
# into segment 1: read it now, before anything is deleted.
LOG_ID=$(head -1 "$CTL" | jq -r .log_id)
[[ "$LOG_ID" =~ ^[0-9a-f]{32}$ ]] || fail "genesis: log_id $LOG_ID is not 32 hex characters"
echo "log id: $LOG_ID"
KEY1="$PREFIX/$LOG_ID/seg-000001"

run "disable coder" 0 "$AH" registry disable coder --config "$CFG" --control-log "$CTL" "${AS[@]}"
run "seal 1" 0 "$AH" audit seal --control-log "$CTL" "${AS[@]}"
expect "seal 1" "^protected: s3-object-lock $SINK_URL key=$KEY1 version=[^ ]+ compliance until "
expect "seal 1" "^sealed: segment 1 seq=1\.\.3 "
VID1=$(printf '%s\n' "$OUT" | sed -n 's/^protected: [^ ]* [^ ]* key=[^ ]* version=\([^ ]*\) .*/\1/p')
[ -n "$VID1" ] || fail "seal 1: no version id on the protected: line"

run "verify after seal" 0 "$AH" audit verify control --control-log "$CTL"
expect "verify after seal" "^      verified — oldest version $VID1 compliance until "
expect "verify after seal" "^protected copies: 1 \(1 verified, 0 missing, 0 mismatch, 0 under-locked, 0 unverifiable\); sink holds 1 objects for this ledger, 1 accounted for"

sha256sum "$CTL.seg-000001" >"$WORK/seg1.sha256"
rm "$CTL.seg-000001"
run "verify with segment 1 missing locally" 1 "$AH" audit verify control --control-log "$CTL"
expect "verify with segment 1 missing locally" "^control ledger segment 1 missing: the manifest lists control.jsonl.seg-000001 and it does not exist"

run "restore segment 1" 0 "$AH" audit restore control --control-log "$CTL" --config "$CFG" "${AS[@]}"
expect "restore segment 1" "^restored: segment 1 from s3-object-lock $SINK_URL version=$VID1 sha256=[0-9a-f]{64} \(nothing was there\)"
expect "restore segment 1" "^control head: seq=4 "
run "restored segment 1 byte-identical" 0 sha256sum -c "$WORK/seg1.sha256"

run "verify after restore" 0 "$AH" audit verify control --control-log "$CTL"
expect "verify after restore" "^protected copies: 1 \(1 verified, 0 missing, 0 mismatch, 0 under-locked, 0 unverifiable\)"

# --- the lock: even the root credential cannot remove the locked version ---
run "stat the locked version" 0 "${MC[@]}" stat --version-id "$VID1" "local/$BUCKET/$KEY1"
code=0
RM_OUT=$("${MC[@]}" rm --version-id "$VID1" "local/$BUCKET/$KEY1" 2>&1) || code=$?
printf '%s\n' "$RM_OUT"
[ "$code" != 0 ] || fail "admin delete of the locked version: mc rm exited 0; compliance did not hold"
grep -qi 'WORM protected' <<<"$RM_OUT" || fail "admin delete of the locked version: refusal does not name the lock"
run "stat the locked version after the refused delete" 0 "${MC[@]}" stat --version-id "$VID1" "local/$BUCKET/$KEY1"
run "verify after the refused delete" 0 "$AH" audit verify control --control-log "$CTL"
expect "verify after the refused delete" "^protected copies: 1 \(1 verified, "

# --- the rebuild: three segments, every sealed file and the manifest lost ---
run "enable coder" 0 "$AH" registry enable coder --config "$CFG" --control-log "$CTL" "${AS[@]}"
run "seal 2" 0 "$AH" audit seal --control-log "$CTL" "${AS[@]}"
expect "seal 2" "^sealed: segment 2 seq=4\.\.6 "
run "disable coder again" 0 "$AH" registry disable coder --config "$CFG" --control-log "$CTL" "${AS[@]}"
run "seal 3" 0 "$AH" audit seal --control-log "$CTL" "${AS[@]}"
expect "seal 3" "^sealed: segment 3 seq=7\.\.8 "

SEALED=("$CTL.seg-000001" "$CTL.seg-000002" "$CTL.seg-000003" "$CTL.segments")
sha256sum "${SEALED[@]}" >"$WORK/sealed.sha256"
cat "$WORK/sealed.sha256"
rm "${SEALED[@]}"

run "rebuild" 0 "$AH" audit restore control --rebuild --log-id "$LOG_ID" --control-log "$CTL" --config "$CFG" "${AS[@]}"
expect "rebuild" "^rebuilt: segments 1–3 from s3-object-lock $SINK_URL \(3 written, 0 replaced\)$"
expect "rebuild" "^control head: seq=9 "

run "verify after rebuild" 0 "$AH" audit verify control --control-log "$CTL"
expect "verify after rebuild" "^protected copies: 3 \(3 verified, 0 missing, 0 mismatch, 0 under-locked, 0 unverifiable\); sink holds 3 objects for this ledger, 3 accounted for"

run "rebuilt files byte-identical" 0 sha256sum -c "$WORK/sealed.sha256"
echo "e2e-worm-minio: PASS"
