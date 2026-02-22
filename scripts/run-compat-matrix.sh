#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

required_vars=(
  RS_S3_ENDPOINT
  RS_S3_REGION
  RS_S3_BUCKET
  RS_S3_ACCESS_KEY
  RS_S3_SECRET_KEY
)

for v in "${required_vars[@]}"; do
  if [[ -z "${!v:-}" ]]; then
    echo "missing required env: $v" >&2
    exit 2
  fi
done

BASE_PREFIX="${S3SYNC_MATRIX_PREFIX:-s3sync-go-compat-matrix/$(date +%Y%m%d-%H%M%S)}"
ENC_PASSWORD="${S3SYNC_MATRIX_PASSWORD:-compat-matrix-password}"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

pass_count=0
fail_count=0

run_sync() {
  local local_dir="$1"
  local prefix="$2"
  shift 2
  (
    cd "$ROOT_DIR"
    go run . sync \
      --local "$local_dir" \
      --endpoint "$RS_S3_ENDPOINT" \
      --region "$RS_S3_REGION" \
      --bucket "$RS_S3_BUCKET" \
      --access-key "$RS_S3_ACCESS_KEY" \
      --secret-key "$RS_S3_SECRET_KEY" \
      --prefix "$prefix" \
      --state-file "$local_dir/.matrix-state.json" \
      --protect-modify-percentage 100 \
      "$@"
  ) >/dev/null
}

run_check_encryption() {
  local prefix="$1"
  (
    cd "$ROOT_DIR"
    go run . check-encryption \
      --endpoint "$RS_S3_ENDPOINT" \
      --region "$RS_S3_REGION" \
      --bucket "$RS_S3_BUCKET" \
      --access-key "$RS_S3_ACCESS_KEY" \
      --secret-key "$RS_S3_SECRET_KEY" \
      --prefix "$prefix" \
      --encryption-password "$ENC_PASSWORD" \
      --encryption-method auto \
      --json
  )
}

record_result() {
  local name="$1"
  local rc="$2"
  if [[ "$rc" -eq 0 ]]; then
    pass_count=$((pass_count + 1))
    printf "[PASS] %s\n" "$name"
  else
    fail_count=$((fail_count + 1))
    printf "[FAIL] %s\n" "$name"
  fi
}

scenario_plain_create_modify_delete() {
  local name="Plain create/modify/delete A<->B"
  local prefix="$BASE_PREFIX/plain/"
  local a="$WORK_DIR/plain-a"
  local b="$WORK_DIR/plain-b"
  mkdir -p "$a/notes" "$b"

  printf "v1\n" > "$a/notes/test.md"
  run_sync "$a" "$prefix"
  run_sync "$b" "$prefix"
  [[ -f "$b/notes/test.md" ]]
  [[ "$(cat "$b/notes/test.md")" == "v1" ]]

  printf "v2-from-b\n" > "$b/notes/test.md"
  run_sync "$b" "$prefix"
  run_sync "$a" "$prefix"
  [[ "$(cat "$a/notes/test.md")" == "v2-from-b" ]]

  rm -f "$a/notes/test.md"
  run_sync "$a" "$prefix"
  run_sync "$b" "$prefix"
  [[ ! -e "$b/notes/test.md" ]]

  printf "[DETAIL] prefix=%s\n" "$prefix"
}

scenario_conflict_keep_larger() {
  local name="Conflict resolution keep_larger"
  local prefix="$BASE_PREFIX/conflict/"
  local a="$WORK_DIR/conflict-a"
  local b="$WORK_DIR/conflict-b"
  mkdir -p "$a/notes" "$b"

  printf "base\n" > "$a/notes/conflict.md"
  run_sync "$a" "$prefix"
  run_sync "$b" "$prefix"

  printf "short\n" > "$a/notes/conflict.md"
  printf "this-is-a-longer-version-from-b\n" > "$b/notes/conflict.md"

  run_sync "$a" "$prefix" --conflict-action keep_larger
  run_sync "$b" "$prefix" --conflict-action keep_larger
  run_sync "$a" "$prefix" --conflict-action keep_larger

  [[ "$(cat "$a/notes/conflict.md")" == "this-is-a-longer-version-from-b" ]]
  [[ "$(cat "$b/notes/conflict.md")" == "this-is-a-longer-version-from-b" ]]

  printf "[DETAIL] prefix=%s\n" "$prefix"
}

scenario_empty_folder_marker_roundtrip() {
  local name="Empty folder marker roundtrip"
  local prefix="$BASE_PREFIX/empty-folder/"
  local a="$WORK_DIR/folder-a"
  local b="$WORK_DIR/folder-b"
  mkdir -p "$a/empty/sub" "$b"

  run_sync "$a" "$prefix"
  run_sync "$b" "$prefix"
  [[ -d "$b/empty/sub" ]]

  rm -rf "$a/empty/sub"
  run_sync "$a" "$prefix"
  run_sync "$b" "$prefix"
  [[ ! -e "$b/empty/sub" ]]

  printf "[DETAIL] prefix=%s\n" "$prefix"
}

scenario_encrypted_roundtrip() {
  local name="Encrypted remotely-sync-base64url roundtrip"
  local prefix="$BASE_PREFIX/encrypted/"
  local a="$WORK_DIR/enc-a"
  local b="$WORK_DIR/enc-b"
  mkdir -p "$a/notes" "$b"

  printf "secret-v1\n" > "$a/notes/secure.md"
  run_sync "$a" "$prefix" --encryption-password "$ENC_PASSWORD" --encryption-method remotely-sync-base64url
  run_sync "$b" "$prefix" --encryption-password "$ENC_PASSWORD" --encryption-method remotely-sync-base64url
  [[ "$(cat "$b/notes/secure.md")" == "secret-v1" ]]

  local check_json
  check_json="$(run_check_encryption "$prefix")"
  [[ "$check_json" == *'"status":"match"'* ]]
  [[ "$check_json" == *'"method":"remotely-sync-base64url"'* ]]

  printf "[DETAIL] prefix=%s\n" "$prefix"
}

scenario_check_encryption_wrong_password() {
  local name="Check-encryption rejects wrong password"
  local prefix="$BASE_PREFIX/encrypted-wrong-password/"
  local a="$WORK_DIR/enc-wrong-a"
  mkdir -p "$a/notes"

  printf "secret-v1\n" > "$a/notes/secure.md"
  run_sync "$a" "$prefix" --encryption-password "$ENC_PASSWORD" --encryption-method remotely-sync-base64url

  set +e
  (
    cd "$ROOT_DIR"
    go run . check-encryption \
      --endpoint "$RS_S3_ENDPOINT" \
      --region "$RS_S3_REGION" \
      --bucket "$RS_S3_BUCKET" \
      --access-key "$RS_S3_ACCESS_KEY" \
      --secret-key "$RS_S3_SECRET_KEY" \
      --prefix "$prefix" \
      --encryption-password "wrong-password" \
      --encryption-method auto \
      --json >/dev/null
  )
  local rc=$?
  set -e
  [[ "$rc" -ne 0 ]]

  printf "[DETAIL] prefix=%s\n" "$prefix"
}

scenario_sync_rejects_missing_password_on_encrypted_remote() {
  local name="Sync rejects missing password on encrypted remote"
  local prefix="$BASE_PREFIX/encrypted-missing-password/"
  local a="$WORK_DIR/enc-missing-a"
  local b="$WORK_DIR/enc-missing-b"
  mkdir -p "$a/notes" "$b"

  printf "secret-v1\n" > "$a/notes/secure.md"
  run_sync "$a" "$prefix" --encryption-password "$ENC_PASSWORD" --encryption-method remotely-sync-base64url

  set +e
  (
    cd "$ROOT_DIR"
    go run . sync \
      --local "$b" \
      --endpoint "$RS_S3_ENDPOINT" \
      --region "$RS_S3_REGION" \
      --bucket "$RS_S3_BUCKET" \
      --access-key "$RS_S3_ACCESS_KEY" \
      --secret-key "$RS_S3_SECRET_KEY" \
      --prefix "$prefix" \
      --state-file "$b/.matrix-state.json" \
      --protect-modify-percentage 100 >/dev/null
  )
  local rc=$?
  set -e
  [[ "$rc" -ne 0 ]]

  printf "[DETAIL] prefix=%s\n" "$prefix"
}

run_scenario() {
  local scenario_func="$1"
  local label="$2"
  set +e
  (
    set -e
    "$scenario_func"
  )
  local rc=$?
  set -e
  record_result "$label" "$rc"
}

echo "Running compatibility matrix"
echo "Bucket: s3://$RS_S3_BUCKET/$BASE_PREFIX"

run_scenario scenario_plain_create_modify_delete "Plain create/modify/delete A<->B"
run_scenario scenario_conflict_keep_larger "Conflict resolution keep_larger"
run_scenario scenario_empty_folder_marker_roundtrip "Empty folder marker roundtrip"
run_scenario scenario_encrypted_roundtrip "Encrypted remotely-sync-base64url roundtrip"
run_scenario scenario_check_encryption_wrong_password "Check-encryption rejects wrong password"
run_scenario scenario_sync_rejects_missing_password_on_encrypted_remote "Sync rejects missing password on encrypted remote"

echo ""
echo "Matrix summary: pass=$pass_count fail=$fail_count"
if [[ "$fail_count" -gt 0 ]]; then
  exit 1
fi
