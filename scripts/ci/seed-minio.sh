#!/bin/sh
# Idempotent: safe to run multiple times. Seeds the e2e-test bucket on MinIO
# with fixture files for the Playwright E2E specs.
# -e: fail fast on any error. -u: catch typos in env-var names early
# (every variable below has a default, but unset vars from the env layer
# would otherwise expand to empty string and fail with a confusing mc error).
set -eu

MC_HOST="${MC_HOST:-http://minio:9000}"
MINIO_USER="${MINIO_USER:-minioadmin}"
MINIO_PASSWORD="${MINIO_PASSWORD:-minioadmin}"
BUCKET="${BUCKET:-e2e-test}"

mc alias set local "$MC_HOST" "$MINIO_USER" "$MINIO_PASSWORD"

# Create bucket if missing (mc mb fails if it exists; check first for idempotency)
if ! mc ls "local/$BUCKET" >/dev/null 2>&1; then
  mc mb "local/$BUCKET"
fi

# Upload the committed regular fixtures
mc cp --recursive /fixtures/ "local/$BUCKET/"

# Special-chars file: cannot be committed on Windows (NTFS forbids ':' '?').
# Generate the file inside the container and upload under the desired key.
echo "special chars regression fixture" > /tmp/special-temp.txt
mc cp /tmp/special-temp.txt "local/$BUCKET/test:colon#hash?question.txt"

# Pagination fixtures: 250 small objects so the /v2 file browser crosses a
# page boundary (items_per_page=200 in the e2e config → page 1 = 200, page 2 =
# remaining 50). Guarded for idempotency: skip if the last object already exists.
if ! mc stat "local/$BUCKET/pagination/file-250.txt" >/dev/null 2>&1; then
  mkdir -p /tmp/pagination
  i=1
  while [ "$i" -le 250 ]; do
    idx=$(printf "%03d" "$i")
    echo "seed-$idx" > "/tmp/pagination/file-$idx.txt"
    i=$((i + 1))
  done
  mc cp --recursive /tmp/pagination/ "local/$BUCKET/pagination/"
fi

echo "Seed complete:"
mc ls "local/$BUCKET"
