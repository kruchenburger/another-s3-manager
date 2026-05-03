#!/bin/sh
# Idempotent: safe to run multiple times. Seeds the e2e-test bucket on MinIO
# with fixture files for the Playwright E2E specs.
set -e

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

echo "Seed complete:"
mc ls "local/$BUCKET"
