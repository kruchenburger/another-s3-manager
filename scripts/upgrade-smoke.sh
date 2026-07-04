#!/usr/bin/env bash
# Upgrade smoke test: prove the last published vanilla-era release upgrades to
# the current image SEAMLESSLY — same data volume, same env file; the only
# thing that changes is the image tag.
#
# Exercises the real upgrade seams:
#   - users.json (v0.1.x file store) -> SQLite auto-migration on first boot
#   - config.json written by v0.1.x (items_per_page et al) loads + migrates
#   - the removed ITEMS_PER_PAGE env var still set in .env -> ignored, no crash
#   - vanilla URLs (/, /login, /admin) now served by the SPA (HTTP 200)
#   - bare /mcp still reachable (307 -> /mcp/), unknown /api/* -> JSON 404
#   - old users log in with their old passwords after the DB migration
#
# Usage:
#   docker build -t another-s3-manager-app .          # build the NEW image
#   bash scripts/upgrade-smoke.sh
#
# Overrides: OLD_IMAGE (default ghcr.io/kruchenburger/another-s3-manager:latest,
# which is v0.1.2 — the last pre-Phase-7 release), NEW_IMAGE, PORT.
set -euo pipefail

OLD_IMAGE="${OLD_IMAGE:-ghcr.io/kruchenburger/another-s3-manager:latest}"
NEW_IMAGE="${NEW_IMAGE:-another-s3-manager-app:latest}"
PORT="${PORT:-18081}"
BASE="http://localhost:${PORT}"
NAME="asm-upgrade-smoke"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Repo-relative bind mount: resolves identically under git-bash and Linux.
DATA_DIR="${ROOT}/.upgrade-smoke-data"
# Under git-bash, MSYS rewrites colon-separated POSIX paths in `docker run -v`
# into a broken Windows spec (the mount silently never happens). Hand docker a
# Windows-style path and disable the rewriting FOR DOCKER ONLY — a global
# export would break curl/mktemp, which rely on the normal path conversion.
if command -v cygpath >/dev/null 2>&1; then
  HOST_DATA_DIR="$(cygpath -m "$DATA_DIR")"
else
  HOST_DATA_DIR="$DATA_DIR"
fi
dockerw() { MSYS_NO_PATHCONV=1 docker "$@"; }

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); echo "  ok: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $1"; }
check() { # check <desc> <expected> <actual>
  if [ "$2" = "$3" ]; then ok "$1"; else fail "$1 (expected '$2', got '$3')"; fi
}
code() { curl -s -o /dev/null -w '%{http_code}' "$1"; }

cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  # Phase-1 files may be root-owned (v0.1.x image ran as root) — wipe from a
  # container so the cleanup works on Linux hosts without sudo.
  dockerw run --rm -v "${HOST_DATA_DIR}:/wipe" alpine sh -c 'rm -rf /wipe/* /wipe/.[!.]* 2>/dev/null || true' >/dev/null 2>&1 || true
  rmdir "${DATA_DIR}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_health() {
  for _ in $(seq 1 60); do
    if [ "$(code "$BASE/health")" = "200" ]; then return 0; fi
    sleep 1
  done
  echo "health check timed out; last container logs:"
  docker logs "$NAME" 2>&1 | tail -40
  exit 1
}

# Same env for BOTH phases — including ITEMS_PER_PAGE, which the new version
# removed: a real user's .env keeps the line, and the app must just ignore it.
# DATA_DIR + S3_FILE_MANAGER_CONFIG mirror what docker-compose.yml has set
# since v0.1.x — that's the deployment contract this test upgrades within.
ENV_ARGS=(
  -e JWT_SECRET_KEY=upgrade-smoke-secret
  -e ADMIN_PASSWORD=UpgradeTest1
  -e COOKIE_SECURE=false
  -e ITEMS_PER_PAGE=200
  -e DATA_DIR=/app/data
  -e S3_FILE_MANAGER_CONFIG=/app/data/config.json
)

rm -rf "${DATA_DIR}" 2>/dev/null || true
mkdir -p "${DATA_DIR}"

echo "== Phase 1: seed real state on the OLD image ($OLD_IMAGE)"
dockerw run -d --name "$NAME" -p "${PORT}:8080" -v "${HOST_DATA_DIR}:/app/data" \
  "${ENV_ARGS[@]}" "$OLD_IMAGE" >/dev/null
wait_health
check "old /health" 200 "$(code "$BASE/health")"
if curl -s "$BASE/" | grep -q "static/script.js"; then
  ok "old / is the vanilla page"
else
  fail "old / is not the vanilla page"
fi

# v0.1.x login: form-encoded, bearer token + csrf token in the response body.
LOGIN_JSON="$(curl -s -X POST "$BASE/api/login" -d 'username=admin' -d 'password=UpgradeTest1')"
TOKEN="$(printf '%s' "$LOGIN_JSON" | sed -n 's/.*"access_token": *"\([^"]*\)".*/\1/p')"
CSRF="$(printf '%s' "$LOGIN_JSON" | sed -n 's/.*"csrf_token": *"\([^"]*\)".*/\1/p')"
if [ -z "$TOKEN" ]; then
  echo "FATAL: admin login on the old image failed: $LOGIN_JSON"
  exit 1
fi
ok "old admin login (bearer)"

# A second user proves the users.json -> SQLite migration end-to-end.
check "old image: create user smokeuser" 200 "$(
  curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/admin/users" \
    -H "Authorization: Bearer $TOKEN" -H "X-CSRF-Token: $CSRF" \
    -F username=smokeuser -F password=UpgradeTest2 \
    -F is_admin=false -F allowed_roles=SmokeRole
)"
# A role + items_per_page land in config.json exactly as a v0.1.x install has them.
check "old image: save config with SmokeRole" 200 "$(
  curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/config" \
    -H "Authorization: Bearer $TOKEN" -H "X-CSRF-Token: $CSRF" \
    -H 'Content-Type: application/json' \
    -d '{"roles":[{"name":"SmokeRole","type":"credentials","access_key_id":"AKIAUPGRADESMOKE0000","secret_access_key":"upgrade-smoke-secret-key"},{"name":"Default","type":"default"}],"items_per_page":200}'
)"

if grep -q '"items_per_page"' "${DATA_DIR}/config.json"; then
  ok "config.json contains items_per_page (v0.1.x fixture)"
else
  fail "config.json is missing the items_per_page fixture key"
fi
if [ -f "${DATA_DIR}/users.json" ]; then
  ok "users.json exists (file-store era)"
else
  fail "users.json missing — old image did not use the file store?"
fi

docker rm -f "$NAME" >/dev/null

# The v0.1.x image ran as root; the current image runs as uid 1001. A real
# upgrade via docker-compose gets this fixed by the init-data sidecar — mirror
# that here so the test models the documented upgrade path.
# (sh -c keeps git-bash's MSYS path mangling away from the container path)
dockerw run --rm -v "${HOST_DATA_DIR}:/app/data" alpine sh -c 'chown -R 1001:1001 /app/data' >/dev/null

echo "== Phase 2: SAME volume + env, only the image changes ($NEW_IMAGE)"
dockerw run -d --name "$NAME" -p "${PORT}:8080" -v "${HOST_DATA_DIR}:/app/data" \
  "${ENV_ARGS[@]}" "$NEW_IMAGE" >/dev/null
wait_health
check "new /health" 200 "$(code "$BASE/health")"

if curl -s "$BASE/" | grep -q 'id="root"'; then
  ok "/ serves the SPA"
else
  fail "/ does not serve the SPA"
fi
check "vanilla bookmark /login serves the SPA" 200 "$(code "$BASE/login")"
check "vanilla bookmark /admin serves the SPA" 200 "$(code "$BASE/admin")"
check "unknown /api/* is a 404 (not the SPA)" 404 "$(code "$BASE/api/definitely-missing")"
check "bare /mcp redirects to /mcp/ (307)" 307 "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/mcp")"

# users.json -> SQLite migration: both users log in with their OLD passwords.
check "admin login after upgrade" 200 "$(
  curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/login" \
    -d 'username=admin' -d 'password=UpgradeTest1'
)"
check "migrated user (smokeuser) login after upgrade" 200 "$(
  curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/login" \
    -d 'username=smokeuser' -d 'password=UpgradeTest2'
)"
if ls "${DATA_DIR}"/users.json.migrated.bak >/dev/null 2>&1; then
  ok "users.json renamed to users.json.migrated.bak"
else
  fail "users.json was not migrated/renamed"
fi

# Admin API through the new cookie auth: the role survived; the API no longer
# exposes items_per_page; the stale key stays on disk until the next save.
COOKIES="$(mktemp)"
curl -s -c "$COOKIES" -o /dev/null -X POST "$BASE/api/login" \
  -d 'username=admin' -d 'password=UpgradeTest1'
CONFIG_JSON="$(curl -s -b "$COOKIES" "$BASE/api/config")"
rm -f "$COOKIES"
if printf '%s' "$CONFIG_JSON" | grep -q '"SmokeRole"'; then
  ok "SmokeRole survived the upgrade"
else
  fail "SmokeRole missing from /api/config after upgrade"
fi
if printf '%s' "$CONFIG_JSON" | grep -q 'items_per_page'; then
  fail "/api/config still exposes items_per_page"
else
  ok "/api/config no longer exposes items_per_page"
fi
if grep -q '"items_per_page"' "${DATA_DIR}/config.json"; then
  ok "stale items_per_page still on disk (dropped on the next admin save)"
else
  fail "stale key vanished from config.json without an admin save"
fi

echo
echo "upgrade-smoke: PASS=${PASS} FAIL=${FAIL}"
[ "$FAIL" = "0" ]
