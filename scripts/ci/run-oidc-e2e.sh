#!/usr/bin/env bash
# Remote CI only. Raw process/browser outputs never become upload inputs.
set -euo pipefail
private_dir=$(mktemp -d)
op_pid=''
asm_pid=''
cleanup() {
  if [[ -n "$asm_pid" ]]; then kill "$asm_pid" 2>/dev/null || true; fi
  if [[ -n "$op_pid" ]]; then kill "$op_pid" 2>/dev/null || true; fi
  if [[ -n "$asm_pid" ]]; then wait "$asm_pid" 2>/dev/null || true; fi
  if [[ -n "$op_pid" ]]; then wait "$op_pid" 2>/dev/null || true; fi
  rm -rf -- "$private_dir"
}
trap cleanup EXIT INT TERM
export DATA_DIR="$private_dir/data"
mkdir -p "$DATA_DIR"
export S3_FILE_MANAGER_CONFIG="$private_dir/config.json"
export PUBLIC_URL='http://asm.oidc.test:8080'
export OIDC_ISSUER='http://op.identity.test:8091'
export OIDC_CLIENT_ID='asm'
unset OIDC_CLIENT_SECRET OIDC_CLIENT_SECRET_FILE
export OIDC_ALLOWED_PRIVATE_ORIGINS='http://op.identity.test:8091'
export OIDC_ALLOW_INSECURE_HTTP=true COOKIE_SECURE=false LOCAL_LOGIN=all
export JWT_SECRET_KEY='oidc-ci-session-secret-canary'
export ADMIN_PASSWORD='FixturePassword1'
export OIDC_E2E=1 E2E_BASE_URL="$PUBLIC_URL"
export OIDC_PRIVATE_OUTPUT="$private_dir/browser"
export NO_PROXY='asm.oidc.test,op.identity.test,127.0.0.1'
export no_proxy="$NO_PROXY"
cat > "$S3_FILE_MANAGER_CONFIG" <<'JSON'
{"roles": [], "auth": {"oidc": {"role_mapping": {"rules": [{"claim": "groups", "value": "data-team", "admin": true}]}}}}
JSON
if ! uv run pytest -o addopts= tests/test_oidc_login_integration.py tests/access/test_access_oidc_tokens.py >"$private_dir/python.log" 2>&1; then
  printf 'OIDC independent-key integration failed; sanitized tail:\n'
  python3 scripts/ci/oidc_sanitize.py "$private_dir/python.log" 60 || true
  exit 1
fi
uv run python -m tests.oidc.fake_op >"$private_dir/op.log" 2>&1 &
op_pid=$!
uv run python -m another_s3_manager.main >"$private_dir/asm.log" 2>&1 &
asm_pid=$!
ready=false
for _ in $(seq 1 60); do
  if curl --noproxy '*' -fsS "$PUBLIC_URL/api/app-info" 2>/dev/null | python -c 'import json,sys; sys.exit(not json.load(sys.stdin)["auth"]["oidc_available"])' 2>/dev/null; then
    ready=true
    break
  fi
  sleep 1
done
if [[ "$ready" != true ]]; then
  printf 'OIDC readiness failed; sanitized tails:\n'
  python3 scripts/ci/oidc_sanitize.py "$private_dir/op.log" 30 || true
  python3 scripts/ci/oidc_sanitize.py "$private_dir/asm.log" 40 || true
  exit 1
fi
result=0
(cd frontend && npx playwright test --project=oidc) >"$private_dir/browser.log" 2>&1 || result=$?
# Nothing from the private directory is uploaded, including on retry/failure.
# Check output-facing policy before emitting even a constant status summary.
if find "$private_dir/browser" -type f \( -name '*.zip' -o -name '*.webm' -o -name '*.png' -o -name '*.html' \) -print -quit 2>/dev/null | grep -q .; then
  printf 'OIDC artifact policy failed; outputs withheld.\n'
  exit 1
fi
summary='OIDC fake-provider browser checks completed.'
if printf '%s' "$summary" | grep -Eq 'oidc-ci-session-secret-canary|FixturePassword1|code=|state=|access_token'; then
  exit 1
fi
if [[ "$result" != 0 ]]; then
  printf 'OIDC browser checks failed; sanitized tails:\n'
  python3 scripts/ci/oidc_sanitize.py "$private_dir/browser.log" 80 || true
  python3 scripts/ci/oidc_sanitize.py "$private_dir/asm.log" 30 || true
  exit "$result"
fi
printf '%s\n' "$summary"
