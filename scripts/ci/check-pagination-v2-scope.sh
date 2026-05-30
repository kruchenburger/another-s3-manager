#!/usr/bin/env bash
# Enforce that the feat/pagination-v2 PR only touches files in the whitelist
# from specs/2026-05-29-pagination-v2-design.md. Run on every commit in the
# PR diff against release/1.0.0.

set -euo pipefail

BASE="${1:-origin/release/1.0.0}"

# Whitelist patterns — anything NOT matching one of these is a scope violation.
# Patterns are extended-regex, matched against the full diff path from repo root.
ALLOW_PATTERNS=(
  # Backend — paginated S3 helper + route branch
  '^src/another_s3_manager/s3_client\.py$'
  '^src/another_s3_manager/main\.py$'
  # Backend tests
  '^tests/test_pagination_v2\.py$'
  # Direct-call tests for list_files broke when new Query() params landed —
  # they invoke the handler as a coroutine, so unspecified args defaulted to
  # the Query sentinel object instead of None. Two-line fix per test to pass
  # max_keys=None + continuation_token=None explicitly. No behaviour change.
  '^tests/test_main_logic\.py$'
  # Frontend types + new config hook + paginated API client + useInfiniteQuery
  '^frontend/src/types/api\.ts$'
  '^frontend/src/hooks/useConfig\.ts$'
  '^frontend/src/features/files/api/filesApi\.ts$'
  '^frontend/src/features/files/hooks/useFiles\.ts$'
  # FileBrowser shell + table/grid sentinel slots
  '^frontend/src/components/FileBrowser/FileBrowser\.tsx$'
  '^frontend/src/components/FileBrowser/FileTable\.tsx$'
  '^frontend/src/components/FileBrowser/FileGrid\.tsx$'
  # Frontend tests
  '^frontend/tests/component/useConfig\.test\.tsx$'
  '^frontend/tests/component/useFiles\.test\.tsx$'
  '^frontend/tests/component/FileBrowser\.pagination\.test\.tsx$'
  # Stale useFiles mocks in pre-existing FileBrowser tests — every mock returns
  # the legacy `{files, total_count, path}` shape. After Task 8 (useInfiniteQuery)
  # they break with `Cannot read 'pages' of undefined`. Two-line fix per file:
  # swap the mock to `{pages: [{directories, files, next_token, has_more}]}` and
  # add `useConfig` mock so FileBrowser's `pageSize` default works. No logic change.
  '^frontend/tests/component/FileBrowser\.download\.test\.tsx$'
  '^frontend/tests/component/FileBrowser\.copyUrl\.test\.tsx$'
  '^frontend/tests/component/FileBrowser\.error\.test\.tsx$'
  '^frontend/tests/component/FileBrowser\.upload\.test\.tsx$'
  # E2E — pagination spec + the shared mc seed script gains a pagination/ block.
  # The plan originally proposed an @aws-sdk/client-s3 TS seed fixture, but the
  # project seeds MinIO via `mc` (scripts/ci/seed-minio.sh, run by both CI and
  # docker-compose.minio.yml). Extending that script is idiomatic and avoids a
  # new aws-sdk dependency just for tests.
  '^frontend/tests/e2e/file-pagination\.spec\.ts$'
  '^scripts/ci/seed-minio\.sh$'
  # Frontend package manifest may receive react-intersection-observer + aws-sdk
  '^frontend/package\.json$'
  '^frontend/package-lock\.json$'
  # CI infra
  '^scripts/ci/check-pagination-v2-scope\.sh$'
  '^\.github/workflows/ci\.yml$'
)

changed_files="$(git diff --name-only "$BASE"...HEAD)"
if [ -z "$changed_files" ]; then
  echo "scope-guard: no files changed against $BASE"
  exit 0
fi

violations=()
while IFS= read -r path; do
  matched=0
  for pattern in "${ALLOW_PATTERNS[@]}"; do
    if [[ "$path" =~ $pattern ]]; then
      matched=1
      break
    fi
  done
  if [ "$matched" -eq 0 ]; then
    violations+=("$path")
  fi
done <<< "$changed_files"

if [ "${#violations[@]}" -gt 0 ]; then
  echo "scope-guard: ${#violations[@]} file(s) changed outside the pagination-v2 whitelist:"
  printf '  - %s\n' "${violations[@]}"
  echo
  echo "If this is intentional, update the whitelist in $0 and explain why in the PR."
  exit 1
fi

echo "scope-guard: all changed file(s) are within whitelist."
