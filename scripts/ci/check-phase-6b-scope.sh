#!/usr/bin/env bash
# Enforce that the Phase 6b PR only touches files in the whitelist from
# specs/2026-05-20-phase-6b-redesign-design.md §2. Run on every commit
# in the PR diff against release/1.0.0.

set -euo pipefail

BASE="${1:-origin/release/1.0.0}"

# Whitelist patterns — anything NOT matching one of these is a scope violation.
# Patterns are extended-regex, matched against the full diff path from repo root.
ALLOW_PATTERNS=(
  '^frontend/src/app/theme\.ts$'
  '^frontend/src/app/themeVariants\.ts$'
  '^frontend/src/components/AppShell/AppShellLayout\.tsx$'
  '^frontend/src/app/ThemePreviewProvider\.tsx$'
  '^frontend/src/app/App\.tsx$'
  '^frontend/src/app/providers\.tsx$'
  '^frontend/src/app/global\.css$'
  '^frontend/src/components/DevThemeSwitcher/'
  '^frontend/src/components/CubeLogo/'
  '^frontend/src/components/BurgerLogo/'
  '^frontend/src/components/Sidebar/.*\.(module\.css|tsx)$'
  '^frontend/src/components/FileBrowser/.*\.module\.css$'
  '^frontend/src/components/AppShell/AppHeader\.tsx$'
  '^frontend/src/pages/HomePage/HomePage\.tsx$'
  '^frontend/src/pages/LoginPage/.*$'
  '^frontend/src/pages/Errors/.*\.tsx$'
  # Error/forbidden pages live directly under pages/ in this codebase,
  # not under pages/Errors/ — adjust the whitelist to match reality.
  '^frontend/src/pages/ForbiddenPage\.tsx$'
  '^frontend/src/pages/NotFoundPage\.tsx$'
  # BurgerLogo replacement also touches these shared shell components.
  '^frontend/src/components/AuthGuard/.*\.tsx$'
  '^frontend/src/components/EmptyState/.*\.tsx$'
  '^frontend/src/components/ErrorBoundary/.*\.tsx$'
  # Component tests live under tests/component/, not co-located in src/.
  '^frontend/tests/component/.*\.test\.tsx$'
  '^frontend/tests/unit/.*\.test\.(ts|tsx)$'
  '^frontend/src/setupTests\.ts$'
  '^frontend/src/components/FileBrowser/FileBrowserHeader\.tsx$'
  '^frontend/src/components/Admin/AdminTableHeader\.tsx$'
  '^frontend/src/pages/SettingsPage/SettingsPage\.tsx$'
  '^frontend/src/pages/admin/SettingsPage\.tsx$'
  '^frontend/src/components/Admin/AdminUserDrawer\.tsx$'
  '^frontend/src/components/Admin/AdminRoleWizard\.tsx$'
  '^scripts/ci/check-phase-6b-scope\.sh$'
  '^scripts/ci/check-prod-bundle\.sh$'
  '^scripts/build/generate-favicon\.py$'
  '^src/another_s3_manager/static/favicon\.ico$'
  '^\.github/workflows/ci\.yml$'
  '^frontend/src/.*\.test\.(ts|tsx)$'
  '^frontend/tests/e2e/visual-regression\.spec\.ts$'
  '^frontend/tests/e2e/fixtures/a11y-helpers\.ts$'
  '^frontend/tests/e2e/visual-regression\.spec\.ts-snapshots/'
  '^pyproject\.toml$'
  '^uv\.lock$'
  # Dockerfile + docker-compose accept the VITE_SHOW_THEME_SWITCHER build-arg
  # so the floating dev theme switcher can be opted into a production smoke build.
  '^Dockerfile$'
  '^docker-compose\.yml$'
  # Upload components — color tokens swapped from hardcoded amber to
  # theme-driven primary (otherwise the progress bar and drag overlay
  # lost their fill when amber stopped being the active palette).
  '^frontend/src/components/Upload/UploadDropZone\.tsx$'
  '^frontend/src/components/Upload/UploadProgress\.tsx$'
  # FileBrowser cells/cards — folder icon colour was hardcoded amber-6;
  # also FileBrowser.tsx wires the bulk-delete batch-invalidation fix.
  '^frontend/src/components/FileBrowser/FileRow\.tsx$'
  '^frontend/src/components/FileBrowser/FileCard\.tsx$'
  '^frontend/src/components/FileBrowser/FileBrowser\.tsx$'
  '^frontend/src/components/FileBrowser/BulkDeleteProgress\.tsx$'
  '^frontend/src/features/files/hooks/useDelete\.ts$'
  # Same skipInvalidation pattern applied to useUpload to stop the file
  # table from flickering loader⇄table during multi-file uploads into the
  # currently-open folder. See FileBrowser.tsx handleUpload comment.
  '^frontend/src/features/files/hooks/useUpload\.ts$'
  # Auth/empty-state shell components — CubeLogo mode swap (idle → static)
  # so the breathing animation doesn't draw attention on every page.
  '^frontend/src/components/EmptyState/.*\.tsx$'
  '^frontend/src/components/AuthGuard/.*\.tsx$'
  '^frontend/src/components/ErrorBoundary/.*\.tsx$'
  # New shared loading component — Mantine Loader with 500ms delay,
  # mih=60vh so it sits at the same place across every screen instead
  # of jumping with content height. Replaces the branded CubeLogo
  # loader after that stalled under heavy file-table render.
  '^frontend/src/components/DelayedLoader/.*\.tsx$'
  # SPA index.html — favicon <link> for the browser tab.
  '^frontend/index\.html$'
  # Vite public/ folder — favicon.ico copied here so it ships in the
  # /v2 build output (static/v2/favicon.ico) for the SPA tab icon.
  '^frontend/public/'
  # Legacy amber colour swaps across shared components — bulk of the
  # post-smoke cleanup so primary-coloured avatars/buttons/badges
  # follow the muted-slate-blue palette instead of staying yellow.
  '^frontend/src/components/AppShell/UserMenu\.tsx$'
  '^frontend/src/components/Sidebar/RoleAvatar\.tsx$'
  '^frontend/src/components/Admin/ResetPasswordModal\.tsx$'
  '^frontend/src/pages/admin/BansPage\.tsx$'
  '^frontend/src/pages/admin/UsersPage\.tsx$'
  '^frontend/src/pages/admin/RolesPage\.tsx$'
  '^frontend/src/pages/ChangePasswordPage\.tsx$'
  '^frontend/src/pages/RolePage\.tsx$'
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
  echo "scope-guard: ${#violations[@]} file(s) changed outside the Phase 6b whitelist:"
  printf '  - %s\n' "${violations[@]}"
  echo
  echo "If this is intentional, update the whitelist in $0 and explain why in the PR."
  exit 1
fi

echo "scope-guard: all changed file(s) are within whitelist."
