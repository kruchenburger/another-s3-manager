#!/usr/bin/env bash
# Enforce that the production bundle does NOT contain dev-only theme names.
# Catches the dev-switcher tree-shaking regression described in spec §3.4.

set -euo pipefail

DIST_DIR="${1:-frontend/dist}"

if [ ! -d "$DIST_DIR" ]; then
  echo "check-prod-bundle: dist/ directory not found at $DIST_DIR — run 'npm run build' first"
  exit 1
fi

# These three theme objects MUST stay out of the production bundle.
forbidden=("graphiteTheme" "faviconBlueTheme" "amberBaselineTheme")
violations=()

# Exclude .map files — source maps preserve original identifiers for debugging
# but are NOT executed at runtime; they don't represent prod bundle behaviour.
for name in "${forbidden[@]}"; do
  if grep -rq --exclude='*.map' "$name" "$DIST_DIR"; then
    matches="$(grep -rln --exclude='*.map' "$name" "$DIST_DIR" | head -5)"
    violations+=("$name found in: $matches")
  fi
done

if [ "${#violations[@]}" -gt 0 ]; then
  echo "check-prod-bundle: ${#violations[@]} dev-only theme(s) leaked into production:"
  printf '  - %s\n' "${violations[@]}"
  echo
  echo "Cause: ThemePreviewProvider is statically importing themeVariants instead of dynamic import."
  echo "Fix: ensure 'import(\"./themeVariants\")' is wrapped in 'if (import.meta.env.DEV)' inside ThemePreviewProvider.tsx."
  exit 1
fi

echo "check-prod-bundle: production bundle clean."
