# Accessibility

`another-s3-manager` runs an automated accessibility baseline against every
covered route (login + post-login + admin) on every PR via
[`@axe-core/playwright`][axe-pw]. The goal is to keep real assistive-tech
blockers from regressing — not to chase a perfect 100 / 100 lighthouse score.

[axe-pw]: https://www.npmjs.com/package/@axe-core/playwright

## What's enforced

- **WCAG 2.1 AA** conformance (axe-core tags `wcag2a`, `wcag2aa`, `wcag21a`,
  `wcag21aa`)
- axe's `best-practice` collection (catches duplicate landmarks, focus order
  issues, etc.)
- **Failure threshold:** any `critical` or `serious` violation on a covered
  route fails the build. `moderate` and `minor` violations are logged to the
  test output but do not block — the rule set at those levels contains a lot
  of debatable items (e.g. `landmark-one-main` on inner-pane SPAs) and we
  don't want a noisy bar.

## What's covered

The spec at `frontend/tests/e2e/a11y.spec.ts` walks every static route
(login + the post-login app shell + admin pages):

- `/login` (unauthenticated — first thing every user sees, so worth a check)
- `/` (home, after login)
- `/change-password`
- `/api-tokens` (self-serve MCP tokens)
- `/admin/users`
- `/admin/bans`
- `/admin/settings`
- `/admin/roles`
- `/admin/roles/new` (3-step wizard)
- `/admin/api-tokens`

Dynamic routes that require seeded S3 data (`/r/:role`, `/r/:role/b/:bucket`,
`/admin/roles/:name`) and modal-open variants (e.g. UserDrawer in edit
mode) are not in the baseline yet — they need a more involved fixture and
will land in a follow-up.

## How to run locally

Backend must be running first:

```bash
docker compose up --build -d
```

Then:

```bash
cd frontend
ADMIN_PASSWORD=<your-local-admin-password> npx playwright test a11y.spec.ts
```

`ADMIN_PASSWORD` defaults to `test-admin-pw-12345` when unset; override to
match whatever your `.env` / docker-compose sets.

Use `--ui` for an interactive viewer:

```bash
npx playwright test a11y.spec.ts --ui
```

## What's NOT enforced (deferred)

- Full keyboard-only navigation audit (manual)
- Screen reader testing (manual, with NVDA / JAWS / VoiceOver)
- Cognitive load / readability metrics
- Mobile-specific a11y (tap target sizing, gesture alternatives)
- `prefers-reduced-motion` compliance for the GSAP-driven `BurgerLogo`
- Dynamic-route + drawer-open variants (see "What's covered" above)

These are tracked in the project backlog and may be picked up post-1.0.0.

## How to fix a flagged violation

The test output prints rule IDs (e.g. `button-name`) and selectors of the
offending elements. Common fixes:

- `button-name` / `link-name` — add `aria-label` to icon-only controls
- `label` — wrap inputs with `<TextInput label="...">` or add `aria-label`
- `color-contrast` — pick a brand-book token with sufficient contrast, or
  override the offending Mantine CSS variable in `cssVariablesResolver`
  inside `frontend/src/app/theme.ts`
- `landmark-one-main` — ensure exactly one `<main>` per page
- `region` — wrap content in semantic landmarks (`<main>`, `<nav>`, `<aside>`)

axe-core docs for each rule: [https://dequeuniversity.com/rules/axe/4.11/](https://dequeuniversity.com/rules/axe/4.11/)

## How to add a new route to the baseline

1. Add a new `test(...)` block in `frontend/tests/e2e/a11y.spec.ts`
2. Navigate to the route and call `expectNoSeriousAxeViolations(page, "<route-name>")`
3. Run locally to capture initial violations and fix them before the PR lands

## Theme overrides for contrast compliance

These changes in `frontend/src/app/theme.ts` keep the baseline green:

1. `Button` and `Badge` components opt in to `autoContrast: true` via
   `Button.extend(...)` / `Badge.extend(...)` in `components`. Mantine then
   picks a high-contrast text colour for filled variants instead of the
   hard-coded white default. Important for our amber primary in dark mode
   (`#ffc107`) where white text produced 1.63:1. autoContrast only affects
   `variant="filled"` (per Mantine 9 docs), so outline / subtle / transparent
   variants are unaffected and keep their explicit colours.

2. `cssVariablesResolver` overrides `--mantine-color-dimmed` to `#9aa5b4`
   (the airify slate "ink-dim") in dark mode, and pins
   `--mantine-color-error` to `red.5` (dark) / `red.8` (light). The airify
   palette makes the dark body `#1a212e` and elevated surfaces `#222b3c`;
   `#9aa5b4` passes AA at 6.47:1 / 5.68:1 against them. The error pins fix
   a gap that predates the coral retune: Mantine's own defaults (`red.8`
   on dark, `red.6` on light) sit below the 4.5:1 AA threshold on our
   bodies. All four ratios are locked by
   `frontend/tests/unit/themeContrast.test.ts`, so palette tuning cannot
   silently regress them. Using the resolver (instead of a separate
   stylesheet) keeps the theme config in one place and dodges the
   CSS-specificity dance that would otherwise be needed to beat Mantine's
   own selectors.

3. The primary filled-hover is pinned per scheme
   (`PRIMARY_HOVER_DARK`/`PRIMARY_HOVER_LIGHT` in `theme.ts`). The design
   mockup's dark hover lightens to `#6d8cb6`, which puts white button text
   at 3.45:1 — the adopted `#57759b` keeps the lighten-on-hover idiom at
   4.75:1. Also locked by `themeContrast.test.ts`.

Future contrast fixes should follow the same pattern: prefer overriding the
relevant Mantine CSS variable via `cssVariablesResolver` over per-component
style overrides, so the change applies everywhere uniformly.

## Mantine 9 upgrade — a11y fixes

The Mantine 8 → 9 upgrade surfaced (and required fixing) four accessibility
regressions, all caught by this axe baseline:

1. **Pre-paint color-scheme flash.** Mantine sets `data-mantine-color-scheme`
   on `<html>` only once `MantineProvider` mounts. Until then, Mantine text
   uses its light default (near-black) while the login shell's `light-dark()`
   background follows the OS `prefers-color-scheme` — black-on-dark when the OS
   prefers dark, a serious `color-contrast` violation. Fixed with a small
   blocking script in `frontend/index.html` that sets the attribute from
   `localStorage` (default `dark`) before first paint — the SPA equivalent of
   Mantine's SSR-only `ColorSchemeScript`.
2. **Dismiss buttons lost their label.** Mantine 9 dropped the built-in
   `aria-label="Close"` on the `CloseButton` that `Modal`/`Drawer`/`Popover`
   render internally, making every ✕ a critical `button-name` violation.
   Restored via `Modal`/`Drawer`/`CloseButton` `defaultProps` in `theme.ts`.
3. **Password-requirements contrast.** The empty-field checklist renders all
   rules in red; Mantine 9's dark body tipped flat `red.7` to 4.03:1 (under
   AA). `PasswordRequirementsList` now uses scheme-aware `light-dark()` shades
   (darker on light surfaces, lighter on dark) for both the red/unmet and
   green/met states.
4. **`getByLabel("Password")` collision (test-only).** Mantine 9's
   "Toggle password visibility" button carries a descriptive `aria-label`
   containing "password", so a substring label match resolves to two elements.
   The e2e login helpers now use `{ exact: true }`.
