# Accessibility

`another-s3-manager` runs an automated accessibility baseline against every
authenticated route on every PR via [`@axe-core/playwright`][axe-pw]. The goal
is to keep real assistive-tech blockers from regressing — not to chase a
perfect 100 / 100 lighthouse score.

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

The spec at `frontend/tests/e2e/a11y.spec.ts` walks every static authenticated
route:

- `/v2/login`
- `/v2/` (home, after login)
- `/v2/change-password`
- `/v2/api-tokens` (self-serve MCP tokens)
- `/v2/admin/users`
- `/v2/admin/bans`
- `/v2/admin/settings`
- `/v2/admin/roles`
- `/v2/admin/roles/new` (3-step wizard)
- `/v2/admin/api-tokens`

Dynamic routes that require seeded S3 data (`/v2/r/:role`, `/v2/r/:role/b/:bucket`,
`/v2/admin/roles/:name`) and modal-open variants (e.g. UserDrawer in edit
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
  override the offending Mantine CSS variable in `frontend/src/app/global.css`
- `landmark-one-main` — ensure exactly one `<main>` per page
- `region` — wrap content in semantic landmarks (`<main>`, `<nav>`, `<aside>`)

axe-core docs for each rule: [https://dequeuniversity.com/rules/axe/4.11/](https://dequeuniversity.com/rules/axe/4.11/)

## How to add a new route to the baseline

1. Add a new `test(...)` block in `frontend/tests/e2e/a11y.spec.ts`
2. Navigate to the route and call `expectNoSeriousAxeViolations(page, "<route-name>")`
3. Run locally to capture initial violations and fix them before the PR lands

## Theme overrides for contrast compliance

Two changes in `frontend/src/app/` shifted the baseline from "10 failing routes"
to "10 passing routes":

1. `theme.ts` enables `autoContrast: true` so Mantine picks a high-contrast
   text colour for filled buttons / badges instead of hard-coded white.
   Important for our amber primary in dark mode (`#ffc107`) where white text
   produced 1.63:1.

2. `global.css` overrides `--mantine-color-dimmed` from `#828282` to `#969696`
   in dark mode. Mantine's default failed 4.5:1 against the standard dark
   body background `#242424` (came in at 4.03:1). The replacement passes AA
   at 4.69:1 with no visible UI shift.

Future contrast fixes should follow the same pattern: prefer overriding the
relevant Mantine CSS variable in `global.css` over per-component overrides,
so the change applies everywhere uniformly.
