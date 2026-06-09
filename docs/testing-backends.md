# Testing storage backends

The app talks to S3 via boto3, so every storage target is reached through the S3
API. Two backends are exercised automatically:

| Backend       | Role type                    | What it proves                                                                                                                     |
| ------------- | ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| **MinIO**     | `s3_compatible`              | Generic S3-compatible path (the default `e2e` job).                                                                                |
| **ministack** | `assume_role`, `credentials` | AWS-native path: STS `assume_role` (temporary credentials) and direct access-key credentials — neither of which MinIO can emulate. |

## ministack (AWS S3 + IAM + STS emulator)

`ministackorg/ministack` runs a local AWS emulator on :4566. It is wired with
**no backend code change**: the app's `assume_role` STS client carries no explicit
endpoint, so botocore's `AWS_ENDPOINT_URL_STS` env var redirects it to ministack.
S3 clients use each role's `endpoint_url` from config.

### Run locally

```bash
docker compose -f docker-compose.yml -f docker-compose.ministack.yml up -d ministack
JWT_SECRET_KEY=x uv run python scripts/ci/seed_ministack.py   # prints role configs
# paste the printed roles into data/config.json, then start the backend with:
#   AWS_ENDPOINT_URL_STS=http://localhost:4566 AWS_REGION=us-east-1 \
#   AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test
cd frontend && npx playwright test ministack.spec.ts
```

CI runs the same in the opt-in `e2e-ministack` job.

### What ministack does NOT cover

- **IAM allow/deny enforcement** — this emulator accepts IAM policies (the seed
  attaches a bucket-scoped policy to document intent) but does **not** enforce
  them on S3 access. A real "deny → 403" assertion needs real AWS or a different
  emulator, so that test is intentionally absent. ministack here proves STS
  `assume_role` and direct-credential validity, not authorization boundaries.
- **R2 / DigitalOcean Spaces / Wasabi** — S3-compatible services with no faithful
  local emulator; their quirks (region, addressing, charset, 403 copy) need a
  real-endpoint smoke check. Deferred (see backlog).
- **Azure Blob** — not S3-compatible; out of scope.
- STS credential **expiry/refresh** and the `profile`/`default` role types —
  deferred to a later phase.
