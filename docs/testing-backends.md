# Testing storage backends

The app talks to S3 via boto3, so every storage target is reached through the S3
API. Two backends are exercised automatically:

| Backend       | Role type                                          | What it proves                                                                                                                                                                |
| ------------- | -------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **MinIO**     | `s3_compatible`                                    | Generic S3-compatible path (the default `e2e` job).                                                                                                                           |
| **ministack** | `assume_role`, `credentials`, `profile`, `default` | AWS-native path: STS `assume_role` (temporary credentials), direct access-key credentials, named AWS profile, and default credential chain — none of which MinIO can emulate. |

## ministack (AWS S3 + IAM + STS emulator)

`ministackorg/ministack` runs a local AWS emulator on :4566. It is wired with
**no backend code change**: the app's `assume_role` STS client carries no explicit
endpoint, so botocore's `AWS_ENDPOINT_URL_STS` env var redirects it to ministack.
S3 clients use each role's `endpoint_url` from config.

### Run locally

```bash
docker compose -f docker-compose.yml -f docker/docker-compose.ministack.yml up -d ministack
JWT_SECRET_KEY=x uv run python scripts/ci/seed_ministack.py \
  --config-out data/config.json \
  --aws-credentials-out data/aws-credentials   # writes config + the profile role's AWS credentials file
# start the backend with:
#   AWS_ENDPOINT_URL_STS=http://localhost:4566 AWS_REGION=us-east-1 \
#   AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \
#   AWS_SHARED_CREDENTIALS_FILE=$PWD/data/aws-credentials
cd frontend && npx playwright test ministack.spec.ts
```

CI runs the same in the opt-in `e2e-ministack` job.

### What ministack does NOT cover

- **IAM allow/deny enforcement** — ministack accepts IAM policies but does not
  enforce them on S3. A 2026-06-12 spike confirmed **LocalStack 3.8.1 community
  (`ENFORCE_IAM=1`) does not enforce S3 IAM either** (a deny-scoped key listed
  the forbidden bucket and got HTTP 200, not AccessDenied) — faithful S3 IAM
  enforcement is LocalStack Pro/Enterprise. So no usable non-real-AWS emulator
  gives a real deny→403; verify it on **real AWS** before a release (see the
  checklist below).
- STS credential **expiry/refresh** is covered by a deterministic backend test
  (`tests/test_s3_client.py`), not E2E (minimum real STS session is 15 min).
- **R2 / DigitalOcean Spaces / Wasabi** — S3-compatible services with no faithful
  local emulator; covered by the real-AWS smoke checklist below.
- **Azure Blob** — not S3-compatible; out of scope (no emulator, no checklist).

### Real-AWS smoke checklist (what no local emulator covers faithfully)

- **IAM allow/deny** — with a bucket-scoped IAM user/role, confirm a denied S3
  op returns the typed 403 in the UI (the boundary no local emulator enforces).
- **R2 / DigitalOcean Spaces / Wasabi** — region handling, addressing style,
  presigned charset, friendly-403 copy, against a real endpoint.
