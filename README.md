# Another S3 Manager

Lightweight, self-hosted web UI for managing files across multiple S3-compatible storage providers.

Works with **AWS S3**, **MinIO**, **Cloudflare R2**, **Wasabi**, and any S3-compatible API.

## Quick Start

```bash
docker run -d -p 8080:8080 \
  -e JWT_SECRET_KEY=$(openssl rand -base64 32) \
  -v s3m-data:/app/data \
  ghcr.io/kruchenburger/another-s3-manager:latest
```

Open `http://localhost:8080` and log in with `admin` / `change_me_pls`.

## Features

- **Multi-provider** — connect AWS accounts, MinIO, R2, Wasabi in one UI
- **Multi-account** — switch between roles (default credentials, named profiles, assume role, direct keys)
- **User management** — create users, assign per-role and per-bucket access
- **Upload & download** — single files, multiple files, or entire folders; drag-and-drop supported
- **Bulk operations** — select and delete multiple files at once
- **Virtual scrolling** — handles directories with millions of objects
- **Security** — JWT auth, bcrypt passwords, CSRF protection, IP ban after failed logins
- **Dark / light theme**

## Configuration

Configure roles through the web UI (**Admin > Configure**) or by editing `config.json`:

```json
{
  "roles": [
    { "name": "AWS Production", "type": "assume_role", "role_arn": "arn:aws:iam::123456789012:role/S3Access" },
    { "name": "Dev Account",    "type": "credentials", "access_key_id": "AKIA...", "secret_access_key": "..." },
    { "name": "Local MinIO",    "type": "credentials", "access_key_id": "minioadmin", "secret_access_key": "minioadmin", "endpoint_url": "http://minio:9000", "path_style": true }
  ]
}
```

Role types: `default`, `profile`, `assume_role`, `credentials`. Any role can include `endpoint_url`, `use_ssl`, `verify_ssl`, `path_style` for S3-compatible services.

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `JWT_SECRET_KEY` | **Required.** Secret for JWT tokens | — |
| `ADMIN_PASSWORD` | Initial admin password | `change_me_pls` |
| `PORT` | Server port | `8080` |
| `AWS_REGION` | Default AWS region | from env |
| `DATA_DIR` | Directory for SQLite DB and runtime data | `/app/data` |
| `MAX_FILE_SIZE` | Max upload size in bytes | `104857600` (100 MB) |
| `DISABLE_DELETION` | Disable delete operations | `false` |
| `ITEMS_PER_PAGE` | Files per page | `200` |

## Storage

User accounts, ban records, and authentication state live in a SQLite database
(`<DATA_DIR>/another_s3_manager.db`). On first startup, if legacy
`users.json` or `bans.json` files are present, they are auto-imported
into the database and renamed to `*.migrated.bak` (kept as backup).

Configuration (`config.json`) remains a file — it's admin-edited
infrequently and benefits from human readability.

DB schema is managed via Alembic. Migrations run at startup
(`alembic upgrade head`).

## Docker Compose

```yaml
services:
  s3-manager:
    image: ghcr.io/kruchenburger/another-s3-manager:latest
    ports: ["8080:8080"]
    environment:
      JWT_SECRET_KEY: ${JWT_SECRET_KEY}
      ADMIN_PASSWORD: ${ADMIN_PASSWORD}
    volumes:
      - ./config.json:/app/config.json
      - s3m-data:/app/data
    restart: unless-stopped

volumes:
  s3m-data:
```

## Try It Locally with MinIO

```bash
docker compose -f docker-compose-demo.yml up
```

This starts MinIO + the app with a pre-configured demo bucket. Open `http://localhost:8080` (app) or `http://localhost:9001` (MinIO console).

## Development

```bash
uv sync                  # install dependencies
uv run pytest --cov      # run tests
uv run ruff check .      # lint
uv run ruff format .     # format
```

## IAM Policy

Minimum permissions needed:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
    "Resource": "arn:aws:s3:::YOUR-BUCKET/*"
  }]
}
```

Add `s3:ListAllMyBuckets` on `*` if you don't want to manually specify allowed buckets per role.

## License

[MIT](LICENSE)
