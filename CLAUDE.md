# Another S3 Manager

Lightweight web UI for managing files in S3 and S3-compatible storage.

## Stack

- **Backend**: Python 3.13+, FastAPI, Boto3, JWT auth
- **Frontend**: Vanilla HTML/JS/CSS (migration to React + Mantine in progress)
- **Deployment**: Docker, Docker Compose, Kubernetes (Helm)
- **Package manager**: uv

## Structure

```
another-s3-manager/
├── src/
│   └── another_s3_manager/
│       ├── __init__.py
│       ├── main.py          # FastAPI app, API endpoints
│       ├── auth.py           # JWT auth, CSRF, ban logic
│       ├── config.py         # Config management (config.json)
│       ├── constants.py      # App constants, paths
│       ├── database.py       # SQLAlchemy engine + session_scope()
│       ├── models.py         # ORM models (User, Role, Ban)
│       ├── rate_limit.py    # slowapi limiter (per-IP, in-memory)
│       ├── s3_client.py      # S3 client, role management
│       ├── users.py          # User management (SQLite via SQLAlchemy)
│       ├── utils.py          # Validation, sanitization
│       └── static/           # Frontend assets (HTML/JS/CSS)
├── alembic/                  # Alembic migrations
├── alembic.ini
├── tests/                    # pytest tests
├── frontend/                 # React + Mantine scaffold (WIP)
├── data/                     # Runtime data (not tracked)
├── pyproject.toml
├── Dockerfile
├── docker-compose.yml
└── uv.lock
```

## Database

- SQLAlchemy 2.0 (sync) + Alembic for migrations
- SQLite at `<DATA_DIR>/another_s3_manager.db`
- Tables: `users`, `user_roles` (junction), `bans` (FK → users with CASCADE)
- Module: `database.py` (engine + `session_scope()`), `models.py` (ORM)
- Auto-migration from `users.json` / `bans.json` on first startup (legacy files renamed to `*.migrated.bak`)

## Migration commands

```bash
# Generate a new migration from model changes
uv run alembic revision --autogenerate -m "describe change"

# Apply migrations
uv run alembic upgrade head

# Rollback one step
uv run alembic downgrade -1
```

## Development Commands

```bash
# Install dependencies
uv sync

# Linter and formatting
uv run ruff check .
uv run ruff format .

# Tests
uv run pytest --cov

# Run locally
JWT_SECRET_KEY=dev-secret uv run python -m another_s3_manager.main

# Docker
docker compose up --build
```

## Versioning

Version is derived from git tag via `APP_VERSION` env var. In local development — `dev`.

## Environment Variables

| Variable                          | Required | Default         | Description                         |
| --------------------------------- | -------- | --------------- | ----------------------------------- |
| `JWT_SECRET_KEY`                  | Yes      | —               | JWT signing secret                  |
| `PORT`                            | No       | `8080`          | Server port                         |
| `UVICORN_HOST`                    | No       | `0.0.0.0`       | Server bind address                 |
| `LOG_LEVEL`                       | No       | `info`          | Logging level                       |
| `ADMIN_PASSWORD`                  | No       | `change_me_pls` | Admin user password                 |
| `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | No       | `180`           | JWT expiration (minutes)            |
| `ITEMS_PER_PAGE`                  | No       | `200`           | Items per page in file listing      |
| `DISABLE_DELETION`                | No       | `false`         | Disable file deletion               |
| `MAX_FILE_SIZE`                   | No       | `104857600`     | Max upload file size (bytes, 100MB) |
| `ENABLE_LAZY_LOADING`             | No       | `true`          | Enable lazy loading for file lists  |
| `AWS_REGION`                      | No       | `us-east-1`     | Default AWS region                  |
| `S3_FILE_MANAGER_CONFIG`          | No       | `config.json`   | Path to config file                 |
| `DATA_DIR`                        | No       | —               | Data dir (SQLite DB + runtime data) |

## Features

- Multiple AWS account support (assume_role, profiles, direct credentials)
- S3-compatible services (MinIO, R2, Wasabi)
- JWT authentication with CSRF protection
- Automatic refresh of expired credentials
- Granular per-role, per-bucket access control
