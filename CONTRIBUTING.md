# Contributing to Another S3 Manager

Thanks for your interest! Here's how to get a working dev setup and submit changes.

## Setup

Requires Python 3.13+ and [uv](https://github.com/astral-sh/uv).

```bash
# Clone your fork
git clone https://github.com/your-username/another-s3-manager.git
cd another-s3-manager

# Install all dependencies (runtime + dev: pytest, ruff, moto, etc.)
uv sync --all-extras

# Copy the env template and set a random JWT_SECRET_KEY
cp .env.example .env
# Edit .env — at minimum set JWT_SECRET_KEY (generate one with:
# python -c 'import secrets; print(secrets.token_urlsafe(32))')

# Run the server
uv run python -m another_s3_manager.main

# Open http://localhost:8080 — log in as admin / change_me_pls
```

State (SQLite DB, `config.json`) lives in `./data` by default. To wipe and start fresh,
`rm -rf data/`.

## Make changes, run checks

```bash
uv run ruff check .            # lint
uv run ruff format --check .   # format check (use `format .` to auto-fix)
uv run pytest --cov            # unit + integration tests
```

CI runs all three on every PR — make them green locally first.

## Branches and commits

- Branch from `main`: `git checkout -b <type>/<short-description>` (e.g. `fix/login-csrf-mismatch`)
- Conventional Commits: `feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `test:`
- Open a PR against `main` (or the active `release/*` branch if one is open)

## Docker

```bash
docker compose up --build      # local dev stack (build from source)
docker compose down            # stop
```

`docker-compose.yml` uses a host bind mount (`./data:/app/data`), so SQLite + config
survive `docker compose down`. To wipe state, delete the dir manually: `rm -rf data/`.

For per-developer overrides (mounting `~/.aws` etc.), copy
`docker-compose.override.example.yml` to `docker-compose.override.yml` (gitignored).

## Reporting bugs

Open an issue with: what you tried, what you expected, what happened, and the relevant
logs (redact any secrets). Reproductions in `docker compose` form are most helpful.
