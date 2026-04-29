FROM python:3.13-slim AS builder
# Pin uv version (never :latest — supply-chain risk; per .claude/rules/docker.md).
COPY --from=ghcr.io/astral-sh/uv:0.11.2 /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock ./
# Two-stage uv sync: first pulls deps only (cached layer), then installs the project
# with --no-editable so static/ assets bundled via package-data ship in the wheel.
RUN uv sync --frozen --no-dev --no-install-project
COPY src/ src/
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.13-slim

# Run as non-root for least-privilege (per .claude/rules/docker.md).
# Home dir is created so boto3 / awscli can find ~/.aws when mounted via compose override.
RUN groupadd --gid 1001 app && \
    useradd --uid 1001 --gid 1001 --create-home --home-dir /home/app app

WORKDIR /app
COPY --from=builder /app/.venv .venv
# Copy from least to most frequently changed for better layer cache reuse:
# alembic.ini almost never changes, migrations/ changes occasionally, src/ changes often.
COPY alembic.ini .
COPY migrations/ migrations/
COPY src/ src/

# /app/data must be writable by the non-root user — DATA_DIR persists SQLite + config.
RUN mkdir -p /app/data && chown -R app:app /app/data /app

ARG BUILD_VERSION=dev
ENV APP_VERSION=${BUILD_VERSION}
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

USER app

# start-period=30s: gives Alembic upgrade + JSON migration time to finish on first boot.
# urlopen timeout=5s prevents the healthcheck from hanging on a wedged event loop.
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health', timeout=5)"

EXPOSE 8080
CMD ["python", "-m", "another_s3_manager.main"]
