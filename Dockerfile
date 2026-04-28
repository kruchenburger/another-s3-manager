FROM python:3.13-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src/ src/
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.13-slim
WORKDIR /app
COPY --from=builder /app/.venv .venv
# Copy from least to most frequently changed for better layer cache reuse:
# alembic.ini almost never changes, migrations/ changes occasionally, src/ changes often.
COPY alembic.ini .
COPY migrations/ migrations/
COPY src/ src/

RUN mkdir -p /app/data

ARG BUILD_VERSION=dev
ENV APP_VERSION=${BUILD_VERSION}
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"

EXPOSE 8080
CMD ["python", "-m", "another_s3_manager.main"]
