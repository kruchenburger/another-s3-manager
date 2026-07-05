# Stage 1: Build the React frontend
FROM node:22-alpine AS frontend-builder
WORKDIR /build
# Copy lockfile + package.json first for layer cache
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
# Opt-in: ship the floating dev theme switcher in this production build for
# visual smoke-testing the Phase 6b palette against amber. Default is empty
# (switcher hidden + themeVariants tree-shaken per check-prod-bundle.sh).
#   docker compose build --build-arg VITE_SHOW_THEME_SWITCHER=1
ARG VITE_SHOW_THEME_SWITCHER=
ENV VITE_SHOW_THEME_SWITCHER=${VITE_SHOW_THEME_SWITCHER}
# Vite build outputs to /build/dist; we redirect via vite.config.ts to ../src/...
# but inside the container we don't have ../src, so override outDir at build time.
RUN npx vite build --outDir /build/dist --emptyOutDir

# Stage 2: Build Python deps
FROM python:3.13-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:0.11.2 /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src/ src/
RUN uv sync --frozen --no-dev --no-editable

# Stage 3: Runtime
FROM python:3.13-slim

RUN groupadd --gid 1001 app && \
    useradd --uid 1001 --gid 1001 --create-home --home-dir /home/app app

WORKDIR /app
ENV APP_PKG=/app/.venv/lib/python3.13/site-packages/another_s3_manager
COPY --from=builder /app/.venv .venv
COPY alembic.ini .
COPY migrations/ migrations/
# SPA bundle goes into the installed package (Stage 2 uses --no-editable, so the
# app imports from the wheel under .venv, not from /app/src/).
COPY --from=frontend-builder /build/dist/ ${APP_PKG}/static/app/

RUN mkdir -p /app/data && chown -R app:app /app/data /app

ARG BUILD_VERSION=dev
ENV APP_VERSION=${BUILD_VERSION}
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

USER app

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health', timeout=5)"

EXPOSE 8080
CMD ["python", "-m", "another_s3_manager.main"]
