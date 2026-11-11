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
# Source maps are for local debugging only: the image would serve them publicly
# and they cost ~1.2 MB compressed (ASM-67).
RUN npx vite build --outDir /build/dist --emptyOutDir \
    && find /build/dist -name '*.map' -delete \
    && find /build/dist -name '*.js' -exec sed -i '/^\/\/# sourceMappingURL=/d' {} +

# Stage 2: Build Python deps
FROM python:3.13-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:0.11.2 /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src/ src/
RUN uv sync --frozen --no-dev --no-editable
# Trim the venv (ASM-67). botocore ships models for every AWS service (~21 MB);
# ASM only builds s3 and sts clients, plus sso / sso-oidc for SSO profiles.
# Guarded by tests/test_botocore_pruning.py (keep the list in sync).
ARG BOTOCORE_KEEP="s3 sts sso sso-oidc"
RUN set -eu; \
    SP=/app/.venv/lib/python3.13/site-packages; \
    for d in "$SP"/botocore/data/*/; do \
        n="$(basename "$d")"; \
        case " $BOTOCORE_KEEP " in *" $n "*) ;; *) rm -rf "$d";; esac; \
    done; \
    for d in "$SP"/boto3/data/*/; do [ "$(basename "$d")" = s3 ] || rm -rf "$d"; done; \
    find "$SP" -depth -type d \( -name tests -o -name test -o -name __pycache__ \) \
        -not -path "*/another_s3_manager/*" -exec rm -rf {} +

# Stage 3: Runtime
FROM python:3.13-slim

# Official MCP Registry ownership check for the OCI package
# (registry.modelcontextprotocol.io): must match "name" in server.json.
# Inherited by the release image built from docker/Dockerfile.release.
LABEL io.modelcontextprotocol.server.name="io.github.kruchenburger/another-s3-manager"

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

# Only the data dir must be writable. A recursive chown of /app would copy the
# whole venv into a second layer (+34 MB compressed, ASM-67); the code stays
# root-owned and read-only for the app user.
RUN mkdir -p /app/data && chown app:app /app/data
# Without it the app keeps config and DB in the package directory inside the
# venv, which is root-owned now. With only the config path set, the data dir
# follows it (constants.get_data_dir); DATA_DIR and config "data_dir" still win,
# so ConfigMap setups that point "data_dir" at a PVC are unaffected.
ENV S3_FILE_MANAGER_CONFIG=/app/data/config.json

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
