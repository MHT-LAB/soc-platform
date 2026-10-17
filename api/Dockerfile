# syntax=docker/dockerfile:1.7
# Base image pinned by digest so a rebuilt tag can't silently change what ships.
# Dependabot proposes digest bumps as PRs.

# ---- build: resolve dependencies from the lockfile into /app/.venv ----
FROM python:3.14-slim-trixie@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170 AS build

RUN pip install --no-cache-dir uv==0.10.12

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project --no-editable
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

# ---- runtime: no build tools, no root ----
FROM python:3.14-slim-trixie@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170 AS runtime

ARG VERSION=0.0.0-dev
ARG GIT_SHA=unknown

ENV PATH=/app/.venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SOC_VERSION=$VERSION \
    SOC_GIT_SHA=$GIT_SHA

RUN groupadd --system --gid 10001 soc \
 && useradd --system --uid 10001 --gid soc --no-create-home --shell /usr/sbin/nologin soc

WORKDIR /app
# Owned by root and not writable by the service user.
COPY --from=build /app/.venv /app/.venv

USER 10001
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).status == 200 else 1)"]

CMD ["uvicorn", "soc_api.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", "--no-server-header"]
