# syntax=docker/dockerfile:1.7
# Base image pinned by digest so a rebuilt tag can't silently change what ships.
# Dependabot proposes digest bumps as PRs.

# ---- build: resolve dependencies from the lockfile into /app/.venv ----
FROM python:3.12-slim-trixie@sha256:4840d514c583a4d3d8cad3940e68dee6f0f6f3635c12fcd0a3d74c21a5b93a54 AS build

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
FROM python:3.12-slim-trixie@sha256:4840d514c583a4d3d8cad3940e68dee6f0f6f3635c12fcd0a3d74c21a5b93a54 AS runtime

ARG VERSION=0.0.0-dev
ARG GIT_SHA=unknown

ENV PATH=/app/.venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SOC_VERSION=$VERSION \
    SOC_GIT_SHA=$GIT_SHA

# TEMPORARY (2026-11-14): the pinned base still ships zlib1g 1:1.3.dfsg+really1.3.1-1+b1, which has
# two HIGH CVEs (CVE-2026-85091, CVE-2026-76844). Debian's fix is in trixie-security, but the upstream
# python image hasn't been rebuilt with it yet. Remove this step at the first base-image bump whose
# image already has +deb13u1 or newer (check: dpkg-query -W zlib1g).
RUN apt-get update \
 && apt-get install -y --no-install-recommends --only-upgrade zlib1g=1:1.3.dfsg+really1.3.1-1+deb13u1 \
 && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 10001 soc \
 && useradd --system --uid 10001 --gid soc --no-create-home --shell /usr/sbin/nologin soc

WORKDIR /app
# Owned by root and not writable by the service user.
COPY --from=build /app/.venv /app/.venv

USER 10001
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).status == 200 else 1)"]

CMD ["uvicorn", "soc_api.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", "--no-server-header", "--no-access-log"]
