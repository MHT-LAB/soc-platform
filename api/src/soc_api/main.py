"""SOC API entry points.

Two apps are built from this code and run as separate services:

* the public app (`soc_api.main:app`): /healthz, /version and later /ingest/.
  It does not include the console router at all, so a misrouted request from
  the internet can never reach the console.
* the console app (`soc_api.console_main:app`): /console and /healthz. It runs
  on the host's loopback, where the public edge cannot reach it.
"""

from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response

from soc_api import console
from soc_api.config import Settings, get_settings

# Sent on every response. The API serves JSON only, so the content policy can
# deny everything; the console (Sprint 3) gets its own policy.
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def _base_app(settings: Settings, title: str) -> FastAPI:
    dev = settings.env == "dev"

    app = FastAPI(
        title=title,
        version=settings.version,
        # Interactive docs describe the attack surface; only expose them in dev.
        docs_url="/docs" if dev else None,
        redoc_url=None,
        openapi_url="/openapi.json" if dev else None,
    )

    @app.middleware("http")
    async def add_security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        # A route may set a narrower policy of its own (the console does);
        # every other response gets the deny-everything default.
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        return response

    # Routes that depend on settings see the same instance the app was built with.
    app.dependency_overrides[get_settings] = lambda: settings

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        """Liveness check used by Docker, the deploy script and the uptime monitor."""
        return {"status": "ok"}

    return app


def create_app(settings: Settings | None = None) -> FastAPI:
    """The public app. Never mounts the console."""
    settings = settings or get_settings()
    app = _base_app(settings, "SOC API")

    @app.get("/version")
    async def version() -> dict[str, str]:
        """Which build is running. Lets a deploy confirm the new image is live."""
        return {"version": settings.version, "git_sha": settings.git_sha}

    return app


def create_console_app(settings: Settings | None = None) -> FastAPI:
    """The console app. Refuses to build in prod without a login allowlist."""
    settings = settings or get_settings()
    # An empty allowlist accepts any login header, so prod refuses to start
    # without one rather than defaulting to open.
    if settings.env == "prod" and not settings.console_allowlist:
        raise ValueError("SOC_CONSOLE_USERS must list at least one login when SOC_ENV=prod")
    app = _base_app(settings, "SOC Console")
    app.include_router(console.router)
    return app


app = create_app()
