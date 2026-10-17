"""SOC API entry point.

Sprint 0 ships only health and version endpoints. The point is to prove the
build -> scan -> sign -> deploy pipeline before any security data flows through it.
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


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    dev = settings.env == "dev"

    app = FastAPI(
        title="SOC API",
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
    app.include_router(console.router)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        """Liveness check used by Docker, the deploy script and the uptime monitor."""
        return {"status": "ok"}

    @app.get("/version")
    async def version() -> dict[str, str]:
        """Which build is running. Lets a deploy confirm the new image is live."""
        return {"version": settings.version, "git_sha": settings.git_sha}

    return app


app = create_app()
