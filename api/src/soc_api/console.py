"""Operations console (v0), reachable only over the tailnet.

Access model: `tailscale serve` terminates HTTPS on the tailnet and forwards to
the API on loopback, adding the caller's verified login in the
Tailscale-User-Login header. The public edge only routes /healthz, so these
paths are unreachable from the internet; requiring the header is the second
layer. Real logins and roles arrive with SSO in Sprint 3.
"""

from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from soc_api import status
from soc_api.config import Settings, get_settings

HERE = Path(__file__).parent
templates = Jinja2Templates(directory=HERE / "templates")  # autoescape on for .html

# The console page runs no script and loads nothing from other origins.
CONSOLE_CSP = (
    "default-src 'none'; style-src 'self'; img-src 'self' data:; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)

router = APIRouter()


def tailnet_user(
    settings: Annotated[Settings, Depends(get_settings)],
    tailscale_user_login: Annotated[str | None, Header()] = None,
) -> str:
    login = (tailscale_user_login or "").strip().lower()
    if not login:
        raise HTTPException(status_code=403, detail="console is only available on the tailnet")
    allow = settings.console_allowlist
    if allow and login not in allow:
        raise HTTPException(status_code=403, detail="not on the console allowlist")
    return login


# Pipeline stages as they exist today. "live" stages are probed; the rest show
# the sprint that delivers them, so the page never pretends something works.
def pipeline(tunnel: status.TunnelStatus, fleet: status.Fleet) -> list[dict[str, str]]:
    if not fleet.configured:
        src_state, src_note = "setup", "connect read-only EDR key"
    elif fleet.error:
        src_state, src_note = "down", f"API error ({fleet.error})"
    else:
        src_state, src_note = "up", f"{fleet.online} of {len(fleet.sensors)} reporting"
    edge_state = {"up": "up", "down": "down"}.get(tunnel.state, "unknown")
    edge_note = (
        f"{tunnel.connections} edge connections" if tunnel.state == "up" else "not connected"
    )
    return [
        {"name": "Sources", "state": src_state, "note": src_note},
        {"name": "Edge tunnel", "state": edge_state, "note": edge_note},
        {"name": "Ingest", "state": "planned", "note": "Sprint 1"},
        {"name": "Cases", "state": "planned", "note": "Sprint 1"},
        {"name": "Pager", "state": "planned", "note": "Sprint 1"},
        {"name": "LLM analyst", "state": "planned", "note": "Sprint 5"},
    ]


SPRINTS = [
    ("S0", "Foundations", "active"),
    ("S1", "Alert path + pager", "next"),
    ("S2", "Resilience", "planned"),
    ("S3", "Ops Overview + SSO", "planned"),
    ("S4", "Detection as code", "planned"),
    ("S5", "LLM triage", "planned"),
]


@router.get("/console", response_class=HTMLResponse)
async def console(
    request: Request,
    user: Annotated[str, Depends(tailnet_user)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> HTMLResponse:
    tunnel = await status.tunnel_status(settings)
    fleet = await status.sensor_fleet(settings)
    digest = settings.image_ref.split("@", 1)[1] if "@" in settings.image_ref else ""
    response = templates.TemplateResponse(
        request,
        "console.html",
        {
            "user": user,
            "now": status.utc_now(),
            "settings": settings,
            "digest": digest,
            "tunnel": tunnel,
            "fleet": fleet,
            "stages": pipeline(tunnel, fleet),
            "sprints": SPRINTS,
        },
    )
    response.headers["Content-Security-Policy"] = CONSOLE_CSP
    return response


@router.get("/console/console.css")
async def console_css(_: Annotated[str, Depends(tailnet_user)]) -> HTMLResponse:
    css = (HERE / "static" / "console.css").read_text()
    return HTMLResponse(css, media_type="text/css")
