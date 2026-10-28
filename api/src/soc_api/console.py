"""Operations console (v0), reachable only over the tailnet.

Access model: `tailscale serve` terminates HTTPS on the tailnet and forwards to
the console service on the host's loopback, adding the caller's verified login
in the Tailscale-User-Login header and removing any value a client sent itself.
The header is only trustworthy on that path. The console therefore runs as its
own app (soc_api.console_main) in its own service on the host network, where
the public tunnel container cannot connect, and the public app does not include
this router at all. The allowlist limits who on the tailnet gets in.
Real logins and roles arrive with SSO in Sprint 3.
"""

from pathlib import Path
from typing import Annotated
from urllib.parse import parse_qs

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool

from soc_api import csrf, status
from soc_api.cases import (
    STATUS_FILTERS,
    CaseDb,
    CasesUnavailable,
    fmt_time,
    parse_case_id,
)
from soc_api.config import Settings, get_settings
from soc_api.text import link_path, visible

HERE = Path(__file__).parent
templates = Jinja2Templates(directory=HERE / "templates")  # autoescape on for .html
# Everything an attacker may have written goes through `vis` (control and bidi characters
# shown as ⟦U+XXXX⟧) and then Jinja's escaping. An alert's link is never an href by itself:
# the template writes the vendor's address and `link_path` supplies only what follows it.
templates.env.filters["utc"] = fmt_time
templates.env.filters["vis"] = visible
templates.env.filters["link_path"] = link_path

# The console page runs no script and loads nothing from other origins.
CONSOLE_CSP = (
    "default-src 'none'; style-src 'self'; img-src 'self' data:; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)

# The case pages have forms, so they may post to themselves and nowhere else. Still no
# script and nothing from another origin.
CASES_CSP = CONSOLE_CSP.replace("form-action 'none'", "form-action 'self'")
MAX_FORM_BYTES = 8192

router = APIRouter()


def tailnet_user(
    settings: Annotated[Settings, Depends(get_settings)],
    tailscale_user_login: Annotated[str | None, Header()] = None,
) -> str:
    login = (tailscale_user_login or "").strip().lower()
    if not login:
        # No identity means either the request didn't come through the tailnet
        # proxy, or it came from a tagged device, which acts as a service rather
        # than a person. Both are refused; say so in a way an operator can act on.
        raise HTTPException(
            status_code=403,
            detail=(
                "no tailnet user identity: open the console over Tailscale from a "
                "personal (untagged) device"
            ),
        )
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
        src_state = "unknown" if fleet.partial else "up"
        src_note = f"{fleet.online} of {len(fleet.sensors)}{'+' if fleet.partial else ''} reporting"
        if fleet.partial:
            src_note += " (partial list)"
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


# ---- cases ----

# What a refused or failed action tells the person. Fixed text: nothing from the request
# or the database is echoed back.
MESSAGES = {
    "note_required": "A note is required to close a case.",
    "note_too_long": "The note is too long (2000 characters at most).",
    "closed": "This case is already closed.",
    "invalid_login": "Your sign-in name was not accepted for the audit trail.",
}


def with_csp(response: Response) -> Response:
    response.headers["Content-Security-Policy"] = CASES_CSP
    return response


def notice(request: Request, user: str, title: str, text: str, code: int) -> Response:
    return with_csp(
        templates.TemplateResponse(
            request, "notice.html", {"user": user, "title": title, "text": text}, status_code=code
        )
    )


def case_db(settings: Settings) -> CaseDb | None:
    url = settings.console_database_url.get_secret_value()
    return CaseDb(url) if url else None


def unavailable(request: Request, user: str, configured: bool) -> Response:
    text = (
        "The case database cannot be reached right now. Alerts are still stored and pushed."
        if configured
        else "Cases are not set up on this host yet (no database login for the console)."
    )
    return notice(request, user, "Cases unavailable", text, 503)


@router.get("/console/cases", response_class=HTMLResponse)
async def cases_page(
    request: Request,
    user: Annotated[str, Depends(tailnet_user)],
    settings: Annotated[Settings, Depends(get_settings)],
    status_filter: Annotated[str, Query(alias="status")] = "active",
) -> Response:
    if status_filter not in STATUS_FILTERS:
        raise HTTPException(status_code=400, detail="unknown status")
    db = case_db(settings)
    if db is None:
        return unavailable(request, user, configured=False)
    try:
        rows = await run_in_threadpool(db.list_cases, status_filter, 200)
    except CasesUnavailable:
        return unavailable(request, user, configured=True)
    return with_csp(
        templates.TemplateResponse(
            request,
            "cases.html",
            {"user": user, "rows": rows, "filter": status_filter, "filters": STATUS_FILTERS},
        )
    )


async def render_case(
    request: Request,
    user: str,
    settings: Settings,
    case_id: str,
    *,
    message: str | None = None,
    code: int = 200,
) -> Response:
    db = case_db(settings)
    if db is None:
        return unavailable(request, user, configured=False)
    try:
        doc = await run_in_threadpool(db.get_case, case_id)
    except CasesUnavailable:
        return unavailable(request, user, configured=True)
    if doc is None:
        raise HTTPException(status_code=404, detail="Not Found")
    secret = settings.console_secret.get_secret_value()
    tokens = {a: csrf.make_token(secret, user, case_id, a) for a in csrf.ACTIONS} if secret else {}
    return with_csp(
        templates.TemplateResponse(
            request,
            "case.html",
            {"user": user, "doc": doc, "tokens": tokens, "message": message},
            status_code=code,
        )
    )


@router.get("/console/case/{case_id}", response_class=HTMLResponse)
async def case_page(
    case_id: str,
    request: Request,
    user: Annotated[str, Depends(tailnet_user)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> Response:
    cid = parse_case_id(case_id)
    if cid is None:
        raise HTTPException(status_code=404, detail="Not Found")
    return await render_case(request, user, settings, cid)


async def read_form(request: Request) -> dict[str, str]:
    """A small urlencoded form, size-capped while it is read."""
    kind = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if kind != "application/x-www-form-urlencoded":
        raise HTTPException(status_code=415, detail="Unsupported Media Type")
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_FORM_BYTES:
            raise HTTPException(status_code=413, detail="Payload Too Large")
    try:
        fields = parse_qs(body.decode("utf-8"), keep_blank_values=True, max_num_fields=10)
    except (UnicodeDecodeError, ValueError):
        raise HTTPException(status_code=400, detail="Bad Request") from None
    return {k: v[-1] for k, v in fields.items()}


async def checked_post(
    request: Request, user: str, settings: Settings, case_id: str, action: str
) -> tuple[str, dict[str, str]]:
    """The three form checks, then the id. Any failure refuses with a fixed message and
    nothing has been written."""
    scheme = "https" if settings.env == "prod" else request.url.scheme
    refused = HTTPException(status_code=403, detail="That request was not accepted.")
    if not csrf.same_origin(request.headers, scheme, settings.console_base_url or None):
        raise refused
    cid = parse_case_id(case_id)
    if cid is None:
        raise HTTPException(status_code=404, detail="Not Found")
    form = await read_form(request)
    secret = settings.console_secret.get_secret_value()
    if not csrf.check_token(secret, form.get("token", ""), user, cid, action):
        raise refused
    return cid, form


def finished(cid: str, result: str) -> Response | None:
    """A redirect back to the case when the action took effect (or already had), a 404
    for an unknown case; None when the person needs to be told why it did not."""
    if result in ("acked", "already", "closed_now"):
        return RedirectResponse(f"/console/case/{cid}", status_code=303)
    if result == "not_found":
        raise HTTPException(status_code=404, detail="Not Found")
    return None


@router.post("/console/case/{case_id}/ack")
async def ack_case(
    case_id: str,
    request: Request,
    user: Annotated[str, Depends(tailnet_user)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> Response:
    cid, _ = await checked_post(request, user, settings, case_id, "ack")
    db = case_db(settings)
    if db is None:
        return unavailable(request, user, configured=False)
    try:
        result = await run_in_threadpool(db.ack, cid, user)
    except CasesUnavailable:
        return unavailable(request, user, configured=True)
    done = finished(cid, result)
    if done is not None:
        return done
    code = 403 if result == "invalid_login" else 409
    return await render_case(
        request, user, settings, cid, message=MESSAGES.get(result, "Not done."), code=code
    )


@router.post("/console/case/{case_id}/close")
async def close_case(
    case_id: str,
    request: Request,
    user: Annotated[str, Depends(tailnet_user)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> Response:
    cid, form = await checked_post(request, user, settings, case_id, "close")
    db = case_db(settings)
    if db is None:
        return unavailable(request, user, configured=False)
    try:
        result = await run_in_threadpool(db.close, cid, user, form.get("note", ""))
    except CasesUnavailable:
        return unavailable(request, user, configured=True)
    done = finished(cid, "closed_now" if result in ("closed", "already") else result)
    if done is not None:
        return done
    code = {"invalid_login": 403}.get(result, 400)
    return await render_case(
        request, user, settings, cid, message=MESSAGES.get(result, "Not done."), code=code
    )


@router.post("/console/case/{case_id}/ack-phone")
async def ack_from_phone(
    case_id: str,
    request: Request,
    user: Annotated[str, Depends(tailnet_user)],
    settings: Annotated[Settings, Depends(get_settings)],
    e: Annotated[int, Query(ge=0)] = 0,
    t: Annotated[str, Query(max_length=64)] = "",
) -> Response:
    """The Acknowledge button on a phone notification.

    Only POST (a link preview must never acknowledge anything). The ntfy app is not a
    browser, so there is no Origin to check; what makes the request genuine is the signed
    link the worker made, plus the tailnet identity and allow-list every console route
    needs. A request that a browser marks as made by another site is refused anyway."""
    site = request.headers.get("sec-fetch-site")
    refused = PlainTextResponse("That request was not accepted.", status_code=403)
    if site not in (None, "same-origin", "none"):
        return refused
    cid = parse_case_id(case_id)
    if cid is None:
        return PlainTextResponse("Not Found", status_code=404)
    key = settings.ack_key.get_secret_value()
    if not key:
        return PlainTextResponse("Phone acknowledgement is not set up.", status_code=503)
    if not csrf.check_phone_token(key, t, cid, e):
        return refused
    db = case_db(settings)
    if db is None:
        return PlainTextResponse("Cases are not set up on this host.", status_code=503)
    try:
        result = await run_in_threadpool(db.ack, cid, user)
    except CasesUnavailable:
        return PlainTextResponse("The case database cannot be reached.", status_code=503)
    replies = {
        "acked": (200, "Acknowledged."),
        "already": (200, "Already acknowledged."),
        "closed": (409, "This case is already closed."),
        "not_found": (404, "Not Found"),
        "invalid_login": (403, MESSAGES["invalid_login"]),
    }
    code, text = replies.get(result, (500, "Not done."))
    return PlainTextResponse(text, status_code=code)
