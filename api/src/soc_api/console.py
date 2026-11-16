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
from typing import Annotated, Any
from urllib.parse import parse_qs

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool

from soc_api import banner, csrf, metrics, status
from soc_api import overview as ov
from soc_api.cases import (
    STATUS_FILTERS,
    VERDICTS,
    BadFilter,
    CaseDb,
    CasesUnavailable,
    fmt_time,
    parse_case_id,
    verdict_label,
)
from soc_api.config import DEFAULT_ROLE, Settings, display_name, get_settings
from soc_api.text import link_path, visible

HERE = Path(__file__).parent
templates = Jinja2Templates(directory=HERE / "templates")  # autoescape on for .html
# Everything an attacker may have written goes through `vis` (control and bidi characters
# shown as ⟦U+XXXX⟧) and then Jinja's escaping. An alert's link is never an href by itself:
# the template writes the vendor's address and `link_path` supplies only what follows it.
templates.env.filters["utc"] = fmt_time
templates.env.filters["vis"] = visible
templates.env.filters["verdict"] = verdict_label
templates.env.filters["link_path"] = link_path

SEVERITIES = ("critical", "high", "medium", "low", "info")


def severity_class(value: object) -> str:
    """The CSS class for a severity. The database only holds these five; anything else is
    drawn as info rather than becoming a class name."""
    return value if isinstance(value, str) and value in SEVERITIES else "info"


templates.env.filters["sev"] = severity_class

# The case history says what happened in words, not in the database's event names.
EVENT_WORDS = {
    "opened": "Case opened",
    "alert_attached": "Another alert added",
    "acked": "Acknowledged",
    "closed": "Closed",
    "severity_raised": "Severity raised",
    "repushed": "Pushed again",
}


def event_label(kind: object) -> str:
    """Plain words for a case event; an event this page does not know is shown as it is."""
    return EVENT_WORDS.get(kind, str(kind)) if isinstance(kind, str) else ""


templates.env.filters["event"] = event_label
# Every page header shows the clock (UTC and local), rendered here when a page does not
# pass its own (the overview pages pass theirs from the database's time).
templates.env.globals["header_clock"] = lambda: ov.clock(None, get_settings().console_timezone)

# The console page runs no script and loads nothing from other origins.
CONSOLE_CSP = (
    "default-src 'none'; style-src 'self'; img-src 'self' data:; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)

# The overview pages load one script from this origin (the UTC clock). Still no inline script,
# no inline style, nothing from another origin, and no form.
OVERVIEW_CSP = CONSOLE_CSP.replace("style-src 'self';", "style-src 'self'; script-src 'self';")

# The case pages have forms, so they may post to themselves and nowhere else. Still no
# script and nothing from another origin.
CASES_CSP = CONSOLE_CSP.replace("form-action 'none'", "form-action 'self'")
MAX_FORM_BYTES = 8192

# admin is the same as analyst until there are settings to guard.
ACTING_ROLES = ("admin", "analyst")

router = APIRouter()


def tailnet_user(
    request: Request,
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
    roles = settings.console_roles
    if roles and login not in roles:
        raise HTTPException(status_code=403, detail="not on the console allowlist")
    # With no allow-list (dev only) everyone is an analyst, as before roles existed.
    request.state.role = roles.get(login, DEFAULT_ROLE)
    # Shown in the header only; identity, roles and the audit trail all use `login`.
    request.state.display_name = display_name(login, settings.display_names)
    return login


# Route-level `dependencies` run in order and before the parameters, so every action route
# lists analyst_user ahead of load_banner (which reads the database).
def analyst_user(
    request: Request,
    user: Annotated[str, Depends(tailnet_user)],
) -> str:
    """The identity for a route that changes something. A viewer is refused here, before the
    route reads the form, checks a token or opens the database: the form token proves the
    page was ours, not that this person may act."""
    if request.state.role not in ACTING_ROLES:
        raise HTTPException(status_code=403, detail="your role is read-only")
    return user


async def load_banner(
    request: Request,
    _: Annotated[str, Depends(tailnet_user)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> None:
    """Work out the degraded banner for a page. Runs after the identity check (the
    dependency is shared), so a refused request never reaches the database. No database
    login for the console means cases are not set up here yet: no banner."""
    request.state.degraded = []
    request.state.health_known = False
    db = case_db(settings)
    if db is None:
        return
    try:
        health = await run_in_threadpool(db.console_health)
    except CasesUnavailable:
        request.state.degraded = [banner.UNREADABLE]
        request.state.health_known = True
        return
    request.state.degraded = banner.notices(health)
    request.state.health_known = True


# Pipeline stages as they exist today. "up", "down" and "unknown" come from a probe; "live"
# is a stage that ships and runs but is not probed here (its health is the Ops Overview's
# job); "planned" shows the sprint that delivers it, so the page never pretends something
# works.
def pipeline(tunnel: status.TunnelStatus, fleet: status.Fleet) -> list[dict[str, str]]:
    if not fleet.configured:
        src_state, src_note = "setup", fleet.setup_note or "posture collector not set up"
    elif fleet.error:
        src_state, src_note = "down", fleet.error
    else:
        src_state = "unknown" if fleet.stale else "up"
        src_note = f"{fleet.online} of {len(fleet.sensors)} reporting"
        if fleet.stale:
            src_note += f" (list {fleet.posture_age} old)"
    edge_state = {"up": "up", "down": "down"}.get(tunnel.state, "unknown")
    edge_note = (
        f"{tunnel.connections} edge connections" if tunnel.state == "up" else "not connected"
    )
    return [
        {"name": "Sources", "state": src_state, "note": src_note},
        {"name": "Edge tunnel", "state": edge_state, "note": edge_note},
        {"name": "Ingest", "state": "live", "note": "see Operations"},
        {"name": "Cases", "state": "live", "note": "see Cases"},
        {"name": "Pager", "state": "live", "note": "see Operations"},
        {"name": "LLM analyst", "state": "planned", "note": "Sprint 5"},
    ]


SPRINTS = [
    ("S0", "Foundations", "done"),
    ("S1", "Alert path + pager", "done"),
    ("S2", "Resilience", "done"),
    ("S3", "Ops Overview + SSO", "active"),
    ("S4", "Detection as code", "next"),
    ("S5", "LLM triage", "planned"),
]


async def posture_fleet(settings: Settings) -> status.Fleet:
    """The sensor panel, read from the database: the rows the posture collector keeps, the same
    ones the Fleet tab shows. The console holds no EDR key and makes no call to the EDR API."""
    db = case_db(settings)
    if db is None:
        return status.Fleet(configured=False, setup_note="no database login for the console yet")
    try:
        data = await run_in_threadpool(db.ops_overview, 1, "all")
    except (CasesUnavailable, BadFilter):
        return status.Fleet(configured=True, error="the database cannot be reached")
    return ov.system_fleet(data)


@router.get("/console", response_class=HTMLResponse, dependencies=[Depends(load_banner)])
async def console(
    request: Request,
    user: Annotated[str, Depends(tailnet_user)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> HTMLResponse:
    tunnel = await status.tunnel_status(settings)
    fleet = await posture_fleet(settings)
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


@router.get("/console/overview.js")
async def overview_js(_: Annotated[str, Depends(tailnet_user)]) -> Response:
    """The one script the overview pages load: it ticks the UTC clock and does nothing else."""
    return Response((HERE / "static" / "overview.js").read_text(), media_type="text/javascript")


@router.get("/console/console.css")
async def console_css(_: Annotated[str, Depends(tailnet_user)]) -> HTMLResponse:
    css = (HERE / "static" / "console.css").read_text()
    return HTMLResponse(css, media_type="text/css")


# ---- metrics ----


@router.get("/metrics")
async def metrics_page(
    _: Annotated[str, Depends(tailnet_user)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> Response:
    """Pipeline counters for a scraper on the host. Same identity and allow-list as every
    console page; it is on the console app only, never on the public one. No detail about a
    failure is returned."""
    db = case_db(settings)
    if db is None:
        return PlainTextResponse("metrics are not set up on this host", status_code=503)
    try:
        rows = await run_in_threadpool(db.pipeline_metrics)
    except CasesUnavailable:
        return PlainTextResponse("the database cannot be reached", status_code=503)
    return PlainTextResponse(metrics.render(rows), media_type=metrics.CONTENT_TYPE)


# ---- cases ----

# What a refused or failed action tells the person. Fixed text: nothing from the request
# or the database is echoed back.
MESSAGES = {
    "note_required": "A note is required to close a case.",
    "note_too_long": "The note is too long (2000 characters at most).",
    "closed": "This case is already closed.",
    "invalid_verdict": "That is not a way to close a case.",
    "invalid_login": "Your sign-in name was not accepted for the audit trail.",
}


def with_csp(response: Response) -> Response:
    response.headers["Content-Security-Policy"] = CASES_CSP
    # Not the app-wide no-referrer: with it, a browser sends `Origin: null` on a form post
    # (Fetch standard), and the Origin check would refuse every Acknowledge and Close.
    # same-origin still sends nothing to other sites.
    response.headers["Referrer-Policy"] = "same-origin"
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


@router.get("/console/cases", response_class=HTMLResponse, dependencies=[Depends(load_banner)])
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
    can_act = request.state.role in ACTING_ROLES
    tokens = (
        {a: csrf.make_token(secret, user, case_id, a) for a in csrf.ACTIONS}
        if secret and can_act
        else {}
    )
    return with_csp(
        templates.TemplateResponse(
            request,
            "case.html",
            {
                "user": user,
                "doc": doc,
                "tokens": tokens,
                "can_act": can_act,
                "message": message,
            },
            status_code=code,
        )
    )


@router.get(
    "/console/case/{case_id}", response_class=HTMLResponse, dependencies=[Depends(load_banner)]
)
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


@router.post(
    "/console/case/{case_id}/ack",
    dependencies=[Depends(analyst_user), Depends(load_banner)],
)
async def ack_case(
    case_id: str,
    request: Request,
    user: Annotated[str, Depends(analyst_user)],
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


@router.post(
    "/console/case/{case_id}/close",
    dependencies=[Depends(analyst_user), Depends(load_banner)],
)
async def close_case(
    case_id: str,
    request: Request,
    user: Annotated[str, Depends(analyst_user)],
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


@router.post(
    "/console/case/{case_id}/close-as",
    dependencies=[Depends(analyst_user), Depends(load_banner)],
)
async def close_case_as(
    case_id: str,
    request: Request,
    user: Annotated[str, Depends(analyst_user)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> Response:
    """Quick close: one of four fixed verdicts and an optional note."""
    cid, form = await checked_post(request, user, settings, case_id, "close-as")
    verdict = form.get("verdict", "")
    if verdict not in VERDICTS:
        return await render_case(
            request, user, settings, cid, message=MESSAGES["invalid_verdict"], code=400
        )
    db = case_db(settings)
    if db is None:
        return unavailable(request, user, configured=False)
    try:
        result = await run_in_threadpool(
            db.close_with_verdict, cid, user, verdict, form.get("note", "")
        )
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
    user: Annotated[str, Depends(analyst_user)],
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


# ---- the Ops Overview pages ----
# Read-only: no form, no action. Four views of the one document ops_overview() returns. The
# period and client filters are links; both come from the query string and are checked here
# (a fixed set, and the slug syntax) before the database is asked, and the database checks the
# client exists.


def overview_csp(response: Response) -> Response:
    response.headers["Content-Security-Policy"] = OVERVIEW_CSP
    return response


def ov_context(page: str, data: dict[str, Any]) -> dict[str, Any]:
    if page == "overview":
        return {
            "title_line": ov.title_line(data),
            "flow": ov.flow(data),
            "tiles": ov.status_tiles(data),
            "response": ov.response(data),
            "queue": ov.queue(data),
            "timeline": ov.timeline(data),
            "funnel": ov.funnel(data),
            "tactics": ov.tactics(data),
            "health": ov.health(data),
        }
    if page == "fleet":
        rows = ov.fleet(data)
        return {
            "rows": rows,
            "offline": sum(1 for r in rows if r["state"] == "down"),
            "quiet": sum(1 for r in rows if r["label"].startswith("quiet")),
        }
    if page == "sources":
        return {"rows": ov.sources(data)}
    return {"rows": ov.rules(data), "inventory": data["rule_inventory"]}


async def render_overview(
    request: Request,
    user: str,
    settings: Settings,
    page: str,
    period: str,
    client: str,
) -> Response:
    try:
        period_key, days, client = ov.parse_filters(period, client)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"unknown {exc}") from None
    db = case_db(settings)
    if db is None:
        return unavailable(request, user, configured=False)
    try:
        data = await run_in_threadpool(db.ops_overview, days, client)
    except BadFilter:
        raise HTTPException(status_code=400, detail="unknown client") from None
    except CasesUnavailable:
        return unavailable(request, user, configured=True)
    context: dict[str, Any] = {
        "user": user,
        "nav_on": page,
        "keep": ov.keep_query(period_key, client),
        "period_label": ov.PERIODS[period_key][1],
        "client": client,
        "filters": ov.filter_links(period_key, client, data["clients"], f"/console/{page}"),
        "clock": ov.clock(data["generated_at"], settings.console_timezone),
        "scripted": True,
        "data": data,
    }
    context.update(ov_context(page, data))
    return overview_csp(templates.TemplateResponse(request, f"{page}.html", context))


@router.get("/console/overview", response_class=HTMLResponse, dependencies=[Depends(load_banner)])
async def overview_page(
    request: Request,
    user: Annotated[str, Depends(tailnet_user)],
    settings: Annotated[Settings, Depends(get_settings)],
    period: Annotated[str, Query(max_length=8)] = ov.DEFAULT_PERIOD,
    client: Annotated[str, Query(max_length=64)] = "all",
) -> Response:
    return await render_overview(request, user, settings, "overview", period, client)


@router.get("/console/fleet", response_class=HTMLResponse, dependencies=[Depends(load_banner)])
async def fleet_page(
    request: Request,
    user: Annotated[str, Depends(tailnet_user)],
    settings: Annotated[Settings, Depends(get_settings)],
    period: Annotated[str, Query(max_length=8)] = ov.DEFAULT_PERIOD,
    client: Annotated[str, Query(max_length=64)] = "all",
) -> Response:
    return await render_overview(request, user, settings, "fleet", period, client)


@router.get("/console/sources", response_class=HTMLResponse, dependencies=[Depends(load_banner)])
async def sources_page(
    request: Request,
    user: Annotated[str, Depends(tailnet_user)],
    settings: Annotated[Settings, Depends(get_settings)],
    period: Annotated[str, Query(max_length=8)] = ov.DEFAULT_PERIOD,
    client: Annotated[str, Query(max_length=64)] = "all",
) -> Response:
    return await render_overview(request, user, settings, "sources", period, client)


@router.get("/console/rules", response_class=HTMLResponse, dependencies=[Depends(load_banner)])
async def rules_page(
    request: Request,
    user: Annotated[str, Depends(tailnet_user)],
    settings: Annotated[Settings, Depends(get_settings)],
    period: Annotated[str, Query(max_length=8)] = ov.DEFAULT_PERIOD,
    client: Annotated[str, Query(max_length=64)] = "all",
) -> Response:
    return await render_overview(request, user, settings, "rules", period, client)
