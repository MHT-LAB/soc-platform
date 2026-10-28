"""The console's case pages: queue, one case, Acknowledge and Close.

The forms are the one thing on the console that changes anything, and your identity is a
header your browser adds to every request, so a page on another site could press them for
you. Each of the three checks (Sec-Fetch-Site, Origin, the form token) is tested on its own:
with only that one wrong, nothing may be written. Alert text is attacker-written, so the
pages are tested with hostile alerts. Real Postgres, the real soc_console login.
"""

import re
import socket
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode

import pytest
from conftest import ROLE_PASSWORD, TestDb
from fastapi.testclient import TestClient
from test_worker_db import Fixture

from soc_api import csrf
from soc_api.cases import fmt_time, parse_case_id
from soc_api.config import Settings
from soc_api.console import CASES_CSP, CONSOLE_CSP
from soc_api.main import create_console_app
from soc_api.text import LC_LINK_PREFIX, link_path, safe_link, visible

SECRET = "console-form-secret-0123456789abcdef"  # noqa: S105 - throwaway
LOGIN = "operator@example.com"
BASE = "https://console.example.net"
GOOD_LINK = "https://app.limacharlie.io/orgs/o/sensors/s/timeline?time=1"
AUTO: Any = object()  # "make the right token"; None means send none


@pytest.fixture
def fx(db: TestDb) -> Fixture:
    return Fixture(db)


def make_client(fx: Fixture, **overrides: Any) -> TestClient:
    base: dict[str, Any] = {
        "env": "prod",
        "console_users": LOGIN,
        "version": "edge",
        "git_sha": "a" * 40,
        "console_database_url": fx.db.sqlalchemy_url("soc_console", ROLE_PASSWORD),
        "console_secret": SECRET,
    }
    settings = Settings(**{**base, **overrides})
    return TestClient(create_console_app(settings), base_url=BASE, follow_redirects=False)


def get_headers(login: str = LOGIN) -> dict[str, str]:
    return {"Tailscale-User-Login": login}


def post_headers(**over: str | None) -> dict[str, str]:
    base: dict[str, str | None] = {
        "Tailscale-User-Login": LOGIN,
        "Sec-Fetch-Site": "same-origin",
        "Origin": BASE,
        "Content-Type": "application/x-www-form-urlencoded",
    }
    base.update(over)
    return {k: v for k, v in base.items() if v is not None}


def post(
    client: TestClient,
    case: Any,
    action: str,
    *,
    token: str | None = AUTO,
    headers: dict[str, str] | None = None,
    fields: dict[str, str] | None = None,
    raw: bytes | None = None,
) -> Any:
    data = dict(fields or {})
    if token is AUTO:
        token = csrf.make_token(SECRET, LOGIN, str(case), action)
    if token is not None:
        data["token"] = token
    body = raw if raw is not None else urlencode(data).encode()
    return client.post(
        f"/console/case/{case}/{action}", content=body, headers=headers or post_headers()
    )


def one_case(fx: Fixture, **alert: Any) -> str:
    fx.alert(**alert)
    fx.assign()
    return str(fx.rows("SELECT id FROM soc_case ORDER BY opened_at DESC, id LIMIT 1")[0][0])


def state(fx: Fixture, case: str) -> tuple[Any, ...]:
    return fx.one(
        "SELECT status, closed_at IS NOT NULL, closing_note, "
        "(SELECT count(*) FROM case_event e WHERE e.case_id = c.id "
        "AND e.kind IN ('acked', 'closed')) "
        "FROM soc_case c WHERE id = %s",
        (case,),
    )


# ---- the helpers ----


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("plain text", "plain text"),
        ("tabs\tand\nnewlines stay", "tabs\tand\nnewlines stay"),
        ("bidi\u202eevil", "bidi⟦U+202E⟧evil"),
        ("esc\x1b[31m", "esc⟦U+001B⟧[31m"),
        ("zero\u200bwidth", "zero⟦U+200B⟧width"),
        ("nul-ish\x7f", "nul-ish⟦U+007F⟧"),
        ("", ""),
        (None, ""),
        ("ünïcode ✓", "ünïcode ✓"),
    ],
)
def test_visible_shows_what_clean_would_drop(raw: str | None, expected: str) -> None:
    assert visible(raw) == expected


def test_visible_cuts_the_input_not_the_marker() -> None:
    assert visible("abc\u202edef", 4) == "abc⟦U+202E⟧"
    assert visible("x" * 1000, 10) == "x" * 10


@pytest.mark.parametrize(
    ("raw", "ok"),
    [
        ("0f8c2ad6-6f0e-4d37-8f2b-3a1b4c5d6e7f", True),
        ("0F8C2AD6-6F0E-4D37-8F2B-3A1B4C5D6E7F", True),
        ("0f8c2ad66f0e4d378f2b3a1b4c5d6e7f", False),  # no dashes
        ("{0f8c2ad6-6f0e-4d37-8f2b-3a1b4c5d6e7f}", False),
        ("urn:uuid:0f8c2ad6-6f0e-4d37-8f2b-3a1b4c5d6e7f", False),
        ("0f8c2ad6-6f0e-4d37-8f2b-3a1b4c5d6e7f ", False),
        ("../etc/passwd", False),
        ("", False),
        ("1", False),
    ],
)
def test_only_a_canonical_uuid_is_a_case_id(raw: str, ok: bool) -> None:
    assert (parse_case_id(raw) == raw.lower()) is ok
    assert (parse_case_id(raw) is not None) is ok


def test_times_are_shown_in_utc_from_a_datetime_or_iso_text() -> None:
    assert fmt_time(datetime(2026, 10, 28, 14, 5, 9, tzinfo=UTC)) == "2026-10-28 14:05:09 UTC"
    assert fmt_time("2026-10-28T10:05:09-04:00") == "2026-10-28 14:05:09 UTC"
    assert fmt_time("not a time") == "?" and fmt_time(None) == "?"


# ---- the form token ----

NOW = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)
CASE = "0f8c2ad6-6f0e-4d37-8f2b-3a1b4c5d6e7f"


def test_a_token_fits_one_login_one_case_one_action_and_one_secret() -> None:
    token = csrf.make_token(SECRET, LOGIN, CASE, "ack", NOW)
    assert csrf.check_token(SECRET, token, LOGIN, CASE, "ack", NOW)
    assert csrf.check_token(SECRET, token, LOGIN.upper(), CASE.upper(), "ack", NOW)
    assert not csrf.check_token(SECRET, token, "other@example.com", CASE, "ack", NOW)
    assert not csrf.check_token(SECRET, token, LOGIN, CASE[:-1] + "0", "ack", NOW)
    assert not csrf.check_token(SECRET, token, LOGIN, CASE, "close", NOW)
    assert not csrf.check_token(SECRET + "x", token, LOGIN, CASE, "ack", NOW)


def test_a_token_lasts_today_and_tomorrow_only() -> None:
    token = csrf.make_token(SECRET, LOGIN, CASE, "ack", NOW)
    assert csrf.check_token(SECRET, token, LOGIN, CASE, "ack", NOW + timedelta(hours=11))
    assert csrf.check_token(SECRET, token, LOGIN, CASE, "ack", NOW + timedelta(days=1))
    assert not csrf.check_token(SECRET, token, LOGIN, CASE, "ack", NOW + timedelta(days=2))
    assert not csrf.check_token(SECRET, token, LOGIN, CASE, "ack", NOW - timedelta(days=1))


@pytest.mark.parametrize("token", ["", "x", "0" * 64, "0" * 63, "0" * 65, "z" * 64, None])
def test_a_wrong_token_is_refused(token: str | None) -> None:
    assert not csrf.check_token(SECRET, token or "", LOGIN, CASE, "ack", NOW)


def test_nothing_is_signed_without_a_secret_or_for_an_unknown_action() -> None:
    with pytest.raises(ValueError, match="form token"):
        csrf.make_token("", LOGIN, CASE, "ack")
    with pytest.raises(ValueError, match="form token"):
        csrf.make_token(SECRET, LOGIN, CASE, "delete")
    assert not csrf.check_token("", "0" * 64, LOGIN, CASE, "ack", NOW)


@pytest.mark.parametrize(
    ("headers", "ok"),
    [
        (
            {"host": "c.example", "sec-fetch-site": "same-origin", "origin": "https://c.example"},
            True,
        ),
        (
            {"host": "c.example", "sec-fetch-site": "cross-site", "origin": "https://c.example"},
            False,
        ),
        (
            {"host": "c.example", "sec-fetch-site": "same-site", "origin": "https://c.example"},
            False,
        ),
        ({"host": "c.example", "sec-fetch-site": "none", "origin": "https://c.example"}, False),
        ({"host": "c.example", "origin": "https://c.example"}, False),
        ({"host": "c.example", "sec-fetch-site": "same-origin"}, False),
        ({"host": "c.example", "sec-fetch-site": "same-origin", "origin": "null"}, False),
        (
            {"host": "c.example", "sec-fetch-site": "same-origin", "origin": "http://c.example"},
            False,
        ),
        (
            {
                "host": "c.example",
                "sec-fetch-site": "same-origin",
                "origin": "https://evil.example",
            },
            False,
        ),
        (
            {"host": "c.example", "sec-fetch-site": "same-origin", "origin": "https://c.example/"},
            False,
        ),
        (
            {
                "host": "c.example",
                "sec-fetch-site": "same-origin",
                "origin": "https://c.example.evil",
            },
            False,
        ),
        ({"sec-fetch-site": "same-origin", "origin": "https://c.example"}, False),
    ],
)
def test_same_origin_needs_both_headers_and_an_exact_match(
    headers: dict[str, str], ok: bool
) -> None:
    assert csrf.same_origin(headers, "https") is ok


def test_the_case_pages_may_post_to_themselves_and_run_nothing() -> None:
    directives = dict(d.split(" ", 1) for d in CASES_CSP.split("; "))
    assert directives["form-action"] == "'self'"
    assert directives["default-src"] == "'none'" and "script-src" not in directives
    assert directives["frame-ancestors"] == "'none'" and directives["base-uri"] == "'none'"
    # the operations page has no forms and still allows none
    assert (
        "form-action 'none'" in CONSOLE_CSP and "'self'" not in CONSOLE_CSP.split("form-action")[1]
    )


def test_with_a_configured_address_only_that_origin_counts() -> None:
    base = {"sec-fetch-site": "same-origin", "host": "127.0.0.1:8081"}
    configured = "https://console.example.net"
    assert csrf.same_origin({**base, "origin": configured}, "https", configured)
    # a proxy that forwards its own Host no longer matters, in either direction
    assert not csrf.same_origin({**base, "origin": "https://127.0.0.1:8081"}, "https", configured)
    assert not csrf.same_origin(
        {**base, "origin": configured, "sec-fetch-site": "cross-site"}, "https", configured
    )
    assert not csrf.same_origin({**base, "origin": configured + "/"}, "https", configured)


@pytest.mark.parametrize(
    "bad",
    [
        "http://console.example.net",
        "https://console.example.net/console",
        "https://Console.example.net",
        "https://user@example.com",
        "https://console.example.net?x=1",
        "console.example.net",
        "https://",
        "javascript:alert(1)",
    ],
)
def test_the_console_address_must_be_a_bare_https_origin(bad: str) -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Settings(console_base_url=bad)


def test_the_console_address_drops_a_trailing_slash() -> None:
    assert Settings(console_base_url="https://c.example.net:8443/").console_base_url == (
        "https://c.example.net:8443"
    )
    assert Settings().console_base_url == ""


def test_behind_a_proxy_that_rewrites_host_the_configured_address_is_what_works(
    fx: Fixture,
) -> None:
    """tailscale serve may forward the Host it connects to; then only the setting helps."""
    case = one_case(fx)
    c = make_client(fx, console_base_url="https://soc.example.ts.net")
    # the browser's Origin is the address it opened, not the Host the app sees
    hostish = post(c, case, "ack")  # Origin https://console.example.net == https://<Host>
    assert hostish.status_code == 403 and untouched(fx, case)
    ok = post(c, case, "ack", headers=post_headers(Origin="https://soc.example.ts.net"))
    assert ok.status_code == 303 and state(fx, case)[0] == "acknowledged"


# ---- the queue ----


def test_the_queue_lists_active_cases_and_filters(fx: Fixture) -> None:
    open_case = one_case(fx, host="host-1", age_min=30)
    acked = one_case(fx, host="host-2", age_min=20)
    closed = one_case(fx, host="host-3", age_min=10)
    c = make_client(fx)
    assert post(c, acked, "ack").status_code == 303
    assert post(c, closed, "close", fields={"note": "test"}).status_code == 303
    page = c.get("/console/cases", headers=get_headers()).text
    assert open_case in page and acked in page and closed not in page
    assert 'class="badge open"' in page and 'class="badge acknowledged"' in page
    assert closed in c.get("/console/cases?status=closed", headers=get_headers()).text
    every = c.get("/console/cases?status=all", headers=get_headers()).text
    assert all(x in every for x in (open_case, acked, closed))


def test_the_queue_row_shows_client_rule_host_and_counts(fx: Fixture) -> None:
    fx.alert(rule="general.Rule One", host="host-1", age_min=20)
    fx.alert(rule="general.Rule One", host="host-1", age_min=5)
    fx.assign()
    page = make_client(fx).get("/console/cases", headers=get_headers()).text
    for needle in ("client-a", "general.Rule One", "host-1"):
        assert needle in page
    assert re.search(r'<td class="r">2</td>', page)


def test_an_unknown_status_filter_is_a_400(fx: Fixture) -> None:
    c = make_client(fx)
    for value in ("bogus", "ACTIVE", "all;", ""):
        assert (
            c.get("/console/cases", params={"status": value}, headers=get_headers()).status_code
            == 400
        )


def test_an_empty_queue_says_so(fx: Fixture) -> None:
    page = make_client(fx).get("/console/cases", headers=get_headers()).text
    assert "No active cases" in page


# ---- one case ----


def test_a_case_page_has_the_alerts_history_and_the_two_forms(fx: Fixture) -> None:
    case = one_case(fx, rule="general.Rule One", host="host-1", link=GOOD_LINK)
    c = make_client(fx)
    r = c.get(f"/console/case/{case}", headers=get_headers())
    assert r.status_code == 200
    assert f"/console/case/{case}/ack" in r.text and f"/console/case/{case}/close" in r.text
    assert "host-1" in r.text and "general.Rule One" in r.text and "opened" in r.text
    # the tokens in the forms are the ones the checker accepts for this login and case
    tokens = re.findall(r'name="token" value="([0-9a-f]{64})"', r.text)
    assert len(tokens) == 2
    assert csrf.check_token(SECRET, tokens[0], LOGIN, case, "ack")
    assert csrf.check_token(SECRET, tokens[1], LOGIN, case, "close")


def test_a_closed_case_shows_its_note_and_no_forms(fx: Fixture) -> None:
    case = one_case(fx)
    c = make_client(fx)
    assert post(c, case, "close", fields={"note": "my own nmap test"}).status_code == 303
    r = c.get(f"/console/case/{case}", headers=get_headers())
    assert "my own nmap test" in r.text and "<form" not in r.text


def test_an_acknowledged_case_offers_close_but_not_ack(fx: Fixture) -> None:
    case = one_case(fx)
    c = make_client(fx)
    post(c, case, "ack")
    r = c.get(f"/console/case/{case}", headers=get_headers())
    assert f"/console/case/{case}/close" in r.text and f"/console/case/{case}/ack" not in r.text


def test_without_the_form_secret_the_forms_are_off(fx: Fixture) -> None:
    case = one_case(fx)
    r = make_client(fx, console_secret="").get(f"/console/case/{case}", headers=get_headers())
    assert r.status_code == 200 and "<form" not in r.text and "form secret is not set" in r.text


def test_a_case_with_many_alerts_says_only_the_newest_are_shown(fx: Fixture) -> None:
    for i in range(105):
        fx.alert(event=f"e{i}", age_min=200 - i * 0.1)
    fx.assign()
    fx.assign()
    case = str(fx.rows("SELECT id FROM soc_case")[0][0])
    r = make_client(fx).get(f"/console/case/{case}", headers=get_headers())
    assert "newest 100 shown" in r.text and r.text.count('<article class="alert">') == 100


# ---- acknowledge and close ----


def test_ack_acknowledges_once_and_redirects_back(fx: Fixture) -> None:
    case = one_case(fx)
    c = make_client(fx)
    r = post(c, case, "ack")
    assert r.status_code == 303 and r.headers["location"] == f"/console/case/{case}"
    assert state(fx, case) == ("acknowledged", False, None, 1)
    again = post(c, case, "ack")
    assert again.status_code == 303 and state(fx, case)[3] == 1  # no second event
    actor = fx.one("SELECT actor FROM case_event WHERE case_id = %s AND kind = 'acked'", (case,))
    assert actor == (LOGIN,)


def test_ack_records_the_lower_cased_login(fx: Fixture) -> None:
    case = one_case(fx)
    c = make_client(fx)
    login = "Operator@Example.com"
    token = csrf.make_token(SECRET, login, case, "ack")
    r = post(c, case, "ack", token=token, headers=post_headers(**{"Tailscale-User-Login": login}))
    assert r.status_code == 303
    assert fx.one("SELECT actor FROM case_event WHERE kind = 'acked'") == (LOGIN,)


def test_close_needs_a_note_and_a_blank_one_changes_nothing(fx: Fixture) -> None:
    case = one_case(fx)
    c = make_client(fx)
    for note in ("", "   ", "\n\t"):
        r = post(c, case, "close", fields={"note": note})
        assert r.status_code == 400 and "A note is required" in r.text
    assert state(fx, case) == ("open", False, None, 0)
    r = post(c, case, "close", fields={"note": "x" * 2001})
    assert r.status_code == 400 and "too long" in r.text and state(fx, case)[0] == "open"


def test_close_records_the_note_and_a_second_close_keeps_it(fx: Fixture) -> None:
    case = one_case(fx)
    c = make_client(fx)
    assert post(c, case, "close", fields={"note": " first reason "}).status_code == 303
    assert state(fx, case) == ("closed", True, "first reason", 1)
    assert post(c, case, "close", fields={"note": "second reason"}).status_code == 303
    assert state(fx, case) == ("closed", True, "first reason", 1)


def test_ack_on_a_closed_case_says_so_and_changes_nothing(fx: Fixture) -> None:
    case = one_case(fx)
    c = make_client(fx)
    post(c, case, "close", fields={"note": "done"})
    r = post(c, case, "ack")
    assert r.status_code == 409 and "already closed" in r.text
    assert state(fx, case)[0] == "closed"


def test_an_unknown_case_is_a_404_for_every_route(fx: Fixture) -> None:
    c = make_client(fx)
    ghost = "00000000-0000-4000-8000-0000000000ff"
    assert c.get(f"/console/case/{ghost}", headers=get_headers()).status_code == 404
    assert post(c, ghost, "ack").status_code == 404
    assert post(c, ghost, "close", fields={"note": "x"}).status_code == 404


@pytest.mark.parametrize(
    "bad", ["not-a-uuid", "1", "..%2F..%2Fetc", "0f8c2ad66f0e4d378f2b3a1b4c5d6e7f"]
)
def test_a_malformed_case_id_is_a_404_before_anything_else(fx: Fixture, bad: str) -> None:
    c = make_client(fx)
    assert c.get(f"/console/case/{bad}", headers=get_headers()).status_code == 404
    assert post(c, bad, "ack", token=None).status_code == 404
    assert post(c, bad, "close", token=None).status_code == 404


# ---- the three form checks, each on its own ----

BAD_FETCH = [None, "cross-site", "same-site", "none", ""]
BAD_ORIGIN = [
    None,
    "null",
    "https://evil.example",
    "http://console.example.net",
    "https://console.example.net/",
    "https://console.example.net.evil.example",
    "",
]


def untouched(fx: Fixture, case: str) -> bool:
    return state(fx, case) == ("open", False, None, 0)


@pytest.mark.parametrize("action", ["ack", "close"])
@pytest.mark.parametrize("fetch", BAD_FETCH)
def test_a_post_that_is_not_marked_same_origin_writes_nothing(
    fx: Fixture, action: str, fetch: str | None
) -> None:
    case = one_case(fx)
    r = post(
        make_client(fx),
        case,
        action,
        headers=post_headers(**{"Sec-Fetch-Site": fetch}),
        fields={"note": "x"},
    )
    assert r.status_code == 403 and untouched(fx, case)


@pytest.mark.parametrize("action", ["ack", "close"])
@pytest.mark.parametrize("origin", BAD_ORIGIN)
def test_a_post_from_another_origin_writes_nothing(
    fx: Fixture, action: str, origin: str | None
) -> None:
    case = one_case(fx)
    r = post(
        make_client(fx), case, action, headers=post_headers(Origin=origin), fields={"note": "x"}
    )
    assert r.status_code == 403 and untouched(fx, case)


def other_case_token(action: str) -> str:
    return csrf.make_token(SECRET, LOGIN, "00000000-0000-4000-8000-0000000000ff", action)


@pytest.mark.parametrize("action", ["ack", "close"])
@pytest.mark.parametrize(
    "which",
    [
        "missing",
        "empty",
        "garbage",
        "other-case",
        "other-action",
        "other-login",
        "old",
        "other-secret",
    ],
)
def test_a_post_without_the_right_token_writes_nothing(
    fx: Fixture, action: str, which: str
) -> None:
    case = one_case(fx)
    other = "close" if action == "ack" else "ack"
    old = datetime.now(UTC) - timedelta(days=3)
    tokens = {
        "missing": None,
        "empty": "",
        "garbage": "f" * 64,
        "other-case": other_case_token(action),
        "other-action": csrf.make_token(SECRET, LOGIN, case, other),
        "other-login": csrf.make_token(SECRET, "someone.else@example.com", case, action),
        "old": csrf.make_token(SECRET, LOGIN, case, action, old),
        "other-secret": csrf.make_token(SECRET + "x", LOGIN, case, action),
    }
    r = post(make_client(fx), case, action, token=tokens[which], fields={"note": "x"})
    assert r.status_code == 403 and untouched(fx, case)


def test_yesterdays_token_still_works(fx: Fixture) -> None:
    case = one_case(fx)
    token = csrf.make_token(SECRET, LOGIN, case, "ack", datetime.now(UTC) - timedelta(days=1))
    assert post(make_client(fx), case, "ack", token=token).status_code == 303


def test_a_correct_post_from_another_login_on_the_allowlist_uses_its_own_token(fx: Fixture) -> None:
    case = one_case(fx)
    c = make_client(fx, console_users=f"{LOGIN},second@example.com")
    mine = csrf.make_token(SECRET, LOGIN, case, "ack")
    r = post(
        c,
        case,
        "ack",
        token=mine,
        headers=post_headers(**{"Tailscale-User-Login": "second@example.com"}),
    )
    assert r.status_code == 403 and untouched(fx, case)  # a token is not transferable


@pytest.mark.parametrize("action", ["ack", "close"])
def test_a_get_cannot_change_anything(fx: Fixture, action: str) -> None:
    case = one_case(fx)
    r = make_client(fx).get(f"/console/case/{case}/{action}", headers=get_headers())
    assert r.status_code == 405 and untouched(fx, case)


def test_the_form_must_be_urlencoded_and_small(fx: Fixture) -> None:
    case = one_case(fx)
    c = make_client(fx)
    assert (
        post(
            c, case, "ack", headers=post_headers(**{"Content-Type": "application/json"})
        ).status_code
        == 415
    )
    assert (
        post(
            c,
            case,
            "ack",
            headers=post_headers(**{"Content-Type": "multipart/form-data; boundary=x"}),
        ).status_code
        == 415
    )
    big = urlencode({"token": "x", "note": "y" * 9000}).encode()
    assert post(c, case, "close", raw=big).status_code == 413
    assert post(c, case, "close", raw=b"token=\xff\xfe").status_code == 400
    assert untouched(fx, case)


def test_every_route_needs_the_allowlist_and_an_identity(fx: Fixture) -> None:
    case = one_case(fx)
    c = make_client(fx)
    stranger = "stranger@example.com"
    assert c.get("/console/cases").status_code == 403
    assert c.get("/console/cases", headers=get_headers(stranger)).status_code == 403
    assert c.get(f"/console/case/{case}", headers=get_headers(stranger)).status_code == 403
    for action in ("ack", "close"):
        token = csrf.make_token(SECRET, stranger, case, action)
        r = post(
            c,
            case,
            action,
            token=token,
            headers=post_headers(**{"Tailscale-User-Login": stranger}),
            fields={"note": "x"},
        )
        assert r.status_code == 403
        assert (
            post(
                c,
                case,
                action,
                headers=post_headers(**{"Tailscale-User-Login": None}),
                fields={"note": "x"},
            ).status_code
            == 403
        )
    assert untouched(fx, case)


# ---- hostile alert text ----

GOOD_LINK_PREFIX = "https://app.limacharlie.io/"


def structure(html: str) -> tuple[set[str], set[str], list[str]]:
    """Which tags and attribute names a page really contains, and where its links go."""
    from html.parser import HTMLParser

    tags: set[str] = set()
    attrs: set[str] = set()
    links: list[str] = []

    class Collect(HTMLParser):
        def handle_starttag(self, tag: str, attributes: list[tuple[str, str | None]]) -> None:
            tags.add(tag)
            for name, value in attributes:
                attrs.add(name.lower())
                if name == "href" and value is not None:
                    links.append(value)

    Collect().feed(html)
    return tags, attrs, links


HOSTILE = '<script>alert(1)</script>"><img src=x onerror=alert(2)>'


def hostile_case(fx: Fixture) -> str:
    return one_case(
        fx,
        rule=f"general.{HOSTILE} \u202eevil\x1b[31m",
        host=f"<b>{HOSTILE}</b>\u200b",
        cat=HOSTILE + "\u202e",
        link="javascript:alert(document.cookie)",
    )


def test_hostile_alert_text_is_shown_as_text_and_never_runs(fx: Fixture) -> None:
    case = hostile_case(fx)
    c = make_client(fx)
    for path in (f"/console/case/{case}", "/console/cases"):
        r = c.get(path, headers=get_headers())
        assert r.status_code == 200
        html = r.text
        assert "<script" not in html.lower()  # not even the page's own: there is no script
        tags, attrs, links = structure(html)
        assert not tags & {"script", "img", "iframe", "object", "embed"}
        assert not [a for a in attrs if a.startswith("on")]
        assert all(h.startswith(("/", GOOD_LINK_PREFIX)) for h in links)
        assert "&lt;script&gt;" in html
        assert "\u202e" not in html and "\u200b" not in html and "\x1b" not in html
        assert "⟦U+202E⟧" in html
        assert r.headers["content-security-policy"] == CASES_CSP
        assert "script-src" not in CASES_CSP and "default-src 'none'" in CASES_CSP
        assert r.headers["x-frame-options"] == "DENY" and r.headers["cache-control"] == "no-store"


def test_a_link_that_is_not_the_vendors_console_is_text_not_an_href(fx: Fixture) -> None:
    case = hostile_case(fx)
    html = make_client(fx).get(f"/console/case/{case}", headers=get_headers()).text
    assert not re.search(r'href="(?!/console|https://app\.limacharlie\.io/)', html)
    assert "javascript:alert" in html  # shown, inert
    assert 'href="javascript' not in html.lower()


def test_the_template_writes_the_vendors_address_itself() -> None:
    """The href's scheme and host are fixed text in the template, never alert data."""
    from pathlib import Path

    template = (Path(__file__).resolve().parents[1] / "src/soc_api/templates/case.html").read_text()
    assert f'href="{LC_LINK_PREFIX}{{{{ path }}}}"' in template
    assert not re.search(r'href="\{\{', template)  # no href starts with a variable
    assert link_path(GOOD_LINK) == GOOD_LINK[len(LC_LINK_PREFIX) :]
    assert link_path("javascript:alert(1)") is None and link_path(None) is None


def test_the_vendors_link_becomes_a_link_without_a_referrer(fx: Fixture) -> None:
    case = one_case(fx, link=GOOD_LINK)
    html = make_client(fx).get(f"/console/case/{case}", headers=get_headers()).text
    assert f'href="{GOOD_LINK}" rel="noreferrer noopener"' in html


@pytest.mark.parametrize(
    "link",
    [
        "http://app.limacharlie.io/x",
        "https://app.limacharlie.io.evil.example/x",
        "https://evil.example/https://app.limacharlie.io/",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        GOOD_LINK + " onclick=alert(1)",
        GOOD_LINK + '"><script>',
    ],
)
def test_only_a_clean_vendor_link_is_ever_an_href(fx: Fixture, link: str) -> None:
    assert safe_link(link) is None
    case = one_case(fx, link=link)
    html = make_client(fx).get(f"/console/case/{case}", headers=get_headers()).text
    assert 'rel="noreferrer noopener"' not in html and "<script" not in html.lower()


def test_a_hostile_note_is_escaped_where_it_is_shown_back(fx: Fixture) -> None:
    case = one_case(fx)
    c = make_client(fx)
    note = f"{HOSTILE}\u202e"
    assert post(c, case, "close", fields={"note": note}).status_code == 303
    html = c.get(f"/console/case/{case}", headers=get_headers()).text
    assert "<script" not in html.lower() and "<img" not in html.lower()
    assert "&lt;script&gt;" in html and "\u202e" not in html and "⟦U+202E⟧" in html


def test_a_hostile_login_cannot_reach_the_audit_trail_or_the_page(fx: Fixture) -> None:
    case = one_case(fx)
    login = "<script>@example.com"
    c = make_client(fx, console_users=login)
    token = csrf.make_token(SECRET, login, case, "ack")
    r = post(c, case, "ack", token=token, headers=post_headers(**{"Tailscale-User-Login": login}))
    assert r.status_code == 403 and "not accepted" in r.text
    assert "<script" not in r.text.lower() and untouched(fx, case)


# ---- when the database is not there ----


def test_a_console_without_a_database_login_says_cases_are_not_set_up(fx: Fixture) -> None:
    c = make_client(fx, console_database_url="")
    for path in ("/console/cases", f"/console/case/{one_case(fx)}"):
        r = c.get(path, headers=get_headers())
        assert r.status_code == 503 and "not set up" in r.text


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.mark.parametrize("what", ["down", "wrong-password"])
def test_a_database_that_cannot_be_reached_is_a_plain_503_that_leaks_nothing(
    fx: Fixture, what: str
) -> None:
    case = one_case(fx)
    url = fx.db.sqlalchemy_url("soc_console", "wrong-password-0123456789abcdef")
    if what == "down":
        url = f"postgresql+psycopg://soc_console:secretpw@127.0.0.1:{free_port()}/soc"
    c = make_client(fx, console_database_url=url)
    pages = [
        c.get("/console/cases", headers=get_headers()),
        c.get(f"/console/case/{case}", headers=get_headers()),
        post(c, case, "ack"),
    ]
    for r in pages:
        assert r.status_code == 503 and "cannot be reached" in r.text
        for secret in (
            "127.0.0.1",
            "secretpw",
            "soc_console",
            "wrong-password",
            "psycopg",
            "Traceback",
        ):
            assert secret not in r.text
    assert c.get("/healthz").status_code == 200  # the console itself stays up
    assert untouched(fx, case)
