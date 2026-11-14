"""Console roles: who may act, and who is on the audit trail.

SOC_CONSOLE_USERS entries are `login` (an analyst, as before roles existed) or `login:role`
with role admin, analyst or viewer. A viewer sees every page and can change nothing: the
action routes refuse a viewer with 403 before the form is read and before the database is
opened, whatever token the form carries.
"""

from typing import Any
from urllib.parse import urlencode

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from test_console_cases import (
    ACK_KEY,
    BASE,
    SECRET,
    make_client,
    one_case,
    post,
    post_headers,
    state,
)
from test_worker_db import Fixture

from soc_api import console, csrf
from soc_api.config import Settings, parse_console_users
from soc_api.main import create_console_app

VIEWER = "watcher@example.com"
ANALYST = "operator@example.com"
ADMIN = "boss@example.com"
USERS = f"{ANALYST}, {ADMIN}:admin, {VIEWER}:Viewer"
CASE = "0f8c2ad6-6f0e-4d37-8f2b-3a1b4c5d6e7f"


@pytest.fixture
def fx(db: Any) -> Fixture:
    return Fixture(db)


# ---- parsing ----


def test_a_login_without_a_role_is_an_analyst_and_roles_are_read_case_insensitively() -> None:
    assert parse_console_users(USERS) == {ANALYST: "analyst", ADMIN: "admin", VIEWER: "viewer"}
    assert parse_console_users(" A@Example.com : ADMIN ,, ") == {"a@example.com": "admin"}
    assert parse_console_users("") == {}
    # the allow-list is the same logins, so existing deploys behave as they did
    assert Settings(console_users="a@example.com, b@example.com").console_allowlist == {
        "a@example.com",
        "b@example.com",
    }


@pytest.mark.parametrize(
    "raw",
    [
        "a@example.com:root",  # unknown role
        "a@example.com:",  # role missing after the colon
        "a@example.com:analyst:extra",
        ":viewer",  # no login
        "a@example.com viewer",  # space instead of a colon
        "a@example.com:viewer, a@example.com:admin",  # one login, two roles
    ],
)
def test_a_bad_entry_stops_the_console_from_starting_in_prod(raw: str) -> None:
    with pytest.raises(ValueError, match="SOC_CONSOLE_USERS"):
        create_console_app(Settings(env="prod", console_users=raw))


def test_a_bad_role_error_does_not_repeat_the_entry() -> None:
    with pytest.raises(ValueError, match="SOC_CONSOLE_USERS") as err:
        create_console_app(Settings(env="prod", console_users="secret-person@example.com:root"))
    assert "secret-person" not in str(err.value)


def test_a_repeated_login_with_the_same_role_is_fine() -> None:
    assert parse_console_users("a@example.com:viewer,a@example.com:viewer") == {
        "a@example.com": "viewer"
    }


# ---- every route that changes something refuses a viewer ----


def action_routes(app: FastAPI) -> list[tuple[str, str]]:
    """(method, path) of every route on the console app that is not a plain read, taken from
    the app's own schema so a route added later cannot be missed by this test."""
    reads = {"get", "head", "options"}
    paths = app.openapi()["paths"]
    return [(m.upper(), p) for p, ops in paths.items() for m in ops if m not in reads]


def test_the_action_routes_are_the_ones_expected() -> None:
    app = create_console_app(Settings(env="dev", console_users=USERS))
    found = set(action_routes(app))
    assert found == {
        ("POST", "/console/case/{case_id}/ack"),
        ("POST", "/console/case/{case_id}/close"),
        ("POST", "/console/case/{case_id}/ack-phone"),
    }


def test_a_viewer_is_refused_on_every_action_route_before_the_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened: list[str] = []

    def no_database(settings: Settings) -> None:
        opened.append("opened")

    monkeypatch.setattr(console, "case_db", no_database)
    settings = Settings(
        env="prod",
        console_users=USERS,
        console_secret=SECRET,
        ack_key=ACK_KEY,
        console_base_url=BASE,
    )
    client = TestClient(create_console_app(settings), base_url=BASE, follow_redirects=False)
    routes = action_routes(client.app)  # type: ignore[arg-type]
    assert routes
    for method, template in routes:
        path = template.replace("{case_id}", CASE)
        if path.endswith("/ack-phone"):
            exp = csrf.phone_expiry()
            path += f"?e={exp}&t={csrf.make_phone_token(ACK_KEY, CASE, exp)}"
        action = path.split("/")[4].split("?")[0] if "/case/" in path else ""
        # The strongest request a viewer could send: same origin, and a genuine token.
        token = csrf.make_token(SECRET, VIEWER, CASE, action) if action in csrf.ACTIONS else ""
        body = urlencode({"token": token, "note": "done"}).encode()
        r = client.request(
            method, path, content=body, headers=post_headers(**{"Tailscale-User-Login": VIEWER})
        )
        assert r.status_code == 403, (method, template)
        assert "read-only" in r.text, (method, template)
    assert opened == []


def test_a_login_that_is_not_listed_is_still_refused_everywhere() -> None:
    client = TestClient(
        create_console_app(Settings(env="prod", console_users=USERS)), base_url=BASE
    )
    r = client.post(
        f"/console/case/{CASE}/ack",
        headers=post_headers(**{"Tailscale-User-Login": "stranger@example.com"}),
    )
    assert r.status_code == 403 and "allowlist" in r.text


# ---- with a database: viewers read, analysts and admins act, actors are logins ----


def get_case_page(fx: Fixture, login: str, case: str) -> Any:
    client = make_client(fx, console_users=USERS)
    return client.get(f"/console/case/{case}", headers={"Tailscale-User-Login": login})


def test_a_viewer_sees_the_pages_without_the_buttons(fx: Fixture) -> None:
    case = one_case(fx)
    client = make_client(fx, console_users=USERS)
    h = {"Tailscale-User-Login": VIEWER}
    assert client.get("/console/cases", headers=h).status_code == 200
    page = client.get(f"/console/case/{case}", headers=h)
    assert page.status_code == 200
    assert "<form" not in page.text and "Acknowledge" not in page.text
    assert 'name="token"' not in page.text and "Close with a note" not in page.text
    assert "read-only" in page.text
    assert client.get("/console", headers=h).status_code in (200, 502, 503)


@pytest.mark.parametrize("login", [ANALYST, ADMIN])
def test_an_analyst_and_an_admin_get_the_buttons(fx: Fixture, login: str) -> None:
    case = one_case(fx)
    page = get_case_page(fx, login, case)
    assert page.status_code == 200
    assert "Acknowledge" in page.text and "Close with a note" in page.text


def test_a_viewer_cannot_ack_or_close_even_with_a_genuine_form_token(fx: Fixture) -> None:
    case = one_case(fx)
    client = make_client(fx, console_users=USERS)
    for action in ("ack", "close"):
        token = csrf.make_token(SECRET, VIEWER, case, action)
        r = client.post(
            f"/console/case/{case}/{action}",
            content=urlencode({"token": token, "note": "n"}).encode(),
            headers=post_headers(**{"Tailscale-User-Login": VIEWER}),
        )
        assert r.status_code == 403
    assert state(fx, case) == ("open", False, None, 0)


def test_an_unmarked_login_still_acts_as_before(fx: Fixture) -> None:
    case = one_case(fx)
    client = make_client(fx, console_users=ANALYST)
    assert post(client, case, "ack").status_code == 303
    assert state(fx, case)[0] == "acknowledged"


def test_every_action_records_the_login_that_did_it(fx: Fixture) -> None:
    ack_case = one_case(fx)
    client = make_client(fx, console_users=USERS, ack_key=ACK_KEY)
    r = client.post(
        f"/console/case/{ack_case}/ack",
        content=urlencode({"token": csrf.make_token(SECRET, ADMIN, ack_case, "ack")}).encode(),
        headers=post_headers(**{"Tailscale-User-Login": ADMIN}),
    )
    assert r.status_code == 303
    r = client.post(
        f"/console/case/{ack_case}/close",
        content=urlencode(
            {"token": csrf.make_token(SECRET, ANALYST, ack_case, "close"), "note": "benign"}
        ).encode(),
        headers=post_headers(),
    )
    assert r.status_code == 303
    phone_case = one_case(fx, rule="other rule")
    exp = csrf.phone_expiry()
    tok = csrf.make_phone_token(ACK_KEY, phone_case, exp)
    r = client.post(
        f"/console/case/{phone_case}/ack-phone?e={exp}&t={tok}",
        headers={"Tailscale-User-Login": ANALYST},
    )
    assert r.status_code == 200
    # Console actions: the login itself. The phone link only carries a case and an expiry, so
    # the person is the verified tailnet login on the request (the link cannot name them).
    rows = fx.rows(
        "SELECT kind, actor FROM case_event WHERE kind IN ('acked', 'closed') ORDER BY at, id"
    )
    assert sorted(rows) == sorted([("acked", ADMIN), ("closed", ANALYST), ("acked", ANALYST)])
    assert all("@" in actor for _, actor in rows)
