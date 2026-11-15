"""Quick close (migration 0013): four one-tap verdicts with an optional note.

The function (close_case_with_verdict) is exercised as soc_console, the way the console
calls it; the route and page through the console app, with the same origin, form-token and
role checks as Acknowledge and Close.
"""

from typing import Any

import psycopg
import pytest
from conftest import TestDb
from test_console_cases import (
    LOGIN,
    SECRET,
    make_client,
    one_case,
    post,
    post_headers,
)
from test_console_roles import USERS, VIEWER
from test_worker_db import Fixture

from soc_api import csrf
from soc_api import db as soc_db
from soc_api.cases import VERDICTS, verdict_label

FUNCTION = "close_case_with_verdict(uuid, text, text, text)"
LABELS = {
    "test": "Our test",
    "authorized_activity": "Our admin work",
    "false_positive": "False positive",
    "duplicate": "Duplicate",
}


@pytest.fixture
def fx(db: TestDb) -> Fixture:
    return Fixture(db)


def quick(fx: Fixture, case: Any, verdict: Any, note: Any = "", login: Any = LOGIN) -> str:
    with fx.db.connect("soc_console") as c:
        row = c.execute(
            "SELECT close_case_with_verdict(%s, %s, %s, %s)", (case, login, verdict, note)
        ).fetchone()
    assert row is not None
    return str(row[0])


def row(fx: Fixture, case: Any) -> tuple[Any, ...]:
    return fx.one(
        "SELECT status, verdict, closing_note, closed_at IS NOT NULL FROM soc_case WHERE id = %s",
        (case,),
    )


def closed_events(fx: Fixture, case: Any) -> list[tuple[Any, ...]]:
    return fx.rows(
        "SELECT actor, body FROM case_event WHERE case_id = %s AND kind = 'closed'", (case,)
    )


# ---- the function ----


def test_the_python_and_sql_verdict_sets_are_the_same() -> None:
    assert set(VERDICTS) == set(LABELS) and VERDICTS == LABELS


@pytest.mark.parametrize("verdict", sorted(LABELS))
def test_each_verdict_closes_with_its_note_and_the_actor(fx: Fixture, verdict: str) -> None:
    case = one_case(fx)
    assert quick(fx, case, verdict, "  pen test on the lab box \n", "Operator@Example.com") == (
        "closed"
    )
    assert row(fx, case) == ("closed", verdict, "pen test on the lab box", True)
    assert closed_events(fx, case) == [
        ("operator@example.com", f"{verdict}: pen test on the lab box")
    ]
    assert fx.one("SELECT count(acked_at) FROM notification") == (1,)  # nothing left to re-send


@pytest.mark.parametrize("note", ["", None, "   \n"])
def test_the_note_may_be_empty_for_a_quick_close(fx: Fixture, note: str | None) -> None:
    case = one_case(fx)
    assert quick(fx, case, "duplicate", note) == "closed"
    assert row(fx, case) == ("closed", "duplicate", None, True)
    assert closed_events(fx, case) == [(LOGIN, "duplicate")]


@pytest.mark.parametrize(
    "verdict", [None, "", "bogus", "TEST", "test ", "malicious", "false positive", "test;--"]
)
def test_an_unknown_verdict_is_refused_in_sql_and_nothing_is_written(
    fx: Fixture, verdict: str | None
) -> None:
    case = one_case(fx)
    assert quick(fx, case, verdict, "n") == "invalid_verdict"
    assert row(fx, case) == ("open", None, None, False)
    assert closed_events(fx, case) == []


def test_a_bad_login_or_a_long_note_or_an_unknown_case_is_refused(fx: Fixture) -> None:
    case = one_case(fx)
    assert quick(fx, case, "test", "n", login="not a login") == "invalid_login"
    assert quick(fx, case, "test", "n", login=None) == "invalid_login"
    assert quick(fx, case, "test", "x" * 2001) == "note_too_long"
    assert quick(fx, "00000000-0000-4000-8000-0000000000ff", "test") == "not_found"
    assert row(fx, case) == ("open", None, None, False)
    assert quick(fx, case, "test", "x" * 2000) == "closed"


def test_an_already_closed_case_is_left_alone_as_close_case_does(fx: Fixture) -> None:
    case = one_case(fx)
    with fx.db.connect("soc_console") as c:
        assert c.execute("SELECT close_case(%s, %s, %s)", (case, LOGIN, "first")).fetchone() == (
            "closed",
        )
    assert quick(fx, case, "false_positive", "second") == "already"
    assert row(fx, case) == ("closed", None, "first", True)  # the old close sets no verdict
    assert len(closed_events(fx, case)) == 1
    other = one_case(fx, host="other-host", event="e2")
    assert quick(fx, other, "test") == "closed"
    assert quick(fx, other, "duplicate", "later") == "already"
    assert row(fx, other)[1] == "test"


def test_an_acknowledged_case_can_be_quick_closed(fx: Fixture) -> None:
    case = one_case(fx)
    with fx.db.connect("soc_console") as c:
        c.execute("SELECT ack_case(%s, %s)", (case, LOGIN))
    assert quick(fx, case, "authorized_activity") == "closed"


def test_the_queue_and_the_case_carry_the_verdict(fx: Fixture) -> None:
    case = one_case(fx)
    quick(fx, case, "false_positive", "tuned")
    with fx.db.connect("soc_console") as c, c.cursor() as cur:
        cur.execute("SELECT * FROM list_cases('closed', 10)")
        names = [d.name for d in cur.description or []]
        listed = [dict(zip(names, r, strict=True)) for r in cur.fetchall()]
        doc = c.execute("SELECT get_case(%s)", (case,)).fetchone()
    assert listed[0]["verdict"] == "false_positive"
    assert doc is not None and doc[0]["case"]["verdict"] == "false_positive"


def test_the_function_is_the_consoles_alone_and_owned_by_the_writer(fx: Fixture) -> None:
    with fx.db.connect() as c:
        for role in ("soc_app", "soc_ingest", "soc_worker", "soc_posture"):
            assert c.execute(
                "SELECT has_function_privilege(%s, %s::regprocedure, 'EXECUTE')", (role, FUNCTION)
            ).fetchone() == (False,), role
        assert c.execute(
            "SELECT has_function_privilege('soc_console', %s::regprocedure, 'EXECUTE')",
            (FUNCTION,),
        ).fetchone() == (True,)
        owner = c.execute(
            "SELECT p.prosecdef, p.proconfig, r.rolname FROM pg_proc p "
            "JOIN pg_roles r ON r.oid = p.proowner WHERE p.oid = %s::regprocedure",
            (FUNCTION,),
        ).fetchone()
        assert owner is not None
        definer, config, rolname = owner
        assert definer and rolname == "soc_console_writer"
        assert config and any(x.startswith("search_path=pg_catalog") for x in config)
        assert c.execute(
            "SELECT has_column_privilege('soc_console_writer', 'soc_case', 'verdict', 'UPDATE')"
        ).fetchone() == (True,)
        # and the console login itself still has no table privileges
        assert c.execute(
            "SELECT has_column_privilege('soc_console', 'soc_case', 'verdict', 'UPDATE')"
        ).fetchone() == (False,)
    with fx.db.connect("soc_console") as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
        c.execute("UPDATE soc_case SET verdict = 'test'")


def test_downgrade_removes_the_function_and_restores_the_old_shapes(fx: Fixture) -> None:
    case = one_case(fx)
    url = fx.db.sqlalchemy_url()
    soc_db.downgrade(url, "0011")
    with fx.db.connect() as c:
        assert c.execute(
            "SELECT count(*) FROM pg_proc WHERE proname = 'close_case_with_verdict'"
        ).fetchone() == (0,)
        assert c.execute(
            "SELECT has_column_privilege('soc_console_writer', 'soc_case', 'verdict', 'UPDATE')"
        ).fetchone() == (False,)
    with fx.db.connect("soc_console") as c, c.cursor() as cur:
        cur.execute("SELECT * FROM list_cases('all', 10)")
        assert "verdict" not in [d.name for d in cur.description or []]
        doc = c.execute("SELECT get_case(%s)", (case,)).fetchone()
        assert doc is not None and "verdict" not in doc[0]["case"]
        assert c.execute("SELECT close_case(%s, %s, 'n')", (case, LOGIN)).fetchone() == ("closed",)
    soc_db.upgrade(url)
    assert quick(fx, one_case(fx, host="again", event="e3"), "test") == "closed"


# ---- the page and the route ----


def post_quick(client: Any, case: str, verdict: str | None, note: str = "", **kw: Any) -> Any:
    fields = {"note": note}
    if verdict is not None:
        fields["verdict"] = verdict
    return post(client, case, "close-as", fields=fields, **kw)


@pytest.mark.parametrize("verdict", sorted(LABELS))
def test_the_button_closes_the_case_with_the_verdict_note_and_actor(
    fx: Fixture, verdict: str
) -> None:
    case = one_case(fx)
    client = make_client(fx)
    r = post_quick(client, case, verdict, "scanning my own lab")
    assert r.status_code == 303 and r.headers["location"] == f"/console/case/{case}"
    assert row(fx, case) == ("closed", verdict, "scanning my own lab", True)
    assert closed_events(fx, case) == [(LOGIN, f"{verdict}: scanning my own lab")]
    page = client.get(f"/console/case/{case}", headers={"Tailscale-User-Login": LOGIN})
    assert LABELS[verdict] in page.text and "scanning my own lab" in page.text
    assert "<form" not in page.text  # a closed case offers nothing more


def test_an_empty_note_is_fine_for_the_buttons_but_not_for_the_free_text_close(
    fx: Fixture,
) -> None:
    client = make_client(fx)
    case = one_case(fx)
    assert post_quick(client, case, "test", "").status_code == 303
    assert row(fx, case)[:3] == ("closed", "test", None)
    other = one_case(fx, host="h2", event="e2")
    r = post(client, other, "close", fields={"note": "  "})
    assert r.status_code == 400 and "note is required" in r.text
    assert row(fx, other)[0] == "open"


@pytest.mark.parametrize("verdict", [None, "", "bogus", "TEST", "malicious"])
def test_an_unknown_verdict_is_a_400_and_nothing_is_written(
    fx: Fixture, verdict: str | None
) -> None:
    case = one_case(fx)
    r = post_quick(make_client(fx), case, verdict, "n")
    assert r.status_code == 400 and "not a way to close" in r.text
    assert row(fx, case) == ("open", None, None, False)
    assert closed_events(fx, case) == []


def test_a_second_quick_close_says_closed_and_keeps_the_first_verdict(fx: Fixture) -> None:
    case = one_case(fx)
    client = make_client(fx)
    assert post_quick(client, case, "test", "first").status_code == 303
    assert post_quick(client, case, "duplicate", "second").status_code == 303  # as close does
    assert row(fx, case) == ("closed", "test", "first", True)
    assert len(closed_events(fx, case)) == 1


def test_an_unknown_case_is_a_404(fx: Fixture) -> None:
    r = post_quick(make_client(fx), "00000000-0000-4000-8000-0000000000ff", "test")
    assert r.status_code == 404


def test_the_form_token_origin_and_content_type_are_still_required(fx: Fixture) -> None:
    case = one_case(fx)
    client = make_client(fx)
    refused = [
        post_quick(client, case, "test", token=None),
        post_quick(client, case, "test", token="0" * 64),
        # a token minted for another action does not work here
        post_quick(client, case, "test", token=csrf.make_token(SECRET, LOGIN, case, "close")),
        post_quick(client, case, "test", headers=post_headers(Origin="https://evil.example.com")),
        post_quick(client, case, "test", headers=post_headers(Origin=None)),
    ]
    assert [r.status_code for r in refused] == [403] * 5
    wrong_type = post_quick(
        client, case, "test", headers=post_headers(**{"Content-Type": "text/plain"})
    )
    assert wrong_type.status_code == 415
    assert row(fx, case) == ("open", None, None, False)


def test_the_quick_buttons_sit_on_the_case_page_without_script(fx: Fixture) -> None:
    case = one_case(fx)
    client = make_client(fx)
    page = client.get(f"/console/case/{case}", headers={"Tailscale-User-Login": LOGIN})
    assert page.status_code == 200
    for verdict, label in LABELS.items():
        assert f'name="verdict" value="{verdict}">{label}</button>' in page.text
    assert f'action="/console/case/{case}/close-as"' in page.text
    assert "Acknowledge" in page.text and "Close with a note" in page.text  # unchanged
    assert "<script" not in page.text and "style=" not in page.text
    assert "onclick" not in page.text and "<style" not in page.text


def test_a_viewer_gets_403_before_the_database_and_no_buttons(fx: Fixture) -> None:
    case = one_case(fx)
    client = make_client(fx, console_users=USERS)
    token = csrf.make_token(SECRET, VIEWER, case, "close-as")
    r = post_quick(
        client,
        case,
        "test",
        "n",
        token=token,
        headers=post_headers(**{"Tailscale-User-Login": VIEWER}),
    )
    assert r.status_code == 403 and "read-only" in r.text
    assert row(fx, case) == ("open", None, None, False)
    page = client.get(f"/console/case/{case}", headers={"Tailscale-User-Login": VIEWER})
    assert page.status_code == 200
    assert "close-as" not in page.text and "Our test" not in page.text
    assert 'name="verdict"' not in page.text


def test_the_queue_shows_the_verdict_in_plain_words(fx: Fixture) -> None:
    client = make_client(fx)
    cases = {
        verdict: one_case(fx, host=f"host-{i}", event=f"e{i}")
        for i, verdict in enumerate(sorted(LABELS))
    }
    for verdict, case in cases.items():
        assert post_quick(client, case, verdict).status_code == 303
    still_open = one_case(fx, host="open-host", event="eo")
    page = client.get("/console/cases?status=closed", headers={"Tailscale-User-Login": LOGIN})
    assert page.status_code == 200
    for label in LABELS.values():
        assert label in page.text
    assert "authorized_activity" not in page.text and "false_positive" not in page.text
    active = client.get("/console/cases", headers={"Tailscale-User-Login": LOGIN})
    assert fx.one("SELECT status FROM soc_case WHERE id = %s", (still_open,)) == ("open",)
    assert active.status_code == 200 and "Our test" not in active.text


def test_verdict_label_never_shows_a_raw_or_odd_value() -> None:
    assert verdict_label("test") == "Our test"
    assert verdict_label(None) == "" and verdict_label("evil<b>") == "" and verdict_label(3) == ""
