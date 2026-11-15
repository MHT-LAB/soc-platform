"""The console's look: severity colors, the shield mark, the phone layout and display names.

Display names are for showing a person's name in the header. They are never an identity: the
roles, the allow-list and the audit trail all keep using the tailnet login.
"""

import re
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from test_console_cases import (
    LOGIN,
    SECRET,
    get_headers,
    make_client,
    one_case,
    post,
)
from test_worker_db import Fixture

from soc_api import console, status
from soc_api.config import Settings, display_name, parse_display_names
from soc_api.main import create_console_app

STATIC = Path(console.HERE / "static" / "console.css")
TEMPLATES = Path(console.HERE / "templates")
TAILNET = {"Tailscale-User-Login": "operator@example.com"}


@pytest.fixture
def fx(db: Any) -> Fixture:
    return Fixture(db)


@pytest.fixture
def fake_probes(monkeypatch: pytest.MonkeyPatch) -> None:
    async def tunnel(_: Settings) -> status.TunnelStatus:
        return status.TunnelStatus("up", 4)

    async def fleet(_: Settings) -> status.Fleet:
        return status.Fleet(
            configured=True, sensors=[status.Sensor("ws-1", "Linux", True, "2026-10-17 18:00:00")]
        )

    monkeypatch.setattr(status, "tunnel_status", tunnel)
    monkeypatch.setattr(status, "sensor_fleet", fleet)


# ---- display names: parsing and fallback ----


def test_display_names_are_read_as_login_equals_name() -> None:
    assert parse_display_names("A@Example.com=Alice A., b@example.com = Bob ") == {
        "a@example.com": "Alice A.",
        "b@example.com": "Bob",
    }
    assert parse_display_names("") == {}


@pytest.mark.parametrize("raw", ["nonsense", "=Name", "a@example.com=", ",,", "a@example.com"])
def test_a_malformed_display_name_entry_is_ignored_not_fatal(raw: str) -> None:
    assert parse_display_names(raw) == {}
    create_console_app(
        Settings(env="prod", console_users="a@example.com", console_display_names=raw)
    )


def test_a_display_name_is_cut_to_64_characters() -> None:
    assert len(parse_display_names("a@example.com=" + "x" * 500)["a@example.com"]) == 64


def test_without_a_configured_name_the_part_before_the_at_sign_is_shown() -> None:
    names = parse_display_names("a@example.com=Alice")
    assert display_name("a@example.com", names) == "Alice"
    assert display_name("A@Example.com", names) == "Alice"
    assert display_name("alex.rivera@example.com", names) == "alex.rivera"
    assert display_name("noat", {}) == "noat"
    assert display_name("@odd", {}) == "@odd"


# ---- the header on every page ----


def test_the_header_has_the_shield_and_the_name_on_the_operations_page(fake_probes: None) -> None:
    client = TestClient(
        create_console_app(
            Settings(
                env="prod",
                console_users="operator@example.com",
                console_display_names="operator@example.com=Alex R.",
                version="edge",
                git_sha="a" * 40,
            )
        )
    )
    page = client.get("/console", headers=TAILNET).text
    assert 'class="shield"' in page and 'class="shield-body"' in page
    assert ">Alex R.</span>" in page
    # the login is still shown, as the tooltip that says who Tailscale verified
    assert 'title="Verified by Tailscale: operator@example.com"' in page
    assert "ring1" not in page  # the old mark is gone


def test_a_display_name_is_escaped_like_any_text(fake_probes: None) -> None:
    hostile = "<img src=x onerror=alert(1)>"
    client = TestClient(
        create_console_app(
            Settings(
                env="prod",
                console_users="operator@example.com",
                console_display_names=f"operator@example.com={hostile}",
                version="edge",
                git_sha="a" * 40,
            )
        )
    )
    page = client.get("/console", headers=TAILNET).text
    assert hostile not in page and "&lt;img src=x onerror=alert(1)&gt;" in page


def test_the_fallback_name_is_shown_when_none_is_configured(fake_probes: None) -> None:
    client = TestClient(
        create_console_app(
            Settings(
                env="prod", console_users="operator@example.com", version="e", git_sha="a" * 40
            )
        )
    )
    assert ">operator</span>" in client.get("/console", headers=TAILNET).text


def test_every_page_has_the_shield_and_no_inline_script_or_style(fx: Fixture) -> None:
    case = one_case(fx)
    client = make_client(fx, console_display_names=f"{LOGIN}=Op")
    pages = ["/console/cases", f"/console/case/{case}", "/console/case/not-a-case"]
    for path in pages:
        r = client.get(path, headers=get_headers())
        if r.status_code == 404:
            continue
        assert 'class="shield"' in r.text, path
        assert "<script" not in r.text.lower() and " style=" not in r.text.lower(), path
        assert "onclick" not in r.text.lower(), path


def test_the_templates_hold_no_inline_script_or_style_attribute() -> None:
    for tpl in TEMPLATES.glob("*.html"):
        text = tpl.read_text().lower()
        # the one script is the overview pages' external clock file (see test_ops_overview_pages)
        text = text.replace('<script src="/console/overview.js" defer></script>', "")
        assert "<script" not in text and "<style" not in text, tpl.name
        assert " style=" not in text, tpl.name


def test_a_display_name_never_changes_who_is_on_the_audit_trail(fx: Fixture) -> None:
    case = one_case(fx)
    client = make_client(fx, console_display_names=f"{LOGIN}=Someone Else")
    assert post(client, case, "ack").status_code == 303
    assert fx.one("SELECT actor FROM case_event WHERE kind = 'acked'") == (LOGIN,)
    page = client.get(f"/console/case/{case}", headers=get_headers()).text
    assert "Someone Else" in page  # the header
    # A name in the config is not a login: it cannot be used to get in.
    spoof = client.get("/console/cases", headers={"Tailscale-User-Login": "someone else"})
    assert spoof.status_code == 403
    assert SECRET not in page


# ---- severity colors ----


@pytest.mark.parametrize("sev", console.SEVERITIES)
def test_the_queue_and_the_case_show_each_severity_with_its_class(fx: Fixture, sev: str) -> None:
    case = one_case(fx, severity=sev)
    client = make_client(fx)
    queue = client.get("/console/cases", headers=get_headers()).text
    one = client.get(f"/console/case/{case}", headers=get_headers()).text
    for page in (queue, one):
        assert f'class="sev {sev}"' in page, sev


def test_an_unexpected_severity_is_drawn_as_info_and_never_becomes_a_class() -> None:
    assert console.severity_class("critical") == "critical"
    for odd in ("", "urgent", 'x" onload="y', None, 3, "CRITICAL"):
        assert console.severity_class(odd) == "info"


def test_the_stylesheet_defines_and_uses_one_color_per_severity() -> None:
    css = STATIC.read_text()
    for sev in console.SEVERITIES:
        assert f"--sev-{sev}:" in css, sev
        assert re.search(rf"\.sev\.{sev}\s*\{{\s*color: var\(--sev-{sev}\)", css), sev
    # the degraded banner uses the same critical color
    assert "var(--sev-critical)" in css.split(".degraded {")[1].split("}")[0]


# ---- theme and phone layout ----


def test_dark_is_the_default_theme_and_light_follows_the_browser() -> None:
    css = STATIC.read_text()
    root = css.split(":root {", 1)[1].split("}", 1)[0]
    assert "color-scheme: dark" in root
    assert "@media (prefers-color-scheme: light)" in css


def test_the_phone_layout_scrolls_the_nav_and_stacks_the_two_tables() -> None:
    css = STATIC.read_text()
    phone = css.split("@media (max-width: 640px)", 1)[1]
    assert "overflow-x: auto" in phone.split("nav {", 1)[1].split("}", 1)[0]
    assert "table.stack" in phone and "display: none" in phone
    # the two stacked tables carry the labels their cells need
    assert phone.count("table.cases td:nth-child(") == 8
    assert phone.count("table.history td:nth-child(") == 4
    assert ".scroll { overflow-x: auto" in css


def test_the_cases_and_history_tables_are_the_stacking_ones(fx: Fixture) -> None:
    case = one_case(fx)
    client = make_client(fx)
    assert 'class="stack cases"' in client.get("/console/cases", headers=get_headers()).text
    assert (
        'class="stack history"' in client.get(f"/console/case/{case}", headers=get_headers()).text
    )


def test_the_fleet_table_scrolls_inside_its_own_box(fake_probes: None) -> None:
    client = TestClient(
        create_console_app(
            Settings(
                env="prod", console_users="operator@example.com", version="e", git_sha="a" * 40
            )
        )
    )
    page = client.get("/console", headers=TAILNET).text
    assert '<div class="scroll"><table>' in page
