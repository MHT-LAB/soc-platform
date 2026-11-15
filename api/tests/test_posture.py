"""The posture collector (soc_api.posture), against a fake vendor API and a real database.

The fake speaks what the collector asks for: a form POST for a token, GET sensors/{oid}
(paged by a continuation token, optionally filtered to online ones), GET hive/dr-*/{oid}
(rule bodies included, which must never be stored) and GET errors/{oid} (messages included,
likewise). It records every path it is asked for, so the tests can prove the collector never
reaches for anything outside its permission list, and above all never for an output listing.
"""

import json
import logging
import threading
import urllib.parse
from collections import deque
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from conftest import ROLE_PASSWORD, TestDb
from test_worker_db import Fixture

from soc_api import posture as p
from soc_api import reconcile as r
from soc_api.config import Settings

KEY = "k" * 40
OID = "11111111-2222-4333-8444-555555555555"
TOKEN = "aaa.bbb.ccc"
SID = "aaaaaaaa-0000-4000-8000-00000000000"
SECRET_BODY = "SECRET-RULE-BODY-DO-NOT-STORE"
SECRET_MESSAGE = "SECRET-ERROR-MESSAGE-DO-NOT-STORE"
LINUX, WINDOWS = 0x20000000, 0x10000000


def sensor_row(n: int, **over: Any) -> dict[str, Any]:
    return {
        "sid": f"{SID}{n}",
        "hostname": f"host-{n}",
        "plat": LINUX,
        "alive": "2025-01-02 03:04:05",
        "version": "4.2.0",
        "is_isolated": False,
        "tags": ["lab"],
        **over,
    }


class FakeLc:
    def __init__(self) -> None:
        self.sensors: list[dict[str, Any]] = [sensor_row(1), sensor_row(2, plat=WINDOWS)]
        self.online: set[str] = {f"{SID}1"}
        self.rules: dict[str, dict[str, Any]] = {
            "dr-general": {
                "Rule One": {"data": {"detect": SECRET_BODY}, "usr_mtd": {"enabled": True}},
                "Rule Two": {"data": {"detect": SECRET_BODY}, "usr_mtd": {"enabled": False}},
            },
            "dr-managed": {"Managed One": {"data": {}, "usr_mtd": {"enabled": True}}},
            "dr-service": {},
        }
        self.errors: Any = {"errors": []}
        self.page_size = 100
        self.api_statuses: deque[int] = deque()
        self.jwt_status = 200
        self.api_body: dict[str, bytes] = {}  # path suffix -> replacement body (once)
        self.fail: dict[str, int] = {}  # path suffix -> status, every time
        self.token = TOKEN
        self.log: list[dict[str, Any]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def _send(self, status: int, body: bytes = b"") -> None:
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers.get("content-length") or 0))
                form = dict(urllib.parse.parse_qsl(body.decode()))
                outer.log.append({"kind": "jwt", "form": form})
                if outer.jwt_status != 200:
                    return self._send(outer.jwt_status)
                if form.get("secret") != KEY or form.get("oid") != OID:
                    return self._send(401)
                self._send(200, json.dumps({"jwt": outer.token}).encode())

            def do_GET(self) -> None:
                parts = urllib.parse.urlsplit(self.path)
                query = dict(urllib.parse.parse_qsl(parts.query))
                outer.log.append({"kind": "get", "path": parts.path, "query": query})
                if outer.api_statuses:
                    return self._send(outer.api_statuses.popleft())
                if self.headers.get("Authorization") != f"Bearer {outer.token}":
                    return self._send(401)
                for suffix, status in outer.fail.items():
                    if parts.path.endswith(suffix):
                        return self._send(status)
                for suffix in list(outer.api_body):
                    if parts.path.endswith(suffix):
                        return self._send(200, outer.api_body.pop(suffix))
                if parts.path == f"/v1/sensors/{OID}":
                    return self._sensors(query)
                if parts.path == f"/v1/errors/{OID}":
                    return self._send(200, json.dumps(outer.errors).encode())
                for hive, records in outer.rules.items():
                    if parts.path == f"/v1/hive/{hive}/{OID}":
                        return self._send(200, json.dumps(records).encode())
                self._send(404)

            def _sensors(self, query: dict[str, str]) -> None:
                rows = outer.sensors
                if query.get("is_online_only") == "true":
                    rows = [x for x in rows if x.get("sid") in outer.online]
                offset = int(query.get("continuation_token", "0"))
                page = rows[offset : offset + outer.page_size]
                reply: dict[str, Any] = {"sensors": page}
                if offset + outer.page_size < len(rows):
                    reply["continuation_token"] = str(offset + outer.page_size)
                self._send(200, json.dumps(reply).encode())

            def log_message(self, *args: object) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def gets(self) -> list[str]:
        return [x["path"] for x in self.log if x["kind"] == "get"]


@pytest.fixture
def lc() -> Iterator[FakeLc]:
    fake = FakeLc()
    yield fake
    fake.server.shutdown()
    fake.server.server_close()


def client(fake: FakeLc, **kw: Any) -> p.PostureClient:
    return p.PostureClient(
        OID, KEY, api_url=fake.url, jwt_url=fake.url + "/jwt", allow_http=True, timeout=3.0, **kw
    )


@pytest.fixture
def fx(db: TestDb) -> Fixture:
    return Fixture(db)


OPEN: list[p.PostureDb] = []


@pytest.fixture(autouse=True)
def close_databases() -> Iterator[None]:
    yield
    while OPEN:
        OPEN.pop().close()


def collector(fx: Fixture, fake: FakeLc, **kw: Any) -> p.Collector:
    db = p.PostureDb(fx.db.sqlalchemy_url("soc_posture", ROLE_PASSWORD))
    OPEN.append(db)
    return p.Collector(client(fake), db, **kw)


def runs(fx: Fixture) -> list[tuple[Any, ...]]:
    return fx.rows("SELECT ok, error, org_error_count, org_error_component FROM posture_run")


def dump_everything(fx: Fixture) -> str:
    return repr(
        [
            fx.rows(f"SELECT * FROM {t}")  # noqa: S608 - fixed names
            for t in ("posture_run", "sensor_state", "sensor_count", "rule_inventory")
        ]
    )


# ---- configuration ----


def settings(**kw: Any) -> Settings:
    base: dict[str, Any] = {
        "env": "prod",
        "posture_lc_key": KEY,
        "posture_lc_oid": OID,
        "posture_database_url": "postgresql+psycopg://u:p@db:5432/soc",
    }
    return Settings(**{**base, **kw})


def test_a_complete_configuration_is_accepted() -> None:
    cfg = p.Config.from_settings(settings())
    assert cfg.interval_s == 300.0 and cfg.api_url == "https://api.limacharlie.io"
    assert cfg.allow_http is False and cfg.health_file == "/tmp/posture-health"  # noqa: S108


@pytest.mark.parametrize(
    ("override", "setting"),
    [
        ({"posture_lc_key": ""}, "SOC_POSTURE_LC_KEY"),
        ({"posture_lc_oid": ""}, "SOC_POSTURE_LC_OID"),
        ({"posture_lc_oid": "not-an-oid"}, "SOC_POSTURE_LC_OID"),
        ({"posture_database_url": ""}, "SOC_POSTURE_DATABASE_URL"),
        ({"posture_api_url": "http://api.example.com"}, "SOC_POSTURE_API_URL"),
        ({"posture_jwt_url": "ftp://jwt.example.com"}, "SOC_POSTURE_JWT_URL"),
    ],
)
def test_a_missing_or_unsafe_setting_stops_the_service_and_names_it(
    override: dict[str, Any], setting: str
) -> None:
    with pytest.raises(ValueError, match=setting) as info:
        p.Config.from_settings(settings(**override))
    assert KEY not in str(info.value)


def test_the_database_is_not_needed_for_the_read_only_check() -> None:
    assert p.Config.from_settings(settings(posture_database_url=""), need_db=False).db_url == ""


def test_an_interval_outside_one_to_ten_minutes_is_refused() -> None:
    for seconds in (10, 59, 601):
        with pytest.raises(ValueError, match="posture_interval_seconds"):
            settings(posture_interval_seconds=seconds)


# ---- one good run ----


def test_a_good_run_stores_sensors_rules_and_errors_and_logs_counts_only(
    fx: Fixture, lc: FakeLc, caplog: pytest.LogCaptureFixture
) -> None:
    lc.errors = {
        "errors": [
            {"component": "older.component", "error": SECRET_MESSAGE, "ts": 100},
            {"component": "newest.component", "error": SECRET_MESSAGE, "ts": 200},
        ]
    }
    caplog.set_level(logging.INFO, logger="soc_api.posture")
    assert collector(fx, lc).cycle() is True
    assert fx.rows(
        "SELECT hostname, platform, version, online, isolated, tags, last_seen IS NOT NULL "
        "FROM sensor_state ORDER BY hostname"
    ) == [
        ("host-1", "Linux", "4.2.0", True, False, ["lab"], True),
        ("host-2", "Windows", "4.2.0", False, False, ["lab"], True),
    ]
    assert fx.rows("SELECT online, offline, isolated FROM sensor_count") == [(1, 1, 0)]
    assert fx.rows("SELECT namespace, name, enabled FROM rule_inventory ORDER BY 1, 2") == [
        ("general", "Rule One", True),
        ("general", "Rule Two", False),
        ("managed", "Managed One", True),
    ]
    assert runs(fx) == [(True, None, 2, "newest.component")]
    [line] = [x.getMessage() for x in caplog.records if "posture outcome" in x.getMessage()]
    assert line == (
        "posture outcome=ok sensors=2 online=1 rules=3 errors=2 skipped=0 namespaces_unavailable=0"
    )
    assert "host-1" not in caplog.text and "Rule One" not in caplog.text


def test_rule_bodies_and_error_messages_are_never_stored(fx: Fixture, lc: FakeLc) -> None:
    lc.errors = {"errors": [{"component": "c.one", "error": SECRET_MESSAGE, "ts": 1}]}
    assert collector(fx, lc).cycle() is True
    everything = dump_everything(fx)
    assert SECRET_BODY not in everything and SECRET_MESSAGE not in everything


def test_a_sensor_going_offline_shows_in_the_state_and_the_series(fx: Fixture, lc: FakeLc) -> None:
    c = collector(fx, lc)
    assert c.cycle()
    lc.online = set()  # the one online sensor drops off
    assert c.cycle()
    assert fx.rows("SELECT hostname, online FROM sensor_state ORDER BY 1") == [
        ("host-1", False),
        ("host-2", False),
    ]
    assert fx.rows("SELECT online, offline FROM sensor_count ORDER BY at, online DESC") == [
        (1, 1),
        (0, 2),
    ]
    lc.online = {f"{SID}1", f"{SID}2"}  # ...and both come back
    assert c.cycle()
    assert fx.rows("SELECT online, offline FROM sensor_count ORDER BY at DESC LIMIT 1") == [(2, 0)]


def test_a_sensor_that_disappears_and_a_rule_that_is_deleted_leave_the_current_state(
    fx: Fixture, lc: FakeLc
) -> None:
    c = collector(fx, lc)
    assert c.cycle()
    lc.sensors = lc.sensors[:1]
    del lc.rules["dr-general"]["Rule Two"]
    assert c.cycle()
    assert fx.rows("SELECT hostname FROM sensor_state") == [("host-1",)]
    assert [r_[0] for r_ in fx.rows("SELECT name FROM rule_inventory ORDER BY 1")] == [
        "Managed One",
        "Rule One",
    ]


def test_isolation_and_tags_come_through(fx: Fixture, lc: FakeLc) -> None:
    lc.sensors = [sensor_row(1, is_isolated=True, tags=["a", "b", 5, "c" * 65])]
    lc.online = set()
    assert collector(fx, lc).cycle()
    assert fx.rows("SELECT isolated, tags FROM sensor_state") == [(True, ["a", "b"])]
    assert fx.rows("SELECT online, offline, isolated FROM sensor_count") == [(0, 1, 1)]


def test_every_page_of_sensors_is_read(fx: Fixture, lc: FakeLc) -> None:
    lc.sensors = [sensor_row(n) for n in range(1, 8)]
    lc.online = {s["sid"] for s in lc.sensors[:3]}
    lc.page_size = 2
    assert collector(fx, lc).cycle()
    assert fx.one("SELECT count(*) FROM sensor_state") == (7,)
    assert fx.rows("SELECT online, offline FROM sensor_count") == [(3, 4)]


def test_extension_sensors_and_unusable_rows_are_skipped(fx: Fixture, lc: FakeLc) -> None:
    lc.sensors = [
        sensor_row(1),
        sensor_row(2, hostname="ext-lc-service"),
        {"hostname": "no-id"},
        sensor_row(3, sid="bad id!"),
        sensor_row(4, sid=7),
    ]
    c = collector(fx, lc)
    assert c.cycle() and c.counts.skipped == 3
    assert fx.rows("SELECT hostname FROM sensor_state") == [("host-1",)]


def test_a_missing_enabled_flag_means_enabled(fx: Fixture, lc: FakeLc) -> None:
    lc.rules = {"dr-general": {"R": {"data": {}}}, "dr-managed": {}, "dr-service": {}}
    assert collector(fx, lc).cycle()
    assert fx.rows("SELECT name, enabled FROM rule_inventory") == [("R", True)]


def test_an_empty_organization_is_a_good_run(fx: Fixture, lc: FakeLc) -> None:
    lc.sensors, lc.online = [], set()
    lc.rules = {"dr-general": {}, "dr-managed": {}, "dr-service": {}}
    lc.errors = {}
    assert collector(fx, lc).cycle()
    assert fx.rows("SELECT online, offline, isolated FROM sensor_count") == [(0, 0, 0)]
    assert runs(fx) == [(True, None, 0, None)]


# ---- what it asks the vendor for ----


def test_it_asks_only_for_sensors_rules_and_errors_and_never_for_outputs(
    fx: Fixture, lc: FakeLc
) -> None:
    assert collector(fx, lc).cycle()
    allowed = {
        f"/v1/sensors/{OID}",
        f"/v1/errors/{OID}",
        f"/v1/hive/dr-general/{OID}",
        f"/v1/hive/dr-managed/{OID}",
        f"/v1/hive/dr-service/{OID}",
    }
    assert set(lc.gets()) == allowed
    assert not any("output" in path for path in lc.gets())
    assert [x["kind"] for x in lc.log].count("jwt") == 1
    assert all(x["form"] == {"oid": OID, "secret": KEY} for x in lc.log if x["kind"] == "jwt")


def test_the_collector_source_has_exactly_three_kinds_of_vendor_path() -> None:
    """Every REST path in the module, by pattern; an output or usage listing would show here."""
    import re

    source = Path(p.__file__).read_text()
    paths = set(re.findall(r'self\._get\(\s*f"([^"]+)"', source))
    assert paths == {
        "sensors/{self.oid}",
        "hive/{RULE_HIVES[namespace]}/{self.oid}",
        "errors/{self.oid}",
    }
    assert set(p.RULE_HIVES.values()) == {"dr-general", "dr-managed", "dr-service"}


# ---- failures write nothing but a failure row ----


def test_a_refused_key_is_a_failed_run_with_no_partial_write(
    fx: Fixture, lc: FakeLc, caplog: pytest.LogCaptureFixture
) -> None:
    lc.jwt_status = 401
    caplog.set_level(logging.INFO, logger="soc_api.posture")
    assert collector(fx, lc).cycle() is False
    assert runs(fx) == [(False, "jwt_http_401", None, None)]
    for table in ("sensor_state", "sensor_count", "rule_inventory"):
        assert fx.one(f"SELECT count(*) FROM {table}") == (0,), table  # noqa: S608
    assert lc.gets() == []
    assert "posture outcome=error code=jwt_http_401" in caplog.text and KEY not in caplog.text


def test_a_failure_after_a_good_run_keeps_the_last_snapshot_whole(fx: Fixture, lc: FakeLc) -> None:
    c = collector(fx, lc)
    assert c.cycle()
    lc.api_statuses.extend([403] * 5)
    assert c.cycle() is False
    assert [r_[0] for r_ in runs(fx)] == [True, False]
    assert fx.one("SELECT count(*) FROM sensor_state") == (2,)
    assert fx.one("SELECT count(*) FROM rule_inventory") == (3,)
    assert fx.one("SELECT count(*) FROM sensor_count") == (1,)


def test_a_rule_listing_that_fails_after_the_sensors_were_read_writes_nothing(
    fx: Fixture, lc: FakeLc
) -> None:
    lc.fail[f"/hive/dr-managed/{OID}"] = 500  # sensors and general rules were already read
    assert collector(fx, lc).cycle() is False
    assert runs(fx) == [(False, "http_5xx", None, None)]
    assert fx.one("SELECT count(*) FROM sensor_state") == (0,)


@pytest.mark.parametrize("status", [400, 403, 404])
def test_a_rules_namespace_the_org_does_not_have_is_skipped_not_a_failed_run(
    fx: Fixture, lc: FakeLc, caplog: pytest.LogCaptureFixture, status: int
) -> None:
    lc.fail[f"/hive/dr-managed/{OID}"] = status
    caplog.set_level(logging.INFO, logger="soc_api.posture")
    assert collector(fx, lc).cycle() is True
    assert fx.rows("SELECT namespace, name FROM rule_inventory ORDER BY 1, 2") == [
        ("general", "Rule One"),
        ("general", "Rule Two"),
    ]
    assert "namespaces_unavailable=1" in caplog.text


@pytest.mark.parametrize("status", [401, 403])
def test_unreadable_org_errors_are_stored_as_unknown_never_as_zero(
    fx: Fixture, lc: FakeLc, caplog: pytest.LogCaptureFixture, status: int
) -> None:
    lc.fail[f"/errors/{OID}"] = status
    caplog.set_level(logging.INFO, logger="soc_api.posture")
    assert collector(fx, lc).cycle() is True
    assert runs(fx) == [(True, None, None, None)]
    assert fx.one("SELECT count(*) FROM sensor_state") == (2,)
    assert "errors=unavailable" in caplog.text


def test_any_other_org_error_failure_still_fails_the_run(fx: Fixture, lc: FakeLc) -> None:
    lc.fail[f"/errors/{OID}"] = 500
    assert collector(fx, lc).cycle() is False
    assert runs(fx) == [(False, "http_5xx", None, None)]
    assert fx.one("SELECT count(*) FROM sensor_state") == (0,)


def test_the_check_reports_unavailable_parts_and_succeeds(
    lc: FakeLc, capsys: pytest.CaptureFixture[str]
) -> None:
    lc.fail[f"/hive/dr-managed/{OID}"] = 400
    lc.fail[f"/errors/{OID}"] = 401
    assert p.check(p.Config(OID, KEY, "", lc.url, lc.url + "/jwt", True, 300.0, "")) == 0
    out = capsys.readouterr().out
    assert "managed=not-available" in out and "general=2" in out
    assert "org errors: not readable" in out


@pytest.mark.parametrize(
    ("suffix", "body", "codes"),
    [
        (f"/sensors/{OID}", b"not json", {"bad_json"}),
        (f"/sensors/{OID}", b"[]", {"bad_shape"}),
        (f"/sensors/{OID}", b'{"sensors": "x"}', {"bad_shape"}),
        (f"/sensors/{OID}", b"NaN", {"bad_json"}),
        (f"/sensors/{OID}", b'{"sensors": [], "continuation_token": ["x"]}', {"bad_cursor"}),
        (f"/hive/dr-general/{OID}", b"[]", {"bad_shape"}),
        (f"/hive/dr-general/{OID}", b'{"R": "not an object"}', {"bad_shape"}),
        (f"/hive/dr-general/{OID}", b'{"R": {"usr_mtd": {"enabled": "yes"}}}', {"bad_shape"}),
        (f"/errors/{OID}", b'{"errors": "x"}', {"bad_shape"}),
        (f"/errors/{OID}", b"[1]", {"bad_shape"}),
    ],
)
def test_malformed_replies_are_refused_without_a_write(
    fx: Fixture, lc: FakeLc, suffix: str, body: bytes, codes: set[str]
) -> None:
    lc.api_body[suffix] = body
    assert collector(fx, lc).cycle() is False
    [(ok, code, _, _)] = runs(fx)
    assert ok is False and code in codes
    assert fx.one("SELECT count(*) FROM sensor_state") == (0,)


def test_an_oversized_reply_is_cut_off_and_refused(
    fx: Fixture, lc: FakeLc, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(r, "MAX_BODY", 1000)
    lc.api_body[f"/sensors/{OID}"] = b'{"sensors": [], "pad": "' + b"A" * 5000 + b'"}'
    assert collector(fx, lc).cycle() is False
    assert runs(fx) == [(False, "too_large", None, None)]


def test_too_many_sensors_pages_or_rules_are_refused(fx: Fixture, lc: FakeLc) -> None:
    lc.sensors = [sensor_row(n) for n in range(1, 6)]
    lc.page_size = 1
    c = collector(fx, lc, limits=p.Limits(max_pages=3))
    assert c.cycle() is False
    assert runs(fx)[-1][1] == "too_many_pages"
    c = collector(fx, lc, limits=p.Limits(max_pages=50, max_sensors=2))
    assert c.cycle() is False and runs(fx)[-1][1] == "too_many_items"
    lc.page_size = 100
    c = collector(fx, lc, limits=p.Limits(max_rules=1))
    assert c.cycle() is False and runs(fx)[-1][1] == "too_many_items"
    assert fx.one("SELECT count(*) FROM sensor_state") == (0,)


def test_a_looping_continuation_token_is_an_error_not_a_loop() -> None:
    class Loop(p.PostureClient):
        def _get(self, path: str, query: dict[str, str]) -> Any:
            return {"sensors": [], "continuation_token": "same"}

    with pytest.raises(r.LcError) as info:
        Loop(OID, KEY).list_sensors(online_only=False)
    assert info.value.code == "bad_cursor"


def test_a_redirect_is_never_followed(fx: Fixture, lc: FakeLc) -> None:
    lc.api_statuses.append(302)
    assert collector(fx, lc).cycle() is False
    assert runs(fx) == [(False, "redirect", None, None)]


def test_plain_http_is_refused_without_the_dev_switch(lc: FakeLc) -> None:
    c = p.PostureClient(OID, KEY, api_url=lc.url, jwt_url=lc.url + "/jwt", allow_http=False)
    with pytest.raises(r.LcError) as info:
        c.list_sensors(online_only=False)
    assert info.value.code == "jwt_bad_url" and lc.log == []  # the key was never sent


def test_the_database_refusing_a_document_is_a_short_code_and_not_a_crash(
    fx: Fixture, lc: FakeLc
) -> None:
    lc.sensors = [sensor_row(1, version="v" * 100)]  # the collector trims; make it overlong anyway
    c = collector(fx, lc)
    real = c.db.record

    def bad(doc: dict[str, Any]) -> None:
        doc["sensors"][0]["hostname"] = "h" * 300
        real(doc)

    c.db.record = bad  # type: ignore[method-assign]
    assert c.cycle() is False
    assert runs(fx) == [(False, "rejected", None, None)]
    assert fx.one("SELECT count(*) FROM sensor_state") == (0,)


def test_a_dead_database_is_a_logged_failure_not_a_crash(
    lc: FakeLc, caplog: pytest.LogCaptureFixture
) -> None:
    db = p.PostureDb("postgresql+psycopg://soc_posture:pw-secret@127.0.0.1:1/soc")
    OPEN.append(db)
    caplog.set_level(logging.INFO, logger="soc_api.posture")
    assert p.Collector(client(lc), db).cycle() is False
    assert "pw-secret" not in caplog.text and "code=db_error" in caplog.text


def test_the_health_file_is_touched_after_good_and_bad_runs(
    fx: Fixture, lc: FakeLc, tmp_path: Path
) -> None:
    marker = tmp_path / "health"
    c = collector(fx, lc, health_file=str(marker))
    assert c.cycle() and marker.exists()
    marker.unlink()
    lc.api_statuses.append(403)
    assert c.cycle() is False and marker.exists()


def test_the_loop_runs_on_the_interval_and_stops_when_asked(fx: Fixture, lc: FakeLc) -> None:
    c = collector(fx, lc, interval_s=300.0)
    clock = [0.0]
    stops = deque([False, False, False, False, True])

    def sleep(seconds: float) -> None:
        clock[0] += 200.0

    c.run(lambda: stops.popleft(), sleep=sleep, monotonic=lambda: clock[0])
    assert len(runs(fx)) == 2  # t=0 and t=400, not at t=200


# ---- shaping ----


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (1_700_000_000, 1_700_000_000.0),
        (1_700_000_000_000, 1_700_000_000.0),
        ("2025-01-02 03:04:05", 1_735_787_045.0),
        ("2025-01-02T03:04:05Z", 1_735_787_045.0),
        ("yesterday", None),
        (None, None),
        (True, None),
        (-5, None),
        ([1], None),
    ],
)
def test_last_seen_is_read_from_numbers_and_dates_and_otherwise_unknown(
    value: Any, expected: float | None
) -> None:
    assert p._epoch(value) == expected


def test_the_newest_org_error_is_the_one_with_the_latest_time() -> None:
    class Stub(p.PostureClient):
        def _get(self, path: str, query: dict[str, str]) -> Any:
            return {
                "errors": [
                    {"component": "late", "ts": 30},
                    {"component": "first", "ts": 10},
                    {"component": "has spaces", "ts": 99},
                    "junk",
                ]
            }

    count, newest = Stub(OID, KEY).org_errors()
    assert count == 4 and newest == "unknown"  # the newest one has an unusable name


# ---- the read-only look ----


def test_check_prints_counts_and_field_names_but_no_names(
    fx: Fixture, lc: FakeLc, capsys: pytest.CaptureFixture[str]
) -> None:
    cfg = p.Config(OID, KEY, "", lc.url, lc.url + "/jwt", True, 300.0, "")
    assert p.check(cfg) == 0
    out = capsys.readouterr().out
    assert "check ok: auth=ok sensors=2 online=1" in out and "general=2 managed=1" in out
    for secret in ("host-1", "Rule One", KEY, SECRET_BODY):
        assert secret not in out


def test_check_reports_a_failure_as_a_code(lc: FakeLc, capsys: pytest.CaptureFixture[str]) -> None:
    lc.jwt_status = 403
    cfg = p.Config(OID, KEY, "", lc.url, lc.url + "/jwt", True, 300.0, "")
    assert p.check(cfg) == 1
    assert capsys.readouterr().out.strip() == "check failed: jwt_http_403"
