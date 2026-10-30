"""The catch-up worker (soc_api.reconcile), against a fake vendor API and a real database.

The fake speaks what the vendor's own SDK documents: a form POST for a token, then a GET
of detections for a window (paged by a cursor, optionally base64(gzip(JSON))) and a GET of
one detection by id. Its list view is a summary without the rule name, the detection time
and the priority, like the real one seems to be, so the whole-record fetch is exercised.
"""

import base64
import gzip
import json
import logging
import threading
import urllib.parse
from collections import deque
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from conftest import ROLE_PASSWORD, TestDb
from test_worker_db import Fixture, claim

from soc_api import reconcile as r
from soc_api import worker as w
from soc_api.config import Settings
from soc_api.ingest import PgStore

KEY = "k" * 40
OID = "11111111-2222-4333-8444-555555555555"
TOKEN = "aaa.bbb.ccc"
CATEGORIES = ("CAT_ONE", "CAT_TWO")
SUMMARY = ("detect_id", "cat", "link", "namespace", "routing", "detect", "detect_mtd", "ts")


def record(
    detect_id: str,
    *,
    at: datetime,
    cat: str = "CAT_ONE",
    host: str = "host-1",
    detected_ago_s: float = 1.0,
    rule: str = "general.Rule One",
    priority: int = 4,
) -> dict[str, Any]:
    """A whole detection, as the by-id endpoint (and a webhook body) has it."""
    detected = at - timedelta(seconds=detected_ago_s)
    return {
        "author": "someone@example.com",
        "cat": cat,
        "detect": {"event": {"COMMAND_LINE": "/usr/bin/true"}},
        "detect_id": detect_id,
        "detect_mtd": {"description": "A rule fired."},
        "gen_time": int(detected.timestamp() * 1000),
        "link": "https://app.limacharlie.io/orgs/o/sensors/s/timeline?time=1",
        "namespace": "general",
        "priority": priority,
        "routing": {"hostname": host, "oid": "t-a"},
        "source": "o.i.s.2",
        "source_rule": rule,
        "ts": int(at.timestamp() * 1000),
    }


class FakeLc:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []
        self.page_size = 100
        self.compress = True
        self.summary_only = True
        self.list_extra: tuple[str, ...] = ()  # fields the list view carries besides the summary
        self.wrap = "detection.event"
        self.api_statuses: deque[int] = deque()
        self.jwt_status = 200
        self.jwt_body: bytes | None = None
        self.location: str | None = None
        self.api_body: bytes | None = None  # replaces the next API reply
        self.missing: set[str] = set()
        self.token = TOKEN
        self.cursor_override: str | None = None
        self.fail_nth_list: int | None = None
        self.lists_served = 0
        self.log: list[dict[str, Any]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def _send(
                self, status: int, body: bytes = b"", extra: dict[str, str] | None = None
            ) -> None:
                self.send_response(status)
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers.get("content-length") or 0))
                form = dict(urllib.parse.parse_qsl(body.decode()))
                outer.log.append({"kind": "jwt", "form": form, "headers": dict(self.headers)})
                if outer.jwt_status != 200:
                    return self._send(outer.jwt_status)
                if form.get("secret") != KEY or form.get("oid") != OID:
                    return self._send(401)
                self._send(200, outer.jwt_body or json.dumps({"jwt": outer.token}).encode())

            def do_GET(self) -> None:
                parts = urllib.parse.urlsplit(self.path)
                query = dict(urllib.parse.parse_qsl(parts.query))
                outer.log.append(
                    {
                        "kind": "get",
                        "path": parts.path,
                        "query": query,
                        "headers": dict(self.headers),
                    }
                )
                if outer.api_statuses:
                    status = outer.api_statuses.popleft()
                    extra = {"Location": outer.location} if outer.location else None
                    return self._send(status, b"", extra)
                if self.headers.get("Authorization") != f"Bearer {outer.token}":
                    return self._send(401)
                if outer.api_body is not None:
                    body, outer.api_body = outer.api_body, None
                    return self._send(200, body)
                base = f"/v1/insight/{OID}/detections"
                if parts.path == base:
                    return self._list(query)
                if parts.path.startswith(base + "/"):
                    return self._one(urllib.parse.unquote(parts.path[len(base) + 1 :]))
                self._send(404)

            def _list(self, query: dict[str, str]) -> None:
                start, end = int(query["start"]) * 1000, int(query["end"]) * 1000
                hits = [x for x in outer.records if start <= x["ts"] <= end]
                outer.lists_served += 1
                if outer.fail_nth_list == outer.lists_served:
                    return self._send(500)
                offset = int(query["cursor"]) if query["cursor"].isdigit() else 0
                page = hits[offset : offset + outer.page_size]
                if outer.summary_only:
                    keep = SUMMARY + outer.list_extra
                    page = [{k: v for k, v in x.items() if k in keep} for x in page]
                nxt = offset + outer.page_size
                reply: dict[str, Any] = {
                    "next_cursor": outer.cursor_override or (str(nxt) if nxt < len(hits) else None)
                }
                raw = json.dumps(page).encode()
                reply["detects"] = (
                    base64.b64encode(gzip.compress(raw)).decode() if outer.compress else page
                )
                self._send(200, json.dumps(reply).encode())

            def _one(self, detect_id: str) -> None:
                found = next((x for x in outer.records if x["detect_id"] == detect_id), None)
                if found is None or detect_id in outer.missing:
                    return self._send(404)
                wrapped: Any = found
                if outer.wrap == "detection.event":
                    wrapped = {"detection": {"event": found}}
                elif outer.wrap == "event":
                    wrapped = {"event": found}
                elif outer.wrap == "wrong":
                    wrapped = {"detection": {"event": {**found, "detect_id": "someone-else"}}}
                self._send(200, json.dumps(wrapped).encode())

            def log_message(self, *args: object) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def gets(self, suffix: str = "") -> list[dict[str, Any]]:
        return [x for x in self.log if x["kind"] == "get" and x["path"].endswith(suffix)]

    def lists(self) -> list[dict[str, Any]]:
        return [x for x in self.gets() if x["path"].endswith("/detections")]

    def by_id(self) -> list[dict[str, Any]]:
        return [x for x in self.gets() if not x["path"].endswith("/detections")]


@pytest.fixture
def lc() -> Iterator[FakeLc]:
    fake = FakeLc()
    yield fake
    fake.server.shutdown()
    fake.server.server_close()


def client(fake: FakeLc, **kw: Any) -> r.LcClient:
    return r.LcClient(
        OID, KEY, api_url=fake.url, jwt_url=fake.url + "/jwt", allow_http=True, timeout=3.0, **kw
    )


def now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


# ---- configuration ----


@pytest.mark.parametrize(
    ("raw", "names"),
    [
        ("A,B", ("A", "B")),
        (" A , B ,, A ", ("A", "B")),
        ("LINUX_Scanner_Or_Attack_Tool", ("LINUX_Scanner_Or_Attack_Tool",)),
        ("a.b-c_d", ("a.b-c_d",)),
    ],
)
def test_categories_are_a_cleaned_unique_list(raw: str, names: tuple[str, ...]) -> None:
    assert r.parse_categories(raw) == names


@pytest.mark.parametrize(
    "raw", ["", " , ", "a b", "a;b", "x" * 129, ",".join(f"c{n}" for n in range(51)), "é"]
)
def test_bad_categories_are_refused(raw: str) -> None:
    with pytest.raises(ValueError, match="SOC_RECONCILE_CATEGORIES"):
        r.parse_categories(raw)


def settings(**kw: Any) -> Settings:
    base: dict[str, Any] = {
        "env": "prod",
        "reconcile_lc_key": KEY,
        "reconcile_lc_oid": OID,
        "reconcile_source": "src-a",
        "reconcile_categories": "CAT_ONE",
        "reconcile_database_url": "postgresql+psycopg://u:p@db:5432/soc",
    }
    return Settings(**{**base, **kw})


def test_a_complete_configuration_is_accepted() -> None:
    cfg = r.Config.from_settings(settings())
    assert cfg.categories == ("CAT_ONE",) and cfg.source == "src-a" and cfg.interval_s == 300.0
    assert cfg.api_url == "https://api.limacharlie.io" and cfg.allow_http is False


@pytest.mark.parametrize(
    ("override", "setting"),
    [
        ({"reconcile_lc_key": ""}, "SOC_RECONCILE_LC_KEY"),
        ({"reconcile_lc_oid": ""}, "SOC_RECONCILE_LC_OID"),
        ({"reconcile_lc_oid": "not-an-oid"}, "SOC_RECONCILE_LC_OID"),
        ({"reconcile_source": ""}, "SOC_RECONCILE_SOURCE"),
        ({"reconcile_source": "Bad Slug"}, "SOC_RECONCILE_SOURCE"),
        ({"reconcile_database_url": ""}, "SOC_RECONCILE_DATABASE_URL"),
        ({"reconcile_categories": ""}, "SOC_RECONCILE_CATEGORIES"),
        ({"reconcile_api_url": "http://api.example.com"}, "SOC_RECONCILE_API_URL"),
        ({"reconcile_jwt_url": "ftp://jwt.example.com"}, "SOC_RECONCILE_JWT_URL"),
        ({"reconcile_api_url": "https://user:pw\x40api.example.com"}, "SOC_RECONCILE_API_URL"),
        ({"reconcile_jwt_url": "https://jwt.example.com/?x=1"}, "SOC_RECONCILE_JWT_URL"),
    ],
)
def test_a_missing_or_unsafe_setting_stops_the_service_and_names_it(
    override: dict[str, Any], setting: str
) -> None:
    with pytest.raises(ValueError, match=setting) as info:
        r.Config.from_settings(settings(**override))
    assert KEY not in str(info.value)


def test_plain_http_is_allowed_only_in_dev() -> None:
    dev = r.Config.from_settings(settings(env="dev", reconcile_api_url="http://fakelc:8090"))
    assert dev.api_url == "http://fakelc:8090" and dev.allow_http is True
    with pytest.raises(ValueError, match="SOC_RECONCILE_API_URL"):
        r.Config.from_settings(settings(reconcile_api_url="http://fakelc:8090"))


def test_the_database_is_not_needed_for_the_read_only_check() -> None:
    cfg = r.Config.from_settings(settings(reconcile_database_url=""), need_db=False)
    assert cfg.db_url == ""


def test_an_interval_outside_one_to_ten_minutes_is_refused() -> None:
    for seconds in (10, 59, 601, 3600):
        with pytest.raises(ValueError, match="reconcile_interval_seconds"):
            settings(reconcile_interval_seconds=seconds)


# ---- the vendor API client ----


def test_the_token_is_asked_for_with_a_form_and_sent_as_a_bearer(lc: FakeLc) -> None:
    c = client(lc)
    assert list(c.list_detections(1, 2, max_pages=5, max_items=50)) == []
    [jwt] = [x for x in lc.log if x["kind"] == "jwt"]
    assert jwt["form"] == {"oid": OID, "secret": KEY}
    assert jwt["headers"]["Content-Type"] == "application/x-www-form-urlencoded"
    [get] = lc.lists()
    assert get["headers"]["Authorization"] == f"Bearer {TOKEN}"
    assert get["query"] == {"start": "1", "end": "2", "cursor": "-", "is_compressed": "true"}


def test_the_token_is_reused_until_it_is_old(lc: FakeLc) -> None:
    clock = [1000.0]
    c = client(lc, clock=lambda: clock[0])
    for _ in range(3):
        list(c.list_detections(1, 2, max_pages=5, max_items=50))
    assert len([x for x in lc.log if x["kind"] == "jwt"]) == 1
    clock[0] += r.TOKEN_REFRESH_S + 1
    list(c.list_detections(1, 2, max_pages=5, max_items=50))
    assert len([x for x in lc.log if x["kind"] == "jwt"]) == 2


def test_a_rejected_token_is_replaced_once_and_the_call_retried(lc: FakeLc) -> None:
    c = client(lc)
    list(c.list_detections(1, 2, max_pages=5, max_items=50))
    lc.token = "new.token.value"
    assert list(c.list_detections(1, 2, max_pages=5, max_items=50)) == []
    assert len([x for x in lc.log if x["kind"] == "jwt"]) == 2
    assert lc.lists()[-1]["headers"]["Authorization"] == "Bearer new.token.value"


def test_a_second_rejection_is_an_error_not_a_loop(lc: FakeLc) -> None:
    lc.api_statuses.extend([401, 401, 401])
    with pytest.raises(r.LcError) as info:
        list(client(lc).list_detections(1, 2, max_pages=5, max_items=50))
    assert info.value.code == "http_401"
    assert len(lc.lists()) == 2  # the first call and the one retry


@pytest.mark.parametrize(
    ("status", "code"),
    [
        (400, "http_400"),
        (403, "http_403"),
        (404, "http_404"),
        (429, "http_429"),
        (418, "http_4xx"),
        (500, "http_5xx"),
        (503, "http_5xx"),
    ],
)
def test_api_failures_become_short_codes(lc: FakeLc, status: int, code: str) -> None:
    lc.api_statuses.append(status)
    with pytest.raises(r.LcError) as info:
        list(client(lc).list_detections(1, 2, max_pages=5, max_items=50))
    assert info.value.code == code


def test_a_redirect_is_never_followed(lc: FakeLc) -> None:
    lc.api_statuses.append(302)
    lc.location = "http://127.0.0.1:1/elsewhere"
    with pytest.raises(r.LcError) as info:
        list(client(lc).list_detections(1, 2, max_pages=5, max_items=50))
    assert info.value.code == "redirect"
    assert len(lc.log) == 2  # the token and the one request; nothing at the Location


def test_a_token_reply_that_could_inject_a_header_is_refused(lc: FakeLc) -> None:
    for token in ("a b", "a\r\nX-Evil: 1", "", "x" * 9000, "a.b.c.d.e", "é"):
        lc.jwt_body = json.dumps({"jwt": token}).encode()
        with pytest.raises(r.LcError) as info:
            list(client(lc).list_detections(1, 2, max_pages=5, max_items=50))
        assert info.value.code == "jwt_bad_shape", token
    assert lc.gets() == []


def test_a_rejected_key_is_a_token_error_not_an_api_error(lc: FakeLc) -> None:
    lc.jwt_status = 401
    with pytest.raises(r.LcError) as info:
        list(client(lc).list_detections(1, 2, max_pages=5, max_items=50))
    assert info.value.code == "jwt_http_401" and lc.gets() == []


def test_the_key_never_appears_in_an_error(lc: FakeLc) -> None:
    lc.jwt_body = b"not json"
    with pytest.raises(r.LcError) as info:
        list(client(lc).list_detections(1, 2, max_pages=5, max_items=50))
    assert KEY not in repr(info.value) and KEY not in str(info.value.__cause__)


def test_plain_http_is_refused_without_the_dev_switch(lc: FakeLc) -> None:
    c = r.LcClient(OID, KEY, api_url=lc.url, jwt_url=lc.url + "/jwt", allow_http=False)
    with pytest.raises(r.LcError) as info:
        list(c.list_detections(1, 2, max_pages=5, max_items=50))
    assert info.value.code == "jwt_bad_url" and lc.log == []  # the key was never sent


def test_an_unreachable_server_is_a_network_error() -> None:
    c = r.LcClient(
        OID,
        KEY,
        api_url="http://127.0.0.1:1",
        jwt_url="http://127.0.0.1:1/jwt",
        allow_http=True,
        timeout=1.0,
    )
    with pytest.raises(r.LcError) as info:
        list(c.list_detections(1, 2, max_pages=5, max_items=50))
    assert info.value.code == "jwt_network"


def test_a_malformed_organization_id_is_refused() -> None:
    with pytest.raises(ValueError, match="organization id"):
        r.LcClient("../etc", KEY)


@pytest.mark.parametrize("body", [b"not json", b"NaN", b"[1,2]", b'"text"', b"\xff\xfe"])
def test_a_reply_that_is_not_a_json_object_is_an_error(lc: FakeLc, body: bytes) -> None:
    lc.api_body = body
    with pytest.raises(r.LcError) as info:
        list(client(lc).list_detections(1, 2, max_pages=5, max_items=50))
    assert info.value.code in ("bad_json", "bad_shape")


def test_an_oversized_reply_is_cut_off(lc: FakeLc, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(r, "MAX_BODY", 1000)
    lc.api_body = b'{"detects": "' + b"A" * 5000 + b'"}'
    with pytest.raises(r.LcError) as info:
        list(client(lc).list_detections(1, 2, max_pages=5, max_items=50))
    assert info.value.code == "too_large"


def test_a_decompression_bomb_is_refused(lc: FakeLc, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(r, "MAX_UNPACKED", 10_000)
    bomb = base64.b64encode(gzip.compress(b"[" + b"0," * 100_000 + b"0]")).decode()
    lc.api_body = json.dumps({"detects": bomb}).encode()
    with pytest.raises(r.LcError) as info:
        list(client(lc).list_detections(1, 2, max_pages=5, max_items=50))
    assert info.value.code == "too_large"


def test_a_decompression_bomb_is_never_inflated_past_the_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Refusing the result is not enough: the memory must not be spent first."""
    import tracemalloc

    monkeypatch.setattr(r, "MAX_UNPACKED", 100_000)
    bomb = base64.b64encode(gzip.compress(b"0" * 60_000_000)).decode()
    tracemalloc.start()
    try:
        with pytest.raises(r.LcError) as info:
            r.unwrap(bomb)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert info.value.code == "too_large"
    assert peak < 5_000_000  # not the sixty megabytes it would have become


@pytest.mark.parametrize(
    "detects", ["!!!not base64!!!", base64.b64encode(b"plain, not gzip").decode(), 5, {"a": 1}]
)
def test_a_bad_detects_value_is_an_error(lc: FakeLc, detects: Any) -> None:
    lc.api_body = json.dumps({"detects": detects}).encode()
    with pytest.raises(r.LcError) as info:
        list(client(lc).list_detections(1, 2, max_pages=5, max_items=50))
    assert info.value.code in ("bad_payload", "bad_shape")


def test_compressed_detects_that_are_not_a_list_are_an_error(lc: FakeLc) -> None:
    packed = base64.b64encode(gzip.compress(b'{"a": 1}')).decode()
    lc.api_body = json.dumps({"detects": packed}).encode()
    with pytest.raises(r.LcError) as info:
        list(client(lc).list_detections(1, 2, max_pages=5, max_items=50))
    assert info.value.code == "bad_shape"


def test_an_uncompressed_list_is_accepted_too(lc: FakeLc) -> None:
    lc.compress = False
    lc.records = [record("d1", at=now())]
    assert [
        x["detect_id"]
        for x in client(lc).list_detections(0, 4_000_000_000, max_pages=5, max_items=50)
    ] == ["d1"]


def test_pages_are_followed_by_their_cursor(lc: FakeLc) -> None:
    at = now()
    lc.records = [record(f"d{n}", at=at - timedelta(seconds=n)) for n in range(7)]
    lc.page_size = 3
    got = list(
        client(lc).list_detections(
            int(at.timestamp()) - 100, int(at.timestamp()) + 5, max_pages=5, max_items=50
        )
    )
    assert sorted(x["detect_id"] for x in got) == sorted(f"d{n}" for n in range(7))
    assert [x["query"]["cursor"] for x in lc.lists()] == ["-", "3", "6"]


def test_a_cursor_that_repeats_is_an_error_not_a_loop(lc: FakeLc) -> None:
    at = now()
    lc.records = [record(f"d{n}", at=at) for n in range(4)]
    lc.page_size = 2
    lc.cursor_override = "same"
    with pytest.raises(r.LcError) as info:
        list(
            client(lc).list_detections(
                int(at.timestamp()) - 5, int(at.timestamp()) + 5, max_pages=50, max_items=500
            )
        )
    assert info.value.code == "bad_cursor"
    assert len(lc.lists()) <= 3


def test_a_cursor_that_is_huge_is_an_error(lc: FakeLc) -> None:
    lc.records = [record("d1", at=now())]
    lc.page_size = 1
    lc.records.append(record("d2", at=now()))
    lc.cursor_override = "x" * 5000
    with pytest.raises(r.LcError) as info:
        list(client(lc).list_detections(0, 4_000_000_000, max_pages=5, max_items=50))
    assert info.value.code == "bad_cursor"


def test_the_page_and_item_caps_stop_a_runaway_source(lc: FakeLc) -> None:
    at = now()
    lc.records = [record(f"d{n}", at=at) for n in range(10)]
    lc.page_size = 1
    window = (int(at.timestamp()) - 5, int(at.timestamp()) + 5)
    with pytest.raises(r.LcError) as pages:
        list(client(lc).list_detections(*window, max_pages=3, max_items=500))
    assert pages.value.code == "too_many_pages"
    with pytest.raises(r.LcError) as items:
        list(client(lc).list_detections(*window, max_pages=50, max_items=4))
    assert items.value.code == "too_many_items"


@pytest.mark.parametrize("wrap", ["detection.event", "event", "top"])
def test_a_whole_record_is_found_in_each_known_wrapper(lc: FakeLc, wrap: str) -> None:
    lc.records = [record("d1", at=now())]
    lc.wrap = wrap
    found = client(lc).get_detection("d1")
    assert found is not None and found[0]["source_rule"] == "general.Rule One"
    assert found[1] == {"detection.event": "detection.event", "event": "event", "top": "top"}[wrap]


def test_a_whole_record_for_another_id_is_an_error(lc: FakeLc) -> None:
    lc.records = [record("d1", at=now())]
    lc.wrap = "wrong"
    with pytest.raises(r.LcError) as info:
        client(lc).get_detection("d1")
    assert info.value.code == "bad_shape"


def test_a_vanished_detection_is_none_and_an_odd_id_is_never_requested(lc: FakeLc) -> None:
    c = client(lc)
    assert c.get_detection("nope") is None
    for odd in ("../x", "a/b", "a b", "", "x" * 300, "a?b=1"):
        assert c.get_detection(odd) is None
    assert len(lc.by_id()) == 1


# ---- the loop, against a real database ----


@pytest.fixture
def fx(db: TestDb) -> Fixture:
    return Fixture(db)


OPEN: list[Any] = []


@pytest.fixture(autouse=True)
def close_connections() -> Iterator[None]:
    yield
    while OPEN:
        OPEN.pop().close()


class Clock:
    def __init__(self) -> None:
        self.now = now()

    def __call__(self) -> datetime:
        return self.now


def make(
    fx: Fixture,
    lc: FakeLc,
    *,
    clock: Clock | None = None,
    source: str = "src-a",
    limits: r.Limits | None = None,
    health: Path | None = None,
) -> r.Reconciler:
    url = fx.db.sqlalchemy_url("soc_reconcile", ROLE_PASSWORD)
    store, cursor = PgStore(url), r.CursorDb(url)
    OPEN.extend([store, cursor])
    return r.Reconciler(
        client(lc),
        store,
        cursor,
        source=source,
        categories=CATEGORIES,
        limits=limits,
        clock=clock or Clock(),
        health_file=str(health) if health else None,
    )


def stored(fx: Fixture) -> list[tuple[Any, ...]]:
    return fx.rows(
        "SELECT event_id, rule, severity, detected_at, client_id FROM alert ORDER BY event_id"
    )


def test_a_detection_only_the_source_has_is_stored_whole(fx: Fixture, lc: FakeLc) -> None:
    clock = Clock()
    lc.records = [record("d1", at=clock.now - timedelta(minutes=10), detected_ago_s=2, priority=6)]
    counts = make(fx, lc, clock=clock).run_once()
    assert (counts.listed, counts.kept, counts.inserted, counts.enriched) == (1, 1, 1, 1)
    [(event, rule, severity, detected, client_id)] = stored(fx)
    assert (
        event == "d1" and rule == "general.Rule One" and severity == "high"
    )  # from the whole record
    assert detected is not None and str(client_id) == fx.clients["a"]
    raw = fx.one("SELECT raw FROM alert")[0]
    assert raw["source_rule"] == "general.Rule One" and raw["routing"]["hostname"] == "host-1"


def test_a_detection_the_webhook_already_stored_is_a_duplicate(fx: Fixture, lc: FakeLc) -> None:
    clock = Clock()
    rec = record("d1", at=clock.now - timedelta(minutes=10))
    with fx.db.connect("soc_ingest") as c:
        assert c.execute(
            "SELECT ingest_alert('src-a', 't-a', 'd1', 'general.Rule One', 'medium', 's', 'a', "
            "NULL, now(), '{}'::jsonb)"
        ).fetchone() == ("inserted",)
    lc.records = [rec]
    counts = make(fx, lc, clock=clock).run_once()
    assert (counts.inserted, counts.duplicate) == (0, 1)
    assert len(stored(fx)) == 1


def test_a_detection_stored_here_is_a_duplicate_for_the_webhook_afterwards(
    fx: Fixture, lc: FakeLc
) -> None:
    clock = Clock()
    lc.records = [record("d1", at=clock.now - timedelta(minutes=10))]
    make(fx, lc, clock=clock).run_once()
    with fx.db.connect("soc_ingest") as c:
        assert c.execute(
            "SELECT ingest_alert('src-a', 't-a', 'd1', 'x', 'low', 's', 'a', NULL, now(), "
            "'{}'::jsonb)"
        ).fetchone() == ("duplicate",)
    assert len(stored(fx)) == 1


def test_only_the_wanted_categories_are_kept(fx: Fixture, lc: FakeLc) -> None:
    clock = Clock()
    at = clock.now - timedelta(minutes=10)
    lc.records = [
        record("d1", at=at, cat="CAT_ONE"),
        record("d2", at=at, cat="CAT_TWO"),
        record("d3", at=at, cat="OTHER"),
        record("d4", at=at, cat="cat_one"),
    ]
    counts = make(fx, lc, clock=clock).run_once()
    assert (counts.listed, counts.kept, counts.skipped, counts.inserted) == (4, 2, 2, 2)
    assert [row[0] for row in stored(fx)] == ["d1", "d2"]
    assert [x["path"].rsplit("/", 1)[1] for x in lc.by_id()] == [
        "d1",
        "d2",
    ]  # nothing fetched for the rest


def test_a_list_that_already_has_every_field_needs_no_whole_record_fetch(
    fx: Fixture, lc: FakeLc
) -> None:
    clock = Clock()
    lc.summary_only = False
    lc.records = [record("d1", at=clock.now - timedelta(minutes=10))]
    counts = make(fx, lc, clock=clock).run_once()
    assert (counts.inserted, counts.enriched) == (1, 0) and lc.by_id() == []


@pytest.mark.parametrize("present", ["source_rule", "gen_time", "priority"])
def test_a_list_record_missing_even_one_field_is_fetched_whole(
    fx: Fixture, lc: FakeLc, present: str
) -> None:
    clock = Clock()
    lc.records = [record("d1", at=clock.now - timedelta(minutes=10))]
    lc.list_extra = (present,)  # the list carries one of the three; the other two are missing
    counts = make(fx, lc, clock=clock).run_once()
    assert (counts.enriched, counts.inserted) == (1, 1) and len(lc.by_id()) == 1


def test_a_detection_the_source_no_longer_has_is_stored_as_the_list_gave_it(
    fx: Fixture, lc: FakeLc
) -> None:
    clock = Clock()
    lc.records = [record("d1", at=clock.now - timedelta(minutes=10))]
    lc.missing = {"d1"}
    counts = make(fx, lc, clock=clock).run_once()
    assert (counts.inserted, counts.degraded) == (1, 1)
    [(_, rule, severity, detected, _)] = stored(fx)
    assert rule is None and severity == "medium" and detected is None


def test_a_failed_whole_record_fetch_holds_the_cursor_and_the_rest_still_lands(
    fx: Fixture, lc: FakeLc
) -> None:
    clock = Clock()
    at = clock.now - timedelta(minutes=10)
    lc.records = [record("d1", at=at), record("d2", at=at)]
    rec = make(fx, lc, clock=clock)
    real = rec.lc.get_detection

    def flaky(detect_id: str) -> Any:
        if detect_id == "d1":
            raise r.LcError("http_503")
        return real(detect_id)

    rec.lc.get_detection = flaky  # type: ignore[method-assign]
    with pytest.raises(r.LcError) as info:
        rec.run_once()
    assert info.value.code == "http_503"
    assert [row[0] for row in stored(fx)] == ["d2"]  # the one that worked is in
    assert fx.one("SELECT reconcile_cursor_get('src-a')")[0] is None  # but the window is not done
    rec.lc.get_detection = real  # type: ignore[method-assign]
    counts = rec.run_once()  # next run: the window is read again
    assert (counts.inserted, counts.duplicate) == (1, 1)
    assert [row[0] for row in stored(fx)] == ["d1", "d2"]


def test_nothing_is_fetched_twice_while_the_overlap_repeats_it(fx: Fixture, lc: FakeLc) -> None:
    clock = Clock()
    lc.records = [record("d1", at=clock.now - timedelta(minutes=5))]
    rec = make(fx, lc, clock=clock)
    rec.run_once()
    later(fx, minutes=5)
    counts = rec.run_once()
    assert (counts.kept, counts.duplicate, counts.inserted, counts.enriched) == (1, 1, 0, 0)
    assert len(lc.by_id()) == 1  # the second pass listed it again but fetched nothing


def test_malformed_items_are_counted_and_do_not_stop_the_rest(fx: Fixture, lc: FakeLc) -> None:
    clock = Clock()
    at = clock.now - timedelta(minutes=10)
    good = record("good", at=at)
    lc.records = [
        good,
        {"cat": "CAT_ONE", "ts": int(at.timestamp() * 1000), "link": "x"},  # no id
        {**record("x", at=at), "detect_id": "a/b"},  # not a plain id
        {**record("y", at=at), "detect_id": 7},
    ]
    lc.summary_only = False
    counts = make(fx, lc, clock=clock).run_once()
    assert (counts.inserted, counts.malformed) == (1, 3)
    assert [row[0] for row in stored(fx)] == ["good"]


def test_items_that_are_not_objects_are_malformed_not_fatal(fx: Fixture, lc: FakeLc) -> None:
    clock = Clock()
    lc.compress = False
    lc.api_body = json.dumps({"detects": [1, "two", None, [3]]}).encode()
    counts = make(fx, lc, clock=clock).run_once()
    assert (counts.listed, counts.malformed, counts.inserted) == (4, 4, 0)


def test_nul_and_surrogates_in_a_record_are_stored_like_the_webhook_would(
    fx: Fixture, lc: FakeLc
) -> None:
    clock = Clock()
    rec = record("d1", at=clock.now - timedelta(minutes=10))
    rec["detect"] = {"event": {"COMMAND_LINE": "evil\x00name \ud800"}}
    lc.records = [rec]
    counts = make(fx, lc, clock=clock).run_once()
    assert counts.inserted == 1
    assert "\x00" not in json.dumps(fx.one("SELECT raw FROM alert")[0])


def test_a_record_too_big_for_the_database_is_counted_and_skipped(fx: Fixture, lc: FakeLc) -> None:
    clock = Clock()
    rec = record("d1", at=clock.now - timedelta(minutes=10))
    rec["detect"] = {"blob": "x" * 300_000}
    lc.records = [rec, record("d2", at=clock.now - timedelta(minutes=10))]
    counts = make(fx, lc, clock=clock).run_once()
    assert (counts.inserted, counts.malformed) == (1, 1)
    assert [row[0] for row in stored(fx)] == ["d2"]
    assert (
        fx.one("SELECT reconcile_cursor_get('src-a')")[0] is not None
    )  # a permanent skip does not block


def test_an_unknown_source_is_a_failure_and_the_cursor_stays(fx: Fixture, lc: FakeLc) -> None:
    clock = Clock()
    lc.records = [record("d1", at=clock.now - timedelta(minutes=10))]
    rec = make(fx, lc, clock=clock, source="no-such-source")
    with pytest.raises(r.LcError) as info:
        rec.run_once()
    assert info.value.code == "unknown_source"
    assert alerts_count(fx) == 0 and fx.one("SELECT count(*) FROM reconcile_cursor") == (0,)


def later(fx: Fixture, *, minutes: float) -> None:
    """Let `minutes` pass for the pipeline: the database refuses a cursor in its own future,
    so time is simulated by moving the cursor back instead of the clock forward."""
    fx.run(
        "UPDATE reconcile_cursor SET window_end = window_end - make_interval(secs => %s)",
        (minutes * 60,),
    )


def alerts_count(fx: Fixture) -> int:
    return int(fx.one("SELECT count(*) FROM alert")[0])


# ---- windows and the cursor ----


def test_a_first_run_looks_back_one_hour_and_the_cursor_ends_a_minute_ago(
    fx: Fixture, lc: FakeLc
) -> None:
    clock = Clock()
    make(fx, lc, clock=clock).run_once()
    [get] = lc.lists()
    end = int(clock.now.timestamp()) - 60
    assert int(get["query"]["end"]) == end and int(get["query"]["start"]) == end - 3600
    cursor = fx.one("SELECT reconcile_cursor_get('src-a')")[0]
    assert int(cursor.timestamp()) == end


def test_later_runs_start_ten_minutes_before_the_cursor(fx: Fixture, lc: FakeLc) -> None:
    clock = Clock()
    rec = make(fx, lc, clock=clock)
    rec.run_once()
    first_end = int(lc.lists()[0]["query"]["end"])
    later(fx, minutes=5)  # five minutes pass: the cursor is that much behind the clock
    rec.run_once()
    second = lc.lists()[-1]["query"]
    assert int(second["start"]) == first_end - 300 - 600
    assert int(second["end"]) == int(clock.now.timestamp()) - 60


def test_a_gap_longer_than_a_day_is_cut_to_a_day(
    fx: Fixture, lc: FakeLc, caplog: pytest.LogCaptureFixture
) -> None:
    clock = Clock()
    fx.run(
        "INSERT INTO reconcile_cursor (source_id, window_end) "
        "SELECT id, now() - interval '5 days' FROM source WHERE slug = 'src-a'"
    )
    caplog.set_level(logging.WARNING, logger="soc_api.reconcile")
    make(fx, lc, clock=clock, limits=r.Limits(max_windows=100)).run_once()
    first = int(lc.lists()[0]["query"]["start"])
    assert first == int(clock.now.timestamp()) - 86400
    assert "reconcile gap" in caplog.text


def test_a_long_gap_is_fetched_in_hourly_windows_that_share_their_edges(
    fx: Fixture, lc: FakeLc
) -> None:
    clock = Clock()
    fx.run(
        "INSERT INTO reconcile_cursor (source_id, window_end) "
        "SELECT id, now() - interval '4 hours' FROM source WHERE slug = 'src-a'"
    )
    make(fx, lc, clock=clock).run_once()
    windows = [(int(x["query"]["start"]), int(x["query"]["end"])) for x in lc.lists()]
    assert len(windows) == 5 and all(b - a <= 3600 for a, b in windows)
    assert all(windows[n + 1][0] == windows[n][1] - 5 for n in range(len(windows) - 1))
    assert windows[-1][1] == int(clock.now.timestamp()) - 60


def test_the_cursor_moves_after_each_window_so_a_failure_keeps_the_progress(
    fx: Fixture, lc: FakeLc
) -> None:
    clock = Clock()
    fx.run(
        "INSERT INTO reconcile_cursor (source_id, window_end) "
        "SELECT id, now() - interval '4 hours' FROM source WHERE slug = 'src-a'"
    )
    rec = make(fx, lc, clock=clock)
    lc.fail_nth_list = 3  # two windows are fetched, then the source fails
    with pytest.raises(r.LcError) as info:
        rec.run_once()
    assert info.value.code == "http_5xx"
    cursor = fx.one("SELECT reconcile_cursor_get('src-a')")[0]
    second_end = int(lc.lists()[1]["query"]["end"])
    assert int(cursor.timestamp()) == second_end  # the end of window two, not three


def test_a_long_gap_takes_a_few_runs_when_it_exceeds_the_per_run_limit(
    fx: Fixture, lc: FakeLc
) -> None:
    clock = Clock()
    fx.run(
        "INSERT INTO reconcile_cursor (source_id, window_end) "
        "SELECT id, now() - interval '10 hours' FROM source WHERE slug = 'src-a'"
    )
    rec = make(fx, lc, clock=clock, limits=r.Limits(max_windows=3))
    assert rec.run_once().windows == 3
    assert rec.run_once().windows == 3
    assert rec.run_once().windows == 3
    assert rec.run_once().windows >= 1


def test_nothing_is_fetched_when_the_cursor_is_already_current(fx: Fixture, lc: FakeLc) -> None:
    clock = Clock()
    fx.run(
        "INSERT INTO reconcile_cursor (source_id, window_end) "
        "SELECT id, now() + interval '30 seconds' FROM source WHERE slug = 'src-a'"
    )
    make(fx, lc, clock=clock, limits=r.Limits(overlap_s=0)).run_once()
    assert lc.lists() == []


def test_a_detection_in_the_overlap_of_a_late_run_is_still_caught(fx: Fixture, lc: FakeLc) -> None:
    clock = Clock()
    rec = make(fx, lc, clock=clock)
    rec.run_once()  # an empty run sets the cursor
    later(fx, minutes=5)
    # the source only now returns a detection from 8 minutes ago (it arrived there late)
    lc.records = [record("late-to-the-source", at=clock.now - timedelta(minutes=8))]
    assert rec.run_once().inserted == 1


# ---- failures, the loop and the log ----


def cursor_state(fx: Fixture) -> tuple[Any, ...] | None:
    return fx.one("SELECT window_end, last_error FROM reconcile_cursor")


def test_a_failed_cycle_records_a_code_and_a_later_good_one_clears_it(
    fx: Fixture, lc: FakeLc
) -> None:
    clock = Clock()
    rec = make(fx, lc, clock=clock)
    lc.api_statuses.append(503)
    assert rec.cycle() is False
    state = cursor_state(fx)
    assert state is not None and state[0] is None and state[1] == "http_5xx"
    assert rec.cycle() is True
    state = cursor_state(fx)
    assert state is not None and state[0] is not None and state[1] is None


def test_a_rejected_key_is_recorded_as_a_token_failure(fx: Fixture, lc: FakeLc) -> None:
    lc.jwt_status = 403
    rec = make(fx, lc)
    assert rec.cycle() is False
    state = cursor_state(fx)
    assert state is not None and state[1] == "jwt_http_403"


def test_a_database_outage_is_a_code_not_a_crash(
    fx: Fixture, lc: FakeLc, caplog: pytest.LogCaptureFixture
) -> None:
    rec = make(fx, lc)
    rec.cursor._params["port"] = 1  # nothing listens there
    caplog.set_level(logging.INFO, logger="soc_api.reconcile")
    assert rec.cycle() is False
    assert "outcome=error code=db_error" in caplog.text


def test_a_surprise_exception_is_contained(
    fx: Fixture, lc: FakeLc, caplog: pytest.LogCaptureFixture
) -> None:
    rec = make(fx, lc)

    def boom() -> r.Counts:
        raise KeyError("secret-looking-text")

    rec.run_once = boom  # type: ignore[method-assign]
    caplog.set_level(logging.INFO, logger="soc_api.reconcile")
    assert rec.cycle() is False
    assert "code=internal kind=KeyError" in caplog.text and "secret-looking-text" not in caplog.text
    state = cursor_state(fx)
    assert state is not None and state[1] == "internal"


def test_one_summary_line_per_pass_and_never_a_key_or_an_address(
    fx: Fixture, lc: FakeLc, caplog: pytest.LogCaptureFixture
) -> None:
    clock = Clock()
    lc.records = [record("d1", at=clock.now - timedelta(minutes=10))]
    caplog.set_level(logging.DEBUG, logger="soc_api.reconcile")
    make(fx, lc, clock=clock).cycle()
    lines = [m for m in caplog.messages if m.startswith("reconcile outcome")]
    assert lines == [
        "reconcile outcome=ok windows=1 listed=1 kept=1 inserted=1 duplicate=0 skipped=0 "
        "malformed=0 enriched=1 degraded=0"
    ]
    everything = caplog.text
    for secret in (KEY, TOKEN, OID, lc.url, "host-1", "d1"):
        assert secret not in everything


def test_the_health_file_is_touched_by_a_pass_that_ran_even_when_the_source_failed(
    fx: Fixture, lc: FakeLc, tmp_path: Path
) -> None:
    health = tmp_path / "health"
    rec = make(fx, lc, health=health)
    lc.api_statuses.append(500)
    rec.cycle()
    assert health.exists()
    health.unlink()
    rec.cycle()
    assert health.exists()


def test_the_health_file_is_not_touched_by_a_surprise(
    fx: Fixture, lc: FakeLc, tmp_path: Path
) -> None:
    health = tmp_path / "health"
    rec = make(fx, lc, health=health)
    rec.run_once = lambda: 1 / 0  # type: ignore[method-assign, assignment, return-value]
    assert rec.cycle() is False and not health.exists()


def test_the_loop_runs_a_pass_at_each_interval_until_told_to_stop(fx: Fixture, lc: FakeLc) -> None:
    rec = make(fx, lc)
    rec.interval_s = 300.0
    passes: list[int] = []
    rec.cycle = lambda: passes.append(1) or True  # type: ignore[method-assign]
    clock = [0.0]
    sleeps: list[float] = []

    def sleep(seconds: float) -> None:
        sleeps.append(seconds)
        clock[0] += 100.0

    rec.run(lambda: len(sleeps) >= 7, sleep=sleep, monotonic=lambda: clock[0])
    assert len(passes) == 3 and set(sleeps) == {1.0}  # at 0, 300 and 600 seconds


# ---- a late alert pages as LATE ----


def test_a_caught_up_alert_has_its_lateness_and_pages_as_late(fx: Fixture, lc: FakeLc) -> None:
    clock = Clock()
    lc.records = [record("d1", at=clock.now - timedelta(minutes=19), detected_ago_s=60)]
    make(fx, lc, clock=clock).run_once()
    fx.assign()
    [page] = claim(fx)
    assert 1100 < page["late_s"] < 1300
    assert w.push_text(page)[0] == "LATE: client-a: Rule One"


def test_an_alert_caught_within_minutes_does_not_page_as_late(fx: Fixture, lc: FakeLc) -> None:
    clock = Clock()
    lc.records = [record("d1", at=clock.now - timedelta(minutes=3), detected_ago_s=5)]
    make(fx, lc, clock=clock).run_once()
    fx.assign()
    [page] = claim(fx)
    assert w.push_text(page)[0] == "client-a: Rule One"


def test_a_caught_up_alert_joins_the_case_of_the_same_rule_and_host(
    fx: Fixture, lc: FakeLc
) -> None:
    clock = Clock()
    with fx.db.connect("soc_ingest") as c:
        raw = json.dumps({"cat": "CAT_ONE", "routing": {"hostname": "host-1"}})
        c.execute(
            "SELECT ingest_alert('src-a', 't-a', 'webhook-one', 'general.Rule One', 'medium', "
            "'s', 'a', NULL, now(), %s::jsonb)",
            (raw,),
        )
    lc.records = [record("missed-one", at=clock.now - timedelta(minutes=10))]
    make(fx, lc, clock=clock).run_once()
    assert fx.assign()[:2] == (2, 1)  # two alerts, one case: the rule and the host match


# ---- the read-only check ----


def test_the_check_reports_counts_and_field_presence_only(
    lc: FakeLc, capsys: pytest.CaptureFixture[str]
) -> None:
    at = datetime.now(UTC) - timedelta(minutes=5)
    lc.records = [
        record("secret-detect-id", at=at, host="secret-host"),
        record("d2", at=at, cat="OTHER"),
    ]
    cfg = r.Config.from_settings(
        settings(
            env="dev",
            reconcile_api_url=lc.url,
            reconcile_jwt_url=lc.url + "/jwt",
            reconcile_categories="CAT_ONE",
        )
    )
    assert r.check(cfg, 60) == 0
    out = capsys.readouterr().out
    assert "check ok: auth=ok window=60m listed=2 matching=1" in out
    assert "listed fields (2 records): detect_id=2 cat=2 source_rule=0 gen_time=0 priority=0" in out
    assert "whole records (1 fetched): detect_id=1 cat=1 source_rule=1 gen_time=1 priority=1" in out
    assert "found at: detection.event=1" in out
    for value in ("secret-detect-id", "secret-host", KEY, TOKEN, OID):
        assert value not in out


def test_the_check_reports_a_failure_by_code_alone(
    lc: FakeLc, capsys: pytest.CaptureFixture[str]
) -> None:
    lc.jwt_status = 401
    cfg = r.Config.from_settings(
        settings(
            env="dev",
            reconcile_api_url=lc.url,
            reconcile_jwt_url=lc.url + "/jwt",
            reconcile_database_url="",
        ),
        need_db=False,
    )
    assert r.check(cfg, 30) == 1
    assert capsys.readouterr().out.strip() == "check failed: jwt_http_401"


def test_the_command_line_names_what_is_missing_and_prints_no_value(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from soc_api import config

    for name in (
        "SOC_RECONCILE_LC_KEY",
        "SOC_RECONCILE_LC_OID",
        "SOC_RECONCILE_SOURCE",
        "SOC_RECONCILE_CATEGORIES",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("SOC_RECONCILE_LC_KEY", KEY)
    config.get_settings.cache_clear()
    try:
        assert r.main(["once"]) == 2
    finally:
        config.get_settings.cache_clear()
    out = capsys.readouterr().out
    assert "SOC_RECONCILE_LC_OID" in out and KEY not in out


def test_the_check_command_rejects_a_silly_window(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from soc_api import config

    monkeypatch.setenv("SOC_RECONCILE_LC_KEY", KEY)
    monkeypatch.setenv("SOC_RECONCILE_LC_OID", OID)
    monkeypatch.setenv("SOC_RECONCILE_SOURCE", "src-a")
    monkeypatch.setenv("SOC_RECONCILE_CATEGORIES", "CAT_ONE")
    config.get_settings.cache_clear()
    try:
        assert r.main(["check", "--minutes", "1"]) == 2
        assert r.main(["check", "--minutes", "99999"]) == 2
    finally:
        config.get_settings.cache_clear()
    assert "--minutes" in capsys.readouterr().out


@pytest.mark.parametrize("gen_time", [10**20, -(10**20), 10**30, 2**63, 0, "soon", None])
def test_an_impossible_detection_time_is_stored_as_unknown_and_never_blocks_the_cursor(
    fx: Fixture, lc: FakeLc, gen_time: Any
) -> None:
    """The webhook refuses such a time before it is converted; this path has no such check,
    so an impossible value must become 'detection time unknown' instead of an exception
    that would fail every pass until the record ages out of the window."""
    clock = Clock()
    rec = record("d1", at=clock.now - timedelta(minutes=10))
    rec["gen_time"] = gen_time
    lc.records = [rec, record("d2", at=clock.now - timedelta(minutes=10))]
    lc.summary_only = False
    counts = make(fx, lc, clock=clock).run_once()
    assert (counts.inserted, counts.windows) == (2, 1)
    rows = dict(fx.rows("SELECT event_id, detected_at FROM alert"))
    assert rows["d1"] is None and rows["d2"] is not None
    assert fx.one("SELECT raw->'gen_time' FROM alert WHERE event_id = 'd1'")[0] == gen_time
