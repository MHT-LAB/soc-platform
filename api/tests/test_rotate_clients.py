"""The HTTPS guard and the two API clients, with a fake `fetch`: no socket is ever opened."""

import io
import json
import urllib.error
import urllib.parse
from typing import Any

import pytest

from soc_api.rotate import lc, net, store
from soc_api.rotate.net import RotateError
from soc_api.rotate.rights import Rights, Secret

OID = "01234567-89ab-cdef-0123-456789abcdef"
LC_KEY = "LCROTATORKEY-aaaaaaaaaaaaaaaa"
CLIENT_ID = "CLIENTID-0123456789"
CLIENT_SECRET = "CLIENTSECRET-aaaaaaaaaaaaaaaa"
JWT = "header.payload.signature-0123456789"
TOKEN = "ACCESSTOKEN-0123456789abcdefghij"
NEW_VALUE = "NEWKEYVALUE-0123456789abcd"
SENTINELS = (LC_KEY, CLIENT_ID, CLIENT_SECRET, NEW_VALUE)


class FakeNet:
    """Stands in for net.fetch: answers from a list and records every call."""

    def __init__(self, *replies: Any) -> None:
        self.replies = list(replies)
        self.calls: list[dict[str, Any]] = []

    def __call__(self, method: str, url: str, **kw: Any) -> bytes:
        self.calls.append({"method": method, "url": url, **kw})
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply if isinstance(reply, bytes) else json.dumps(reply).encode()


SECRETS_URL = "https://secrets.example.test"


def rights(url: str = SECRETS_URL) -> Rights:
    return Rights(
        Secret(LC_KEY), Secret(CLIENT_ID), Secret(CLIENT_SECRET), url, "proj-12345678", "dev"
    )


def urls_and_headers(fake: FakeNet) -> str:
    return " ".join(f"{c['url']} {c.get('headers')}" for c in fake.calls)


# ---- the HTTPS guard ----


class FakeResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *_a: object) -> None:
        return None

    def read(self, n: int) -> bytes:
        return self._body[:n]


class FakeOpener:
    def __init__(self, result: Any) -> None:
        self.result = result

    def open(self, request: Any, timeout: float) -> Any:  # noqa: A003 - mirrors OpenerDirector
        if isinstance(self.result, Exception):
            raise self.result
        return FakeResponse(self.result)


HOSTS = frozenset({"api.example.com"})


@pytest.mark.parametrize(
    "url",
    [
        "http://api.example.com/x",
        "ftp://api.example.com/x",
        "https://evil.example.org/x",
        "https://api.example.com.evil.org/x",
        "https://user:pw" + chr(64) + "api.example.com/x",  # credentials in the URL
        "https://api.example.com:8443/x",
    ],
)
def test_only_https_to_the_named_host_without_credentials_or_a_port(
    monkeypatch: pytest.MonkeyPatch, url: str
) -> None:
    monkeypatch.setattr(net, "_OPENER", FakeOpener(b"{}"))
    with pytest.raises(RotateError) as exc:
        net.fetch("GET", url, hosts=HOSTS)
    assert exc.value.code == "bad_url"


def test_a_good_call_returns_the_body(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(net, "_OPENER", FakeOpener(b'{"ok": true}'))
    assert net.fetch("GET", "https://api.example.com/x", hosts=HOSTS) == b'{"ok": true}'


@pytest.mark.parametrize(
    ("status", "code"),
    [(302, "redirect"), (401, "http_401"), (404, "http_404"), (418, "http_4xx"), (503, "http_5xx")],
)
def test_a_status_becomes_a_short_code_and_a_redirect_is_never_followed(
    monkeypatch: pytest.MonkeyPatch, status: int, code: str
) -> None:
    err = urllib.error.HTTPError("https://api.example.com/x", status, "m", {}, io.BytesIO(b"body"))  # type: ignore[arg-type]
    monkeypatch.setattr(net, "_OPENER", FakeOpener(err))
    with pytest.raises(RotateError) as exc:
        net.fetch("GET", "https://api.example.com/x", hosts=HOSTS)
    assert exc.value.code == code


def test_network_trouble_and_oversize_bodies_are_short_codes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(net, "_OPENER", FakeOpener(urllib.error.URLError(TimeoutError())))
    with pytest.raises(RotateError, match="timeout"):
        net.fetch("GET", "https://api.example.com/x", hosts=HOSTS)
    monkeypatch.setattr(net, "_OPENER", FakeOpener(urllib.error.URLError("refused")))
    with pytest.raises(RotateError, match="network"):
        net.fetch("GET", "https://api.example.com/x", hosts=HOSTS)
    monkeypatch.setattr(net, "_OPENER", FakeOpener(b"x" * 50))
    with pytest.raises(RotateError, match="too_large"):
        net.fetch("GET", "https://api.example.com/x", hosts=HOSTS, max_bytes=10)


# ---- the detection vendor ----

KEYS_REPLY = {
    "oldkeyid0001": {"key_name": "x", "priv": ["sensor.list", "dr.list"]},
    "otherkey0002": {"name": "y", "perms": "dr.list,org.get"},
}


def vendor(*replies: Any) -> tuple[lc.LimaCharlieKeys, FakeNet]:
    fake = FakeNet({"jwt": JWT}, *replies)
    return lc.LimaCharlieKeys(OID, Secret(LC_KEY), fetch=fake), fake


def test_listing_logs_in_with_the_key_in_the_body_and_reads_names_and_permissions() -> None:
    client, fake = vendor(KEYS_REPLY)
    keys = client.list_keys()
    assert keys["oldkeyid0001"].perms == {"sensor.list", "dr.list"}
    assert keys["otherkey0002"].name == "y" and keys["otherkey0002"].perms == {"dr.list", "org.get"}
    login, call = fake.calls
    assert login["method"] == "POST" and login["url"] == lc.JWT_URL
    assert urllib.parse.parse_qs(login["data"].decode()) == {"oid": [OID], "secret": [LC_KEY]}
    assert call["method"] == "GET" and call["url"] == f"{lc.API_URL}/orgs/{OID}/keys"
    assert call["headers"]["Authorization"] == f"Bearer {JWT}"


def test_the_rotator_key_is_only_ever_in_the_login_body_never_a_url_or_header() -> None:
    client, fake = vendor(KEYS_REPLY, {"api_key": NEW_VALUE, "key_hash": "newkeyid0003"}, {})
    client.list_keys()
    client.create_key("x-20261118", ("dr.list",))
    client.delete_key("oldkeyid0001")
    for call in fake.calls[1:]:
        assert LC_KEY not in call["url"] and LC_KEY not in str(call.get("headers"))
    assert LC_KEY not in urls_and_headers(fake)


def test_creating_sends_the_name_and_permissions_and_keeps_the_value_secret() -> None:
    client, fake = vendor({"api_key": NEW_VALUE, "key_hash": "newkeyid0003"})
    new = client.create_key("x-20261118", ("sensor.list", "dr.list"))
    assert new.id == "newkeyid0003" and new.value.reveal() == NEW_VALUE
    assert NEW_VALUE not in repr(new) and NEW_VALUE not in str(new)
    post = fake.calls[1]
    assert post["method"] == "POST"
    assert urllib.parse.parse_qs(post["data"].decode()) == {
        "key_name": ["x-20261118"],
        "perms": ["sensor.list,dr.list"],
    }


def test_deleting_sends_the_exact_id() -> None:
    client, fake = vendor({"success": True})
    client.delete_key("oldkeyid0001")
    delete = fake.calls[1]
    assert delete["method"] == "DELETE"
    assert urllib.parse.parse_qs(delete["data"].decode()) == {"key_hash": ["oldkeyid0001"]}


def test_an_id_that_is_not_an_id_is_refused_before_any_call() -> None:
    client, fake = vendor()
    with pytest.raises(RotateError, match="bad_key_id"):
        client.delete_key("x; DROP")
    assert fake.calls == []


def test_an_expired_token_is_renewed_once_and_only_once() -> None:
    fake = FakeNet({"jwt": JWT}, RotateError("http_401"), {"jwt": JWT + "2"}, KEYS_REPLY)
    assert lc.LimaCharlieKeys(OID, Secret(LC_KEY), fetch=fake).list_keys()
    fake2 = FakeNet({"jwt": JWT}, RotateError("http_401"), {"jwt": JWT}, RotateError("http_401"))
    with pytest.raises(RotateError, match="http_401"):
        lc.LimaCharlieKeys(OID, Secret(LC_KEY), fetch=fake2).list_keys()


@pytest.mark.parametrize(
    "doc",
    [
        [],
        {"oldkeyid0001": "not a dict"},
        {"oldkeyid0001": {"key_name": "x"}},  # no permissions: never guessed
        {"oldkeyid0001": {"priv": ["a.b"]}},  # no name
        {"bad id": {"key_name": "x", "priv": []}},
        {"oldkeyid0001": {"key_name": "x", "priv": [1, 2]}},
    ],
)
def test_a_list_reply_of_an_unexpected_shape_is_refused(doc: Any) -> None:
    client, _ = vendor(doc)
    with pytest.raises(RotateError, match="bad_shape"):
        client.list_keys()


@pytest.mark.parametrize(
    "doc",
    [
        {},
        {"api_key": "short", "key_hash": "newkeyid0003"},
        {"api_key": NEW_VALUE},
        {"key_hash": "newkeyid0003"},
    ],
)
def test_a_create_reply_of_an_unexpected_shape_is_refused(doc: Any) -> None:
    client, _ = vendor(doc)
    with pytest.raises(RotateError, match="bad_shape"):
        client.create_key("x-20261118", ("dr.list",))


def test_a_bad_login_reply_and_a_bad_org_id_are_refused() -> None:
    fake = FakeNet({"jwt": "has spaces"})
    with pytest.raises(RotateError, match="jwt_bad_shape"):
        lc.LimaCharlieKeys(OID, Secret(LC_KEY), fetch=fake).list_keys()
    fake2 = FakeNet(RotateError("http_401"))
    with pytest.raises(RotateError, match="jwt_http_401"):
        lc.LimaCharlieKeys(OID, Secret(LC_KEY), fetch=fake2).list_keys()
    with pytest.raises(RotateError, match="bad_oid"):
        lc.LimaCharlieKeys("not-an-oid", Secret(LC_KEY))


def test_nothing_here_ever_calls_the_outputs_api() -> None:
    client, fake = vendor(KEYS_REPLY, {"api_key": NEW_VALUE, "key_hash": "newkeyid0003"}, {})
    client.list_keys()
    client.create_key("x-20261118", ("dr.list",))
    client.delete_key("oldkeyid0001")
    assert "output" not in urls_and_headers(fake).lower()
    assert all(c["url"].endswith("/keys") or c["url"] == lc.JWT_URL for c in fake.calls)


# ---- the secrets manager ----


def manager(*replies: Any) -> tuple[store.SecretsManager, FakeNet]:
    fake = FakeNet({"accessToken": TOKEN}, *replies)
    return store.SecretsManager(rights(), fetch=fake), fake


def test_a_read_logs_in_by_json_body_and_asks_for_one_name_in_one_project_path() -> None:
    client, fake = manager({"secret": {"secretValue": NEW_VALUE}})
    assert client.get("/SOC", "AUTO_KEY_VALUE").reveal() == NEW_VALUE
    login, read = fake.calls
    assert json.loads(login["data"]) == {"clientId": CLIENT_ID, "clientSecret": CLIENT_SECRET}
    parsed = urllib.parse.urlsplit(read["url"])
    assert parsed.path == "/api/v3/secrets/raw/AUTO_KEY_VALUE"
    assert urllib.parse.parse_qs(parsed.query) == {
        "workspaceId": ["proj-12345678"],
        "environment": ["dev"],
        "secretPath": ["/SOC"],
    }
    assert read["headers"]["Authorization"] == f"Bearer {TOKEN}"


def test_a_write_sends_the_value_in_the_body_only() -> None:
    client, fake = manager({})
    client.set("/SOC", "AUTO_KEY_VALUE", Secret(NEW_VALUE))
    write = fake.calls[1]
    assert write["method"] == "PATCH" and NEW_VALUE not in write["url"]
    assert json.loads(write["data"])["secretValue"] == NEW_VALUE
    assert NEW_VALUE not in str(write.get("headers"))


def test_no_credential_is_ever_in_a_url_or_header() -> None:
    client, fake = manager({"secret": {"secretValue": NEW_VALUE}}, {})
    client.get("/SOC", "AUTO_KEY_VALUE")
    client.set("/SOC", "AUTO_KEY_VALUE", Secret(NEW_VALUE))
    text = urls_and_headers(fake)
    for sentinel in (CLIENT_ID, CLIENT_SECRET, NEW_VALUE):
        assert sentinel not in text


@pytest.mark.parametrize(
    ("path", "name"),
    [
        ("SOC", "A_KEY"),
        ("/SOC/../x y", "A_KEY"),
        ("/SOC", "bad name"),
        ("/SOC", "../etc"),
        ("/SOC", ""),
    ],
)
def test_a_path_or_name_that_could_change_the_request_is_refused_before_any_call(
    path: str, name: str
) -> None:
    client, fake = manager({"secret": {"secretValue": "v"}})
    with pytest.raises(RotateError):
        client.get(path, name)
    assert fake.calls == []


@pytest.mark.parametrize(
    "doc", [{}, {"secret": {}}, {"secret": {"secretValue": 5}}, {"secret": {"secretValue": ""}}]
)
def test_a_read_reply_of_an_unexpected_shape_is_refused(doc: Any) -> None:
    client, _ = manager(doc)
    with pytest.raises(RotateError, match="bad_shape"):
        client.get("/SOC", "AUTO_KEY_VALUE")


def test_a_failed_or_malformed_login_is_a_short_code() -> None:
    fake = FakeNet(RotateError("http_401"))
    with pytest.raises(RotateError, match="login_http_401"):
        store.SecretsManager(rights(), fetch=fake).get("/SOC", "A_KEY")
    fake2 = FakeNet({"accessToken": "has spaces"})
    with pytest.raises(RotateError, match="login_bad_shape"):
        store.SecretsManager(rights(), fetch=fake2).get("/SOC", "A_KEY")


def test_the_secrets_manager_may_only_reach_the_host_it_was_given() -> None:
    client, fake = manager({"secret": {"secretValue": NEW_VALUE}})
    client.get("/SOC", "AUTO_KEY_VALUE")
    assert all(c["hosts"] == frozenset({"secrets.example.test"}) for c in fake.calls)
    assert all(c["url"].startswith(SECRETS_URL + "/") for c in fake.calls)


@pytest.mark.parametrize(
    "url", ["http://secrets.example.test", "https://secrets.example.test/x", "https://a", ""]
)
def test_an_address_that_is_not_a_plain_https_host_is_refused_before_any_call(url: str) -> None:
    fake = FakeNet({"accessToken": TOKEN})
    with pytest.raises(RotateError, match="bad_url"):
        store.SecretsManager(rights(url), fetch=fake)
    assert fake.calls == []
