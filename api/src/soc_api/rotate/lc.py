"""The detection vendor's key API: list, create and delete keys.

`[C]` marks what is not confirmed against the vendor's documentation or a live call: the REST
paths and the shape of each reply. The parsers therefore refuse anything unexpected instead of
guessing, and `rotate.sh --preflight` makes only the read calls (the login and the list) so the
real shapes can be checked before a first rotation changes anything.

Never calls anything under `output.*` (the list of outputs returns secrets in plain text), and
the key value the vendor returns on creation goes straight into a `Secret`.
"""

import json
import re
import urllib.parse
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from soc_api.rotate import net
from soc_api.rotate.net import RotateError
from soc_api.rotate.rights import Secret

API_URL = "https://api.limacharlie.io/v1"
JWT_URL = "https://jwt.limacharlie.io"
HOSTS = frozenset({"api.limacharlie.io", "jwt.limacharlie.io"})
OID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
KEY_VALUE_RE = re.compile(r"[A-Za-z0-9._-]{16,128}")
KEY_ID_RE = re.compile(r"[A-Za-z0-9._-]{8,128}")
JWT_RE = re.compile(r"[A-Za-z0-9._-]{20,4096}")
MAX_KEYS = 5000
JSON_FORM = {"Content-Type": "application/x-www-form-urlencoded"}


@dataclass(frozen=True)
class VendorKey:
    id: str
    name: str
    perms: frozenset[str]


@dataclass(frozen=True)
class NewKey:
    id: str
    value: Secret


def parse_keys(doc: Any) -> dict[str, VendorKey]:
    """`[C]` A table of key id to {name, permissions}. Anything else is refused."""
    if isinstance(doc, dict) and isinstance(doc.get("keys"), dict):
        doc = doc["keys"]
    if not isinstance(doc, dict) or len(doc) > MAX_KEYS:
        raise RotateError("bad_shape")
    out: dict[str, VendorKey] = {}
    for key_id, entry in doc.items():
        if not (
            isinstance(key_id, str) and KEY_ID_RE.fullmatch(key_id) and isinstance(entry, dict)
        ):
            raise RotateError("bad_shape")
        name = entry.get("key_name", entry.get("name"))
        perms = entry.get("priv", entry.get("perms", entry.get("permissions")))
        if isinstance(perms, str):
            perms = [p for p in perms.split(",") if p]
        if not (
            isinstance(name, str)
            and isinstance(perms, list)
            and all(isinstance(p, str) for p in perms)
        ):
            raise RotateError("bad_shape")
        out[key_id] = VendorKey(key_id, name[:128], frozenset(perms))
    return out


def parse_new_key(doc: Any) -> NewKey:
    """`[C]` The reply to a create: the new key's value and its id."""
    value = doc.get("api_key") if isinstance(doc, dict) else None
    key_id = doc.get("key_hash") if isinstance(doc, dict) else None
    if not (isinstance(value, str) and KEY_VALUE_RE.fullmatch(value)):
        raise RotateError("bad_shape")
    if not (isinstance(key_id, str) and KEY_ID_RE.fullmatch(key_id)):
        raise RotateError("bad_shape")
    return NewKey(key_id, Secret(value))


class LimaCharlieKeys:
    """Key management for one organization, signed in with the rotator's own key."""

    def __init__(
        self, oid: str, rotator_key: Secret, *, fetch: Callable[..., bytes] = net.fetch
    ) -> None:
        if not OID_RE.fullmatch(oid):
            raise RotateError("bad_oid")
        self.oid = oid
        self._key = rotator_key
        self._fetch = fetch
        self._jwt: str | None = None

    def _token(self) -> str:
        body = urllib.parse.urlencode({"oid": self.oid, "secret": self._key.reveal()}).encode()
        try:
            raw = self._fetch("POST", JWT_URL, hosts=HOSTS, data=body, headers=JSON_FORM)
        except RotateError as exc:
            raise RotateError(f"jwt_{exc.code}") from None
        doc = _json(raw)
        token = doc.get("jwt") if isinstance(doc, dict) else None
        if not (isinstance(token, str) and JWT_RE.fullmatch(token)):
            raise RotateError("jwt_bad_shape")
        return token

    def _call(self, method: str, form: dict[str, str] | None = None) -> Any:
        url = f"{API_URL}/orgs/{self.oid}/keys"  # [C] the path
        data = urllib.parse.urlencode(form).encode() if form is not None else None
        for attempt in (0, 1):
            if self._jwt is None:
                self._jwt = self._token()
            headers = {"Authorization": f"Bearer {self._jwt}", "Accept": "application/json"}
            if data is not None:
                headers |= JSON_FORM
            try:
                raw = self._fetch(method, url, hosts=HOSTS, data=data, headers=headers)
            except RotateError as exc:
                if exc.code == "http_401" and attempt == 0:
                    self._jwt = None  # expired: one new token, one retry
                    continue
                raise
            return _json(raw) if raw.strip() else {}
        raise RotateError("http_401")  # not reached

    def list_keys(self) -> dict[str, VendorKey]:
        with _step("vendor_list"):
            return parse_keys(self._call("GET"))

    def create_key(self, name: str, perms: tuple[str, ...]) -> NewKey:
        with _step("vendor_create"):
            return parse_new_key(self._call("POST", {"key_name": name, "perms": ",".join(perms)}))

    def delete_key(self, key_id: str) -> None:
        with _step("vendor_delete"):
            if not KEY_ID_RE.fullmatch(key_id):
                raise RotateError("bad_key_id")
            self._call("DELETE", {"key_hash": key_id})  # [C] the id is sent as `key_hash`


@contextmanager
def _step(name: str) -> Iterator[None]:
    """Prefix a failure with the step it happened in, so a code says where, not just what."""
    try:
        yield
    except RotateError as exc:
        raise RotateError(f"{name}_{exc.code}") from None


def _json(raw: bytes) -> Any:
    try:
        return json.loads(raw)
    except (ValueError, RecursionError):
        raise RotateError("bad_json") from None
