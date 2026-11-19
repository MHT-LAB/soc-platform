"""The secrets manager: log in as the rotator's machine identity, read and write one value.

`[C]` marks the REST paths and reply shapes that are not confirmed against a live call; the
parsers refuse anything unexpected. `rotate.sh --preflight` makes the login and a read so they
can be checked before a first rotation writes anything. The identity is a member of one
project only, so a value outside it cannot be reached however the call is made.
"""

import json
import re
import urllib.parse
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

from soc_api.rotate import net
from soc_api.rotate.net import RotateError
from soc_api.rotate.rights import Rights, Secret

# The service address comes with the rights (SECRETS_URL), not from this file: a host name
# only, https only, and it is the only host these calls may reach.
URL_RE = re.compile(r"https://[a-z0-9][a-z0-9.-]{1,251}[a-z0-9]")
TOKEN_RE = re.compile(r"[A-Za-z0-9._-]{20,4096}")
NAME_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
PATH_RE = re.compile(r"/[A-Za-z0-9/_-]{0,200}")
MAX_VALUE = 4096
JSON_HEADERS = {"Content-Type": "application/json", "Accept": "application/json"}


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


class SecretsManager:
    def __init__(self, rights: Rights, *, fetch: Callable[..., bytes] = net.fetch) -> None:
        if not URL_RE.fullmatch(rights.secrets_url):
            raise RotateError("bad_url")
        self._rights = rights
        self._base = rights.secrets_url
        self._hosts = frozenset({urllib.parse.urlsplit(rights.secrets_url).hostname or ""})
        self._fetch = fetch
        self._token: str | None = None

    def _login(self) -> str:
        body = json.dumps(
            {
                "clientId": self._rights.client_id.reveal(),
                "clientSecret": self._rights.client_secret.reveal(),
            }
        ).encode()
        try:  # [C] the login path
            raw = self._fetch(
                "POST",
                f"{self._base}/api/v1/auth/universal-auth/login",
                hosts=self._hosts,
                data=body,
                headers=JSON_HEADERS,
            )
        except RotateError as exc:
            raise RotateError(f"login_{exc.code}") from None
        doc = _json(raw)
        token = doc.get("accessToken") if isinstance(doc, dict) else None
        if not (isinstance(token, str) and TOKEN_RE.fullmatch(token)):
            raise RotateError("login_bad_shape")
        return token

    def _call(self, method: str, url: str, body: dict[str, str] | None = None) -> Any:
        data = json.dumps(body).encode() if body is not None else None
        for attempt in (0, 1):
            if self._token is None:
                self._token = self._login()
            headers = {**JSON_HEADERS, "Authorization": f"Bearer {self._token}"}
            try:
                raw = self._fetch(method, url, hosts=self._hosts, data=data, headers=headers)
            except RotateError as exc:
                if exc.code == "http_401" and attempt == 0:
                    self._token = None
                    continue
                raise
            return _json(raw) if raw.strip() else {}
        raise RotateError("http_401")  # not reached

    def _scope(self, path: str) -> dict[str, str]:
        if not PATH_RE.fullmatch(path):
            raise RotateError("bad_path")
        return {
            "workspaceId": self._rights.project_id,
            "environment": self._rights.environment,
            "secretPath": path,
        }

    def get(self, path: str, name: str) -> Secret:
        with _step("secrets_read"):
            if not NAME_RE.fullmatch(name):
                raise RotateError("bad_name")
            query = urllib.parse.urlencode(self._scope(path))
            doc = self._call("GET", f"{self._base}/api/v3/secrets/raw/{name}?{query}")  # [C]
            inner = doc.get("secret") if isinstance(doc, dict) else None
            value = inner.get("secretValue") if isinstance(inner, dict) else None
            if not (isinstance(value, str) and 0 < len(value) <= MAX_VALUE):
                raise RotateError("bad_shape")
            return Secret(value)

    def set(self, path: str, name: str, value: Secret) -> None:
        with _step("secrets_write"):
            if not NAME_RE.fullmatch(name):
                raise RotateError("bad_name")
            body = {**self._scope(path), "secretValue": value.reveal()}
            self._call("PATCH", f"{self._base}/api/v3/secrets/raw/{name}", body)  # [C]
