"""One guarded HTTPS call, standard library only (the apply step runs on the host).

https only, only the named hosts, no redirects (a 3xx is an error, never followed), a timeout
and a size cap. A failure is a short lowercase code, never the response, the URL or a header,
because any of those can carry a credential.
"""

import http.client
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping

MAX_BODY = 1024 * 1024
Fetch = Callable[..., bytes]


class RotateError(Exception):
    """A failure with a short code that is safe to print and log."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


_OPENER = urllib.request.OpenerDirector()
for _handler in (
    urllib.request.HTTPHandler(),
    urllib.request.HTTPSHandler(),
    urllib.request.HTTPDefaultErrorHandler(),
    urllib.request.HTTPErrorProcessor(),
    urllib.request.UnknownHandler(),
):
    _OPENER.add_handler(_handler)  # no redirect handler: a 3xx is an error, never followed


def _http_code(status: int) -> str:
    if 300 <= status < 400:
        return "redirect"
    if status in (400, 401, 403, 404, 408, 409, 429):
        return f"http_{status}"
    return "http_4xx" if 400 <= status < 500 else "http_5xx"


def fetch(
    method: str,
    url: str,
    *,
    hosts: frozenset[str],
    data: bytes | None = None,
    headers: Mapping[str, str] | None = None,
    timeout: float = 20.0,
    max_bytes: int = MAX_BODY,
) -> bytes:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in hosts or parts.username or parts.port:
        raise RotateError("bad_url")
    request = urllib.request.Request(  # noqa: S310 - scheme and host are checked above
        url, data=data, headers=dict(headers or {}), method=method
    )
    try:
        with _OPENER.open(request, timeout=timeout) as resp:
            raw: bytes = resp.read(max_bytes + 1)
    except urllib.error.HTTPError as exc:
        exc.close()  # the error is also an open response; release its socket
        raise RotateError(_http_code(exc.code)) from None
    except urllib.error.URLError as exc:
        raise RotateError(
            "timeout" if isinstance(exc.reason, TimeoutError) else "network"
        ) from None
    except TimeoutError:
        raise RotateError("timeout") from None
    except (OSError, http.client.HTTPException):
        raise RotateError("network") from None
    if len(raw) > max_bytes:
        raise RotateError("too_large")
    return raw
