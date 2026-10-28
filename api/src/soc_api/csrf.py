"""Protection for the console's state-changing forms (Ack, Close).

The console has no sessions or cookies: who you are is a header that `tailscale serve`
adds to every request from your device. That is exactly what a malicious page can ride
on: your browser sends it along with a form post the page made it send. So every POST
must pass three independent checks, and any one failing writes nothing:

1. Sec-Fetch-Site is `same-origin` (the browser says the request came from this site);
2. Origin is exactly this console's own origin;
3. a form token that only this page could have been given: an HMAC over your login, the
   case, the action and the UTC day, made with a secret the page's visitors never see.
   It is accepted today and yesterday, so a form opened just before midnight still works.
"""

import hashlib
import hmac
from collections.abc import Mapping
from datetime import UTC, date, datetime, timedelta

ACTIONS = ("ack", "close")


def _mac(secret: str, login: str, case_id: str, action: str, day: date) -> str:
    message = "\n".join(("console-form", login.lower(), case_id.lower(), action, day.isoformat()))
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()


def make_token(
    secret: str, login: str, case_id: str, action: str, now: datetime | None = None
) -> str:
    if action not in ACTIONS or not secret:
        raise ValueError("cannot make a form token")
    return _mac(secret, login, case_id, action, (now or datetime.now(UTC)).date())


def check_token(
    secret: str, token: str, login: str, case_id: str, action: str, now: datetime | None = None
) -> bool:
    if action not in ACTIONS or not secret or not token or len(token) != 64:
        return False
    today = (now or datetime.now(UTC)).date()
    # Both days are always computed, so the time taken does not depend on which matched.
    ok_today = hmac.compare_digest(token, _mac(secret, login, case_id, action, today))
    ok_yesterday = hmac.compare_digest(
        token, _mac(secret, login, case_id, action, today - timedelta(days=1))
    )
    return ok_today or ok_yesterday


def same_origin(headers: Mapping[str, str], scheme: str) -> bool:
    """Sec-Fetch-Site says same-origin and Origin equals scheme://Host. `scheme` is https
    in production (the only way in is `tailscale serve`, which terminates TLS)."""
    host = headers.get("host", "")
    if not host or headers.get("sec-fetch-site") != "same-origin":
        return False
    return headers.get("origin") == f"{scheme}://{host}"
