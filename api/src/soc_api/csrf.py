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


def same_origin(headers: Mapping[str, str], scheme: str, expected: str | None = None) -> bool:
    """Sec-Fetch-Site says same-origin and Origin is this console's own origin.

    `expected` is the console's configured address (SOC_CONSOLE_BASE_URL), and when it is
    set nothing else counts: what Host a proxy forwards is then irrelevant. Without it,
    the origin is scheme://Host; `scheme` is https in production (the only way in is
    `tailscale serve`, which terminates TLS)."""
    if headers.get("sec-fetch-site") != "same-origin":
        return False
    if expected:
        return headers.get("origin") == expected
    host = headers.get("host", "")
    return bool(host) and headers.get("origin") == f"{scheme}://{host}"


# ---- the Acknowledge button on a phone notification ----
#
# The ntfy app is not a browser: its request has no Origin and no Sec-Fetch-Site, so the
# form checks cannot apply. What it carries instead is a link the worker made: an HMAC over
# the case and an expiry, with a key (SOC_ACK_KEY) that is not the form secret and a
# different signing context, so neither kind of token can ever pass as the other. The link
# crosses the push server, so it is good for one case, one action and 24 hours, and the
# request still has to arrive over the tailnet from an allowed person.

PHONE_LIFETIME = 24 * 3600
PHONE_SLACK = 3600  # an expiry further out than lifetime + slack is not one we issued


def make_phone_token(key: str, case_id: str, expires: int) -> str:
    if not key:
        raise ValueError("cannot make a phone token")
    message = "\n".join(("phone-ack-v1", case_id.lower(), str(int(expires))))
    return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()


def phone_expiry(now: datetime | None = None) -> int:
    return int((now or datetime.now(UTC)).timestamp()) + PHONE_LIFETIME


def check_phone_token(
    key: str, token: str, case_id: str, expires: int, now: datetime | None = None
) -> bool:
    if not key or len(token) != 64:
        return False
    current = int((now or datetime.now(UTC)).timestamp())
    in_window = current <= expires <= current + PHONE_LIFETIME + PHONE_SLACK
    # The MAC is always computed, so the time taken does not say whether the expiry was right.
    mac_ok = hmac.compare_digest(token, make_phone_token(key, case_id, expires))
    return in_window and mac_ok
