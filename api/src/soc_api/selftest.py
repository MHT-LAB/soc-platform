"""Send one synthetic, signed detection to the ingest route and report the result.

Run it inside the api container, which already holds the webhook secret, so no
secret is ever typed or copied:

    docker compose ... exec -T api python -m soc_api.selftest [--repeat] [--url URL]

It signs a made-up detection (rule `soc-selftest`, a fresh `gen_time`, an
organisation id that matches no real source, so the alert lands in Unassigned and
is easy to tell from client alerts) and posts it to the local app, or to the
public address with `--url https://<host>`. Only the HTTP status and the detection
id are printed: never the secret, the signature or the body. `--repeat` sends the
identical body twice to show that a repeat is accepted and stored once.

Exit status is 0 when every delivery was accepted (200), 1 otherwise.
"""

import argparse
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from urllib.parse import urlsplit

from soc_api.ingest import SIGNATURE_HEADER, parse_secrets

LOCAL_URL = "http://127.0.0.1:8080"
# An organisation id no source is bound to.
SELFTEST_OID = "00000000-0000-4000-8000-000000000000"
SELFTEST_RULE = "soc-selftest"
TIMEOUT_SECONDS = 10

# Only plain HTTP(S): no file:// or ftp:// handler, no redirects, no proxy from the
# environment. A URL of any other kind cannot be opened even if a caller skips the
# scheme check in main().
_OPENER = urllib.request.OpenerDirector()
for _handler in (
    urllib.request.HTTPHandler(),
    urllib.request.HTTPSHandler(),
    urllib.request.HTTPDefaultErrorHandler(),
    urllib.request.HTTPErrorProcessor(),
    urllib.request.UnknownHandler(),  # any other scheme raises instead of returning None
):
    _OPENER.add_handler(_handler)


def build_body(detect_id: str, now_ms: int) -> bytes:
    """Compact JSON with sorted keys, the same shape LimaCharlie sends."""
    doc = {
        "author": "soc-selftest",
        "cat": SELFTEST_RULE,
        "detect_id": detect_id,
        "detect_mtd": {"description": "SOC ingest self-test"},
        "gen_time": now_ms,
        "priority": 1,
        "routing": {"oid": SELFTEST_OID},
        "source_rule": SELFTEST_RULE,
    }
    return json.dumps(doc, separators=(",", ":"), sort_keys=True).encode()


def sign(secret: bytes, body: bytes) -> str:
    return hmac.new(secret, body, hashlib.sha256).hexdigest()


def post(url: str, body: bytes, signature: str) -> str:
    """Return the HTTP status as text, or a short failure word. Nothing else leaks."""
    request = urllib.request.Request(  # noqa: S310 - the opener only speaks HTTP(S)
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", SIGNATURE_HEADER: signature},
    )
    try:
        with _OPENER.open(request, timeout=TIMEOUT_SECONDS) as response:
            return str(response.status)
    except urllib.error.HTTPError as exc:
        return str(exc.code)
    except OSError:
        return "unreachable"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="python -m soc_api.selftest")
    parser.add_argument("--url", default=LOCAL_URL, help="base URL (default: the local app)")
    parser.add_argument("--source", help="source name (default: the first configured)")
    parser.add_argument("--repeat", action="store_true", help="send the same body twice")
    args = parser.parse_args(argv)

    base = urlsplit(args.url)
    if base.scheme not in ("http", "https") or not base.netloc:
        print("--url must be http(s)://host[:port]")
        return 2

    try:
        secrets = parse_secrets(os.environ.get("SOC_INGEST_SECRETS", ""))
    except ValueError as exc:
        print(exc)
        return 2
    if not secrets:
        print("SOC_INGEST_SECRETS is not set here; run this inside the api container")
        return 2
    source = args.source or next(iter(secrets))
    if source not in secrets:
        print("that source is not configured")
        return 2

    detect_id = f"selftest-{uuid.uuid4()}"
    body = build_body(detect_id, int(time.time() * 1000))
    signature = sign(secrets[source][0], body)
    url = f"{base.scheme}://{base.netloc}/ingest/{source}"

    ok = True
    for _ in range(2 if args.repeat else 1):
        status = post(url, body, signature)
        print(f"status={status} detect_id={detect_id}")
        ok = ok and status == "200"
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
