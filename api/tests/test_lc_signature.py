"""Pin the LimaCharlie webhook signature recipe, as captured from a real delivery.

Observed (spike S0): the `lc-signature` header is the lowercase hex HMAC-SHA256 of the raw
request body bytes, keyed with the output's `secret_key` string (UTF-8). There is no timestamp
header; `gen_time` (ms) sits inside the signed body. These tests fail if the recipe is
implemented with the wrong encoding, hash, key handling or signed bytes.
"""

import base64
import hashlib
import hmac
import json
from pathlib import Path

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "lc-webhook" / "detect.json"
SECRET = "test-secret-not-real"  # noqa: S105
# Computed once with the recipe above over the committed fixture; do not regenerate casually.
EXPECTED = "589559a5923e457a75d7d4b8715f15f3b4194ce44f9a4923202eae79c745d989"


def sign(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_known_answer_over_raw_bytes() -> None:
    assert sign(SECRET, FIXTURE.read_bytes()) == EXPECTED


def test_signature_is_lowercase_hex_not_base64() -> None:
    body = FIXTURE.read_bytes()
    digest = hmac.new(SECRET.encode(), body, hashlib.sha256).digest()
    assert EXPECTED != base64.b64encode(digest).decode()
    assert len(EXPECTED) == 64
    assert EXPECTED == EXPECTED.lower()


def test_signed_bytes_are_the_raw_body_not_a_reserialization() -> None:
    body = FIXTURE.read_bytes()
    pretty = json.dumps(json.loads(body), indent=2).encode()
    spaced = json.dumps(json.loads(body), sort_keys=True).encode()
    assert sign(SECRET, pretty) != EXPECTED
    assert sign(SECRET, spaced) != EXPECTED
    assert sign(SECRET, body + b"\n") != EXPECTED


def test_other_hash_or_secret_does_not_match() -> None:
    body = FIXTURE.read_bytes()
    assert hmac.new(SECRET.encode(), body, hashlib.sha1).hexdigest() != EXPECTED  # noqa: S324
    assert sign("another-secret", body) != EXPECTED
    assert sign(SECRET, body[:-1]) != EXPECTED


def test_fixture_shape_matches_a_real_delivery() -> None:
    body = FIXTURE.read_bytes()
    doc = json.loads(body)
    assert isinstance(doc, dict), "one detection per request, not a list"
    assert {"detect_id", "gen_time", "source", "source_rule", "routing", "detect"} <= doc.keys()
    assert body == json.dumps(doc, separators=(",", ":"), sort_keys=True).encode()
    assert not body.endswith(b"\n")
