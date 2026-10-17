from fastapi.testclient import TestClient

from soc_api.config import Settings
from soc_api.main import SECURITY_HEADERS, create_app


def client(env: str = "prod") -> TestClient:
    return TestClient(create_app(Settings(env=env, version="1.2.3", git_sha="abc1234")))


def test_healthz_ok() -> None:
    r = client().get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_version_reports_build() -> None:
    r = client().get("/version")
    assert r.json() == {"version": "1.2.3", "git_sha": "abc1234"}


def test_security_headers_on_every_response() -> None:
    for path in ("/healthz", "/version", "/does-not-exist"):
        r = client().get(path)
        for name, value in SECURITY_HEADERS.items():
            assert r.headers[name] == value, f"{name} missing on {path}"


def test_docs_hidden_in_prod() -> None:
    c = client("prod")
    assert c.get("/docs").status_code == 404
    assert c.get("/openapi.json").status_code == 404


def test_docs_available_in_dev() -> None:
    assert client("dev").get("/openapi.json").status_code == 200
