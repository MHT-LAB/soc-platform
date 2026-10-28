"""The ingest outcome lines must reach the process's stderr (and so `docker logs`).

The in-process caplog tests in test_ingest.py cannot see this: pytest attaches its own
handler to the root logger, which hides that nothing in the real app configures logging.
These tests run the real entry point module in a child process.
"""

import json
import logging
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from soc_api.logs import configure_logging

SRC = Path(__file__).resolve().parents[1] / "src"
SECRET = "child-process-secret-0123"  # noqa: S105 - throwaway
CHILD = """
from fastapi.testclient import TestClient
from soc_api.main import app  # the module the Dockerfile runs: soc_api.main:app
c = TestClient(app)
h = {"content-type": "application/json"}
c.post("/ingest/lc-main", content=b"{}", headers={**h, "lc-signature": "f" * 64})
c.post("/ingest/lc-zzzz", content=b"{}", headers=h)
"""


def child_env() -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": str(SRC),
        "SOC_ENV": "dev",
        "SOC_INGEST_SECRETS": json.dumps({"lc-main": [SECRET]}),
    }


def run_child() -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed arguments, no shell
        [sys.executable, "-c", CHILD], env=child_env(), capture_output=True, text=True, timeout=60
    )


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def call(url: str, data: bytes | None = None) -> int:
    headers = {"content-type": "application/json", "lc-signature": "f" * 64} if data else {}
    req = urllib.request.Request(url, data=data, headers=headers)  # noqa: S310 - local http only
    try:
        with urllib.request.urlopen(req, timeout=2) as r:  # noqa: S310
            return int(r.status)
    except urllib.error.HTTPError as e:
        return e.code


def test_real_entrypoint_writes_ingest_outcomes_to_stderr() -> None:
    r = run_child()
    assert r.returncode == 0, r.stderr
    lines = [ln for ln in r.stderr.splitlines() if "ingest outcome=" in ln]
    assert len(lines) == 2, r.stderr
    assert "outcome=bad_signature status=401 source=lc-main" in lines[0]
    assert "outcome=not_found status=404 source=-" in lines[1]
    # a UTC timestamp first, so retry timing can be read off the log
    assert lines[0][:4].isdigit() and "Z INFO soc_api.ingest " in lines[0]
    assert SECRET not in r.stderr


def test_configure_logging_is_idempotent() -> None:
    logger = logging.getLogger("soc_api")
    configure_logging()
    configure_logging()
    marked = [h for h in logger.handlers if getattr(h, "_soc_api_handler", False)]
    assert len(marked) == 1
    assert logger.level == logging.INFO


def test_uvicorn_as_in_the_dockerfile_keeps_the_outcome_lines() -> None:
    """uvicorn configures logging before it imports the app; the lines must survive that."""
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    cmd = [sys.executable, "-m", "uvicorn", "soc_api.main:app", "--host", "127.0.0.1"]
    cmd += ["--port", str(port), "--proxy-headers", "--no-server-header", "--no-access-log"]
    proc = subprocess.Popen(  # noqa: S603 - fixed arguments, no shell
        cmd, env=child_env(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    try:
        deadline = time.monotonic() + 30
        while True:
            try:
                if call(f"{base}/healthz") == 200:
                    break
            except OSError:
                pass
            assert time.monotonic() < deadline and proc.poll() is None, "uvicorn did not start"
            time.sleep(0.2)
        assert call(f"{base}/ingest/lc-main", b"{}") == 401
    finally:
        proc.terminate()
        out, err = proc.communicate(timeout=15)
    lines = [ln for ln in (out + err).splitlines() if "ingest outcome=" in ln]
    assert len(lines) == 1, out + err
    assert "outcome=bad_signature status=401 source=lc-main" in lines[0]
    assert SECRET not in out + err
