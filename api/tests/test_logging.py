"""The ingest outcome lines must reach the process's stderr (and so `docker logs`).

The in-process caplog tests in test_ingest.py cannot see this: pytest attaches its own
handler to the root logger, which hides that nothing in the real app configures logging.
These tests run the real entry point module in a child process.
"""

import json
import logging
import os
import subprocess
import sys
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


def run_child() -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": str(SRC),
        "SOC_ENV": "dev",
        "SOC_INGEST_SECRETS": json.dumps({"lc-main": [SECRET]}),
    }
    return subprocess.run(  # noqa: S603 - fixed arguments, no shell
        [sys.executable, "-c", CHILD], env=env, capture_output=True, text=True, timeout=60
    )


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
