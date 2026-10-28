"""Process logging for the public and console apps.

Nothing else configures Python logging, and the root logger only passes WARNING, so
without this the `ingest outcome=...` lines in ingest.py never reach `docker logs`.
Only the `soc_api` loggers are set up here (INFO, stderr, UTC timestamps so retry
timing can be read off the log); the uvicorn access log stays off (Dockerfile).
"""

import logging
import sys
import time

_MARK = "_soc_api_handler"


def configure_logging(level: int = logging.INFO) -> None:
    """Idempotent: a second call neither adds a second handler nor changes the first."""
    logger = logging.getLogger("soc_api")
    logger.setLevel(level)
    if any(getattr(h, _MARK, False) for h in logger.handlers):
        return
    handler = logging.StreamHandler(sys.stderr)
    formatter = logging.Formatter("%(asctime)sZ %(levelname)s %(name)s %(message)s")
    formatter.converter = time.gmtime
    handler.setFormatter(formatter)
    setattr(handler, _MARK, True)
    logger.addHandler(handler)
