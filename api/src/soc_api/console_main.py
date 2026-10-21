"""Console entry point: `uvicorn soc_api.console_main:app` (host loopback only)."""

from soc_api.main import create_console_app

app = create_console_app()
