# soc-api

FastAPI service for ingest, cases and the console API.

```bash
uv sync                      # create the virtualenv from uv.lock
uv run pytest                # tests
uv run ruff check . && uv run ruff format --check . && uv run mypy
SOC_ENV=dev uv run uvicorn soc_api.main:app --reload --port 8080
```
