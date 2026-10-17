.PHONY: setup test lint scrub up down

setup:            ## install dev dependencies and git hooks
	cd api && uv sync
	pre-commit install

test:             ## unit tests
	cd api && uv run pytest -q -W error

lint:             ## ruff, formatting, strict types, Dockerfile lint
	cd api && uv run ruff check . && uv run ruff format --check . && uv run mypy
	hadolint api/Dockerfile

scrub:            ## block private identifiers
	scripts/scrub-check.sh

up:               ## run the stack locally (needs Docker)
	docker compose -f deploy/compose.yml up -d --build

down:
	docker compose -f deploy/compose.yml down
