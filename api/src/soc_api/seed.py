"""Load a tenant (client, sites, endpoints, sources) from a seed file.

    SOC_MIGRATE_URL=postgresql+psycopg://owner@host/db python -m soc_api.seed seed.json

The synthetic demo tenant is fixtures/acme-demo/seed.json; real tenants come from
the private deploy repo. Run it as the owner role.

Safe to run again: a row that already exists with the same values is left alone.
A row that exists with different values stops the run with an error and changes
nothing, so a typo can never quietly re-point a source at another client.
"""

import json
import os
import sys
from pathlib import Path
from typing import Any

from sqlalchemy import Connection, create_engine, text


class SeedConflict(Exception):
    """A seed row clashes with a different row already in the database."""


def _same(what: str, key: str, existing: Any, wanted: dict[str, Any]) -> None:
    """Raise unless every wanted column already holds the wanted value."""
    differing = sorted(col for col, value in wanted.items() if existing[col] != value)
    if differing:
        raise SeedConflict(f"{what} {key!r} exists with different {', '.join(differing)}")


def _client(conn: Connection, client: dict[str, Any]) -> Any:
    wanted = {
        "name": client["name"],
        "tenant_id": client.get("tenant_id"),
        "status": client.get("status", "pilot"),
        "timezone": client.get("timezone", "America/New_York"),
    }
    row = (
        conn.execute(
            text("SELECT id, name, tenant_id, status, timezone FROM client WHERE slug = :slug"),
            {"slug": client["slug"]},
        )
        .mappings()
        .first()
    )
    if row is None:
        return conn.execute(
            text(
                "INSERT INTO client (slug, name, tenant_id, status, timezone) "
                "VALUES (:slug, :name, :tenant_id, :status, :timezone) RETURNING id"
            ),
            {"slug": client["slug"], **wanted},
        ).scalar_one()
    _same("client", client["slug"], row, wanted)
    return row["id"]


def _site(conn: Connection, client_id: Any, site: dict[str, Any]) -> Any:
    wanted = {"controller_site_id": site.get("controller_site_id")}
    row = (
        conn.execute(
            text("SELECT id, controller_site_id FROM site WHERE client_id = :c AND name = :name"),
            {"c": client_id, "name": site["name"]},
        )
        .mappings()
        .first()
    )
    if row is None:
        return conn.execute(
            text(
                "INSERT INTO site (client_id, name, controller_site_id) "
                "VALUES (:c, :name, :controller_site_id) RETURNING id"
            ),
            {"c": client_id, "name": site["name"], **wanted},
        ).scalar_one()
    _same("site", site["name"], row, wanted)
    return row["id"]


def _endpoint(conn: Connection, client_id: Any, site_id: Any, endpoint: dict[str, Any]) -> None:
    wanted = {
        "client_id": client_id,
        "site_id": site_id,
        "hostname": endpoint.get("hostname"),
        "platform": endpoint.get("platform"),
    }
    row = (
        conn.execute(
            text(
                "SELECT client_id, site_id, hostname, platform FROM endpoint WHERE sensor_id = :s"
            ),
            {"s": endpoint["sensor_id"]},
        )
        .mappings()
        .first()
    )
    if row is None:
        conn.execute(
            text(
                "INSERT INTO endpoint (client_id, site_id, sensor_id, hostname, platform) "
                "VALUES (:client_id, :site_id, :sensor_id, :hostname, :platform)"
            ),
            {**wanted, "sensor_id": endpoint["sensor_id"]},
        )
        return
    _same("endpoint", endpoint["sensor_id"], row, wanted)


def _source(conn: Connection, client_id: Any, source: dict[str, Any]) -> None:
    wanted = {
        "client_id": client_id,
        "type": source["type"],
        "external_id": source.get("external_id"),
    }
    row = (
        conn.execute(
            text("SELECT client_id, type, external_id FROM source WHERE slug = :slug"),
            {"slug": source["slug"]},
        )
        .mappings()
        .first()
    )
    if row is None:
        conn.execute(
            text(
                "INSERT INTO source (client_id, slug, type, external_id) "
                "VALUES (:client_id, :slug, :type, :external_id)"
            ),
            {**wanted, "slug": source["slug"]},
        )
        return
    _same("source", source["slug"], row, wanted)


def seed(url: str, seed_file: Path) -> None:
    """Insert the tenant in `seed_file`, all or nothing."""
    data: dict[str, Any] = json.loads(seed_file.read_text())
    engine = create_engine(url)
    try:
        with engine.begin() as conn:
            client_id = _client(conn, data["client"])
            sites = {s["name"]: _site(conn, client_id, s) for s in data.get("sites", [])}
            for endpoint in data.get("endpoints", []):
                site_name = endpoint.get("site")
                if site_name is not None and site_name not in sites:
                    raise SeedConflict(
                        f"endpoint {endpoint['sensor_id']!r} names an unknown site {site_name!r}"
                    )
                _endpoint(conn, client_id, sites.get(site_name), endpoint)
            sources = list(data.get("sources", []))
            if "source" in data:
                sources.append(data["source"])
            for source in sources:
                _source(conn, client_id, source)
    finally:
        engine.dispose()


def seed_demo(url: str, seed_file: Path) -> None:
    """The synthetic demo tenant (kept for the tests and the demo runbook)."""
    seed(url, seed_file)


def main(argv: list[str]) -> int:
    url = os.environ.get("SOC_MIGRATE_URL")
    if not url or len(argv) != 1:
        print("usage: SOC_MIGRATE_URL=<owner url> python -m soc_api.seed <seed.json>")
        return 2
    try:
        seed(url, Path(argv[0]))
    except SeedConflict as exc:
        print(f"seed refused, nothing changed: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
