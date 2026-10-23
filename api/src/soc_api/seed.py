"""Seed the synthetic demo tenant (acme-demo) from fixtures/acme-demo/seed.json."""

import json
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, text


def seed_demo(url: str, seed_file: Path) -> None:
    """Insert the demo client, site, endpoints and source. Run as the owner role."""
    seed: dict[str, Any] = json.loads(seed_file.read_text())
    engine = create_engine(url)
    with engine.begin() as conn:
        client_id = conn.execute(
            text(
                "INSERT INTO client (slug, name, tenant_id, status, timezone) "
                "VALUES (:slug, :name, :tenant_id, :status, :timezone) RETURNING id"
            ),
            seed["client"],
        ).scalar_one()
        sites: dict[str, Any] = {}
        for site in seed["sites"]:
            sites[site["name"]] = conn.execute(
                text(
                    "INSERT INTO site (client_id, name, controller_site_id) "
                    "VALUES (:client_id, :name, :controller_site_id) RETURNING id"
                ),
                {**site, "client_id": client_id},
            ).scalar_one()
        for endpoint in seed["endpoints"]:
            conn.execute(
                text(
                    "INSERT INTO endpoint (client_id, site_id, sensor_id, hostname, platform) "
                    "VALUES (:client_id, :site_id, :sensor_id, :hostname, :platform)"
                ),
                {
                    "client_id": client_id,
                    "site_id": sites[endpoint["site"]],
                    "sensor_id": endpoint["sensor_id"],
                    "hostname": endpoint["hostname"],
                    "platform": endpoint["platform"],
                },
            )
        conn.execute(
            text(
                "INSERT INTO source (client_id, slug, type, external_id) "
                "VALUES (:client_id, :slug, :type, :external_id)"
            ),
            {**seed["source"], "client_id": client_id},
        )
    engine.dispose()
