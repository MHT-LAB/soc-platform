"""Load a tenant (client, sites, endpoints, sources) from a seed file.

    SOC_MIGRATE_URL=postgresql+psycopg://owner@host/db python -m soc_api.seed seed.json
    SOC_MIGRATE_URL=... python -m soc_api.seed --activity seed.json

With --activity the seed file's "activity" section is loaded too: three weeks of synthetic
alerts, cases, pages, acknowledgements, sensors (one offline), a posture run and deploy marks,
so the console's Ops Overview shows something real-looking. For the demo tenant only.

The synthetic demo tenant is fixtures/acme-demo/seed.json; real tenants come from
the private deploy repo. Run it as the owner role.

Safe to run again: a row that already exists with the same values is left alone.
A row that exists with different values stops the run with an error and changes
nothing, so a typo can never quietly re-point a source at another client.
"""

import json
import os
import random
import sys
import uuid
from datetime import UTC, datetime, timedelta
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


def seed_activity(url: str, seed_file: Path, now: datetime | None = None) -> None:
    """Load the demo tenant's synthetic activity (the seed file's "activity" section).

    Everything is made up and deterministic for a given seed value, laid out backwards from
    `now`. It refuses to run twice (the tenant already has alerts) and, like the rest of this
    module, does everything in one transaction. Run it as the owner role.
    """
    data: dict[str, Any] = json.loads(seed_file.read_text())
    spec = data["activity"]
    now = now or datetime.now(UTC)
    rng = random.Random(spec["seed"])  # noqa: S311 - synthetic demo data
    days = int(spec["days"])
    engine = create_engine(url)
    try:
        with engine.begin() as conn:
            client_id = _client(conn, data["client"])
            if conn.execute(
                text("SELECT count(*) FROM alert WHERE client_id = :c"), {"c": client_id}
            ).scalar_one():
                raise SeedConflict("the demo activity is already loaded in this database")
            if "source" in data:
                _source(conn, client_id, data["source"])
            for source in spec["sources"]:
                _source(conn, client_id, source)
            slugs = [data["source"]["slug"], *(s["slug"] for s in spec["sources"])]
            source_ids = {
                slug: conn.execute(
                    text("SELECT id FROM source WHERE slug = :s"), {"s": slug}
                ).scalar_one()
                for slug in slugs
            }
            _activity_cases(conn, client_id, source_ids, spec, rng, now)
            _activity_state(conn, source_ids, spec, now, days)
    finally:
        engine.dispose()


def _platform_code(spec: dict[str, Any], rule: dict[str, Any], host: str) -> int:
    """The platform code the vendor puts in an alert's routing: the adapter's for a syslog
    or vendor-feed source (spec 'alert_platforms'), else Linux for srv hosts and Windows."""
    fixed = spec.get("alert_platforms", {}).get(rule["source"])
    if isinstance(fixed, int):
        return fixed
    return 0x20000000 if host.startswith("srv") else 0x10000000


def _activity_state(
    conn: Connection, source_ids: dict[str, Any], spec: dict[str, Any], now: datetime, days: int
) -> None:
    """Sensors (one offline, one isolated), posture runs, the rule inventory, catch-up
    cursors, a backup and the deploy marks."""
    for n, host in enumerate(spec["hosts"], start=1):
        offline = host == spec["offline_host"]
        conn.execute(
            text(
                "INSERT INTO sensor_state (sid, hostname, platform, version, online, isolated, "
                "tags, last_seen, updated_at) VALUES (:sid, :host, :platform, :version, :online, "
                ":isolated, '{demo}', :seen, :updated)"
            ),
            {
                "sid": f"demo-sensor-{n + 100:04d}",
                "host": host,
                "platform": "linux" if host.startswith("srv") else "windows",
                "version": "4.33.12",
                "online": not offline,
                "isolated": host == spec["isolated_host"],
                "seen": now - (timedelta(hours=3) if offline else timedelta(seconds=40)),
                "updated": now - timedelta(seconds=50),
            },
        )
    # Syslog and vendor adapters: one that has not sent a message for days (quiet, which is
    # amber and healthy for a source that speaks rarely) and the rest reporting.
    adapters = spec.get("adapters", [])
    for n, adapter in enumerate(adapters, start=len(spec["hosts"]) + 1):
        quiet = timedelta(hours=adapter["quiet_hours"])
        conn.execute(
            text(
                "INSERT INTO sensor_state (sid, hostname, platform, version, online, isolated, "
                "tags, last_seen, updated_at) VALUES (:sid, :host, :platform, NULL, :online, "
                "false, '{demo}', :seen, :updated)"
            ),
            {
                "sid": f"demo-sensor-{n + 100:04d}",
                "host": adapter["hostname"],
                "platform": adapter["platform"],
                "online": not quiet,
                "seen": now - (quiet or timedelta(seconds=40)),
                "updated": now - timedelta(seconds=50),
            },
        )
    quiet_adapters = sum(1 for a in adapters if a["quiet_hours"])
    for i in range(12):
        at = now - timedelta(minutes=5 * i + 2)
        conn.execute(
            text(
                "INSERT INTO sensor_count (at, online, offline, isolated) "
                "VALUES (:at, :on, :off, 1)"
            ),
            {
                "at": at,
                "on": len(spec["hosts"]) + len(adapters) - 1 - quiet_adapters,
                "off": 1 + quiet_adapters,
            },
        )
        conn.execute(
            text("INSERT INTO posture_run (at, ok, org_error_count) VALUES (:at, true, 0)"),
            {"at": at},
        )
    disabled = set(spec["disabled_rules"])
    for name in [r["rule"] for r in spec["rules"]] + list(spec["inventory_only"]):
        conn.execute(
            text(
                "INSERT INTO rule_inventory (namespace, name, enabled) "
                "VALUES ('general', :n, :e) ON CONFLICT DO NOTHING"
            ),
            {"n": name, "e": name not in disabled},
        )
    caught_up = ["acme-lc", *(s["slug"] for s in spec["sources"] if s["catchup"])]
    for slug in caught_up:
        conn.execute(
            text(
                "INSERT INTO reconcile_cursor (source_id, window_end, last_success, started_at) "
                "VALUES (:s, :now, :ok, :started)"
            ),
            {
                "s": source_ids[slug],
                "now": now,
                "ok": now - timedelta(minutes=3),
                "started": now - timedelta(days=days),
            },
        )
    conn.execute(
        text("UPDATE backup_state SET last_ok_at = :at, last_bytes = 48000000"),
        {"at": now - timedelta(hours=3)},
    )
    for d in spec["deploys"]:
        conn.execute(
            text("INSERT INTO deploy_event (at, sha) VALUES (:at, :sha)"),
            {"at": now - timedelta(hours=d["hours_ago"]), "sha": d["sha"]},
        )


def _activity_cases(
    conn: Connection,
    client_id: Any,
    source_ids: dict[str, Any],
    spec: dict[str, Any],
    rng: random.Random,
    now: datetime,
) -> None:
    """Cases with their alerts, pages, acknowledgements and closes."""
    days = int(spec["days"])
    analyst = str(spec["analyst"])
    rules = spec["rules"]
    weights = [r["weight"] for r in rules]
    # busier in working hours (UTC), quieter at night
    hour_weight = [0.25] * 6 + [0.6] * 2 + [1.0] * 10 + [0.6] * 3 + [0.3] * 3

    def when() -> datetime:
        while True:
            at = now - timedelta(seconds=days * 86400 * rng.random() ** 1.5)
            if rng.random() < hour_weight[at.hour]:
                return at

    cases: list[dict[str, Any]] = []
    alerts: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    pages: list[dict[str, Any]] = []

    def event(
        case_id: uuid.UUID, at: datetime, actor: str, kind: str, body: str | None = None
    ) -> None:
        events.append(
            {"c": client_id, "case": case_id, "at": at, "actor": actor, "kind": kind, "body": body}
        )

    for n in range(int(spec["cases"])):
        rule = rng.choices(rules, weights)[0]
        host = rng.choice(spec["hosts"])
        opened = when()
        if n < 4:  # a few recent open ones for the queue
            opened = now - timedelta(minutes=rng.randint(6, 170))
        case_id = uuid.UUID(int=rng.getrandbits(128), version=4)
        age = (now - opened).total_seconds()
        lane = rule["lane"]
        status = "open"
        if age > 4 * 3600:
            status = rng.choices(["closed", "acknowledged", "open"], [0.88, 0.1, 0.02])[0]
        elif age > 1800:
            status = rng.choices(["acknowledged", "open", "closed"], [0.5, 0.4, 0.1])[0]
        if n < 4:
            status = "open" if n % 2 else "acknowledged"
        if lane == "quiet" and age > 3600:
            status = "closed"
        closed_at = None
        if status == "closed":
            closed_at = min(
                opened + timedelta(seconds=rng.randint(600, 21600)), now - timedelta(minutes=1)
            )
        note = "Reviewed with the owner; expected activity." if closed_at else None
        cases.append(
            {
                "id": case_id,
                "c": client_id,
                "sev": rule["severity"],
                "status": status,
                "lane": "vendor" if lane == "vendor" else None,
                "opened": opened,
                "closed": closed_at,
                "note": note,
            }
        )
        for j in range(rng.randint(1, 7 if lane != "paged" else 4)):
            received = opened + timedelta(minutes=j * rng.randint(1, 12))
            if received > now:
                received = now - timedelta(seconds=rng.randint(30, 120))
            alerts.append(
                {
                    "id": uuid.UUID(int=rng.getrandbits(128), version=4),
                    "c": client_id,
                    "s": source_ids[rule["source"]],
                    "ev": f"demo-{n:04d}-{j}",
                    "rule": rule["rule"],
                    "sev": rule["severity"],
                    "summary": rule["rule"].split(".", 1)[1].replace(".", " ") + " on " + host,
                    "mitre": rule["mitre"],
                    "raw": json.dumps(
                        {
                            "cat": rule["rule"],
                            "routing": {"hostname": host, "plat": _platform_code(spec, rule, host)},
                        }
                    ),
                    "case": case_id,
                    "detected": received - timedelta(seconds=rng.randint(1, 20)),
                    "received": received,
                }
            )

        event(case_id, opened, "system", "opened")
        if lane == "paged":
            created = opened + timedelta(seconds=1)
            failed = n == 20 and age > 3 * 86400
            sent = created + timedelta(seconds=9.5 if rng.random() < 0.02 else rng.uniform(1, 4.5))
            acked_at = None
            if status in ("acknowledged", "closed") and not failed:
                acked_at = sent + timedelta(seconds=rng.randint(40, 1500))
                event(case_id, acked_at, analyst, "acked")
            pages.append(
                {
                    "c": client_id,
                    "case": case_id,
                    "created": created,
                    "sent": None if failed else sent,
                    "acked": acked_at,
                    "status": "failed" if failed else "sent",
                }
            )
        if closed_at:
            event(case_id, closed_at, analyst, "closed", note)
    conn.execute(
        text(
            "INSERT INTO soc_case (id, client_id, severity, status, lane, opened_at, closed_at, "
            "closing_note) VALUES (:id, :c, :sev, :status, :lane, :opened, :closed, :note)"
        ),
        cases,
    )
    conn.execute(
        text(
            "INSERT INTO alert (id, client_id, source_id, event_id, rule, severity, summary, "
            "mitre_hint, raw, case_id, detected_at, received_at) VALUES (:id, :c, :s, :ev, "
            ":rule, :sev, :summary, :mitre, CAST(:raw AS jsonb), :case, :detected, :received)"
        ),
        alerts,
    )
    conn.execute(
        text(
            "INSERT INTO case_event (client_id, case_id, at, actor, kind, body) "
            "VALUES (:c, :case, :at, :actor, :kind, :body)"
        ),
        events,
    )
    conn.execute(
        text(
            "INSERT INTO notification (client_id, case_id, channel, kind, priority, status, "
            "attempts, created_at, next_attempt_at, sent_at, acked_at) VALUES (:c, :case, "
            "'ntfy', 'page', 5, :status, 1, :created, :created, :sent, :acked)"
        ),
        pages,
    )


def main(argv: list[str]) -> int:
    url = os.environ.get("SOC_MIGRATE_URL")
    activity = argv[:1] == ["--activity"]
    args = argv[1:] if activity else argv
    if not url or len(args) != 1:
        print("usage: SOC_MIGRATE_URL=<owner url> python -m soc_api.seed [--activity] <seed.json>")
        return 2
    try:
        seed(url, Path(args[0]))
        if activity:
            seed_activity(url, Path(args[0]))
    except SeedConflict as exc:
        print(f"seed refused, nothing changed: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
