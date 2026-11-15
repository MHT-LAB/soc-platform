"""Where alerts come from: ops_overview() also counts alerts by kind of origin.

Revision ID: 0016
Revises: 0015

The signal flow draws one curve per fleet group (endpoints, network sensors, vendor feeds)
into "alerts in", sized by that group's share of the period's alerts. ops_overview() now
returns that count as a new top-level key:

  origins: {endpoint, network, feed, unknown}

Each alert is classified from the platform code the vendor wrote in its own routing
(raw -> routing -> plat), with the same table the posture collector uses for sensors
(status.PLATFORMS and signalflow.kind_of): Windows, Linux, macOS, iOS, Android and ChromeOS
are endpoints; VPN and the syslog adapters are network sensors; every other adapter (JSON,
email, any code not in the table) is a vendor feed; an alert with no usable platform code
is unknown. The Python twin is signalflow.origin_kind(); a test makes the two agree for
every code. Neither a source slug nor a sensor id is read or returned.

The function is rewritten from its stored definition (CREATE OR REPLACE keeps owner,
search_path and grants) with one line added, and the migration refuses to run if the line
it changes is not there exactly once. Downgrade removes that line again, which gives the
0012 definition back exactly.
"""

from alembic import op
from sqlalchemy import text

revision = "0016"
down_revision = "0015"

ANCHOR = "'totals', v_totals,"
ADDED = """'totals', v_totals,
        'origins', (SELECT jsonb_build_object(
            'endpoint', count(*) FILTER (WHERE k = 'endpoint'),
            'network', count(*) FILTER (WHERE k = 'network'),
            'feed', count(*) FILTER (WHERE k = 'feed'),
            'unknown', count(*) FILTER (WHERE k = 'unknown'))
          FROM (SELECT CASE
                  WHEN coalesce(a.raw #>> '{routing,plat}', '') !~ '^[0-9]{1,10}$'
                      THEN 'unknown'
                  WHEN (a.raw #>> '{routing,plat}')::bigint IN
                      (268435456, 536870912, 805306368, 1073741824, 1342177280, 1610612736)
                      THEN 'endpoint'
                  WHEN (a.raw #>> '{routing,plat}')::bigint IN
                      (1879048192, 2147483648, 167772160)
                      THEN 'network'
                  ELSE 'feed' END AS k
                FROM alert a
                WHERE a.received_at >= since AND (cid IS NULL OR a.client_id = cid)) o),"""


def _swap(old: str, new: str) -> None:
    conn = op.get_bind()
    definition = conn.execute(
        text("SELECT pg_get_functiondef('ops_overview(integer, text)'::regprocedure)")
    ).scalar_one()
    if definition.count(old) != 1:
        raise RuntimeError("ops_overview() is not the definition this migration expects")
    conn.execute(text("GRANT soc_console_writer TO current_user"))
    conn.exec_driver_sql(definition.replace(old, new))


def upgrade() -> None:
    _swap(ANCHOR, ADDED)


def downgrade() -> None:
    _swap(ADDED, ANCHOR)
