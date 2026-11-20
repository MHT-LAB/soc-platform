"""The posture collector: what the detection source says about our own setup.

    python -m soc_api.posture            run (the compose `posture` service)
    python -m soc_api.posture once       one pass, print the result line, exit
    python -m soc_api.posture check      read-only look at the vendor API (counts only)

Every few minutes it reads, with a read-only key (`soc-posture`), three things:

* the sensor fleet: id, host name, platform, version, online, isolated, tags, last seen
  (GET sensors/{oid}, once for everyone and once with the online filter, as the status page
  does);
* the detection-and-response rule inventory: namespace, name and enabled, for the general,
  managed and service namespaces (the `dr-*` hives). The reply carries the rule bodies; they
  are parsed and dropped on the spot, never stored, logged or returned;
* with the stamp key (optional), whether each general rule is still what the deploy wrote:
  the stamp is recomputed from the body just read, compared, and the body is dropped (see
  `Drift`);
* the organization's errors (GET errors/{oid}): how many, and the newest one's component name.
  The messages are never read into anything that is kept.

and hands one document to the database (`posture_record`), which validates it and replaces the
current state in one transaction. Any failure (a refused key, a shape we do not know, a list
that is too long, a timeout) records a short code (`posture_fail`) and writes nothing else, so
the stored state is always one whole, consistent snapshot, and the pager's STALE check notices
a collector that stops succeeding.

Usage and quota are NOT read: the key has no billing permission and the endpoint was not
confirmed to answer to a read-only key. Output (destination) listings are NEVER requested:
they return secrets.

Same rules as the catch-up worker: https only, no redirects, timeouts, size caps, responses
are data (parsed JSON, never executed), the key is never logged, every failure is a short
code, and one structured log line per run with counts only (no host names).

The database role (soc_posture) can call posture_record() and posture_fail() and nothing else.
"""

import argparse
import json
import logging
import re
import signal
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psycopg

from soc_api.config import Settings, get_settings
from soc_api.logs import configure_logging
from soc_api.reconcile import OID_RE, LcClient, LcError, _service_url
from soc_api.rules.stamp import (
    MANIFEST_ABSENT,
    MANIFEST_BAD,
    MANIFEST_NAME,
    MANIFEST_NONE,
    MIN_KEY_CHARS,
    RULE_CHANGED,
    RULE_OK,
    check_manifest,
    classify_rule,
)
from soc_api.status import platform_name
from soc_api.worker import Db

log = logging.getLogger("soc_api.posture")

SID_RE = re.compile(r"[A-Za-z0-9-]{8,64}")
NAMESPACE_RE = re.compile(r"[a-z0-9-]{1,32}")
COMPONENT_RE = re.compile(r"[A-Za-z0-9_.:-]{1,40}")
TAG_RE = re.compile(r"[^\x00-\x1f\x7f]{1,64}")
# The detection-and-response rule hives, by the namespace name the inventory shows.
RULE_HIVES = {"general": "dr-general", "managed": "dr-managed", "service": "dr-service"}


@dataclass(frozen=True)
class Limits:
    max_pages: int = 50
    max_sensors: int = 5000
    max_rules: int = 5000  # per namespace
    max_errors: int = 100000  # the count we are willing to store
    max_hostname: int = 253


# ---- drift: is each rule still what the deploy wrote? ----

PREFIX_RE = re.compile(r"[A-Za-z0-9 ._-]{3,64}")
STAMP_KEY_RE = re.compile(rf"[A-Za-z0-9._-]{{{MIN_KEY_CHARS},255}}")
MAX_MISSING = 200  # names kept for the Rules tab; the count is exact below this


class Drift:
    """Checks the general namespace against the stamps the deploy wrote.

    Fed one rule at a time while the listing is parsed (`feed`); it keeps a verdict per rule
    name and, for the manifest, the list of managed names it vouches for. Rule bodies, tags
    and comments are used on the spot and never kept. With no stamp key, `Drift` is not
    built and nothing is stored (drift unchecked, never "no drift")."""

    def __init__(self, key: str, prefixes: tuple[str, ...]) -> None:
        self._key = key
        self._prefixes = prefixes
        self._pending: list[tuple[str, Any, Any, bool, Any]] = []
        self.manifest: str = MANIFEST_NONE
        self._listed: frozenset[str] = frozenset()
        self.verdicts: dict[str, str] = {}
        self._seen: set[str] = set()

    def feed(self, name: str, enabled: bool, record: dict[str, Any]) -> None:
        self._seen.add(name)
        meta = record.get("usr_mtd")
        meta = meta if isinstance(meta, dict) else {}
        data = record.get("data")
        data = data if isinstance(data, dict) else {}
        detect, respond = data.get("detect"), data.get("respond")
        tags = meta.get("tags")
        if name == MANIFEST_NAME:
            self.manifest, listed = check_manifest(
                self._key, detect, respond, enabled, tags, meta.get("comment")
            )
            self._listed = frozenset(listed)
            return
        # The verdict needs the manifest's list, which may come later in the listing.
        self._pending.append((name, detect, respond, enabled, tags))

    def finish(self) -> tuple[dict[str, str], dict[str, Any]]:
        """({rule name: ok|changed|unmanaged} for the managed rules, the manifest document)."""
        for name, detect, respond, enabled, tags in self._pending:
            verdict = classify_rule(
                self._key, self._prefixes, name, detect, respond, enabled, tags, self._listed
            )
            if verdict is not None:
                self.verdicts[name] = verdict
        self._pending = []
        if self.manifest == MANIFEST_NONE and any(
            v in (RULE_OK, RULE_CHANGED) for v in self.verdicts.values()
        ):
            # Stamped rules but no manifest: the manifest was deleted (or never written).
            self.manifest = MANIFEST_ABSENT
        missing = sorted(n for n in self._listed if n not in self._seen)
        doc = {
            "manifest": self.manifest,
            "missing_count": len(missing),
            "missing": missing[:MAX_MISSING],
        }
        return self.verdicts, doc


# ---- the vendor API ----


class PostureClient(LcClient):
    """The token and the guarded fetch of the catch-up worker's client, with the three
    read-only calls the collector needs."""

    def list_sensors(
        self, *, online_only: bool, limits: Limits | None = None
    ) -> list[dict[str, Any]]:
        lim = limits or Limits()
        rows: list[dict[str, Any]] = []
        query: dict[str, str] = {"is_online_only": "true"} if online_only else {}
        seen: set[str] = set()
        for _ in range(lim.max_pages):
            resp = self._get(f"sensors/{self.oid}", query)
            if not isinstance(resp, dict):
                raise LcError("bad_shape")
            page = resp.get("sensors", [])
            if not isinstance(page, list):
                raise LcError("bad_shape")
            rows.extend(row for row in page if isinstance(row, dict))
            if len(rows) > lim.max_sensors:
                raise LcError("too_many_items")
            token = resp.get("continuation_token")
            if not token:
                return rows
            if not isinstance(token, str) or len(token) > 2048 or token in seen:
                raise LcError("bad_cursor")
            seen.add(token)
            query = {**query, "continuation_token": token}
        raise LcError("too_many_pages")

    def list_rules(
        self,
        namespace: str,
        limits: Limits | None = None,
        inspect: Callable[[str, bool, dict[str, Any]], None] | None = None,
    ) -> list[tuple[str, bool]]:
        """(name, enabled) of every rule of one namespace. Bodies are dropped here; `inspect`
        (drift) sees each record on the way and must not keep it."""
        lim = limits or Limits()
        resp = self._get(f"hive/{RULE_HIVES[namespace]}/{self.oid}", {})
        if not isinstance(resp, dict):
            raise LcError("bad_shape")
        if len(resp) > lim.max_rules:
            raise LcError("too_many_items")
        out: list[tuple[str, bool]] = []
        for name, record in resp.items():
            if not isinstance(record, dict):
                raise LcError("bad_shape")
            meta = record.get("usr_mtd")
            enabled = meta.get("enabled") if isinstance(meta, dict) else None
            # An absent flag means enabled (the platform's default); anything else that is
            # not a boolean is a shape we do not know.
            if enabled is not None and not isinstance(enabled, bool):
                raise LcError("bad_shape")
            if not 1 <= len(name) <= 255:
                raise LcError("bad_shape")
            flag = True if enabled is None else enabled
            if inspect is not None:
                inspect(name, flag, record)
            out.append((name, flag))
        del resp
        return out

    def org_errors(self, limits: Limits | None = None) -> tuple[int, str | None]:
        """(how many errors the organization has, the newest one's component name).
        Messages are not read."""
        lim = limits or Limits()
        resp = self._get(f"errors/{self.oid}", {})
        errors = resp.get("errors") if isinstance(resp, dict) else None
        if errors is None and isinstance(resp, dict) and not resp:
            errors = []
        if not isinstance(errors, list):
            raise LcError("bad_shape")
        if len(errors) > lim.max_errors:
            raise LcError("too_many_items")
        best: tuple[float, int, str] | None = None
        for position, item in enumerate(errors):
            if not isinstance(item, dict):
                continue
            ts = item.get("ts")
            stamp = float(ts) if isinstance(ts, int | float) and not isinstance(ts, bool) else 0.0
            component = item.get("component")
            code = (
                component
                if isinstance(component, str) and COMPONENT_RE.fullmatch(component)
                else "unknown"
            )
            if best is None or (stamp, position) >= best[:2]:
                best = (stamp, position, code)  # the newest stamp; the later row breaks a tie
        return len(errors), None if best is None else best[2]


# ---- shaping what the vendor sent ----


def _epoch(value: object) -> float | None:
    """A last-seen time as epoch seconds, from a number (seconds or milliseconds) or an
    ISO-like text; None when it is not one we understand."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        seconds = float(value) / 1000 if value > 1e11 else float(value)
    elif isinstance(value, str):
        try:
            when = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
        seconds = (when if when.tzinfo else when.replace(tzinfo=UTC)).timestamp()
    else:
        return None
    return seconds if 0 <= seconds <= 4102444800 else None


def _text(value: object, limit: int) -> str | None:
    if isinstance(value, str) and value:
        return "".join(c for c in value[:limit] if c.isprintable())
    return None


def shape_sensors(
    everyone: list[dict[str, Any]], online: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], int]:
    """The sensor list as the database wants it, and how many rows were skipped.

    A row without a usable id is skipped; the platform's own extension sensors (host name
    starting `ext-`) are not sources and are skipped, as on the status page."""
    online_ids = {str(s["sid"]) for s in online if isinstance(s.get("sid"), str)}
    out: dict[str, dict[str, Any]] = {}
    skipped = 0
    for row in everyone:
        sid = row.get("sid")
        if not isinstance(sid, str) or not SID_RE.fullmatch(sid):
            skipped += 1
            continue
        hostname = _text(row.get("hostname"), Limits.max_hostname) or "?"
        if hostname.startswith("ext-"):
            continue
        plat = row.get("plat")
        platform = (
            platform_name(plat)
            if isinstance(plat, int) and not isinstance(plat, bool)
            else _text(plat, 40) or "Unknown"
        )
        isolated = row.get("is_isolated", row.get("isolated"))
        raw_tags = row.get("tags")
        tags: list[str] = []
        if isinstance(raw_tags, list):
            tags = [t for t in raw_tags if isinstance(t, str) and TAG_RE.fullmatch(t)][:20]
        out[sid] = {
            "sid": sid,
            "hostname": hostname,
            "platform": platform[:40],
            "version": _text(row.get("version", row.get("sensor_version")), 40),
            "online": sid in online_ids,
            "isolated": isolated is True,
            "tags": tags,
            "last_seen_s": _epoch(row.get("alive")),
        }
    return list(out.values()), skipped


# ---- the database side ----


class PostureDb(Db):
    """The two write functions, as soc_posture."""

    def record(self, doc: dict[str, Any]) -> None:
        self._run("SELECT posture_record(%s::jsonb)", (json.dumps(doc, separators=(",", ":")),))

    def fail(self, code: str) -> None:
        self._run("SELECT posture_fail(%s)", (code,))


# ---- configuration ----


@dataclass(frozen=True)
class Config:
    oid: str
    key: str
    db_url: str
    api_url: str
    jwt_url: str
    allow_http: bool
    interval_s: float
    health_file: str
    stamp_key: str = field(default="", repr=False)
    prefixes: tuple[str, ...] = ()

    @staticmethod
    def from_settings(s: Settings, *, need_db: bool = True) -> "Config":
        """Everything the service needs, or a ValueError that names a setting (never a value)."""
        key = s.posture_lc_key.get_secret_value()
        db_url = s.posture_database_url.get_secret_value()
        if not key:
            raise ValueError("SOC_POSTURE_LC_KEY is missing (env/posture-lc.env)")
        if not OID_RE.fullmatch(s.posture_lc_oid):
            raise ValueError("SOC_POSTURE_LC_OID is missing or malformed (env/posture-lc.env)")
        if need_db and not db_url:
            raise ValueError("SOC_POSTURE_DATABASE_URL is missing (env/posture-db.env)")
        allow_http = s.env == "dev"
        stamp_key = s.posture_stamp_key.get_secret_value()
        prefixes: tuple[str, ...] = ()
        if stamp_key:
            if not STAMP_KEY_RE.fullmatch(stamp_key):
                raise ValueError("SOC_POSTURE_STAMP_KEY is malformed (env/posture-rules.env)")
            prefixes = tuple(p for p in s.posture_rules_prefixes.split("|") if p)
            if not all(PREFIX_RE.fullmatch(p) for p in prefixes):
                raise ValueError("SOC_POSTURE_RULES_PREFIXES is malformed (env/posture-rules.env)")
        return Config(
            oid=s.posture_lc_oid,
            key=key,
            db_url=db_url,
            api_url=_service_url("SOC_POSTURE_API_URL", s.posture_api_url, allow_http),
            jwt_url=_service_url("SOC_POSTURE_JWT_URL", s.posture_jwt_url, allow_http),
            allow_http=allow_http,
            interval_s=s.posture_interval_seconds,
            health_file=s.posture_health_file,
            stamp_key=stamp_key,
            prefixes=prefixes,
        )

    def client(self) -> PostureClient:
        return PostureClient(
            self.oid,
            self.key,
            api_url=self.api_url,
            jwt_url=self.jwt_url,
            allow_http=self.allow_http,
        )


# ---- the service ----


@dataclass
class Counts:
    sensors: int = 0
    online: int = 0
    rules: int = 0
    errors: int | None = 0  # None: the key cannot read the organization's errors
    skipped: int = 0
    namespaces_unavailable: int = 0
    drifted: int | None = None  # None: drift not checked (no stamp key)

    def line(self) -> str:
        return " ".join(f"{k}={'unavailable' if v is None else v}" for k, v in vars(self).items())


# A rules namespace the organization does not have (no managed rule sets, say) answers one
# of these; it is skipped, not a failed run. The org-error list answers 401/403 when the
# key's permissions do not cover it (the client has already retried once with a fresh
# token); it is stored as unknown, never as zero. Every other failure still fails the
# whole run, with nothing written.
NAMESPACE_UNAVAILABLE = frozenset({"http_400", "http_403", "http_404"})
ERRORS_UNREADABLE = frozenset({"http_401", "http_403"})


def rules_by_namespace(
    lc: PostureClient, limits: Limits, drift: Drift | None = None
) -> tuple[dict[str, list[tuple[str, bool]]], list[str]]:
    """The rules of every namespace that answered, and the namespaces that are not there.
    `drift`, when given, looks at the general namespace's rules as they are read."""
    found: dict[str, list[tuple[str, bool]]] = {}
    missing: list[str] = []
    for ns in RULE_HIVES:
        try:
            found[ns] = lc.list_rules(ns, limits, drift.feed if drift and ns == "general" else None)
        except LcError as exc:
            if exc.code not in NAMESPACE_UNAVAILABLE:
                raise
            missing.append(ns)
    return found, missing


def errors_or_unknown(lc: PostureClient, limits: Limits) -> tuple[int | None, str | None]:
    try:
        return lc.org_errors(limits)
    except LcError as exc:
        if exc.code not in ERRORS_UNREADABLE:
            raise
        return None, None


def _drifted(verdicts: dict[str, str], doc: dict[str, Any] | None) -> int | None:
    """How many things are wrong: rules changed or unmanaged, rules missing, a bad manifest."""
    if doc is None:
        return None
    wrong = sum(1 for v in verdicts.values() if v != RULE_OK)
    return (
        wrong + int(doc["missing_count"]) + int(doc["manifest"] in (MANIFEST_BAD, MANIFEST_ABSENT))
    )


def collect(
    lc: PostureClient, limits: Limits, drift: Drift | None = None
) -> tuple[dict[str, Any], Counts]:
    """One whole snapshot from the vendor, or an LcError. Nothing is stored here.
    With `drift`, each general rule carries its verdict and the document a `drift` block."""
    everyone = lc.list_sensors(online_only=False, limits=limits)
    online = lc.list_sensors(online_only=True, limits=limits)
    sensors, skipped = shape_sensors(everyone, online)
    found, missing = rules_by_namespace(lc, limits, drift)
    verdicts: dict[str, str] = {}
    drift_doc: dict[str, Any] | None = None
    if drift is not None and "general" in found:
        verdicts, drift_doc = drift.finish()
    rules = [
        {
            "namespace": ns,
            "name": name,
            "enabled": enabled,
            "drift": verdicts.get(name) if ns == "general" else None,
        }
        for ns, listed in found.items()
        for name, enabled in listed
    ]
    count, newest = errors_or_unknown(lc, limits)
    counts = Counts(
        sensors=len(sensors),
        online=sum(1 for s in sensors if s["online"]),
        rules=len(rules),
        errors=count,
        skipped=skipped,
        namespaces_unavailable=len(missing),
        drifted=_drifted(verdicts, drift_doc),
    )
    doc: dict[str, Any] = {
        "sensors": sensors,
        "rules": rules,
        "org_errors": {"count": count, "newest": newest},
    }
    if drift_doc is not None:
        doc["drift"] = drift_doc
    return doc, counts


class Collector:
    def __init__(
        self,
        lc: PostureClient,
        db: PostureDb,
        *,
        interval_s: float = 300.0,
        limits: Limits | None = None,
        health_file: str | None = None,
        stamp_key: str = "",
        prefixes: tuple[str, ...] = (),
    ) -> None:
        self.stamp_key = stamp_key
        self.prefixes = prefixes
        self.lc = lc
        self.db = db
        self.interval_s = interval_s
        self.limits = limits or Limits()
        self.health_file = health_file
        self.counts = Counts()

    def run_once(self) -> Counts:
        self.counts = Counts()
        drift = Drift(self.stamp_key, self.prefixes) if self.stamp_key else None
        doc, counts = collect(self.lc, self.limits, drift)
        self.counts = counts
        self.db.record(doc)
        return counts

    def _touch_health(self) -> None:
        if self.health_file:
            try:
                Path(self.health_file).touch()
            except OSError:
                log.error("health outcome=cannot_write")

    def _record_failure(self, code: str) -> None:
        try:
            self.db.fail(code)
        except psycopg.Error as exc:
            log.error("posture outcome=db_error kind=%s", type(exc).__name__)

    def cycle(self) -> bool:
        """One pass with every failure turned into a code, a log line and a failure row."""
        try:
            counts = self.run_once()
        except LcError as exc:
            code = exc.code
        except psycopg.errors.RaiseException:
            code = "rejected"  # the database refused the document: nothing was written
        except psycopg.Error:
            code = "db_error"
        except Exception as exc:  # the loop must outlive anything the vendor sends
            log.error("posture outcome=error code=internal kind=%s", type(exc).__name__)
            self._record_failure("internal")
            return False
        else:
            log.info("posture outcome=ok %s", counts.line())
            self._touch_health()
            return True
        self._record_failure(code)
        log.warning("posture outcome=error code=%s", code)
        self._touch_health()  # alive, if not succeeding: the pager's STALE check covers that
        return False

    def run(
        self,
        should_stop: Callable[[], bool],
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        next_at = 0.0
        while not should_stop():
            if monotonic() >= next_at:
                self.cycle()
                next_at = monotonic() + self.interval_s
            sleep(1.0)


# ---- the read-only look ----


def check(cfg: Config) -> int:
    """Ask the vendor API once and say what shape came back. Counts and field names only:
    no host names, no rule names, no key. Writes nothing."""
    lim = Limits()
    lc = cfg.client()
    try:
        everyone = lc.list_sensors(online_only=False, limits=lim)
        online = lc.list_sensors(online_only=True, limits=lim)
        sensors, skipped = shape_sensors(everyone, online)
        found, missing = rules_by_namespace(lc, lim)
        count, newest = errors_or_unknown(lc, lim)
    except LcError as exc:
        print(f"check failed: {exc.code}")
        return 1
    kept_online = sum(1 for s in sensors if s["online"])
    print(
        f"check ok: auth=ok sensors={len(sensors)} online={kept_online} skipped={skipped} "
        "(kept sensors; the platform's own extension sensors are dropped)"
    )
    print(
        f"raw API rows: all={len(everyone)} online={len(online)} "
        "(before the extension sensors are dropped)"
    )
    fields = ("sid", "hostname", "plat", "alive", "version", "is_isolated", "tags")
    print(
        "sensor fields ("
        + str(len(everyone))
        + " rows): "
        + " ".join(f"{f}={sum(f in r for r in everyone)}" for f in fields)
    )
    print(
        "rules: "
        + " ".join(
            f"{ns}={len(found[ns])}" if ns in found else f"{ns}=not-available" for ns in RULE_HIVES
        )
    )
    if count is None:
        print("org errors: not readable with this key (stored as unknown)")
    else:
        print(f"org errors: count={count} newest_component={'yes' if newest else 'none'}")
    return 0


# ---- the command line ----


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="python -m soc_api.posture")
    parser.add_argument("command", nargs="?", default="run", choices=["run", "once", "check"])
    args = parser.parse_args(argv)
    configure_logging()
    try:
        cfg = Config.from_settings(get_settings(), need_db=args.command != "check")
    except ValueError as exc:
        print(exc)  # names a setting, never a value
        return 2
    if args.command == "check":
        return check(cfg)

    db = PostureDb(cfg.db_url)
    collector = Collector(
        cfg.client(),
        db,
        interval_s=cfg.interval_s,
        health_file=cfg.health_file,
        stamp_key=cfg.stamp_key,
        prefixes=cfg.prefixes,
    )
    try:
        if args.command == "once":
            return 0 if collector.cycle() else 1
        stopping = False

        def request_stop(_signum: int, _frame: object) -> None:
            nonlocal stopping
            stopping = True

        signal.signal(signal.SIGTERM, request_stop)
        signal.signal(signal.SIGINT, request_stop)
        log.info("posture outcome=started")
        collector.run(lambda: stopping)
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
