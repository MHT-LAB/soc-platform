"""Deploy detection rules from git to the detection source, one reviewed step at a time.

    python -m soc_api.rules_deploy        (the one-shot compose `rules` service, started by
                                           deploy/rules-deploy.sh; never by deploy.sh)

What it does, in order, and stops at the first thing that is wrong:

1. Checks the rules directory with the same contract and replay as CI (`soc_api.rules`). A
   rule that fails either is never deployed.
2. Reads the live rules of the general namespace and works out the difference for the
   MANAGED set only: rules named in git, rules whose name starts with a managed prefix, and
   rules that carry a stamp. Every other live rule (lab rules, other tools') is counted and
   named, never changed or deleted.
3. Prints the plan (names first, then the body difference) and asks for a typed `yes` at the
   terminal. Nothing but `yes` changes anything. With nothing to do it says so and asks
   nothing.
4. Applies: adds and changes first, then removals, then the manifest rule. Each rule written
   gets a stamp tag (`git:<12 hex>`, an HMAC of its behaviour, see `soc_api.rules.stamp`) and
   the commit in its comment. The metadata of the vendor's API is replaced as a whole, so the
   rule's other tags and fields are sent back as they were.
5. Writes a one-line record for the operator's log.

Only the `rule` kind of the organization's own folder (`orgs/<org>/`) is deployed here.

The vendor key (`soc-rules-deploy`: dr.list, dr.set, dr.del) and the stamp key are read from
the environment of this one container and never printed: every failure is a short code.
Responses are data, size-capped and parsed as JSON, never executed. https only, no redirects.
"""

import difflib
import json
import os
import re
import sys
import time
import urllib.parse
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from soc_api.reconcile import OID_RE, TOKEN_REFRESH_S, LcClient, LcError
from soc_api.reconcile import _json as parse_json
from soc_api.rules.loader import RuleFile, load_tree
from soc_api.rules.stamp import (
    MANIFEST_DETECT,
    MANIFEST_NAME,
    MANIFEST_RESPOND,
    MIN_KEY_CHARS,
    TAG_PREFIX,
    has_stamp_tag,
    manifest_comment,
    parse_manifest_comment,
    stamp_tag,
)
from soc_api.rules.validate import check_tree, replay_tree

HIVE = "dr-general"
MAX_RULES = 5000
KEY_RE = re.compile(r"[A-Za-z0-9._-]{16,128}")
ORG_RE = re.compile(r"[a-z0-9-]{1,32}")
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
# The stamp key and the prefixes come through a compose env file: only characters it cannot
# read as a quote, a comment or a variable.
STAMP_KEY_RE = re.compile(rf"[A-Za-z0-9._-]{{{MIN_KEY_CHARS},255}}")
PREFIX_RE = re.compile(r"[A-Za-z0-9 ._-]{3,64}")
MAX_PROBLEMS_SHOWN = 20

OK, FAILED, DECLINED, REFUSED = 0, 1, 3, 2


class ConfigError(Exception):
    """A missing or malformed setting. Names the setting, never its value."""


# ---- the vendor API (writes) ----


@dataclass(frozen=True)
class LiveRule:
    name: str
    detect: Any
    respond: Any
    enabled: bool
    tags: list[str]
    usr_mtd: dict[str, Any]  # as the platform has it, sent back whole on a change
    etag: str | None


class Backend(Protocol):
    """What a deploy needs from the platform (the real client, or a fake in tests)."""

    def list_rules(self) -> dict[str, "LiveRule"]: ...

    def set_rule(
        self, name: str, data: dict[str, Any], usr_mtd: dict[str, Any], etag: str | None
    ) -> None: ...

    def delete_rule(self, name: str) -> None: ...


class RulesClient(LcClient):
    """The token and guarded fetch of the catch-up worker's client, with the three calls a
    deploy needs: list the general rules (with bodies), set one, delete one."""

    def _send(self, method: str, path: str, form: Mapping[str, str] | None = None) -> Any:
        url = f"{self.api_url}/v1/{path}"
        body = urllib.parse.urlencode(form).encode() if form is not None else None
        extra = {"Content-Type": "application/x-www-form-urlencoded"} if body is not None else {}
        for attempt in (0, 1):
            if self._jwt is None or self._clock() - self._jwt_at > TOKEN_REFRESH_S:
                self._refresh()
            try:
                raw = self._fetch(
                    method,
                    url,
                    data=body,
                    headers={"Authorization": f"Bearer {self._jwt}", "Accept": "application/json"}
                    | extra,
                )
            except LcError as exc:
                if exc.code == "http_401" and attempt == 0:
                    self._jwt = None  # expired or revoked early: one new token, one retry
                    continue
                raise
            return parse_json(raw) if raw.strip() else {}
        raise LcError("http_401")  # not reached

    def list_rules(self) -> dict[str, LiveRule]:
        resp = self._get(f"hive/{HIVE}/{self.oid}", {})
        if not isinstance(resp, dict) or len(resp) > MAX_RULES:
            raise LcError("bad_shape")
        out: dict[str, LiveRule] = {}
        for name, record in resp.items():
            if not isinstance(record, dict) or not 1 <= len(name) <= 255:
                raise LcError("bad_shape")
            data = record.get("data")
            meta = record.get("usr_mtd")
            sys_meta = record.get("sys_mtd")
            if not isinstance(data, dict) or not isinstance(meta, dict | None):
                raise LcError("bad_shape")
            meta = meta or {}
            enabled = meta.get("enabled")
            if enabled is not None and not isinstance(enabled, bool):
                raise LcError("bad_shape")
            tags = meta.get("tags", [])
            if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
                raise LcError("bad_shape")
            etag = sys_meta.get("etag") if isinstance(sys_meta, dict) else None
            out[name] = LiveRule(
                name=name,
                detect=data.get("detect"),
                respond=data.get("respond"),
                enabled=True if enabled is None else enabled,  # absent means enabled
                tags=tags,
                usr_mtd=meta,
                etag=etag if isinstance(etag, str) else None,
            )
        return out

    def set_rule(
        self, name: str, data: dict[str, Any], usr_mtd: dict[str, Any], etag: str | None
    ) -> None:
        form = {"data": json.dumps(data), "usr_mtd": json.dumps(usr_mtd)}
        if etag is not None:
            form["etag"] = etag  # the platform refuses the write if the rule changed since
        quoted = urllib.parse.quote(name, safe="")
        self._send("POST", f"hive/{HIVE}/{self.oid}/{quoted}/data", form)

    def delete_rule(self, name: str) -> None:
        self._send("DELETE", f"hive/{HIVE}/{self.oid}/{urllib.parse.quote(name, safe='')}")


# ---- settings ----


@dataclass(frozen=True)
class Config:
    key: str = field(repr=False)
    oid: str
    stamp_key: str = field(repr=False)
    commit: str
    rules_dir: Path
    org: str
    prefixes: tuple[str, ...]
    out_dir: Path

    @staticmethod
    def from_env(env: Mapping[str, str]) -> "Config":
        def need(name: str, pattern: re.Pattern[str]) -> str:
            value = env.get(name, "")
            if not pattern.fullmatch(value):
                raise ConfigError(f"{name} is missing or malformed")
            return value

        # No defaults for who the rules belong to: the private deploy side says (public code).
        prefixes = tuple(env.get("SOC_RULES_PREFIXES", "").split("|"))
        if not all(PREFIX_RE.fullmatch(p) for p in prefixes):
            raise ConfigError("SOC_RULES_PREFIXES is missing or malformed")
        return Config(
            key=need("SOC_RULES_LC_KEY", KEY_RE),
            oid=need("SOC_RULES_LC_OID", OID_RE),
            stamp_key=need("SOC_RULES_STAMP_KEY", STAMP_KEY_RE),
            commit=need("SOC_RULES_COMMIT", COMMIT_RE),
            rules_dir=Path(env.get("SOC_RULES_DIR", "/rules")),
            org=need("SOC_RULES_ORG", ORG_RE),
            prefixes=prefixes,
            out_dir=Path(env.get("SOC_RULES_OUT", "/out")),
        )


# ---- what git wants ----


@dataclass(frozen=True)
class Desired:
    name: str
    detect: dict[str, Any]
    respond: list[Any]
    enabled: bool
    source: str


def load_desired(root: Path, org: str) -> tuple[dict[str, Desired], list[str]]:
    """The rules of `orgs/<org>/` (kind `rule`) as the platform should have them, and the
    reasons any cannot be deployed. The contract and replay are run first, over the whole
    tree, exactly as CI does."""
    problems = [str(p) for p in check_tree(root)] + [str(p) for p in replay_tree(root)]
    wanted: dict[str, Desired] = {}
    folder = f"orgs/{org}/"
    files: list[RuleFile] = [rf for rf in load_tree(root) if rf.where.startswith(folder)]
    for rf in files:
        data = rf.data
        if not isinstance(data, dict) or data.get("kind", "rule") != "rule":
            continue  # fp and fim files live in other hives; not this tool's job (yet)
        name = data.get("name")
        enabled = data.get("enabled")
        detect, respond = data.get("detect"), data.get("respond")
        if not isinstance(name, str) or name == MANIFEST_NAME:
            problems.append(f"{rf.rel}: the name is missing or reserved")
        elif not isinstance(enabled, bool):
            problems.append(f"{rf.rel}: needs an explicit true or false 'enabled' to be deployed")
        elif not isinstance(detect, dict) or not isinstance(respond, list):
            problems.append(f"{rf.rel}: needs a 'detect' object and a 'respond' list")
        elif name in wanted:
            problems.append(f"{rf.rel}: the name {name!r} is used twice")
        else:
            wanted[name] = Desired(name, detect, respond, enabled, rf.rel)
    if not problems and not wanted:
        problems.append(f"no deployable rules under {folder}")
    return wanted, problems


# ---- the plan ----


@dataclass(frozen=True)
class Change:
    kind: str  # "add" | "change" | "remove"
    name: str
    desired: Desired | None
    live: LiveRule | None
    body_differs: bool  # False: only the stamp is new or wrong ("adopt")


@dataclass(frozen=True)
class Plan:
    changes: list[Change]
    unchanged: int
    unmanaged: list[str]
    manifest_comment: str
    manifest_write: bool
    manifest_live: LiveRule | None

    @property
    def nothing(self) -> bool:
        return not self.changes and not self.manifest_write

    def count(self, kind: str) -> int:
        return sum(1 for c in self.changes if c.kind == kind)


def make_plan(
    cfg: Config, wanted: dict[str, Desired], live: dict[str, LiveRule], at: int = 0
) -> Plan:
    """`at` (epoch seconds) is the deploy time a NEW manifest carries; a manifest that already
    lists exactly these names and stamps is left alone, so a second run has nothing to do."""
    changes: list[Change] = []
    unchanged = 0
    for name in sorted(wanted):
        want = wanted[name]
        have = live.get(name)
        tag = stamp_tag(cfg.stamp_key, want.detect, want.respond, want.enabled)
        if have is None:
            changes.append(Change("add", name, want, None, True))
            continue
        same_body = (
            have.detect == want.detect
            and have.respond == want.respond
            and have.enabled == want.enabled
        )
        stamps = [t for t in have.tags if t.startswith(TAG_PREFIX)]
        if same_body and stamps == [tag]:
            unchanged += 1
        else:
            changes.append(Change("change", name, want, have, not same_body))
    unmanaged: list[str] = []
    for name in sorted(live):
        if name in wanted or name == MANIFEST_NAME:
            continue
        rule = live[name]
        if name.startswith(cfg.prefixes) or has_stamp_tag(rule.tags):
            changes.append(Change("remove", name, None, rule, True))
        else:
            unmanaged.append(name)
    order = {"add": 0, "change": 1, "remove": 2}
    changes.sort(key=lambda c: (order[c.kind], c.name))

    stamps_wanted = {
        name: stamp_tag(cfg.stamp_key, w.detect, w.respond, w.enabled) for name, w in wanted.items()
    }
    old = live.get(MANIFEST_NAME)
    m_tag = stamp_tag(cfg.stamp_key, MANIFEST_DETECT, MANIFEST_RESPOND, False)
    parsed = parse_manifest_comment(cfg.stamp_key, old.usr_mtd.get("comment")) if old else None
    fresh = (
        old is not None
        and old.detect == MANIFEST_DETECT
        and old.respond == MANIFEST_RESPOND
        and old.enabled is False
        and old.tags == [m_tag]
        and parsed is not None
        and parsed[0] == stamps_wanted
    )
    if fresh and old is not None:
        comment = str(old.usr_mtd.get("comment"))
    else:
        comment = manifest_comment(cfg.stamp_key, stamps_wanted, at or int(time.time()))
    return Plan(changes, unchanged, unmanaged, comment, not fresh, old)


def _pretty(rule: Desired | LiveRule) -> list[str]:
    body = {"detect": rule.detect, "respond": rule.respond, "enabled": rule.enabled}
    return json.dumps(body, indent=2, sort_keys=True, ensure_ascii=False).splitlines()


def _line_diff(old: list[str], new: list[str], context: int = 2) -> list[str]:
    """Changed lines marked - and +, with a little unchanged text around them."""
    out: list[str] = []
    matcher = difflib.SequenceMatcher(None, old, new, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            same = old[i1:i2]
            if len(same) > 2 * context:
                same = [*same[:context], "...", *same[-context:]]
            out += [" " + line for line in same]
        else:
            out += ["-" + line for line in old[i1:i2]]
            out += ["+" + line for line in new[j1:j2]]
    return out


def render(plan: Plan) -> list[str]:
    """The plan as lines for the terminal: names first, then the bodies."""
    mark = {"add": "+ add   ", "change": "~ change", "remove": "- remove"}
    lines = ["Rules to change (general namespace, managed set only):"]
    for c in plan.changes:
        note = "" if c.body_differs else "   (same behaviour; only the stamp is new or wrong)"
        lines.append(f"  {mark[c.kind]}  {c.name}{note}")
    if plan.manifest_write:
        lines.append(f"  ~ manifest  {MANIFEST_NAME}  (the list of managed names)")
    lines.append(
        f"Unchanged: {plan.unchanged}.  Not managed here, left alone: {len(plan.unmanaged)}"
        + (f" ({', '.join(plan.unmanaged)})" if plan.unmanaged else "")
    )
    for c in plan.changes:
        if c.kind == "add" and c.desired:
            lines += ["", f"=== + {c.name}", *_pretty(c.desired)]
        elif c.kind == "remove" and c.live:
            lines += ["", f"=== - {c.name}  (deleted from the platform)", *_pretty(c.live)]
        elif c.kind == "change" and c.desired and c.live and c.body_differs:
            diff = _line_diff(_pretty(c.live), _pretty(c.desired))
            lines += ["", f"=== ~ {c.name}", *diff]
    return lines


# ---- apply ----


def _usr_mtd(live: LiveRule | None, enabled: bool, tag: str, comment: str) -> dict[str, Any]:
    """The whole metadata, because the platform replaces it as a whole: the rule's own other
    fields and tags go back as they were; only `enabled`, the stamp tag and the comment are ours."""
    meta = dict(live.usr_mtd) if live else {}
    others = [t for t in (live.tags if live else []) if not t.startswith(TAG_PREFIX)]
    meta["enabled"] = enabled
    meta["tags"] = [*others, tag]
    meta["comment"] = comment
    return meta


def apply(cfg: Config, client: Backend, plan: Plan, say: Callable[[str], None]) -> int:
    """Write the plan. Returns how many steps were done; raises LcError at the first failure."""
    done = 0
    commit_note = f"git {cfg.commit[:12]}"
    for c in plan.changes:
        if c.kind == "remove":
            client.delete_rule(c.name)
        else:
            want = c.desired
            assert want is not None  # noqa: S101 - add and change always carry a rule
            tag = stamp_tag(cfg.stamp_key, want.detect, want.respond, want.enabled)
            meta = _usr_mtd(c.live, want.enabled, tag, commit_note)
            data = {"detect": want.detect, "respond": want.respond}
            client.set_rule(c.name, data, meta, c.live.etag if c.live else None)
        done += 1
        say(f"  done: {c.kind} {c.name}")
    if plan.manifest_write:
        m_tag = stamp_tag(cfg.stamp_key, MANIFEST_DETECT, MANIFEST_RESPOND, False)
        meta = _usr_mtd(plan.manifest_live, False, m_tag, plan.manifest_comment)
        data = {"detect": MANIFEST_DETECT, "respond": MANIFEST_RESPOND}
        etag = plan.manifest_live.etag if plan.manifest_live else None
        client.set_rule(MANIFEST_NAME, data, meta, etag)
        done += 1
        say(f"  done: manifest {MANIFEST_NAME}")
    return done


# ---- the run ----


def record_line(cfg: Config, plan: Plan | None, result: str, now: datetime) -> str:
    """One line for the deploy log and the vault Build Log: no key, no rule bodies."""
    counts = (
        f"added={plan.count('add')} changed={plan.count('change')} "
        f"removed={plan.count('remove')} unchanged={plan.unchanged} unmanaged={len(plan.unmanaged)}"
        if plan
        else "added=0 changed=0 removed=0"
    )
    stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    return (
        f"rules-deploy {stamp} org={cfg.oid[:8]} commit={cfg.commit[:12]} {counts} result={result}"
    )


def _write_record(cfg: Config, line: str, say: Callable[[str], None]) -> None:
    try:
        (cfg.out_dir / "record.txt").write_text(line + "\n", encoding="utf-8")
    except OSError:
        say("warning: could not write the record file; the line above is the record")
    say(line)


def run(
    cfg: Config,
    client: Backend,
    confirm: Callable[[str], bool],
    say: Callable[[str], None] = print,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> int:
    """The whole deploy. 0: done or nothing to do. 1: failed part-way. 2: refused before
    changing anything. 3: not confirmed."""
    wanted, problems = load_desired(cfg.rules_dir, cfg.org)
    if problems:
        for p in problems[:MAX_PROBLEMS_SHOWN]:
            say(p)
        if len(problems) > MAX_PROBLEMS_SHOWN:
            say(f"... and {len(problems) - MAX_PROBLEMS_SHOWN} more")
        say(f"refused: {len(problems)} problem(s) in the rules; nothing was changed")
        _write_record(cfg, record_line(cfg, None, "refused-rules", now()), say)
        return REFUSED
    try:
        live = client.list_rules()
    except LcError as exc:
        say(f"refused: could not read the live rules ({exc.code}); nothing was changed")
        _write_record(cfg, record_line(cfg, None, f"refused-{exc.code}", now()), say)
        return REFUSED
    plan = make_plan(cfg, wanted, live, int(now().timestamp()))
    if plan.nothing:
        say(
            f"Nothing to do: {plan.unchanged} managed rules already match git at {cfg.commit[:12]}."
        )
        _write_record(cfg, record_line(cfg, plan, "nothing-to-do", now()), say)
        return OK
    for line in render(plan):
        say(line)
    say("")
    if not confirm(f"Apply this to the platform from commit {cfg.commit[:12]}? Type yes: "):
        say("Not confirmed: nothing was changed.")
        _write_record(cfg, record_line(cfg, plan, "declined", now()), say)
        return DECLINED
    try:
        apply(cfg, client, plan, say)
    except LcError as exc:
        say(f"FAILED part-way ({exc.code}). Run it again: it works out what is left.")
        _write_record(cfg, record_line(cfg, plan, f"failed-{exc.code}", now()), say)
        return FAILED
    _write_record(cfg, record_line(cfg, plan, "applied", now()), say)
    return OK


def tty_confirm(prompt: str) -> bool:
    """A typed `yes` read from the terminal. No terminal means no."""
    if not sys.stdin.isatty():
        print("no terminal to ask on: nothing was changed")
        return False
    try:
        return input(prompt).strip() == "yes"
    except EOFError:
        return False


def main() -> int:
    try:
        cfg = Config.from_env(os.environ)
    except ConfigError as exc:
        print(f"refused: {exc}")
        return REFUSED
    return run(cfg, RulesClient(cfg.oid, cfg.key), tty_confirm)


if __name__ == "__main__":
    sys.exit(main())
