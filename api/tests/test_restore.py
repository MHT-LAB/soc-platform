"""deploy/restore.sh.

The script runs for real. The database container and the encryption tool are replaced by
small stubs (SOC_INIT_TEST is the only way to swap them in, and it is refused for root), so
what is checked is the script's own behaviour: what it refuses, in which order it acts, what
it leaves behind and what it never exposes. Two tests use the real `age` where it is
installed. The restore against a real database is scripts/test-restore-stack.sh."""

import hashlib
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

DEPLOY = Path(__file__).resolve().parents[2] / "deploy"
RESTORE = DEPLOY / "restore.sh"
BASH = shutil.which("bash") or "/bin/bash"

SECRET = "AGE-SECRET-KEY-1" + "Q" * 58
OTHER_SECRET = "AGE-SECRET-KEY-1" + "Z" * 58
PLAIN_DUMP = "PGDMP-fake-database-dump\nrow: customer-host-17\n"
GLOBALS = (
    "CREATE ROLE postgres;\n"
    "ALTER ROLE postgres WITH SUPERUSER INHERIT CREATEROLE CREATEDB LOGIN REPLICATION BYPASSRLS;\n"
    "CREATE ROLE soc_owner;\n"
    "ALTER ROLE soc_owner WITH NOSUPERUSER INHERIT CREATEROLE NOCREATEDB LOGIN;\n"
    "CREATE ROLE soc_ingest;\n"
    "ALTER ROLE soc_ingest WITH NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB LOGIN "
    "CONNECTION LIMIT 10;\n"
    "GRANT soc_worker_writer TO soc_owner GRANTED BY postgres;\n"
)
SET = "soc-20261104T061700Z"

not_root = pytest.mark.skipif(os.geteuid() == 0, reason="needs a non-root user")

COMPOSE_STUB = r"""#!/bin/bash
# stands in for soc-compose.sh. Every call is written to $STUB_LOG.
log() { [[ -z "${STUB_LOG:-}" ]] || echo "$*" >> "$STUB_LOG"; }
[[ -z "${STUB_ENV_LOG:-}" ]] || env >> "$STUB_ENV_LOG"
[[ -z "${STUB_LOCK_LOG:-}" ]] || {
  if [[ -d "$SOC_STATE_DIR/backups/.lock" ]]; then echo held >> "$STUB_LOCK_LOG"
  else echo free >> "$STUB_LOCK_LOG"; fi
}
log "compose $*"
case "$1" in
  up) [[ -z "${STUB_UP_FAIL:-}" ]] ;;
  ps) printf '%b\n' "${STUB_RUNNING:-db}" ;;
  run) [[ -z "${STUB_MIGRATE_FAIL:-}" ]] ;;
  exec)
    [[ "$2 $3" == "-T db" ]] || exit 99
    shift 3
    cmd="$1"; shift
    case "$cmd" in
      pg_isready) [[ -z "${STUB_DB_DOWN:-}" ]] ;;
      pg_restore)
        if [[ "$1" == "--list" ]]; then
          body="$(cat)"
          [[ "$body" != *BAD* ]] || exit 1
          [[ -n "${STUB_NO_TABLES:-}" ]] || echo "; TABLE public alert soc_owner"
        else
          log "pg_restore $*"
          [[ -z "${STUB_RESTORE_FAIL:-}" ]] || exit 1
          cat > "${STUB_RESTORED:-/dev/null}"
        fi ;;
      psql)
        args="$*"
        if [[ "$args" == *"-c "* ]]; then sql="${args#*-c }"; else sql="$(cat)"; fi
        case "$sql" in
          *pg_database*) log "psql exists"; echo "${STUB_SOC_EXISTS:-1}" ;;
          *query_to_xml*) log "psql rows"; echo "${STUB_ROWS:-0}" ;;
          *alembic_version*) log "psql summary"; echo "${STUB_SUMMARY:-7 3 0008}" ;;
          *"DROP DATABASE"*) log "psql drop"; [[ -z "${STUB_DROP_FAIL:-}" ]] ;;
          *"IF NOT EXISTS"*)
            log "psql roles"
            printf '%s' "$sql" > "${STUB_GLOBALS_OUT:-/dev/null}"
            [[ -z "${STUB_ROLES_FAIL:-}" ]] ;;
          *) log "psql unknown"; exit 97 ;;
        esac ;;
      *) exit 98 ;;
    esac ;;
  *) exit 99 ;;
esac
"""

# "decrypts" what the other test file's stub "encrypts": a header, then rot13. The key it
# wants is in a file beside it, never in the environment.
AGE_STUB = r"""#!/bin/bash
[[ -z "${STUB_AGE_LOG:-}" ]] || echo "age $*" >> "$STUB_AGE_LOG"
[[ -z "${STUB_ENV_LOG:-}" ]] || env >> "$STUB_ENV_LOG"
[[ "${1:-}" == "-d" && "${2:-}" == "-i" && "${3:-}" == "-" && "${4:-}" == "-o" ]] || exit 2
out="$5"; in="$6"
key="$(cat)"
[[ "$key" == "$(cat "$(dirname "$0")/expected-key")" ]] || {
  echo "age: error: no identity matched any of the recipients" >&2; exit 1; }
head -n1 "$in" | grep -qx age-stub || exit 1
tail -n +2 "$in" | tr 'A-Za-z' 'N-ZA-Mn-za-m' > "$out"
"""


def write_exe(path: Path, body: str) -> Path:
    path.write_text(body)
    path.chmod(0o755)
    return path


def rot13(text: str) -> str:
    import codecs

    return codecs.encode(text, "rot13")


@pytest.fixture
def stubs(tmp_path: Path) -> Path:
    d = tmp_path / "stubs"
    d.mkdir()
    write_exe(d / "soc-compose.sh", COMPOSE_STUB)
    write_exe(d / "age", AGE_STUB)
    (d / "expected-key").write_text(SECRET)
    return d


def host(state: Path, *, pgdata: bool = True) -> Path:
    (state / "env").mkdir(parents=True, exist_ok=True)
    (state / "env" / "db.env").write_text("POSTGRES_PASSWORD=x\n")
    (state / "env" / "db-owner.env").write_text("SOC_MIGRATE_URL=x\n")
    if pgdata:
        (state / "pgdata").mkdir(exist_ok=True)
    return state


def make_set(
    folder: Path,
    name: str = SET,
    *,
    dump: str = PLAIN_DUMP,
    globals_: str = GLOBALS,
) -> Path:
    """Write a backup set the way backup.sh does (with the stub 'age'); return its .sha256."""
    folder.mkdir(parents=True, exist_ok=True)
    dump_f = folder / f"{name}.dump.age"
    glob_f = folder / f"{name}.globals.sql.age"
    dump_f.write_text("age-stub\n" + rot13(dump))
    glob_f.write_text("age-stub\n" + rot13(globals_))
    sums = folder / f"{name}.sha256"
    sums.write_text(
        f"{hashlib.sha256(dump_f.read_bytes()).hexdigest()}  {dump_f.name}\n"
        f"{hashlib.sha256(glob_f.read_bytes()).hexdigest()}  {glob_f.name}\n"
    )
    return sums


def run_restore(
    state: Path,
    stubs: Path,
    arg: str | None = SET,
    *,
    key: str | None = SECRET,
    test_mode: bool = True,
    **env: Any,
) -> subprocess.CompletedProcess[str]:
    full = {"PATH": "/usr/bin:/bin", "SOC_STATE_DIR": str(state)}
    if test_mode:
        full.update(
            SOC_INIT_TEST="1",
            SOC_COMPOSE=str(stubs / "soc-compose.sh"),
            SOC_RESTORE_AGE=str(stubs / "age"),
            SOC_RESTORE_TRIES="2",
            SOC_RESTORE_SLEEP="0",
        )
    full.update(env)
    return subprocess.run(  # noqa: S603 - fixed argv, our own script
        [BASH, str(RESTORE), *([arg] if arg is not None else [])],
        env=full,
        input=(key + "\n") if key is not None else "",
        capture_output=True,
        text=True,
        timeout=60,
    )


def calls(log: Path) -> list[str]:
    return log.read_text().splitlines() if log.exists() else []


def leftovers(state: Path) -> list[str]:
    """Anything that should not survive a run: temporary folders, plain dump text."""
    found = [p.name for p in state.iterdir() if p.name.startswith(".restore.")]
    for p in state.rglob("*"):
        rel = p.relative_to(state)
        if rel.parts[0] in ("stubs", "capture"):  # the test's own stubs and what they recorded
            continue
        if p.is_file() and b"PGDMP-fake" in p.read_bytes():
            found.append(str(rel))
    return found


def good(
    tmp_path: Path, stubs: Path, **env: Any
) -> tuple[subprocess.CompletedProcess[str], dict[str, Path]]:
    host(tmp_path)
    make_set(tmp_path / "backups")
    (tmp_path / "capture").mkdir(exist_ok=True)
    paths = {
        "log": tmp_path / "calls.log",
        "restored": tmp_path / "capture" / "restored.out",
        "globals": tmp_path / "capture" / "globals.out",
    }
    r = run_restore(
        tmp_path,
        stubs,
        STUB_LOG=str(paths["log"]),
        STUB_RESTORED=str(paths["restored"]),
        STUB_GLOBALS_OUT=str(paths["globals"]),
        **env,
    )
    return r, paths


def refused(
    tmp_path: Path, stubs: Path, expect: str, *, make: bool = True, **env: Any
) -> subprocess.CompletedProcess[str]:
    host(tmp_path)
    if make:
        make_set(tmp_path / "backups")
    log = tmp_path / "calls.log"
    r = run_restore(tmp_path, stubs, STUB_LOG=str(log), **env)
    assert r.returncode != 0, r.stdout
    assert expect in r.stderr, r.stderr
    assert r.stdout == ""
    assert leftovers(tmp_path) == []
    assert not (tmp_path / "backups" / ".lock").exists()
    return r


# ---- the good run ----


@not_root
def test_a_good_run_restores_in_the_right_order_and_says_so_in_one_line(
    tmp_path: Path, stubs: Path
) -> None:
    r, p = good(tmp_path, stubs)
    assert r.returncode == 0, r.stderr
    assert r.stdout == f"restore outcome=ok set={SET} alerts=7 cases=3 revision=0008\n"
    assert r.stderr == ""
    # the container calls (exec ...) are logged too; what matters is this order of steps
    steps = [c for c in calls(p["log"]) if not c.startswith("compose exec")]
    assert steps == [
        "compose up -d db",
        "compose ps --status running --services",
        "psql exists",
        "psql rows",
        "psql roles",
        "psql drop",
        "pg_restore -U postgres -d soc --exit-on-error --single-transaction",
        "compose run --rm migrate",
        "psql summary",
        "compose up -d api console",
    ]
    assert p["restored"].read_text() == PLAIN_DUMP


@not_root
def test_only_the_app_and_the_console_are_started_never_tunnel_worker_or_catch_up(
    tmp_path: Path, stubs: Path
) -> None:
    r, p = good(tmp_path, stubs)
    assert r.returncode == 0, r.stderr
    ups = [c for c in calls(p["log"]) if c.startswith("compose up")]
    assert ups == ["compose up -d db", "compose up -d api console"]
    everything = "\n".join(calls(p["log"]))
    for service in ("tunnel", "worker", "reconcile", "cloudflared"):
        assert service not in everything


@not_root
def test_the_roles_become_create_if_missing_and_no_password_is_sent(
    tmp_path: Path, stubs: Path
) -> None:
    r, p = good(tmp_path, stubs)
    assert r.returncode == 0, r.stderr
    sent = p["globals"].read_text()
    plain_lines = sent.splitlines()  # a bare statement would fail on a role that exists
    assert not any(line.startswith("CREATE ROLE ") for line in plain_lines)
    assert sent.count("IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = ") == 3
    for role in ("postgres", "soc_owner", "soc_ingest"):
        assert f"rolname = '{role}') THEN CREATE ROLE {role}; END IF;" in sent
    assert "ALTER ROLE soc_ingest WITH NOSUPERUSER" in sent  # the attributes still go
    assert "GRANT soc_worker_writer TO soc_owner" in sent  # and so do the memberships
    assert "PASSWORD" not in sent


@not_root
def test_nothing_in_plain_text_is_left_anywhere(tmp_path: Path, stubs: Path) -> None:
    r, _ = good(tmp_path, stubs)
    assert r.returncode == 0, r.stderr
    assert leftovers(tmp_path) == []
    assert PLAIN_DUMP not in r.stdout + r.stderr


@not_root
def test_a_set_can_be_named_by_the_path_of_its_checksum_file_from_anywhere(
    tmp_path: Path, stubs: Path
) -> None:
    host(tmp_path)
    elsewhere = tmp_path / "from-the-nas"
    sums = make_set(elsewhere)
    (tmp_path / "capture").mkdir()
    out = tmp_path / "capture" / "out"
    r = run_restore(tmp_path, stubs, str(sums), STUB_RESTORED=str(out))
    assert r.returncode == 0, r.stderr
    assert out.read_text() == PLAIN_DUMP
    assert sorted(p.name for p in elsewhere.iterdir()) == [  # the set itself is not touched
        f"{SET}.dump.age",
        f"{SET}.globals.sql.age",
        f"{SET}.sha256",
    ]


# ---- the set must be whole and unchanged, before anything is decrypted ----


@not_root
@pytest.mark.parametrize("victim", [f"{SET}.dump.age", f"{SET}.globals.sql.age"])
def test_a_changed_file_is_refused_before_the_key_is_used_or_anything_starts(
    tmp_path: Path, stubs: Path, victim: str
) -> None:
    host(tmp_path)
    make_set(tmp_path / "backups")
    f = tmp_path / "backups" / victim
    f.write_text(f.read_text() + "x")
    log, age_log = tmp_path / "calls.log", tmp_path / "age.log"
    r = run_restore(tmp_path, stubs, STUB_LOG=str(log), STUB_AGE_LOG=str(age_log))
    assert (
        r.returncode != 0 and "step=checksum" in r.stderr and "checksum_does_not_match" in r.stderr
    )
    assert not log.exists() and not age_log.exists()  # no container call, no decryption
    assert leftovers(tmp_path) == []


@not_root
@pytest.mark.parametrize("missing", [f"{SET}.dump.age", f"{SET}.globals.sql.age", f"{SET}.sha256"])
def test_a_set_with_a_file_missing_is_refused(tmp_path: Path, stubs: Path, missing: str) -> None:
    host(tmp_path)
    make_set(tmp_path / "backups")
    (tmp_path / "backups" / missing).unlink()
    r = run_restore(tmp_path, stubs, STUB_LOG=str(tmp_path / "calls.log"))
    assert r.returncode != 0 and "step=set" in r.stderr
    assert not (tmp_path / "calls.log").exists()


@not_root
@pytest.mark.parametrize(
    "rewrite",
    [
        lambda d, g: f"{d}  {SET}.dump.age\n",  # one line
        lambda d, g: f"{d}  {SET}.dump.age\n{g}  {SET}.globals.sql.age\n{d}  extra\n",  # three
        lambda d, g: f"{d}  ../{SET}.dump.age\n{g}  {SET}.globals.sql.age\n",  # a path
        lambda d, g: f"{'0' * 64}  {SET}.dump.age\n{g}  {SET}.globals.sql.age\n",  # wrong digest
        lambda d, g: f"{d[:-1]}  {SET}.dump.age\n{g}  {SET}.globals.sql.age\n",  # short digest
        lambda d, g: f"{d}  {SET}.dump.age\n{d}  {SET}.dump.age\n",  # one file twice
    ],
)
def test_a_checksum_file_that_is_not_exactly_the_two_expected_lines_is_refused(
    tmp_path: Path, stubs: Path, rewrite: Any
) -> None:
    host(tmp_path)
    sums = make_set(tmp_path / "backups")
    folder = tmp_path / "backups"
    d = hashlib.sha256((folder / f"{SET}.dump.age").read_bytes()).hexdigest()
    g = hashlib.sha256((folder / f"{SET}.globals.sql.age").read_bytes()).hexdigest()
    sums.write_text(rewrite(d, g))
    r = run_restore(tmp_path, stubs, STUB_LOG=str(tmp_path / "calls.log"))
    assert r.returncode != 0 and "step=checksum" in r.stderr
    assert not (tmp_path / "calls.log").exists()


@not_root
@pytest.mark.parametrize(
    "arg", [None, "", "soc-1", "../soc-20261104T061700Z", "soc-20261104T061700Z/../x", "backup"]
)
def test_the_set_argument_must_be_a_set_name_or_a_checksum_path(
    tmp_path: Path, stubs: Path, arg: str | None
) -> None:
    host(tmp_path)
    make_set(tmp_path / "backups")
    r = run_restore(tmp_path, stubs, arg, STUB_LOG=str(tmp_path / "calls.log"))
    assert r.returncode != 0 and "restore outcome=failed" in r.stderr
    assert not (tmp_path / "calls.log").exists()


@not_root
def test_two_arguments_are_refused(tmp_path: Path, stubs: Path) -> None:
    host(tmp_path)
    make_set(tmp_path / "backups")
    r = subprocess.run(  # noqa: S603
        [BASH, str(RESTORE), SET, SET],
        env={
            "PATH": "/usr/bin:/bin",
            "SOC_STATE_DIR": str(tmp_path),
            "SOC_INIT_TEST": "1",
            "SOC_COMPOSE": str(stubs / "soc-compose.sh"),
        },
        input=SECRET + "\n",
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert r.returncode != 0 and "usage" in r.stderr


# ---- the key ----


@not_root
def test_a_wrong_key_stops_at_decryption_before_the_database_is_touched(
    tmp_path: Path, stubs: Path
) -> None:
    refused(tmp_path, stubs, "step=decrypt reason=could_not_decrypt", key=OTHER_SECRET)
    assert not (tmp_path / "calls.log").exists()


@not_root
@pytest.mark.parametrize("victim", [f"{SET}.dump.age", f"{SET}.globals.sql.age"])
def test_one_file_that_cannot_be_decrypted_stops_the_run_even_if_the_other_can(
    tmp_path: Path, stubs: Path, victim: str
) -> None:
    host(tmp_path)
    sums = make_set(tmp_path / "backups")
    folder = tmp_path / "backups"
    (folder / victim).write_text("not an age file at all\n")  # the checksum is made to match
    sums.write_text(
        "".join(
            f"{hashlib.sha256((folder / name).read_bytes()).hexdigest()}  {name}\n"
            for name in (f"{SET}.dump.age", f"{SET}.globals.sql.age")
        )
    )
    log = tmp_path / "calls.log"
    r = run_restore(tmp_path, stubs, STUB_LOG=str(log))
    assert r.returncode != 0 and "step=decrypt reason=could_not_decrypt" in r.stderr
    assert not log.exists() and leftovers(tmp_path) == []


@not_root
@pytest.mark.parametrize(
    "typed",
    [
        "",
        "not a key",
        "AGE-SECRET-" + "KEY-1abc",  # too short to be one
        "age1" + "q" * 58,  # a public key
        SECRET + "x y",
        " " + SECRET,
    ],
)
def test_something_that_is_not_an_age_private_key_is_refused_at_once(
    tmp_path: Path, stubs: Path, typed: str
) -> None:
    refused(tmp_path, stubs, "step=key reason=that_is_not_an_age_private_key", key=typed)
    assert not (tmp_path / "calls.log").exists()


@not_root
def test_the_key_is_never_an_argument_never_in_the_environment_and_never_printed(
    tmp_path: Path, stubs: Path
) -> None:
    env_log, age_log, log = tmp_path / "env.log", tmp_path / "age.log", tmp_path / "calls.log"
    r, _ = good(tmp_path, stubs, STUB_ENV_LOG=str(env_log), STUB_AGE_LOG=str(age_log))
    assert r.returncode == 0, r.stderr
    assert env_log.exists() and age_log.exists()  # the stubs really did look
    for text in (
        env_log.read_text(),
        age_log.read_text(),
        r.stdout,
        r.stderr,
        (tmp_path / "calls.log").read_text() if log.exists() else "",
    ):
        assert SECRET not in text and "QQQQQQQQQQ" not in text
    assert "-d -i - -o" in age_log.read_text()  # the key travels on standard input
    for p in tmp_path.rglob("*"):  # and it is in no file the run wrote
        if p.is_file() and stubs not in p.parents and p.name != "env.log":
            assert SECRET.encode() not in p.read_bytes(), p


@not_root
def test_the_test_switches_do_nothing_without_the_test_switch(tmp_path: Path, stubs: Path) -> None:
    host(tmp_path)
    make_set(tmp_path / "backups")
    r = run_restore(tmp_path, stubs, test_mode=False, SOC_COMPOSE=str(stubs / "soc-compose.sh"))
    assert r.returncode != 0 and "reason=run_as_root" in r.stderr


# ---- what it refuses to touch ----


@not_root
def test_a_host_without_its_secret_files_or_data_directory_is_refused(
    tmp_path: Path, stubs: Path
) -> None:
    make_set(tmp_path / "backups")
    (tmp_path / "env").mkdir()
    r = run_restore(tmp_path, stubs, STUB_LOG=str(tmp_path / "calls.log"))
    assert r.returncode != 0 and "missing_db.env" in r.stderr
    (tmp_path / "env" / "db.env").write_text("x\n")
    (tmp_path / "env" / "db-owner.env").write_text("x\n")
    r = run_restore(tmp_path, stubs, STUB_LOG=str(tmp_path / "calls.log"))
    assert r.returncode != 0 and "missing_pgdata" in r.stderr
    assert not (tmp_path / "calls.log").exists()


@not_root
def test_a_database_with_rows_in_it_is_never_overwritten(tmp_path: Path, stubs: Path) -> None:
    refused(
        tmp_path,
        stubs,
        "step=empty reason=database_already_has_data_refusing_to_overwrite",
        STUB_ROWS="1",
    )
    seen = calls(tmp_path / "calls.log")
    assert "psql rows" in seen
    assert not any(c in ("psql roles", "psql drop") or "pg_restore -U" in c for c in seen)


@not_root
def test_a_running_stack_is_refused_and_nothing_is_changed(tmp_path: Path, stubs: Path) -> None:
    for running in ("db\napi", "api", "db\nconsole\nworker"):
        refused(tmp_path, stubs, "step=empty reason=stack_is_running", STUB_RUNNING=running)
        seen = calls(tmp_path / "calls.log")
        assert not any(c in ("psql roles", "psql drop") for c in seen)
        (tmp_path / "calls.log").unlink()


@not_root
def test_the_database_alone_running_is_what_a_restore_expects(tmp_path: Path, stubs: Path) -> None:
    r, _ = good(tmp_path, stubs, STUB_RUNNING="db")
    assert r.returncode == 0, r.stderr


@not_root
def test_a_database_that_is_not_there_yet_counts_as_empty(tmp_path: Path, stubs: Path) -> None:
    r, p = good(tmp_path, stubs, STUB_SOC_EXISTS="0")
    assert r.returncode == 0, r.stderr
    assert "psql rows" not in calls(p["log"])  # nothing to count


@not_root
def test_a_database_that_never_becomes_healthy_is_reported(tmp_path: Path, stubs: Path) -> None:
    refused(
        tmp_path, stubs, "step=database reason=database_did_not_become_healthy", STUB_DB_DOWN="1"
    )


@not_root
def test_a_database_that_will_not_start_is_reported(tmp_path: Path, stubs: Path) -> None:
    refused(tmp_path, stubs, "step=database reason=could_not_start_the_database", STUB_UP_FAIL="1")


@not_root
@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"dump": "BAD dump"}, "dump_is_not_readable"),
        ({"globals_": "-- nothing here\n"}, "roles_dump_has_no_roles"),
        (
            {"globals_": GLOBALS + "ALTER ROLE soc_ingest PASSWORD 'hunter2hunter2';\n"},
            "roles_dump_contains_a_password",
        ),
        (
            {"globals_": GLOBALS + "CREATE ROLE evil SUPERUSER;\n"},
            "roles_dump_has_a_line_this_does_not_understand",
        ),
        (
            {"globals_": GLOBALS + "CREATE ROLE a; DROP DATABASE soc;\n"},
            "roles_dump_has_a_line_this_does_not_understand",
        ),
    ],
)
def test_a_dump_that_fails_its_checks_is_refused_before_anything_is_changed(
    tmp_path: Path, stubs: Path, kwargs: dict[str, str], reason: str
) -> None:
    host(tmp_path)
    make_set(tmp_path / "backups", **kwargs)
    log = tmp_path / "calls.log"
    r = run_restore(tmp_path, stubs, STUB_LOG=str(log))
    assert r.returncode != 0 and f"step=verify reason={reason}" in r.stderr
    assert not any(c in ("psql roles", "psql drop", "psql rows") for c in calls(log))
    assert leftovers(tmp_path) == []


@not_root
def test_a_dump_that_lists_no_tables_is_refused(tmp_path: Path, stubs: Path) -> None:
    refused(tmp_path, stubs, "step=verify reason=dump_lists_no_tables", STUB_NO_TABLES="1")


# ---- failures part-way ----


@not_root
def test_a_failed_load_leaves_an_empty_database_so_the_command_can_be_run_again(
    tmp_path: Path, stubs: Path
) -> None:
    host(tmp_path)
    make_set(tmp_path / "backups")
    log = tmp_path / "calls.log"
    r = run_restore(tmp_path, stubs, STUB_LOG=str(log), STUB_RESTORE_FAIL="1")
    assert r.returncode != 0 and "step=load reason=pg_restore_failed" in r.stderr
    seen = calls(log)
    drops = [i for i, c in enumerate(seen) if c == "psql drop"]
    assert len(drops) == 2  # dropped to load, and dropped + recreated empty after the failure
    assert "compose run --rm migrate" not in seen and "compose up -d api console" not in seen
    assert leftovers(tmp_path) == [] and not (tmp_path / "backups" / ".lock").exists()


@not_root
def test_a_failed_database_recreate_also_tries_to_leave_an_empty_one(
    tmp_path: Path, stubs: Path
) -> None:
    host(tmp_path)
    make_set(tmp_path / "backups")
    log = tmp_path / "calls.log"
    r = run_restore(tmp_path, stubs, STUB_LOG=str(log), STUB_DROP_FAIL="1")
    assert r.returncode != 0 and "reason=could_not_recreate_the_database" in r.stderr
    assert calls(log).count("psql drop") == 2
    assert not any("pg_restore -U" in c for c in calls(log))


@not_root
def test_a_failure_creating_the_roles_changes_no_database(tmp_path: Path, stubs: Path) -> None:
    refused(tmp_path, stubs, "step=roles reason=could_not_create_the_roles", STUB_ROLES_FAIL="1")
    assert "psql drop" not in calls(tmp_path / "calls.log")


@not_root
def test_a_failed_migration_keeps_the_restored_data_and_does_not_start_the_app(
    tmp_path: Path, stubs: Path
) -> None:
    host(tmp_path)
    make_set(tmp_path / "backups")
    log = tmp_path / "calls.log"
    r = run_restore(tmp_path, stubs, STUB_LOG=str(log), STUB_MIGRATE_FAIL="1")
    assert r.returncode != 0 and "step=migrate reason=migration_job_failed" in r.stderr
    seen = calls(log)
    assert seen.count("psql drop") == 1  # the restored data is not thrown away
    assert "compose up -d api console" not in seen
    assert leftovers(tmp_path) == []


# ---- locking ----


@not_root
def test_backup_is_locked_out_while_a_restore_runs_and_the_lock_is_released_after(
    tmp_path: Path, stubs: Path
) -> None:
    lock_log = tmp_path / "lock.log"
    r, _ = good(tmp_path, stubs, STUB_LOCK_LOG=str(lock_log))
    assert r.returncode == 0, r.stderr
    seen = lock_log.read_text().split()
    assert seen and set(seen) == {"held"}  # held at every container call
    assert not (tmp_path / "backups" / ".lock").exists()


@not_root
def test_a_live_backup_or_restore_blocks_a_second_one_and_its_lock_is_left_alone(
    tmp_path: Path, stubs: Path
) -> None:
    host(tmp_path)
    make_set(tmp_path / "backups")
    holder = subprocess.Popen(["sleep", "30"])  # noqa: S603, S607 - a live process to name
    try:
        lock = tmp_path / "backups" / ".lock"
        lock.mkdir()
        (lock / "pid").write_text(str(holder.pid))
        r = run_restore(tmp_path, stubs, STUB_LOG=str(tmp_path / "calls.log"))
        assert r.returncode != 0 and "reason=a_backup_or_restore_is_running" in r.stderr
        assert lock.is_dir() and (lock / "pid").read_text() == str(holder.pid)
        assert not (tmp_path / "calls.log").exists()
    finally:
        holder.kill()
        holder.wait()


@not_root
def test_a_lock_left_by_a_dead_process_is_taken_over(tmp_path: Path, stubs: Path) -> None:
    host(tmp_path)
    make_set(tmp_path / "backups")
    gone = subprocess.Popen(["true"])  # noqa: S603, S607
    gone.wait()
    lock = tmp_path / "backups" / ".lock"
    lock.mkdir()
    (lock / "pid").write_text(str(gone.pid))
    r = run_restore(tmp_path, stubs)
    assert r.returncode == 0, r.stderr
    assert not lock.exists()


# ---- with the real age ----


def real_age() -> tuple[str, str] | None:
    age, keygen = shutil.which("age"), shutil.which("age-keygen")
    if not (age and keygen):
        if os.environ.get("SOC_REQUIRE_AGE"):
            pytest.fail("SOC_REQUIRE_AGE is set but age is not installed")
        pytest.skip("age is not installed")
    assert age and keygen
    return age, keygen


def real_set(tmp_path: Path) -> tuple[str, str]:
    """A set encrypted with real age; returns (private key, public key)."""
    age, keygen = real_age() or ("", "")
    pair = subprocess.run([keygen], capture_output=True, text=True, check=True)  # noqa: S603
    private = next(x for x in pair.stdout.splitlines() if x.startswith("AGE-SECRET-KEY-"))
    public = subprocess.run(  # noqa: S603
        [keygen, "-y"], input=private + "\n", capture_output=True, text=True, check=True
    ).stdout.strip()
    folder = tmp_path / "backups"
    folder.mkdir(parents=True)
    lines = []
    for suffix, body in ((".dump", PLAIN_DUMP), (".globals.sql", GLOBALS)):
        plain = tmp_path / "plain"
        plain.write_text(body)
        out = folder / f"{SET}{suffix}.age"
        subprocess.run([age, "-r", public, "-o", str(out), str(plain)], check=True)  # noqa: S603
        plain.unlink()
        lines.append(f"{hashlib.sha256(out.read_bytes()).hexdigest()}  {out.name}")
    (folder / f"{SET}.sha256").write_text("\n".join(lines) + "\n")
    return private, public


@not_root
def test_with_real_age_the_typed_key_decrypts_the_set_and_the_database_gets_the_dump(
    tmp_path: Path, stubs: Path
) -> None:
    real_age()
    host(tmp_path)
    private, _ = real_set(tmp_path)
    (tmp_path / "capture").mkdir()
    out, g = tmp_path / "capture" / "restored.out", tmp_path / "capture" / "g.out"
    r = run_restore(
        tmp_path,
        stubs,
        key=private,
        SOC_RESTORE_AGE=shutil.which("age") or "",
        STUB_RESTORED=str(out),
        STUB_GLOBALS_OUT=str(g),
    )
    assert r.returncode == 0, r.stderr
    assert out.read_text() == PLAIN_DUMP
    assert "CREATE ROLE soc_ingest" in g.read_text()
    assert leftovers(tmp_path) == []


@not_root
def test_with_real_age_another_key_cannot_open_the_set(tmp_path: Path, stubs: Path) -> None:
    real_age()
    host(tmp_path)
    real_set(tmp_path)
    _, keygen = real_age() or ("", "")
    other = subprocess.run([keygen], capture_output=True, text=True, check=True)  # noqa: S603
    wrong = next(x for x in other.stdout.splitlines() if x.startswith("AGE-SECRET-KEY-"))
    log = tmp_path / "calls.log"
    r = run_restore(
        tmp_path, stubs, key=wrong, SOC_RESTORE_AGE=shutil.which("age") or "", STUB_LOG=str(log)
    )
    assert r.returncode != 0 and "step=decrypt reason=could_not_decrypt" in r.stderr
    assert not log.exists() and leftovers(tmp_path) == []
