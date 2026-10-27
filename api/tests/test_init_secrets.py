"""deploy/init-secrets.sh: creates the host's secret files, tells the operator the
values exactly once, never overwrites, and can rebuild the files from the
secrets manager's copy. These run the real script (SOC_INIT_TEST skips the root
check and chown, and is refused for root)."""

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
from sqlalchemy.engine import make_url

from soc_api.db import MIN_PASSWORD_LENGTH
from soc_api.ingest import MIN_SECRET_LEN, parse_secrets

SCRIPT = Path(__file__).resolve().parents[2] / "deploy" / "init-secrets.sh"
BASH = shutil.which("bash") or "/bin/bash"
SLUG = "lc-0123456789abcdef"
HOST = "soc.example.com"
FILES = ("env/db.env", "env/db-owner.env", "env/ingest.env")
NAMES = (
    "SOC_DB_SUPERUSER_PASSWORD",
    "SOC_DB_OWNER_PASSWORD",
    "SOC_DB_INGEST_PASSWORD",
    "SOC_INGEST_LC_SLUG",
    "SOC_INGEST_LC_HMAC",
)

not_root = pytest.mark.skipif(os.geteuid() == 0, reason="needs a non-root user")


def run(
    state: Path, *args: str, test_mode: bool = True, **env: str
) -> subprocess.CompletedProcess[str]:
    full = {"PATH": "/usr/bin:/bin", "SOC_STATE_DIR": str(state), **env}
    if test_mode:
        full["SOC_INIT_TEST"] = "1"
    return subprocess.run(  # noqa: S603 - fixed argv, our own script
        [BASH, str(SCRIPT), *args],
        env=full,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def parse_env(path: Path) -> dict[str, str]:
    out = {}
    for line in path.read_text().splitlines():
        key, _, value = line.partition("=")
        out[key] = value
    return out


def printed_block(stdout: str) -> dict[str, str]:
    return {k: v for k, _, v in (line.partition("=") for line in stdout.splitlines()) if k in NAMES}


def tree(state: Path) -> set[str]:
    return {str(p.relative_to(state)) for p in state.rglob("*")}


@not_root
def test_a_run_creates_the_files_with_strict_modes(tmp_path: Path) -> None:
    r = run(tmp_path, SLUG, HOST)
    assert r.returncode == 0, r.stderr
    for f in FILES:
        assert stat.S_IMODE((tmp_path / f).stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "env").stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / "pgdata").stat().st_mode) == 0o700
    assert (tmp_path / "seed").is_dir()
    assert list((tmp_path / "pgdata").iterdir()) == []
    # no temporary files left behind
    assert tree(tmp_path) == {
        "env",
        "env/db.env",
        "env/db-owner.env",
        "env/ingest.env",
        "pgdata",
        "seed",
    }


@not_root
def test_the_files_agree_with_each_other_and_with_what_the_app_accepts(tmp_path: Path) -> None:
    assert run(tmp_path, SLUG, HOST).returncode == 0
    db = parse_env(tmp_path / "env/db.env")
    owner = parse_env(tmp_path / "env/db-owner.env")
    ingest = parse_env(tmp_path / "env/ingest.env")

    # the soc_ingest password is the same in the migration job and in the app's URL
    ingest_url = make_url(ingest["SOC_INGEST_DATABASE_URL"])
    assert ingest_url.username == "soc_ingest"
    assert ingest_url.password == owner["SOC_INGEST_DB_PASSWORD"]
    assert (ingest_url.host, ingest_url.port, ingest_url.database) == ("db", 5432, "soc")
    # the owner URL uses the owner password from db.env
    owner_url = make_url(owner["SOC_MIGRATE_URL"])
    assert owner_url.username == "soc_owner"
    assert owner_url.password == db["SOC_DB_OWNER_PASSWORD"]
    assert (owner_url.host, owner_url.database) == ("db", "soc")
    # the app's own parser accepts the secrets, and they are long enough for the tools
    secrets = parse_secrets(ingest["SOC_INGEST_SECRETS"])
    assert list(secrets) == [SLUG]
    assert len(secrets[SLUG]) == 1
    assert len(secrets[SLUG][0]) >= MIN_SECRET_LEN
    assert len(owner["SOC_INGEST_DB_PASSWORD"]) >= MIN_PASSWORD_LENGTH
    # four different random values
    values = [
        db["POSTGRES_PASSWORD"],
        db["SOC_DB_OWNER_PASSWORD"],
        owner["SOC_INGEST_DB_PASSWORD"],
        secrets[SLUG][0].decode(),
    ]
    assert len(set(values)) == 4
    assert all(re.fullmatch(r"[0-9a-f]{48,64}", v) for v in values)


@not_root
def test_the_printed_block_matches_the_files_exactly(tmp_path: Path) -> None:
    r = run(tmp_path, SLUG, HOST)
    block = printed_block(r.stdout)
    assert set(block) == set(NAMES)
    db = parse_env(tmp_path / "env/db.env")
    owner = parse_env(tmp_path / "env/db-owner.env")
    secrets = parse_secrets(parse_env(tmp_path / "env/ingest.env")["SOC_INGEST_SECRETS"])
    assert block["SOC_DB_SUPERUSER_PASSWORD"] == db["POSTGRES_PASSWORD"]
    assert block["SOC_DB_OWNER_PASSWORD"] == db["SOC_DB_OWNER_PASSWORD"]
    assert block["SOC_DB_INGEST_PASSWORD"] == owner["SOC_INGEST_DB_PASSWORD"]
    assert block["SOC_INGEST_LC_SLUG"] == SLUG
    assert block["SOC_INGEST_LC_HMAC"] == secrets[SLUG][0].decode()
    # the EDR output instructions carry the destination and the same key
    assert f"https://{HOST}/ingest/{SLUG}" in r.stdout
    assert f"secret_key:       {block['SOC_INGEST_LC_HMAC']}" in r.stdout
    assert "Do not paste" in r.stdout
    assert r.stderr == ""


@not_root
def test_two_runs_never_produce_the_same_secrets(tmp_path: Path) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    first = printed_block(run(a, SLUG, HOST).stdout)
    second = printed_block(run(b, SLUG, HOST).stdout)
    secret_names = [n for n in NAMES if n != "SOC_INGEST_LC_SLUG"]
    assert all(first[n] != second[n] for n in secret_names)


@not_root
def test_secrets_are_not_written_anywhere_but_the_three_env_files(tmp_path: Path) -> None:
    r = run(tmp_path, SLUG, HOST)
    block = printed_block(r.stdout)
    secret_values = [v for k, v in block.items() if k != "SOC_INGEST_LC_SLUG"]
    allowed = {tmp_path / f for f in FILES}
    for path in tmp_path.rglob("*"):
        if path.is_file() and path not in allowed:
            text = path.read_text()
            assert not any(s in text for s in secret_values), path
    assert not (tmp_path / "deploy.log").exists()


@not_root
@pytest.mark.parametrize(
    "slug",
    [
        "", "lc-", "lc-0123456789abcde", "lc-0123456789abcdef0", "LC-0123456789abcdef",
        "lc-0123456789ABCDEF", "xx-0123456789abcdef", "lc-0123456789abcd_f",
        "lc-0123456789abcd-f", "lc-0123456789abcdef\n", "../lc-0123456789abcdef",
    ],
)  # fmt: skip
def test_a_malformed_source_name_is_refused_before_anything_is_created(
    tmp_path: Path, slug: str
) -> None:
    r = run(tmp_path, slug, HOST)
    assert r.returncode == 1
    assert "FAILED" in r.stderr
    assert tree(tmp_path) == set()


@not_root
@pytest.mark.parametrize(
    "host",
    [
        "",
        "localhost",
        "SOC.EXAMPLE.COM",
        "soc example.com",
        "a/b.com",
        "-x.example.com",
        "x.com:8080",
    ],
)
def test_a_malformed_public_host_is_refused(tmp_path: Path, host: str) -> None:
    r = run(tmp_path, SLUG, host)
    assert r.returncode == 1
    assert tree(tmp_path) == set()


@not_root
@pytest.mark.parametrize("args", [(), (SLUG,), (SLUG, HOST, "extra"), ("--bogus",)])
def test_wrong_arguments_print_usage(tmp_path: Path, args: tuple[str, ...]) -> None:
    r = run(tmp_path, *args)
    assert r.returncode == 1
    assert "usage" in r.stderr
    assert tree(tmp_path) == set()


@not_root
@pytest.mark.parametrize("existing", FILES)
def test_it_never_overwrites_and_creates_nothing_else(tmp_path: Path, existing: str) -> None:
    (tmp_path / "env").mkdir()
    target = tmp_path / existing
    target.write_text("KEEP=me\n")
    before = tree(tmp_path)
    r = run(tmp_path, SLUG, HOST)
    assert r.returncode == 1
    assert "already exists" in r.stderr
    assert target.read_text() == "KEEP=me\n"
    assert tree(tmp_path) == before
    assert "SOC_DB" not in r.stdout


@not_root
def test_a_data_directory_that_already_holds_data_is_refused(tmp_path: Path) -> None:
    (tmp_path / "pgdata").mkdir()
    (tmp_path / "pgdata" / "PG_VERSION").write_text("16\n")
    r = run(tmp_path, SLUG, HOST)
    assert r.returncode == 1
    assert "already holds data" in r.stderr
    assert not (tmp_path / "env").exists()


@not_root
def test_an_empty_existing_data_directory_is_fine(tmp_path: Path) -> None:
    (tmp_path / "pgdata").mkdir()
    assert run(tmp_path, SLUG, HOST).returncode == 0


@not_root
def test_without_root_and_without_the_test_switch_it_refuses(tmp_path: Path) -> None:
    r = run(tmp_path, SLUG, HOST, test_mode=False)
    assert r.returncode == 1
    assert "run as root" in r.stderr
    assert tree(tmp_path) == set()


# ---- restore from the secrets manager's copy ----


def restore_env(block: dict[str, str]) -> dict[str, str]:
    return dict(block)


@not_root
def test_restore_rebuilds_byte_identical_files_and_prints_no_secret(tmp_path: Path) -> None:
    first = run(tmp_path, SLUG, HOST)
    block = printed_block(first.stdout)
    originals = {f: (tmp_path / f).read_bytes() for f in FILES}
    for f in FILES:
        (tmp_path / f).unlink()
    # the database directory is kept: restoring secrets for data that still exists
    (tmp_path / "pgdata" / "PG_VERSION").write_text("16\n")

    r = run(tmp_path, "--restore", **restore_env(block))
    assert r.returncode == 0, r.stderr
    for f in FILES:
        assert (tmp_path / f).read_bytes() == originals[f]
        assert stat.S_IMODE((tmp_path / f).stat().st_mode) == 0o600
    secret_values = [v for k, v in block.items() if k != "SOC_INGEST_LC_SLUG"]
    assert not any(s in r.stdout + r.stderr for s in secret_values)


@not_root
@pytest.mark.parametrize("missing", NAMES)
def test_restore_needs_all_five_values(tmp_path: Path, missing: str) -> None:
    block = printed_block(run(tmp_path / "src", SLUG, HOST).stdout)
    del block[missing]
    r = run(tmp_path / "dst", "--restore", **block)
    assert r.returncode == 1
    dst = tmp_path / "dst"
    assert not dst.exists() or tree(dst) == set()


@not_root
@pytest.mark.parametrize(
    ("name", "bad"),
    [
        ("SOC_DB_OWNER_PASSWORD", "short"),
        ("SOC_DB_OWNER_PASSWORD", "g" * 48),
        ("SOC_DB_INGEST_PASSWORD", "a" * 48 + "@evil"),
        ("SOC_INGEST_LC_HMAC", "A" * 64),
        ("SOC_INGEST_LC_SLUG", "lc-short"),
    ],
)
def test_restore_rejects_values_that_could_break_the_urls_or_files(
    tmp_path: Path, name: str, bad: str
) -> None:
    block = printed_block(run(tmp_path / "src", SLUG, HOST).stdout)
    block[name] = bad
    dst = tmp_path / "dst"
    r = run(dst, "--restore", **block)
    assert r.returncode == 1
    assert not dst.exists() or not (dst / "env").exists()


@not_root
def test_restore_also_refuses_to_overwrite(tmp_path: Path) -> None:
    block = printed_block(run(tmp_path, SLUG, HOST).stdout)
    before = (tmp_path / "env/db.env").read_bytes()
    r = run(tmp_path, "--restore", **block)
    assert r.returncode == 1
    assert (tmp_path / "env/db.env").read_bytes() == before
