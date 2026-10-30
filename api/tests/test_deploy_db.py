"""deploy.sh with a database on the host: start it, wait for health, migrate with the
new image, and only then swap the services. Same fake cosign/docker/curl setup as the
source-check tests; the fake docker logs every call and can fail the migration."""

import stat
import subprocess
from pathlib import Path

import pytest
from test_deploy_source_check import BASH, DEPLOY, IMAGE, REPO_DIGEST, Host

FAKE_DOCKER = """#!/usr/bin/env bash
echo "docker $* [profiles=${COMPOSE_PROFILES-unset}]" >> "$FAKE_LOG"
case "$1" in
  buildx) printf '%s\\n' "$FAKE_LABELS"; exit 0 ;;
  compose)
    if [[ "$*" == *" ps -q "* ]]; then echo cid; fi
    if [[ "$*" == *" up -d db"* ]]; then exit "${FAKE_UP_DB_RC:-0}"; fi
    if [[ "$*" == *" run --rm migrate"* ]]; then exit "${FAKE_MIGRATE_RC:-0}"; fi
    exit 0 ;;
  inspect)
    if [[ "$*" == *Health* ]]; then echo "${FAKE_DB_HEALTH:-healthy}"; else echo imgid; fi
    exit 0 ;;
  image) printf '%s\\n' "$FAKE_REPODIGEST"; exit 0 ;;
esac
exit 0
"""

OLD_IMAGE = "ghcr.io/mht-lab/soc-api@sha256:" + "0" * 64


class DbHost(Host):
    def __init__(self, tmp: Path, *, db_env: bool = True, owner_env: bool = True) -> None:
        super().__init__(tmp)
        for name, body in (("docker", FAKE_DOCKER), ("sleep", "#!/usr/bin/env bash\nexit 0\n")):
            path = self.bin / name
            path.write_text(body)
            path.chmod(path.stat().st_mode | stat.S_IXUSR)
        if db_env:
            (self.state / "env" / "db.env").write_text("POSTGRES_PASSWORD=x\n")
        if owner_env:
            (self.state / "env" / "db-owner.env").write_text("SOC_MIGRATE_URL=x\n")
        self.image_env = self.state / "env" / "image.env"

    def with_previous_image(self) -> None:
        self.image_env.write_text(f"SOC_API_IMAGE={OLD_IMAGE}\nSOC_STATE_DIR={self.state}\n")

    def deploy(self, **extra: str) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(self.tmp),
            "SOC_STATE_DIR": str(self.state),
            "SOC_TEST_BIN": str(self.bin),
            "SOC_SOURCE_DIR": str(self.src),
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "FAKE_LOG": str(self.log),
            "FAKE_DIGEST": REPO_DIGEST,
            "FAKE_REPODIGEST": f"{IMAGE}@{REPO_DIGEST}",
            "FAKE_LABELS": Host.labels(self.main),
            **extra,
        }
        return subprocess.run(  # noqa: S603 - fixed argv, our own script
            [BASH, str(DEPLOY), "edge"],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    def calls(self) -> list[str]:
        return [line for line in self.log.read_text().splitlines() if "docker compose" in line]


def index(calls: list[str], needle: str) -> int:
    hits = [i for i, c in enumerate(calls) if needle in c]
    assert hits, f"no call containing {needle!r} in {calls}"
    return hits[0]


def test_with_a_database_it_migrates_before_the_services_are_swapped(tmp_path: Path) -> None:
    host = DbHost(tmp_path)
    (host.state / "pgdata").mkdir()
    r = host.deploy()
    assert r.returncode == 0, r.stdout
    calls = host.calls()
    start_db = index(calls, " up -d db")
    migrate = index(calls, " run --rm migrate")
    swap = index(calls, " up -d --remove-orphans")
    assert start_db < migrate < swap
    # the db profile is on for every compose call, set by the script
    assert all("[profiles=db]" in c for c in calls)
    assert "migrations applied" in r.stdout
    assert (host.state / "seed").is_dir()


def test_a_failed_migration_restores_the_previous_image_and_swaps_nothing(
    tmp_path: Path,
) -> None:
    host = DbHost(tmp_path)
    (host.state / "pgdata").mkdir()
    host.with_previous_image()
    r = host.deploy(FAKE_MIGRATE_RC="1")
    assert r.returncode == 1
    assert "migration failed" in r.stdout
    assert f"SOC_API_IMAGE={OLD_IMAGE}\n" in host.image_env.read_text()
    assert not any(" up -d --remove-orphans" in c for c in host.calls())


def test_a_failed_first_migration_leaves_no_image_env_behind(tmp_path: Path) -> None:
    host = DbHost(tmp_path)
    (host.state / "pgdata").mkdir()
    r = host.deploy(FAKE_MIGRATE_RC="1")
    assert r.returncode == 1
    assert not host.image_env.exists()


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        ({"FAKE_DB_HEALTH": "starting"}, "database is not healthy"),
        ({"FAKE_UP_DB_RC": "1"}, "database did not start"),
    ],
)
def test_a_database_that_will_not_start_stops_the_deploy_before_the_swap(
    tmp_path: Path, extra: dict[str, str], message: str
) -> None:
    host = DbHost(tmp_path)
    (host.state / "pgdata").mkdir()
    host.with_previous_image()
    r = host.deploy(**extra)
    assert r.returncode == 1
    assert message in r.stdout
    calls = host.calls()
    assert not any(" run --rm migrate" in c for c in calls)
    assert not any(" up -d --remove-orphans" in c for c in calls)
    assert f"SOC_API_IMAGE={OLD_IMAGE}\n" in host.image_env.read_text()


def test_without_database_files_it_skips_migrations_and_says_so(tmp_path: Path) -> None:
    host = DbHost(tmp_path, db_env=False, owner_env=False)
    # A stray profile in the operator's shell must not turn the database on.
    r = host.deploy(COMPOSE_PROFILES="db")
    assert r.returncode == 0, r.stdout
    assert "skipping migrations" in r.stdout
    calls = host.calls()
    assert not any(" run --rm migrate" in c or " up -d db" in c for c in calls)
    assert all("[profiles=unset]" in c for c in calls)


@pytest.mark.parametrize(("db_env", "owner_env"), [(True, False), (False, True)])
def test_half_a_database_setup_is_refused_before_anything_changes(
    tmp_path: Path, db_env: bool, owner_env: bool
) -> None:
    host = DbHost(tmp_path, db_env=db_env, owner_env=owner_env)
    (host.state / "pgdata").mkdir()
    r = host.deploy()
    assert r.returncode == 1
    assert "must both exist" in r.stdout
    assert not host.changed_the_host


def test_an_empty_database_file_counts_as_missing(tmp_path: Path) -> None:
    host = DbHost(tmp_path)
    (host.state / "pgdata").mkdir()
    (host.state / "env" / "db-owner.env").write_text("")
    r = host.deploy()
    assert r.returncode == 1
    assert "must both exist" in r.stdout
    assert not host.changed_the_host


def test_a_missing_data_directory_is_refused_before_anything_changes(tmp_path: Path) -> None:
    host = DbHost(tmp_path)
    r = host.deploy()
    assert r.returncode == 1
    assert "pgdata is missing" in r.stdout
    assert not host.changed_the_host


# ---- the pager worker is an optional profile ----


def test_a_host_with_a_worker_file_turns_the_worker_profile_on(tmp_path: Path) -> None:
    host = DbHost(tmp_path)
    (host.state / "pgdata").mkdir()
    (host.state / "env" / "worker.env").write_text("SOC_NTFY_TOPIC=x\n")
    r = host.deploy()
    assert r.returncode == 0, r.stdout
    calls = host.calls()
    assert calls and all("[profiles=db,worker]" in c for c in calls)
    assert index(calls, " run --rm migrate") < index(calls, " up -d --remove-orphans")


def test_without_a_worker_file_the_worker_stays_off(tmp_path: Path) -> None:
    host = DbHost(tmp_path)
    (host.state / "pgdata").mkdir()
    r = host.deploy()
    assert r.returncode == 0, r.stdout
    assert all("[profiles=db]" in c for c in host.calls())  # no worker profile


def test_a_worker_file_without_a_database_is_refused_before_anything_changes(
    tmp_path: Path,
) -> None:
    host = DbHost(tmp_path, db_env=False, owner_env=False)
    (host.state / "env" / "worker.env").write_text("SOC_NTFY_TOPIC=x\n")
    r = host.deploy()
    assert r.returncode == 1
    assert "has no database" in r.stdout
    assert host.calls() == [] and not host.image_env.exists()


def test_an_empty_worker_file_is_refused(tmp_path: Path) -> None:
    host = DbHost(tmp_path)
    (host.state / "pgdata").mkdir()
    (host.state / "env" / "worker.env").write_text("")
    r = host.deploy()
    assert r.returncode == 1
    assert "is empty" in r.stdout
    assert host.calls() == []


def test_a_profile_set_in_the_shell_cannot_turn_the_worker_on(tmp_path: Path) -> None:
    host = DbHost(tmp_path)
    (host.state / "pgdata").mkdir()
    r = host.deploy(COMPOSE_PROFILES="db,worker")
    assert r.returncode == 0, r.stdout
    assert all("[profiles=db]" in c for c in host.calls())


# ---- the catch-up worker is an optional profile, on only when both its files exist ----


def reconcile_files(host: "DbHost", *, db: bool = True, lc: bool = True) -> None:
    if db:
        (host.state / "env" / "reconcile-db.env").write_text("SOC_RECONCILE_DATABASE_URL=x\n")
    if lc:
        (host.state / "env" / "reconcile-lc.env").write_text("SOC_RECONCILE_LC_KEY=x\n")


def test_both_catch_up_files_turn_the_catch_up_profile_on(tmp_path: Path) -> None:
    host = DbHost(tmp_path)
    (host.state / "pgdata").mkdir()
    reconcile_files(host)
    r = host.deploy()
    assert r.returncode == 0, r.stdout
    calls = host.calls()
    assert calls and all("[profiles=db,reconcile]" in c for c in calls)
    assert index(calls, " run --rm migrate") < index(calls, " up -d --remove-orphans")


def test_the_pager_and_catch_up_profiles_can_both_be_on(tmp_path: Path) -> None:
    host = DbHost(tmp_path)
    (host.state / "pgdata").mkdir()
    (host.state / "env" / "worker.env").write_text("SOC_NTFY_TOPIC=x\n")
    reconcile_files(host)
    r = host.deploy()
    assert r.returncode == 0, r.stdout
    assert all("[profiles=db,worker,reconcile]" in c for c in host.calls())


def test_the_database_file_alone_leaves_the_catch_up_worker_off(tmp_path: Path) -> None:
    """After init-reconcile.sh and before the vendor key: the deploy gives the role its login."""
    host = DbHost(tmp_path)
    (host.state / "pgdata").mkdir()
    reconcile_files(host, lc=False)
    r = host.deploy()
    assert r.returncode == 0, r.stdout
    assert all("[profiles=db]" in c for c in host.calls())


def test_without_catch_up_files_it_stays_off(tmp_path: Path) -> None:
    host = DbHost(tmp_path)
    (host.state / "pgdata").mkdir()
    r = host.deploy()
    assert r.returncode == 0, r.stdout
    assert not any("reconcile" in c for c in host.calls())


def test_the_vendor_key_file_without_the_database_file_is_refused(tmp_path: Path) -> None:
    host = DbHost(tmp_path)
    (host.state / "pgdata").mkdir()
    reconcile_files(host, db=False)
    r = host.deploy()
    assert r.returncode == 1
    assert "init-reconcile.sh" in r.stdout
    assert host.calls() == [] and not host.image_env.exists()


@pytest.mark.parametrize("empty", ["reconcile-db.env", "reconcile-lc.env"])
def test_an_empty_catch_up_file_is_refused(tmp_path: Path, empty: str) -> None:
    host = DbHost(tmp_path)
    (host.state / "pgdata").mkdir()
    reconcile_files(host)
    (host.state / "env" / empty).write_text("")
    r = host.deploy()
    assert r.returncode == 1
    assert host.calls() == []


def test_catch_up_files_without_a_database_are_refused_before_anything_changes(
    tmp_path: Path,
) -> None:
    host = DbHost(tmp_path, db_env=False, owner_env=False)
    reconcile_files(host)
    r = host.deploy()
    assert r.returncode == 1
    assert "has no database" in r.stdout
    assert host.calls() == [] and not host.image_env.exists()


def test_a_profile_set_in_the_shell_cannot_turn_the_catch_up_worker_on(tmp_path: Path) -> None:
    host = DbHost(tmp_path)
    (host.state / "pgdata").mkdir()
    r = host.deploy(COMPOSE_PROFILES="db,reconcile")
    assert r.returncode == 0, r.stdout
    assert all("[profiles=db]" in c for c in host.calls())
