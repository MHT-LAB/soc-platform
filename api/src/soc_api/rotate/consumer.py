"""What the apply step does on the host for one consumer: rewrite its env file, recreate its
service, run its health check.

The env file is replaced whole (written to a temporary file, flushed, renamed) with the same
owner and mode, and the old file is kept as `<name>.prev` until the run is over, so a failed
check can put it straight back. Services are recreated, not restarted: an env file is read
when a container is created. Health checks are chosen by name from `CHECKS`; a key file can
never carry a command. Child processes get no standard input (the rights came in on it) and
a minimal environment; their output is discarded, only the exit code is used.
"""

import os
import re
import stat
import subprocess
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from soc_api.rotate.keys import ENV_FILE_RE, ENV_RE, SERVICE_RE, SUPPORTED_CHECKS
from soc_api.rotate.net import RotateError
from soc_api.rotate.rights import Secret

# The form every consumer file holds for a key (the init scripts check the same one).
VALUE_RE = re.compile(r"[A-Za-z0-9._-]{16,128}")
# name -> (compose service to run it in, the command in that container)
CHECKS: dict[str, tuple[str, tuple[str, ...]]] = {
    "posture_check": ("posture", ("python", "-m", "soc_api.posture", "check")),
}
RESTART_TIMEOUT_S = 300
CHECK_TIMEOUT_S = 240
KEPT_ENV = ("PATH", "HOME", "SOC_STATE_DIR", "SOC_OVERLAY")

assert set(CHECKS) == set(SUPPORTED_CHECKS)  # noqa: S101 - one list in two places must agree


def _sync_dir(folder: Path) -> None:
    fd = os.open(folder, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_new(path: Path, text: str, like: os.stat_result) -> None:
    """Create `path` (it must not exist) with the original's owner and mode, flushed."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        if os.geteuid() == 0:
            os.fchown(fd, like.st_uid, like.st_gid)
        os.fchmod(fd, stat.S_IMODE(like.st_mode))
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


class HostConsumer:
    def __init__(
        self,
        state_root: Path,
        compose: Path,
        *,
        run: Callable[..., Any] = subprocess.run,
        environ: Mapping[str, str] = os.environ,
    ) -> None:
        self._root = state_root
        self._compose = compose
        self._run = run
        self._env = {k: environ[k] for k in KEPT_ENV if k in environ}

    def _path(self, env_file: str) -> Path:
        if not ENV_FILE_RE.fullmatch(env_file):
            raise RotateError("bad_env_file")
        return self._root / env_file

    def install(self, env_file: str, var: str, value: Secret) -> None:
        """Replace the one variable; keep everything else byte for byte; keep the old file."""
        if not ENV_RE.fullmatch(var) or not VALUE_RE.fullmatch(value.reveal()):
            raise RotateError("bad_value")
        path = self._path(env_file)
        prev = Path(f"{path}.prev")
        if prev.exists():
            raise RotateError("prev_exists")  # a leftover from a failed run: look at it first
        try:
            original = path.read_text(encoding="utf-8")
            info = path.stat()
        except (OSError, UnicodeDecodeError):
            raise RotateError("env_unreadable") from None
        lines = original.split("\n")
        hits = [i for i, line in enumerate(lines) if line.startswith(f"{var}=")]
        if len(hits) != 1:
            raise RotateError("env_var_missing" if not hits else "env_var_twice")
        lines[hits[0]] = f"{var}={value.reveal()}"
        staged = path.with_name(f".{path.name}.new")
        try:
            _write_new(prev, original, info)
            staged.unlink(missing_ok=True)
            _write_new(staged, "\n".join(lines), info)
            os.replace(staged, path)
            _sync_dir(path.parent)
        except OSError:
            staged.unlink(missing_ok=True)
            prev.unlink(missing_ok=True)
            raise RotateError("env_write_failed") from None
        # Read it back. If the file does not hold the new value, the health check would pass on
        # the OLD key and the old key would then be revoked under a working-looking service.
        try:
            now_holds = [
                ln
                for ln in path.read_text(encoding="utf-8").split("\n")
                if ln.startswith(f"{var}=")
            ]
        except (OSError, UnicodeDecodeError):
            now_holds = []
        if now_holds != [f"{var}={value.reveal()}"]:
            staged.unlink(missing_ok=True)
            try:
                os.replace(prev, path)
            except OSError:
                pass  # the caller's rollback reports what is left
            raise RotateError("env_readback_failed")

    def restore(self, env_file: str) -> None:
        path = self._path(env_file)
        prev = Path(f"{path}.prev")
        try:
            os.replace(prev, path)
            _sync_dir(path.parent)
        except OSError:
            raise RotateError("restore_failed") from None

    def discard_prev(self, env_file: str) -> None:
        Path(f"{self._path(env_file)}.prev").unlink(missing_ok=True)

    def _compose_run(self, args: Sequence[str], timeout: int) -> bool:
        try:
            done = self._run(  # noqa: S603 - fixed argv built from validated names
                [str(self._compose), *args],
                env=self._env,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return False
        except OSError:
            raise RotateError("cannot_run") from None
        return bool(done.returncode == 0)

    def restart(self, services: Sequence[str]) -> None:
        for svc in services:
            if not SERVICE_RE.fullmatch(svc):
                raise RotateError("bad_service")
            if not self._compose_run(
                ["up", "-d", "--force-recreate", "--no-deps", svc], RESTART_TIMEOUT_S
            ):
                raise RotateError("restart_failed")

    def check(self, name: str) -> bool:
        if name not in CHECKS:
            raise RotateError("no_such_check")
        service, command = CHECKS[name]
        return self._compose_run(["run", "--rm", "-T", service, *command], CHECK_TIMEOUT_S)
