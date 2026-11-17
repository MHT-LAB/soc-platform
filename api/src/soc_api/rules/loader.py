"""Finding and reading rule files, and the problem report both checks produce."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class RuleFile:
    rel: str  # path relative to the scanned directory, with forward slashes
    data: Any  # the parsed JSON; empty when `error` is set
    error: str = ""


@dataclass(frozen=True)
class Problem:
    file: str
    message: str

    def __str__(self) -> str:
        return f"{self.file}: {self.message}"


def load_tree(root: Path) -> list[RuleFile]:
    """Every *.json under root, in a fixed order. A file that is not valid JSON is kept, with
    its error, so it is reported rather than skipped."""
    found: list[RuleFile] = []
    for path in sorted(root.rglob("*.json")):
        rel = path.relative_to(root).as_posix()
        try:
            found.append(RuleFile(rel, json.loads(path.read_text(encoding="utf-8"))))
        except (OSError, ValueError) as exc:
            found.append(RuleFile(rel, None, f"cannot be read as JSON: {exc}"))
    return found
