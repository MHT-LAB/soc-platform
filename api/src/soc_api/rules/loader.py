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
    # Where the file sits for classification: `rel`, with orgs/ and orgs/<org>/ put back in
    # front when the scanned directory is one of those. Empty means the same as `rel`.
    place: str = ""

    @property
    def where(self) -> str:
        return self.place or self.rel


@dataclass(frozen=True)
class Problem:
    file: str
    message: str

    def __str__(self) -> str:
        return f"{self.file}: {self.message}"


def context_prefix(root: Path) -> list[str]:
    """The folders above `root` that decide what its files are: ["orgs"] when root is the
    folder of org folders, ["orgs", <org>] when root is one org's folder, else nothing. Only the
    scanned folder and its parent are looked at, so a deeper scan root is never an overlay."""
    resolved = root.resolve()
    if resolved.name == "orgs":
        return ["orgs"]
    if resolved.parent.name == "orgs":
        return ["orgs", resolved.name]
    return []


def load_tree(root: Path) -> list[RuleFile]:
    """Every *.json under root, in a fixed order. A file that is not valid JSON is kept, with
    its error, so it is reported rather than skipped."""
    prefix = context_prefix(root)
    found: list[RuleFile] = []
    for path in sorted(root.rglob("*.json")):
        rel = path.relative_to(root).as_posix()
        place = "/".join([*prefix, rel]) if prefix else ""
        try:
            found.append(RuleFile(rel, json.loads(path.read_text(encoding="utf-8")), "", place))
        except (OSError, ValueError) as exc:
            found.append(RuleFile(rel, None, f"cannot be read as JSON: {exc}", place))
    return found
