"""Shared helpers for the key rotation tests: fake key files, a throwaway register folder."""

from pathlib import Path

COMMIT = "ab" * 20


def key_text(
    key_id: str,
    *,
    method: str = "manual",
    sensitive: bool = False,
    period: int | None = -1,
    ready: bool | None = None,
    name: str = "A key",
    check: str = "Prove it works",
    extra: str = "",
) -> str:
    """One valid key file as the private register writes it (period -1 = the right default)."""
    if period == -1:
        period = (30 if sensitive else 90) if method != "none" else None
    lines = [
        f'id = "{key_id}"',
        f'name = "{name}"',
        'vendor = "limacharlie"',
        f'method = "{method}"',
        f"sensitive = {str(sensitive).lower()}",
        'console_name = "x"',
        'purpose = "x"',
    ]
    if period is not None:
        lines.append(f"period_days = {period}")
    if ready is not None:
        lines.append(f"ready = {str(ready).lower()}")
    if extra:
        lines.append(extra)
    if method == "manual":
        lines += ["", "[manual]", 'consumers = "somewhere"', f'check = "{check}"', 'how = "steps"']
    return "\n".join(lines) + "\n"


def make_register(root: Path, files: dict[str, str]) -> Path:
    """A folder of key files: {"posture": text} becomes posture.toml."""
    folder = root / "keys"
    folder.mkdir(exist_ok=True)
    for stem, text in files.items():
        (folder / f"{stem}.toml").write_text(text)
    return folder
