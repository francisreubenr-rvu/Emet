from __future__ import annotations

from pathlib import Path


def resolve_local_path(path_value: str, *, allowed_root: str, expect_file: bool = True) -> tuple[str | None, str]:
    candidate = Path(path_value).expanduser().resolve()
    root = Path(allowed_root).expanduser().resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None, "Path is outside allowed root"
    if expect_file and (not candidate.exists() or not candidate.is_file()):
        return None, "File path not found"
    if not expect_file and (not candidate.exists() or not candidate.is_dir()):
        return None, "Directory path not found"
    return str(candidate), "ok"


def write_scanner_artifact(*, scan_id: str, scanner: str, payload: str, suffix: str) -> str:
    base = Path("artifacts") / scan_id
    base.mkdir(parents=True, exist_ok=True)
    path = base / f"{scanner}.{suffix}"
    path.write_text(payload or "", encoding="utf-8")
    return str(path)
