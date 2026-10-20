"""Check an installed copy against the MANIFEST.sha256 shipped in the release archive."""
from __future__ import annotations

import hashlib
from pathlib import Path

from .core import Invalid

MANIFEST = "MANIFEST.sha256"
IGNORED_DIRS = {".local", "__pycache__", ".pytest_cache", ".venv", "dist", ".git"}
IGNORED_SUFFIXES = (".pyc", ".sqlite3", ".sqlite3-wal", ".sqlite3-shm", ".log", ".lock", ".DS_Store")


def manifest_lines(root, files):
    return "".join(f"{hashlib.sha256((Path(root) / f).read_bytes()).hexdigest()}  {f.as_posix()}\n" for f in files)


def verify_install(root):
    """Return (changed, missing, extra) relative paths; all empty means the copy is the released one."""
    root = Path(root)
    path = root / MANIFEST
    if not path.exists():
        raise Invalid(f"{MANIFEST} absent : ce dossier ne vient pas d'une archive publiée")
    expected = {}
    for line in path.read_text().splitlines():
        digest, _, name = line.partition("  ")
        expected[name] = digest
    changed, missing = [], []
    for name, digest in expected.items():
        file = root / name
        if not file.is_file():
            missing.append(name)
        elif hashlib.sha256(file.read_bytes()).hexdigest() != digest:
            changed.append(name)
    extra = sorted(p.relative_to(root).as_posix() for p in root.rglob("*")
                   if p.is_file() and p.name != MANIFEST and p.relative_to(root).as_posix() not in expected
                   and not (IGNORED_DIRS & set(p.relative_to(root).parts)) and not p.name.endswith(IGNORED_SUFFIXES))
    return sorted(changed), sorted(missing), extra
