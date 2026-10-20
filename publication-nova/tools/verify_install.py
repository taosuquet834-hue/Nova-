#!/usr/bin/env python3
"""Standalone check of an installed Nova folder against its MANIFEST.sha256 (standard library only).

It deliberately does not import novacoin: a tampered package must not be able to vouch for itself.
Run it from a copy you trust, and compare the MANIFEST.sha256 itself with the one in the signed release.
Usage: python tools/verify_install.py [folder]        exit code 0 = identical to the release
"""
import hashlib
import json
import sys
from pathlib import Path

IGNORED_DIRS = {".local", "__pycache__", ".pytest_cache", ".venv", "dist", ".git"}
IGNORED_SUFFIXES = (".pyc", ".sqlite3", ".sqlite3-wal", ".sqlite3-shm", ".log", ".lock", ".DS_Store")


def verify(root):
    root = Path(root)
    manifest = root / "MANIFEST.sha256"
    if not manifest.exists():
        raise SystemExit("MANIFEST.sha256 absent : ce dossier ne vient pas d'une archive publiée")
    expected = dict(line.split("  ", 1)[::-1] for line in manifest.read_text().splitlines() if line)
    changed = sorted(n for n, d in expected.items()
                     if (root / n).is_file() and hashlib.sha256((root / n).read_bytes()).hexdigest() != d)
    missing = sorted(n for n in expected if not (root / n).is_file())
    extra = sorted(p.relative_to(root).as_posix() for p in root.rglob("*")
                   if p.is_file() and p.name != "MANIFEST.sha256" and p.relative_to(root).as_posix() not in expected
                   and not (IGNORED_DIRS & set(p.relative_to(root).parts)) and not p.name.endswith(IGNORED_SUFFIXES))
    return changed, missing, extra


if __name__ == "__main__":
    folder = sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
    changed, missing, extra = verify(folder)
    print(json.dumps({"changed": changed, "missing": missing, "extra": extra}, ensure_ascii=False, indent=2))
    if changed or missing:
        print("DIFFÉRENT de l'archive publiée.", file=sys.stderr)
        sys.exit(1)
    print("Identique à l'archive publiée" + (" (fichiers en plus signalés)" if extra else "") + ".")
