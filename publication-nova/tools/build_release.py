#!/usr/bin/env python3
"""Reproducible release archive: same sources -> byte-identical zip and checksums.

Usage: python tools/build_release.py [--out dist]
Writes <out>/nova-<version>.zip, <out>/SHA256SUMS and <out>/RELEASE.json. Nothing is uploaded or published.
"""
import argparse
import hashlib
import json
import os
import re
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXED_DATE = (2026, 10, 20, 0, 0, 0)
EXCLUDED_DIRS = {".local", "__pycache__", ".pytest_cache", ".venv", "dist", ".git", "build"}
EXCLUDED_SUFFIXES = (".pyc", ".sqlite3", ".sqlite3-wal", ".sqlite3-shm", ".token", ".pem", ".key", ".crt",
                     ".password", ".zip", ".egg-info", ".DS_Store", ".lock", ".log")
EXECUTABLE = ("Lancer Nova.command",)


def included(root):
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if path.is_dir() or EXCLUDED_DIRS & set(relative.parts) or path.name.endswith(EXCLUDED_SUFFIXES):
            continue
        yield relative


def version():
    return re.search(r'__version__ = "([^"]+)"', (ROOT / "novacoin" / "__init__.py").read_text()).group(1)


def build(root=ROOT, out="dist"):
    root, out = Path(root), Path(out)
    out.mkdir(parents=True, exist_ok=True)
    name = f"nova-{version()}"
    archive = out / f"{name}.zip"
    files = list(included(root))
    sys.path.insert(0, str(root))
    from novacoin.install_check import MANIFEST, manifest_lines
    files = [f for f in files if f.name != MANIFEST]
    manifest = manifest_lines(root, files)
    entries = {relative.as_posix(): (root / relative).read_bytes() for relative in files}
    entries[MANIFEST] = manifest.encode()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for path in sorted(entries):                       # one sorted listing, manifest included
            info = zipfile.ZipInfo(f"{name}/{path}", FIXED_DATE)
            info.create_system = 3
            executable = Path(path).name in EXECUTABLE or path.startswith("tools/") and path.endswith(".py")
            info.external_attr = (0o755 if executable else 0o644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, entries[path], compresslevel=9)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (out / "SHA256SUMS").write_text(f"{digest}  {archive.name}\n")
    sys.path.insert(0, str(root))
    from novacoin.core import NETWORK
    from novacoin.verify import source_digest
    release = {"version": version(), "network": NETWORK, "archive": archive.name, "sha256": digest,
               "files": len(files) + 1, "source_sha256": source_digest(root)}
    (out / "RELEASE.json").write_text(json.dumps(release, indent=2) + "\n")
    return release


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="dist")
    parser.add_argument("--sign-with", help="Fichier de clé de publication (mot de passe : NOVA_RELEASE_KEY_PASSWORD)")
    args = parser.parse_args()
    info = build(ROOT, args.out)
    if args.sign_with:
        from novacoin.release_sign import sign_file
        info["signature"] = str(sign_file(args.sign_with, os.environ["NOVA_RELEASE_KEY_PASSWORD"],
                                          Path(args.out) / info["archive"]).name)
    print(json.dumps(info, indent=2))
