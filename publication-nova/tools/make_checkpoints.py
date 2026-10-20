#!/usr/bin/env python3
"""Export official checkpoints (every 100th block buried at least 50 deep) from a node database.

Usage: python tools/make_checkpoints.py chain.sqlite3 > checkpoints.json
Load them on other nodes with:  python -m novacoin node ... --checkpoints-file checkpoints.json
Publish the file next to a release only after checking the hashes against several independent nodes.
"""
import hashlib
import json
import sqlite3
import sys


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                                     allow_nan=False).encode()).hexdigest()


def main(path):
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    blocks = [json.loads(r[0]) for r in db.execute("SELECT payload FROM blocks ORDER BY height")]
    tip = len(blocks) - 1
    keys = ("version", "network", "height", "previous", "timestamp", "target", "nonce", "merkle_root")
    return {str(h): digest({k: blocks[h][k] for k in keys}) for h in range(100, tip - 49, 100)}


if __name__ == "__main__":
    print(json.dumps(main(sys.argv[1]), indent=2))
