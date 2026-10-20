#!/usr/bin/env python3
"""Compare the memory used by two Nova versions opening the same long chain.

Usage: python tools/measure_memory.py --blocks 20000 --versions DIR_A DIR_B
Builds one database with the code of the first folder, then starts a fresh process per folder and reports the
peak resident memory after the node has loaded and validated the chain. Uses the easy laboratory network.
"""
import argparse
import os
import subprocess
import sys
import tempfile
import time

BUILD = """
import sys, time
sys.path.insert(0, {root!r})
from novacoin import core
class Clock:
    now = int(time.time()) - 10_000_000
    def time(self): return self.now
    def __getattr__(self, name): return getattr(time, name)
core.time = Clock()
from novacoin.node import Node
from novacoin.wallet import address
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
node, key = Node({data!r}), Ed25519PrivateKey.generate()
for _ in range({blocks}):
    core.time.now += 10
    node.mine_one(address(key))
node.close()
"""

MEASURE = """
import resource, sys, time
sys.path.insert(0, {root!r})
from novacoin.node import Node
started = time.time()
node = Node({data!r})
seconds = time.time() - started
peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
peak = peak / 1024 if sys.platform != "darwin" else peak / (1024 * 1024)
print("%d %.0f %.1f" % (node.status()["height"], peak, seconds))
node.close()
"""


def run(code, **kw):
    env = {**os.environ, "NOVA_EASY": "1", "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run([sys.executable, "-c", code.format(**kw)], env=env, text=True, capture_output=True, check=True).stdout


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--blocks", type=int, default=20000)
    parser.add_argument("--versions", nargs="+", required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        started = time.time()
        run(BUILD, root=os.path.abspath(args.versions[-1]), data=tmp + "/node", blocks=args.blocks)
        print(f"chaîne de {args.blocks} blocs construite en {time.time() - started:.0f} s")
        for folder in args.versions:
            height, peak, seconds = run(MEASURE, root=os.path.abspath(folder), data=tmp + "/node").split()
            print(f"{os.path.basename(os.path.abspath(folder)):<14} hauteur {height}  mémoire maximale {peak} Mo  démarrage {seconds} s")
