"""Power-loss style test: kill -9 a mining node over and over; the database must always be consistent."""
import json
import os
import random
import signal
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from novacoin.core import Invalid
from novacoin.node import request_json
from novacoin.wallet import address, build_transaction

ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / "tools" / "independent_check.py"


def start(data, port):
    process = subprocess.Popen([sys.executable, "-m", "novacoin", "node", "--data", str(data), "--port", str(port),
                                "--p2p-port", str(port + 1)], cwd=ROOT, env={**os.environ, "NOVA_EASY": "1"},
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(150):
        try:
            request_json(f"http://127.0.0.1:{port}/api/status")
            return process
        except Invalid:
            time.sleep(0.1)
    process.kill()
    pytest.fail("node did not start")


def snapshot_and_check(data, target):
    """Consistent copy of the database (as SQLite would recover it), then SQLite and protocol checks."""
    src = sqlite3.connect(f"file:{data / 'chain.sqlite3'}?mode=ro", uri=True)
    dst = sqlite3.connect(target)
    src.backup(dst)
    assert dst.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    dst.close(); src.close()
    done = subprocess.run([sys.executable, str(CHECK), str(target)], text=True, capture_output=True,
                          env={**os.environ, "NOVA_EASY": "1"})
    assert done.returncode == 0, done.stdout + done.stderr
    return done.stdout


def test_kill_nine_while_mining_and_paying_never_corrupts_the_database(tmp_path):
    rng, key, data = random.Random(3), Ed25519PrivateKey.generate(), tmp_path / "node"
    port = 43000 + os.getpid() % 400
    heights = []
    for round_number in range(8):
        process = start(data, port)
        token = (data / "admin.token").read_text().strip()
        base = f"http://127.0.0.1:{port}"
        request_json(base + "/api/automine", {"enabled": True, "address": address(key)}, token)
        deadline = time.time() + rng.uniform(0.4, 1.6)
        while time.time() < deadline:                       # payments keep the mempool and the database busy
            try:
                coins = request_json(base + "/api/balance?address=" + address(key))["utxos"]
                request_json(base + "/api/transactions", build_transaction(
                    key, coins, address(Ed25519PrivateKey.generate()), 10 ** 8, 200_000))
            except Invalid:
                pass
            time.sleep(0.05)
        process.send_signal(signal.SIGKILL)                  # no chance to close anything cleanly
        process.wait()
        out = snapshot_and_check(data, tmp_path / f"snap{round_number}.sqlite3")
        heights.append(int(out.split("hauteur ")[1].split(",")[0]))
    assert heights == sorted(heights) and heights[-1] > heights[0]      # progress survived every crash
    process = start(data, port)                                          # and a final normal start still works
    try:
        assert request_json(f"http://127.0.0.1:{port}/api/status")["height"] >= heights[-1]
    finally:
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=30)
