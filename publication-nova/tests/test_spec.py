"""The specification is sufficient: an implementation written from PROTOCOLE.md alone agrees with the node."""
import os
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from novacoin.core import UNIT, block_id
from novacoin.node import Node
from novacoin.wallet import address, build_transaction

ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / "tools" / "independent_check.py"


def run_check(database):
    env = {**os.environ, "NOVA_EASY": "1"}
    return subprocess.run([sys.executable, str(CHECK), str(database)], env=env, text=True, capture_output=True)


def snapshot(source, target):
    """Consistent copy of a live node database (its recent data may still sit in the WAL file)."""
    src = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
    dst = sqlite3.connect(target)
    src.backup(dst)
    dst.close()
    src.close()
    return target


@pytest.fixture(scope="module")
def database(tmp_path_factory):
    """A chain with payments, a split transaction and more than one difficulty window."""
    path = tmp_path_factory.mktemp("spec") / "node"
    node = Node(path)
    alice, bob, carol = (Ed25519PrivateKey.generate() for _ in range(3))
    try:
        for _ in range(6):
            node.mine_one(address(alice))
        node.submit(build_transaction(alice, node.balance(address(alice))["utxos"], address(bob), 12 * UNIT, 200_000))
        node.mine_one(address(bob))
        node.submit(build_transaction(bob, node.balance(address(bob))["utxos"], address(carol), 3 * UNIT, 300_000))
        for _ in range(30):                                   # crosses at least one retargeting boundary
            node.mine_one(address(carol))
        yield snapshot(path / "chain.sqlite3", path.parent / "snapshot.sqlite3"), node
    finally:
        node.close()


def test_independent_implementation_accepts_the_real_chain(database):
    path, node = database
    result = run_check(path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert f"hauteur {node.status()['height']}" in result.stdout
    assert block_id(node.chain[-1]) in result.stdout and str(node.work) in result.stdout
    assert any(b["target"] != node.chain[1]["target"] for b in node.chain[1:])     # difficulty really moved


@pytest.mark.parametrize("tamper", ["reward", "timestamp", "signature", "merkle", "target"])
def test_independent_implementation_rejects_tampering(database, tmp_path, tamper):
    import json
    path, node = database
    copy = tmp_path / "t.sqlite3"
    shutil.copy(path, copy)               # `path` is already a consistent snapshot
    db = sqlite3.connect(copy)
    height = 8
    block = json.loads(db.execute("SELECT payload FROM blocks WHERE height=?", (height,)).fetchone()[0])
    if tamper == "reward" and block["transactions"][0]["outputs"]:
        block["transactions"][0]["outputs"][0]["amount"] += 1
    elif tamper == "timestamp":
        block["timestamp"] -= 10_000
    elif tamper == "merkle":
        block["merkle_root"] = "f" * 64
    elif tamper == "target":
        block["target"] //= 2
    elif tamper == "signature":
        height = 7                                              # the block holding the first payment
        block = json.loads(db.execute("SELECT payload FROM blocks WHERE height=?", (height,)).fetchone()[0])
        payment = [t for t in block["transactions"] if t.get("type") != "coinbase"]
        if not payment:
            pytest.skip("no payment in this block")
        payment[0]["signature"] = "00" * 64
    db.execute("UPDATE blocks SET payload=? WHERE height=?", (json.dumps(block), height))
    db.commit()
    db.close()
    result = run_check(copy)
    assert result.returncode == 1 and "INVALIDE" in result.stdout


def test_wrong_network_or_missing_file_fails_cleanly(database, tmp_path):
    path, _ = database
    env = {k: v for k, v in os.environ.items() if k != "NOVA_EASY"}          # real-network constants
    result = subprocess.run([sys.executable, str(CHECK), str(path)], env=env, text=True, capture_output=True)
    assert result.returncode == 1 and "genesis" in result.stdout
    assert subprocess.run([sys.executable, str(CHECK)], text=True, capture_output=True).returncode == 2


def test_spec_constants_match_the_implementation():
    from novacoin import core
    text = (ROOT / "PROTOCOLE.md").read_text()
    for needle in (core.NETWORK.replace("-easy", ""), "60 secondes", "256 000", "NOVA-TX-V1", "NOVA-P2P-V4",
                   "210 000", "21 000 000", "60 s"):
        assert needle in text
    assert core.ADJUST_INTERVAL == 20 and core.MAX_FUTURE_SECONDS == 60 and core.COINBASE_MATURITY == 2
    assert core.BLOCK_VERSION == 2 and core.TX_VERSION == 1 and core.MAX_BLOCK_TXS == 200
