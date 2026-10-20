"""V11 (second set): self-test, file permissions, route limits, bandwidth budget, install manifest, token rotation."""
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from helpers import call
from novacoin import selftest
from novacoin.core import Invalid
from novacoin.install_check import verify_install
from novacoin.node import Node
from novacoin.p2p import RateLimiter
from test_network import network  # noqa: F401  (fixture)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import build_release  # noqa: E402


def test_selftest_passes_and_detects_a_broken_primitive(monkeypatch):
    selftest.run_selftest()
    monkeypatch.setattr(selftest, "ED_SIGNATURE", b"\x00" * 64)
    with pytest.raises(Invalid, match="Ed25519"):
        selftest.run_selftest()
    monkeypatch.undo()
    monkeypatch.setattr(selftest, "SHA256_ABC", "00" * 32)
    with pytest.raises(Invalid, match="SHA-256"):
        selftest.run_selftest()


def test_node_refuses_to_start_when_the_selftest_fails(tmp_path, monkeypatch):
    from novacoin import node as module

    def broken():
        raise Invalid("Auto-test : simulé")
    monkeypatch.setattr(module, "run_selftest", broken)
    with pytest.raises(Invalid, match="Auto-test"):
        Node(tmp_path / "n")
    assert not (tmp_path / "n" / "chain.sqlite3").exists()          # nothing was created


def test_loose_permissions_are_repaired_and_reported(tmp_path):
    node = Node(tmp_path / "n")
    node.close()
    for path in (tmp_path / "n" / "node.key", tmp_path / "n" / "admin.token"):
        path.chmod(0o644)
    (tmp_path / "n").chmod(0o755)
    again = Node(tmp_path / "n")
    try:
        assert (tmp_path / "n").stat().st_mode & 0o077 == 0
        assert (tmp_path / "n" / "node.key").stat().st_mode & 0o077 == 0
        assert (tmp_path / "n" / "admin.token").stat().st_mode & 0o077 == 0
        event = next(e for e in again.events() if e["kind"] == "permissions_fixed")
        assert set(event["details"]["files"]) == {"n", "node.key", "admin.token"}
    finally:
        again.close()


def test_route_specific_body_limits(network):
    nodes, _, _, _ = network
    url = nodes[0].p2p_url
    with pytest.raises(Invalid, match="Taille"):
        call(url, "/p2p/transactions", {"x": "y" * 25_000})              # a payment is at most 16 000 bytes
    with pytest.raises(Invalid, match="Taille"):
        call(url, "/p2p/status", {"x": "y" * 5_000})                      # routes that take no body get a tiny budget


def test_download_bandwidth_is_budgeted_per_peer(network):
    nodes, _, _, _ = network
    node, url = nodes[0], nodes[0].p2p_url
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from novacoin.wallet import address
    key = Ed25519PrivateKey.generate()
    for _ in range(5):
        node.mine_one(address(key))
    from helpers import identity
    who = identity()
    node.bandwidth_limiter = RateLimiter(capacity=3_000, per_second=0.001)      # room for about one small batch
    answers = []
    for _ in range(4):
        try:
            answers.append(len(call(url, "/p2p/blocks?from=0&limit=6", who=who)["blocks"]))
        except Invalid as exc:
            answers.append(str(exc))
    assert answers[0] == 6 and "Débit" in answers[-1]
    assert call(url, "/p2p/hashes?from=0&limit=6", who=who)["hashes"]           # small answers still pass
    other = call(url, "/p2p/blocks?from=0&limit=1", who=identity())              # another peer has its own budget
    assert len(other["blocks"]) == 1


def test_ratelimiter_cost_is_capped_by_capacity():
    limiter = RateLimiter(capacity=10, per_second=1)
    assert limiter.allow("k", now=0, cost=1000)            # an oversized request can still use a full bucket
    assert not limiter.allow("k", now=0.1, cost=5)
    assert limiter.allow("k", now=6, cost=5)


# ------------------------------------------------------------------ installation manifest

def test_release_contains_a_manifest_that_detects_changes(tmp_path):
    info = build_release.build(ROOT, tmp_path / "out")
    archive = tmp_path / "out" / info["archive"]
    with zipfile.ZipFile(archive) as zf:
        zf.extractall(tmp_path / "x")
    root = tmp_path / "x" / f"nova-{info['version']}"
    assert verify_install(root) == ([], [], [])
    (root / "novacoin" / "core.py").write_text((root / "novacoin" / "core.py").read_text() + "\n# backdoor\n")
    (root / "novacoin" / "wallet.py").unlink()
    (root / "novacoin" / "extra.py").write_text("print('hi')\n")
    changed, missing, extra = verify_install(root)
    assert changed == ["novacoin/core.py"] and missing == ["novacoin/wallet.py"] and extra == ["novacoin/extra.py"]
    # the standalone script (stdlib only) still works although a module was deleted and another doctored
    done = subprocess.run([sys.executable, str(ROOT / "tools" / "verify_install.py"), str(root)],
                          text=True, capture_output=True)
    assert done.returncode == 1 and "DIFFÉRENT" in done.stderr and "novacoin/core.py" in done.stdout
    clean = tmp_path / "clean"
    with zipfile.ZipFile(archive) as zf:
        zf.extractall(clean)
    good = subprocess.run([sys.executable, str(ROOT / "tools" / "verify_install.py"), str(clean / f"nova-{info['version']}")],
                          text=True, capture_output=True)
    assert good.returncode == 0 and "Identique" in good.stdout
    with pytest.raises(Invalid, match="absent"):
        verify_install(tmp_path)


def test_build_stays_reproducible_with_the_manifest(tmp_path):
    first, second = build_release.build(ROOT, tmp_path / "a"), build_release.build(ROOT, tmp_path / "b")
    assert first["sha256"] == second["sha256"]


# ------------------------------------------------------------------ token rotation

def test_token_rotation_replaces_the_token_only_when_the_node_is_stopped(tmp_path):
    node = Node(tmp_path / "n")
    old = node.token
    run = lambda: subprocess.run([sys.executable, "-m", "novacoin", "token-rotate", "--data", str(tmp_path / "n")],
                                 cwd=ROOT, text=True, capture_output=True)
    busy = run()
    assert busy.returncode == 1 and "Arrêter le nœud" in busy.stderr
    assert (tmp_path / "n" / "admin.token").read_text().strip() == old
    node.close()
    done = run()
    assert done.returncode == 0
    new = (tmp_path / "n" / "admin.token").read_text().strip()
    assert new != old and len(new) >= 32 and (tmp_path / "n" / "admin.token").stat().st_mode & 0o077 == 0
    again = Node(tmp_path / "n")
    try:
        assert again.token == new
    finally:
        again.close()
