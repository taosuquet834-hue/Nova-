"""V11: hardening that needs no outside help (key encryption, persistent bans, anti-eclipse limits,
automatic checkpoints, reorganisation evidence, alerts, signed journal, backups, release signing)."""
import copy
import hashlib
import json
import os
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from helpers import call
from novacoin import core
from novacoin.attack_bench import SimulatedClock
from novacoin.core import Invalid
from novacoin.hdwallet import HDWallet
from novacoin.node import Node, NodeServer, PeerServer, request_json
from novacoin.p2p import key_is_encrypted, protect_key
from novacoin.release_sign import generate_release_key, sign_file, verify_file
from novacoin.wallet import address

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = "un mot de passe long 123"


@pytest.fixture(autouse=True)
def no_env_password(monkeypatch):
    for name in ("NOVA_NODE_PASSWORD", "NOVA_NODE_PASSWORD_FILE"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def clock(monkeypatch):
    """Blocks come every 10 simulated seconds, so the difficulty stays put on long chains."""
    sim = SimulatedClock()
    monkeypatch.setattr(core, "time", sim)
    return sim


def mine(node, key, count=1, clock=None):
    for _ in range(count):
        if clock:
            clock.now += core.TARGET_SECONDS
        node.mine_one(address(key))


# ------------------------------------------------------------------ encrypted identity key

def test_node_key_can_be_encrypted_and_tls_still_works(tmp_path):
    node = Node(tmp_path / "a", key_password=PASSWORD)
    node_id = node.node_id
    server = PeerServer(("127.0.0.1", 0), node)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        assert node.key_encrypted and key_is_encrypted(tmp_path / "a")
        assert b"ENCRYPTED" in (tmp_path / "a" / "node.key").read_bytes()
        assert call(f"https://127.0.0.1:{server.server_port}", "/p2p/status", expected=node_id)["network"]
        assert node.status()["security"]["key_encrypted"] is True
    finally:
        server.shutdown(); server.server_close(); node.close()
    with pytest.raises(Invalid, match="chiffrée"):
        Node(tmp_path / "a")
    with pytest.raises(Invalid, match="incorrect"):
        Node(tmp_path / "a", key_password="mauvais mot de passe 1")
    again = Node(tmp_path / "a", key_password=PASSWORD)
    try:
        assert again.node_id == node_id                             # same identity after restart
    finally:
        again.close()


def test_protect_and_unprotect_an_existing_key(tmp_path):
    plain = Node(tmp_path / "a")
    node_id = plain.node_id
    plain.close()
    assert not key_is_encrypted(tmp_path / "a")
    protect_key(tmp_path / "a", PASSWORD)
    assert key_is_encrypted(tmp_path / "a") and (tmp_path / "a" / "node.key").stat().st_mode & 0o077 == 0
    with pytest.raises(Invalid):
        protect_key(tmp_path / "a", "autre mot de passe 123", "mauvais mot de passe 1")
    protect_key(tmp_path / "a", None, PASSWORD)
    again = Node(tmp_path / "a")
    try:
        assert again.node_id == node_id and not again.key_encrypted
    finally:
        again.close()


def test_cli_key_protect_then_start_with_password_file(tmp_path):
    data = tmp_path / "n"
    Node(data).close()
    env = {**os.environ, "NOVA_EASY": "1", "NOVA_NEW_NODE_PASSWORD": PASSWORD}
    done = subprocess.run([sys.executable, "-m", "novacoin", "key-protect", "--data", str(data)], cwd=ROOT,
                          env=env, text=True, capture_output=True)
    assert done.returncode == 0 and key_is_encrypted(data)
    short = subprocess.run([sys.executable, "-m", "novacoin", "key-protect", "--data", str(data)], cwd=ROOT,
                           env={**env, "NOVA_NEW_NODE_PASSWORD": "court", "NOVA_NODE_PASSWORD": PASSWORD},
                           text=True, capture_output=True)
    assert short.returncode == 1 and "12 caractères" in short.stderr
    port = 42000 + os.getpid() % 500
    base = [sys.executable, "-m", "novacoin", "node", "--data", str(data), "--port", str(port), "--p2p-port", str(port + 1)]
    refused = subprocess.run(base, cwd=ROOT, env={k: v for k, v in env.items() if k != "NOVA_NEW_NODE_PASSWORD"},
                             text=True, capture_output=True, timeout=30)
    assert refused.returncode == 1 and "chiffrée" in refused.stderr
    secret = tmp_path / "pw"
    secret.write_text(PASSWORD)
    process = subprocess.Popen(base, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env={**env, "NOVA_NODE_PASSWORD_FILE": str(secret)})
    try:
        for _ in range(100):
            try:
                assert request_json(f"http://127.0.0.1:{port}/api/status")["security"]["key_encrypted"] is True
                break
            except Invalid:
                time.sleep(0.2)
        else:
            pytest.fail("node did not start")
    finally:
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=20)
    assert process.returncode == 0


# ------------------------------------------------------------------ persistent bans

def test_bans_survive_a_restart_and_expired_ones_do_not(tmp_path):
    offender = "ab" * 32
    node = Node(tmp_path / "n")
    node.penalize(None, offender, 500, "test")
    assert node.is_banned(None, offender)
    with node.db:
        node.db.execute("INSERT INTO bans VALUES('id', ?, ?)", ("cd" * 32, int(time.time()) - 5))   # long expired
    node.close()
    again = Node(tmp_path / "n")
    try:
        assert again.is_banned(None, offender) and not again.is_banned(None, "cd" * 32)
        assert again.status()["security"]["bans"][0]["key"] == offender
    finally:
        again.close()


# ------------------------------------------------------------------ anti-eclipse limits

def test_discovery_is_limited_per_network_and_reserves_half_the_table(tmp_path):
    node = Node(tmp_path / "n")
    try:
        node.add_peer("https://192.168.5.1:2000")                      # chosen by the operator: not limited
        node.add_peer("https://192.168.5.2:2000")
        assert not node._may_add_peer("https://192.168.5.3:2000", "a1" * 32)        # third in the same /16
        assert node._may_add_peer("https://10.5.5.3:2000", "a1" * 32)                  # another /16 is fine
        assert node._may_add_peer("https://127.0.0.1:2001", "a2" * 32)               # loopback lab is exempt
        assert node._may_add_peer("https://127.0.0.1:2002", "a3" * 32)
        for i in range(8):
            node._remember_discovered(f"https://10.{i}.0.1:2000")
        assert not node._may_add_peer("https://172.16.0.9:2000", "a4" * 32)          # discovered slots are full
    finally:
        node.close()
    again = Node(tmp_path / "n")
    try:
        assert len(again.discovered) == 8                                           # persisted
    finally:
        again.close()


# ------------------------------------------------------------------ automatic checkpoints and reorg evidence

def fork(tmp_path, clock, shared, own, other, **kwargs):
    """Node a (limits as given) and node b share `shared` blocks, then mine `own` and `other` blocks apart."""
    key, rival = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    a, b = Node(tmp_path / "a", **kwargs), Node(tmp_path / "b", max_reorg=0)
    mine(a, key, shared, clock)
    assert b.adopt(copy.deepcopy(a.chain))
    base = clock.now
    mine(a, key, own, clock)
    clock.now = base
    mine(b, rival, other, clock)
    clock.now += 10_000
    return a, b


def test_automatic_checkpoints_are_recorded_persisted_and_enforced(tmp_path, clock):
    a, b = fork(tmp_path, clock, shared=95, own=70, other=130, max_reorg=200)       # fork below block 100
    try:
        assert a.auto_checkpoints == {100: a.ids[100]}                              # block 100 is buried 65 deep
        assert a.status()["security"]["auto_checkpoints"] == 1
        with pytest.raises(Invalid, match="point de contrôle"):                     # heavier, within the limit, but rewrites block 100
            a.adopt(copy.deepcopy(b.chain))
        assert a.status()["height"] == 165
        a.set_max_reorg(0)                                                          # explicit administrator override
        assert a.adopt(copy.deepcopy(b.chain)) and a.status()["tip"] == b.status()["tip"]
        assert any(e["kind"] == "autocheckpoint_reset" for e in a.events())
        assert a.auto_checkpoints == {100: a.ids[100]}                              # re-recorded on the new chain
    finally:
        a.close(); b.close()


def test_make_checkpoints_tool_agrees_with_the_node(tmp_path, clock):
    node, key = Node(tmp_path / "n"), Ed25519PrivateKey.generate()
    try:
        mine(node, key, 260, clock)
        snapshot = tmp_path / "snap.sqlite3"
        src = sqlite3.connect(f"file:{tmp_path / 'n' / 'chain.sqlite3'}?mode=ro", uri=True)
        dst = sqlite3.connect(snapshot); src.backup(dst); dst.close(); src.close()
        out = subprocess.run([sys.executable, str(ROOT / "tools" / "make_checkpoints.py"), str(snapshot)],
                             text=True, capture_output=True)
        exported = {int(h): d for h, d in json.loads(out.stdout).items()}
        assert exported == node.auto_checkpoints and set(exported) == {100, 200}
    finally:
        node.close()


def test_reorg_evidence_margin_grows_with_depth(tmp_path, clock):
    a, b = fork(tmp_path, clock, shared=5, own=15, other=16)                        # 15 erased, only ~7 % more work on the branch
    try:
        with pytest.raises(Invalid, match="au moins 10 %"):
            a.adopt(copy.deepcopy(b.chain))
        assert any(e["kind"] == "reorg_refused" for e in a.events())
        a.max_reorg = 0                                                             # the margin is part of the default policy only
        assert a.adopt(copy.deepcopy(b.chain))
    finally:
        a.close(); b.close()
    clock.now = SimulatedClock().now
    a, b = fork(tmp_path / "x", clock, shared=5, own=8, other=12)                   # +50 % on the branch: accepted
    try:
        assert a.adopt(copy.deepcopy(b.chain)) and a.status()["tip"] == b.status()["tip"]
    finally:
        a.close(); b.close()
    clock.now = SimulatedClock().now
    a, b = fork(tmp_path / "y", clock, shared=5, own=22, other=26)                  # 22 erased: needs +25 %, has ~18 %
    try:
        with pytest.raises(Invalid, match="au moins 25 %"):
            a.adopt(copy.deepcopy(b.chain))
    finally:
        a.close(); b.close()


# ------------------------------------------------------------------ alerts

def levels(node):
    with node.lock:
        return [(a["level"], a["message"]) for a in node.alerts()]


def test_alerts_cover_isolation_peers_clock_stall_version_and_bans(tmp_path, clock):
    node, key = Node(tmp_path / "n"), Ed25519PrivateKey.generate()
    try:
        assert ("info", "La clé d'identité du nœud n'est pas chiffrée (commande key-protect)") in levels(node)
        node.set_isolated(True)
        assert any("volontairement isolé" in m for _, m in levels(node))
        node.set_isolated(False)
        for port in (3001, 3002):
            node.add_peer(f"https://192.168.{port}.1:2000")
        node.peer_health = {p: {"ok": False, "error": "x"} for p in node.peers}
        assert levels(node)[0][0] == "critical" and "Aucun pair joignable" in levels(node)[0][1]
        urls = list(node.peers)
        node.peer_health = {urls[0]: {"ok": True, "skew": 45}, urls[1]: {"ok": False}}
        text = " | ".join(m for _, m in levels(node))
        assert "Un seul pair joignable" in text and "Horloge décalée de 45 s" in text
        mine(node, key, 2, clock)                                                    # last block is ~10000 s old in real time
        assert any("Aucun nouveau bloc" in m for _, m in levels(node))
        node.newer_seen.add(urls[0])
        node.reorg_blocked = {"removed_blocks": 60, "limit": 50}
        node.penalize(None, "ee" * 32, 500, "test")
        out = levels(node)
        assert out[0][0] == "critical" and "60 blocs" in out[0][1]                   # most serious first
        assert any("version plus récente" in m for _, m in out) and any("banni" in m for _, m in out)
        assert [a["level"] for a in node.status()["alerts"]] == [lv for lv, _ in out]
    finally:
        node.close()


# ------------------------------------------------------------------ tamper-evident, signed journal

def test_journal_is_hash_chained_signed_and_detects_tampering(tmp_path):
    node = Node(tmp_path / "n")
    try:
        for i in range(300):                                                         # more than the 200 rows kept
            node.record_event("test", f"événement {i}", {"i": i})
        state = node.journal_state()
        assert state["ok"] and state["entries"] == 200 and len(state["head"]) == 64
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(node.node_id)).verify(
            bytes.fromhex(state["signature"]), state["head"].encode())              # head is signed by the node key
        with node.db:                                                                # a legacy row without hash is tolerated
            node.db.execute("INSERT INTO events(timestamp,kind,message,details) VALUES(1,'old','x','{}')")
        node._journal_cache = None
        assert node.journal_state()["ok"]
        with node.db:
            node.db.execute("UPDATE events SET message='falsifié' WHERE id=(SELECT id FROM events WHERE kind='test' ORDER BY id LIMIT 1 OFFSET 40)")
        node._journal_cache = None
        tampered = node.journal_state()
        assert not tampered["ok"] and tampered["first_bad"] is not None
        assert any(lv == "critical" and "altéré" in m for lv, m in levels(node))
    finally:
        node.close()


# ------------------------------------------------------------------ wallet: verified backup, locking

def test_wallet_backup_is_verified_and_locking_works(tmp_path):
    wallet, phrase = HDWallet.create(tmp_path / "w.json", PASSWORD)
    first, second = wallet.new_address(), wallet.new_address()
    wallet.add_contact("Bob", first)
    assert wallet.backup(tmp_path / "b.json", "mot de passe de sauvegarde") == [first, second]
    with pytest.raises(Invalid, match="incorrect"):
        HDWallet.load(tmp_path / "b.json", PASSWORD)                                # a different password protects the copy
    restored = HDWallet.load(tmp_path / "b.json", "mot de passe de sauvegarde")
    assert restored.seed == wallet.seed and restored.resolve("Bob") == first
    with pytest.raises(Invalid):
        wallet.backup(tmp_path / "c.json", "court")
    wallet.lock()
    with pytest.raises(Invalid, match="verrouillé"):
        wallet.key(0)
    wallet.unlock(PASSWORD)
    assert address(wallet.key(0)) == first
    idle = HDWallet.load(tmp_path / "w.json", PASSWORD)
    idle.lock_after = 0.05
    idle.key(0)
    time.sleep(0.15)
    with pytest.raises(Invalid, match="inactivité"):
        idle.key(0)
    with pytest.raises(Invalid):
        idle.key(0)                                                                  # stays locked until unlocked


def test_cli_wallet_backup_roundtrip(tmp_path):
    env = {**os.environ, "NOVA_EASY": "1", "NOVA_WALLET_PASSWORD": PASSWORD, "NOVA_BACKUP_PASSWORD": "mot de passe de sauvegarde"}
    run = lambda *a: subprocess.run([sys.executable, "-m", "novacoin", *a], cwd=ROOT, env=env, text=True, capture_output=True)
    assert run("hd-create", "--wallet", str(tmp_path / "w.json")).returncode == 0
    done = run("hd-backup", "--wallet", str(tmp_path / "w.json"), "--backup", str(tmp_path / "b.json"))
    assert done.returncode == 0 and json.loads(done.stdout)["verified"] is True
    assert json.loads(run("hd-check-backup", "--wallet", str(tmp_path / "w.json"), "--backup", str(tmp_path / "b.json")).stdout)["backup_matches_wallet"]
    other = run("hd-create", "--wallet", str(tmp_path / "o.json"))
    assert other.returncode == 0
    mismatch = run("hd-check-backup", "--wallet", str(tmp_path / "o.json"), "--backup", str(tmp_path / "b.json"))
    assert mismatch.returncode == 1


# ------------------------------------------------------------------ release signatures

def test_release_signature_binds_file_name_content_and_trusted_key(tmp_path):
    key_file = tmp_path / "release.key"
    public = generate_release_key(key_file, "mot de passe de publication")
    assert key_file.stat().st_mode & 0o077 == 0
    archive = tmp_path / "nova-1.1.0rc1.zip"
    archive.write_bytes(b"contenu de l'archive")
    signature = sign_file(key_file, "mot de passe de publication", archive)
    assert verify_file(archive, signature, public) == hashlib.sha256(b"contenu de l'archive").hexdigest()
    with pytest.raises(Invalid):
        sign_file(key_file, "mauvais mot de passe 12", archive)
    tampered = tmp_path / "nova-1.1.0rc1.zip"
    tampered.write_bytes(b"contenu modifie")
    with pytest.raises(Invalid, match="modifié"):
        verify_file(tampered, signature, public)
    other_name = tmp_path / "autre.zip"
    other_name.write_bytes(b"contenu de l'archive")
    with pytest.raises(Invalid, match="autre fichier"):
        verify_file(other_name, signature, public)
    # an attacker re-signs a malicious archive with their own key and embeds their own public key:
    # verification uses only the key the user trusts, so it fails.
    evil_key = tmp_path / "evil.key"
    evil_public = generate_release_key(evil_key, "mot de passe de l'attaquant")
    archive.write_bytes(b"archive piegee")
    forged = sign_file(evil_key, "mot de passe de l'attaquant", archive, tmp_path / "forged.sig")
    assert json.loads(forged.read_text())["public_key"] == evil_public
    with pytest.raises(Invalid, match="clé de publication de confiance"):
        verify_file(archive, forged, public)
    with pytest.raises(Invalid):
        verify_file(archive, tmp_path / "absent.sig", public)
    archive.write_bytes(b"contenu de l'archive")
    ok = subprocess.run([sys.executable, "-m", "novacoin", "verify-release", "--file", str(archive), "--sig",
                         str(signature), "--pubkey", public], cwd=ROOT, text=True, capture_output=True)
    assert ok.returncode == 0 and "Signature valide" in ok.stdout
    bad = subprocess.run([sys.executable, "-m", "novacoin", "verify-release", "--file", str(archive), "--sig",
                          str(forged), "--pubkey", public], cwd=ROOT, text=True, capture_output=True)
    assert bad.returncode == 1


def test_margin_is_not_diluted_by_a_long_shared_chain(tmp_path, clock):
    """Regression: the margin applies to the competing branches, not to the whole chain's work."""
    a, b = fork(tmp_path, clock, shared=120, own=10, other=13)                       # 30 % more on the branch
    try:
        assert a.adopt(copy.deepcopy(b.chain)) and a.status()["tip"] == b.status()["tip"]
    finally:
        a.close(); b.close()


def test_release_keygen_and_sign_commands_end_to_end(tmp_path):
    env = {**os.environ, "NOVA_EASY": "1", "NOVA_RELEASE_KEY_PASSWORD": "mot de passe de publication"}
    cli = lambda *a: subprocess.run([sys.executable, "-m", "novacoin", *a], cwd=ROOT, env=env, text=True, capture_output=True)
    made = cli("release-keygen", "--out", str(tmp_path / "release.key"))
    assert made.returncode == 0 and "HORS LIGNE" in made.stderr
    public = json.loads(made.stdout)["public_key"]
    assert (tmp_path / "release.key").stat().st_mode & 0o077 == 0
    again = cli("release-keygen", "--out", str(tmp_path / "release.key"))
    assert again.returncode != 0                                                    # never overwrites an existing key
    archive = tmp_path / "nova-x.zip"
    archive.write_bytes(b"archive")
    assert cli("release-sign", "--key", str(tmp_path / "release.key"), "--file", str(archive)).returncode == 0
    ok = cli("verify-release", "--file", str(archive), "--sig", str(archive) + ".sig", "--pubkey", public)
    assert ok.returncode == 0 and "Signature valide" in ok.stdout
    wrong = cli("release-sign", "--key", str(tmp_path / "release.key"), "--file", str(archive))
    assert wrong.returncode == 0
    bad_env = {**env, "NOVA_RELEASE_KEY_PASSWORD": "un autre mot de passe long"}
    refused = subprocess.run([sys.executable, "-m", "novacoin", "release-sign", "--key", str(tmp_path / "release.key"),
                              "--file", str(archive)], cwd=ROOT, env=bad_env, text=True, capture_output=True)
    assert refused.returncode == 1 and "mot de passe incorrect" in refused.stderr
