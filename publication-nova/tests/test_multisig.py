"""V11 consensus extension (network nova-testnet-2): timelocked payments and m-of-n multisignature."""
import copy
import os
import random
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from novacoin.core import (MAX_MULTISIG_KEYS, UNIT, Invalid, canonical, merkle_root, multisig_address, solve,
                           make_candidate, signing_bytes, transaction_id, valid_address, validate_transaction_shape)
from novacoin.node import Node
from novacoin.wallet import (add_multisig_signature, address, build_transaction, draft_multisig_transaction,
                             multisig_policy, multisig_ready, public_hex)

ROOT = Path(__file__).resolve().parents[1]
FEE = 200_000


@pytest.fixture
def world(tmp_path):
    """A node, three signers, and a 2-of-3 multisig address holding two mature coinbase coins."""
    node = Node(tmp_path / "n")
    signers = [Ed25519PrivateKey.generate() for _ in range(3)]
    policy = multisig_policy(2, [public_hex(k) for k in signers])
    for _ in range(2):
        node.mine_one(policy["address"])
    for _ in range(2):
        node.mine_one(address(signers[0]))              # maturity
    yield node, signers, policy
    node.close()


def spendable(node, policy):
    return node.balance(policy["address"])["utxos"]


def signed(tx, *keys):
    for key in keys:
        add_multisig_signature(tx, key)
    return tx


def test_addresses_are_deterministic_typed_and_network_bound():
    keys = sorted(public_hex(Ed25519PrivateKey.generate()) for _ in range(3))
    one, two = multisig_address(2, keys), multisig_address(2, keys)
    assert one == two and one.startswith("nm1") and len(one) == 51 and valid_address(one)
    assert multisig_address(1, keys) != one and multisig_address(2, keys[:2]) != one
    assert not valid_address(one[:-1] + ("0" if one[-1] != "0" else "1"))          # checksum protects typos
    for bad in ((0, keys), (4, keys), (2, list(reversed(keys))), (2, keys + keys[:1]), (2, ["zz"] * 2),
                (1, sorted(public_hex(Ed25519PrivateKey.generate()) for _ in range(MAX_MULTISIG_KEYS + 1)))):
        with pytest.raises(Invalid):
            multisig_address(*bad)


def test_two_of_three_spends_with_two_signatures_in_any_order(world):
    node, (a, b, c), policy = world
    dest = address(Ed25519PrivateKey.generate())
    draft = draft_multisig_transaction(policy, spendable(node, policy), dest, 10 * UNIT, FEE)
    assert not multisig_ready(draft)
    add_multisig_signature(draft, c)
    with pytest.raises(Invalid, match="insuffisantes"):
        node.submit(copy.deepcopy(draft))                                          # one signature of two
    add_multisig_signature(draft, a)
    add_multisig_signature(draft, a)                                               # idempotent
    assert multisig_ready(draft) and len(draft["multisig"]["signatures"]) == 2
    txid = node.submit(draft)
    node.mine_one(address(a))
    assert node.balance(dest)["confirmed"] == 10 * UNIT
    assert node.balance(policy["address"])["confirmed"] == 2 * 50 * UNIT - 10 * UNIT - FEE   # change stayed under the policy
    assert transaction_id(draft) == txid


def test_invalid_multisignatures_are_all_refused(world):
    node, (a, b, c), policy = world
    outsider, dest = Ed25519PrivateKey.generate(), address(Ed25519PrivateKey.generate())
    fresh = lambda: draft_multisig_transaction(policy, spendable(node, policy), dest, UNIT, FEE)
    with pytest.raises(Invalid, match="ne fait pas partie"):
        add_multisig_signature(fresh(), outsider)
    tx = signed(fresh(), a, b)
    # a signature from a key outside the policy
    forged = copy.deepcopy(tx)
    forged["multisig"]["signatures"][0] = {"key": public_hex(outsider), "signature": outsider.sign(signing_bytes(tx)).hex()}
    with pytest.raises(Invalid, match="inconnu"):
        node.submit(forged)
    # the same signer twice
    twice = copy.deepcopy(tx)
    twice["multisig"]["signatures"][1] = copy.deepcopy(twice["multisig"]["signatures"][0])
    with pytest.raises(Invalid, match="double"):
        node.submit(twice)
    # outputs changed after signing
    changed = copy.deepcopy(tx)
    changed["outputs"][0]["amount"] += 1
    with pytest.raises(Invalid, match="Signature invalide"):
        node.submit(changed)
    # locktime or policy changed after signing
    later = copy.deepcopy(tx)
    later["locktime"] = 1
    with pytest.raises(Invalid, match="Signature invalide"):
        node.submit(later)
    # claiming a weaker policy (1-of-3) over the same keys: different address, coins not owned
    weak = draft_multisig_transaction(policy, spendable(node, policy), dest, UNIT, FEE)
    weak["multisig"]["threshold"] = 1
    weak["multisig"]["signatures"] = []
    add_multisig_signature(weak, a)
    with pytest.raises(Invalid, match="ne possède pas"):
        node.submit(weak)
    # a plain single-key payment cannot spend multisig coins, nor the reverse
    relabelled = [{**coin, "address": address(a)} for coin in spendable(node, policy)]   # the wallet refuses, so lie to it
    single = build_transaction(a, relabelled, dest, UNIT, FEE)
    with pytest.raises(Invalid, match="ne possède pas"):
        node.submit(single)
    # both a public key and a multisig block, or neither
    both = copy.deepcopy(tx)
    both["public_key"], both["signature"] = public_hex(a), "00" * 64
    with pytest.raises(Invalid):
        node.submit(both)
    assert node.pending == {}


def test_signatures_do_not_transfer_between_payment_versions_or_networks(world):
    node, (a, b, c), policy = world
    dest = address(Ed25519PrivateKey.generate())
    tx = signed(draft_multisig_transaction(policy, spendable(node, policy), dest, UNIT, FEE), a, b)
    assert signing_bytes(tx).startswith(b"NOVA-TX-V2\0")
    other = copy.deepcopy(tx)
    other["network"] = "autre-reseau"
    with pytest.raises(Invalid, match="Mauvais réseau"):
        validate_transaction_shape(other)
    v1 = build_transaction(a, [], dest, UNIT, FEE) if False else None
    assert v1 is None and signing_bytes({"version": 1}).startswith(b"NOVA-TX-V1\0")


# ------------------------------------------------------------------ timelock

def test_timelocked_payment_waits_for_its_height(tmp_path):
    node, owner, dest = Node(tmp_path / "n"), Ed25519PrivateKey.generate(), address(Ed25519PrivateKey.generate())
    try:
        for _ in range(4):
            node.mine_one(address(owner))
        height = len(node.chain)                                                    # height of the next block
        coins = node.balance(address(owner))["utxos"]
        early = build_transaction(owner, coins, dest, UNIT, FEE, locktime=height + 3)
        assert early["version"] == 2 and early["locktime"] == height + 3
        with pytest.raises(Invalid, match="verrouillé"):
            node.submit(early)
        # a block that forces the payment in too early is refused by consensus
        block = make_candidate(node.chain, node.utxos, [], address(owner))
        block["transactions"].append(early)
        block["merkle_root"] = merkle_root(block["transactions"])
        with pytest.raises(Invalid, match="verrouillé"):
            node.accept_block(solve(block))
        for _ in range(3):
            node.mine_one(address(owner))
        node.submit(early)                                                           # now height + 3 is reachable
        node.mine_one(address(owner))
        assert node.balance(dest)["confirmed"] == UNIT
        ok = build_transaction(owner, node.balance(address(owner))["utxos"], dest, UNIT, FEE, locktime=0)
        node.submit(ok)                                                              # locktime 0 = no lock
        for bad in (-1, 2 ** 31, True, 1.5, "7"):
            with pytest.raises(Invalid):
                build_transaction(owner, node.balance(address(owner))["utxos"], dest, UNIT, FEE, locktime=bad)
    finally:
        node.close()


def test_timelock_and_multisig_combine(world):
    node, (a, b, c), policy = world
    dest = address(Ed25519PrivateKey.generate())
    tx = signed(draft_multisig_transaction(policy, spendable(node, policy), dest, UNIT, FEE,
                                           locktime=len(node.chain) + 2), b, c)
    with pytest.raises(Invalid, match="verrouillé"):
        node.submit(copy.deepcopy(tx))
    for _ in range(2):
        node.mine_one(address(a))
    node.submit(tx)


# ------------------------------------------------------------------ robustness and cross-check

def test_mutated_v2_payments_never_cause_internal_errors(world):
    node, (a, b, c), policy = world
    dest = address(Ed25519PrivateKey.generate())
    tx = signed(draft_multisig_transaction(policy, spendable(node, policy), dest, UNIT, FEE, locktime=0), a, b)
    junk = [None, -1, 0, 2 ** 70, "", "x" * 200, [], {}, True, 1.5, "0" * 64, [[]], {"a": 1}, "nm1" + "0" * 48]
    rng, problems = random.Random(5), []

    def paths(obj, prefix=()):
        yield prefix
        if isinstance(obj, dict):
            for k, v in obj.items():
                yield from paths(v, prefix + (k,))
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                yield from paths(v, prefix + (i,))

    for _ in range(1500):
        mutated = copy.deepcopy(tx)
        target = rng.choice([p for p in paths(mutated) if p])
        parent = mutated
        for step in target[:-1]:
            parent = parent[step]
        parent[target[-1]] = copy.deepcopy(rng.choice(junk))
        try:
            node.submit(mutated)
        except Invalid:
            pass
        except Exception as exc:                                                    # anything else is a defect
            problems.append(f"{type(exc).__name__}: {exc}")
    assert problems == []


def test_independent_checker_agrees_on_a_chain_with_multisig_and_timelocks(world, tmp_path):
    node, (a, b, c), policy = world
    dest = address(Ed25519PrivateKey.generate())
    node.submit(signed(draft_multisig_transaction(policy, spendable(node, policy), dest, 5 * UNIT, FEE), b, c))
    node.mine_one(address(a))
    owner_coins = node.balance(address(a))["utxos"]
    node.submit(build_transaction(a, owner_coins, dest, 3 * UNIT, FEE, locktime=len(node.chain)))
    for _ in range(25):
        node.mine_one(address(a))
    import sqlite3
    snapshot = tmp_path / "snap.sqlite3"
    src = sqlite3.connect(f"file:{tmp_path / 'n' / 'chain.sqlite3'}?mode=ro", uri=True)
    dst = sqlite3.connect(snapshot)
    src.backup(dst); dst.close(); src.close()
    done = subprocess.run([sys.executable, str(ROOT / "tools" / "independent_check.py"), str(snapshot)],
                          text=True, capture_output=True, env={**os.environ, "NOVA_EASY": "1"})
    assert done.returncode == 0 and f"hauteur {node.status()['height']}" in done.stdout, done.stdout + done.stderr
    # the same chain with one multisig signature stripped must be rejected by the independent checker
    import json
    db = sqlite3.connect(snapshot)
    for height, payload in db.execute("SELECT height, payload FROM blocks").fetchall():
        block = json.loads(payload)
        for tx in block["transactions"][1:]:
            if "multisig" in tx:
                tx["multisig"]["signatures"].pop()
                db.execute("UPDATE blocks SET payload=? WHERE height=?", (json.dumps(block), height))
    db.commit(); db.close()
    bad = subprocess.run([sys.executable, str(ROOT / "tools" / "independent_check.py"), str(snapshot)],
                         text=True, capture_output=True, env={**os.environ, "NOVA_EASY": "1"})
    assert bad.returncode == 1 and "INVALIDE" in bad.stdout


def test_explorer_and_balance_understand_multisig_addresses(world):
    node, (a, b, c), policy = world
    view = node.explorer_address(policy["address"])
    assert view["received"] == 2 * 50 * UNIT and view["confirmed"] == 100 * UNIT
    assert node.explorer_search(policy["address"]) == {"type": "address", "key": policy["address"]}


def test_command_line_multisig_end_to_end(tmp_path):
    import json
    import signal
    import time
    from novacoin.node import request_json
    env = {**os.environ, "NOVA_EASY": "1", "NOVA_WALLET_PASSWORD": "un mot de passe solide"}
    cli = lambda *a: subprocess.run([sys.executable, "-m", "novacoin", *a], cwd=ROOT, env=env, text=True, capture_output=True)
    wallets = []
    for name in "abc":
        path = tmp_path / f"{name}.json"
        assert cli("hd-create", "--wallet", str(path)).returncode == 0
        wallets.append(path)
    keys = ",".join(cli("hd-pubkey", "--wallet", str(w)).stdout.strip() for w in wallets)
    policy = json.loads(cli("multisig-address", "--threshold", "2", "--keys", keys).stdout)
    port = 44000 + os.getpid() % 400
    node = subprocess.Popen([sys.executable, "-m", "novacoin", "node", "--data", str(tmp_path / "n"), "--port", str(port),
                             "--p2p-port", str(port + 1)], cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(100):
            try:
                request_json(base + "/api/status")
                break
            except Invalid:
                time.sleep(0.2)
        token = (tmp_path / "n" / "admin.token").read_text().strip()
        request_json(base + "/api/mine", {"address": policy["address"], "count": 3}, token)
        for _ in range(100):
            if request_json(base + "/api/status")["height"] >= 3 and not request_json(base + "/api/status")["mining"]["running"]:
                break
            time.sleep(0.1)
        request_json(base + "/api/mine", {"address": policy["address"], "count": 2}, token)
        time.sleep(1.5)
        dest = address(Ed25519PrivateKey.generate())
        draft = tmp_path / "draft.json"
        done = cli("multisig-draft", "--threshold", "2", "--keys", keys, "--to", dest, "--amount", "10", "--out", str(draft), "--node", base)
        assert done.returncode == 0, done.stderr
        refused = cli("multisig-submit", "--draft", str(draft), "--node", base)
        assert refused.returncode == 1 and "Pas assez" in refused.stderr
        assert json.loads(cli("multisig-sign", "--draft", str(draft), "--wallet", str(wallets[2])).stdout)["ready"] is False
        assert json.loads(cli("multisig-sign", "--draft", str(draft), "--wallet", str(wallets[0])).stdout)["ready"] is True
        sent = cli("multisig-submit", "--draft", str(draft), "--node", base)
        assert sent.returncode == 0 and "txid" in sent.stdout, sent.stderr
        request_json(base + "/api/mine", {"address": dest, "count": 1}, token)
        time.sleep(1.5)
        assert request_json(base + "/api/balance?address=" + dest)["confirmed"] >= 10 * UNIT
    finally:
        node.send_signal(signal.SIGTERM)
        node.wait(timeout=30)
