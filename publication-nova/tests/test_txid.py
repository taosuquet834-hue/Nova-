"""V13 consensus change: a payment's identifier does not depend on its signatures (no malleability)."""
import copy
import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from novacoin.core import Invalid, canonical, merkle_root, solve, make_candidate, transaction_id
from novacoin.node import Node
from novacoin.wallet import (add_multisig_signature, address, build_transaction, draft_multisig_transaction,
                             multisig_policy, public_hex)

FEE = 200_000
UNIT = 10 ** 8


def independent_id(tx):
    """The rule written out again: hash of the canonical JSON without signatures."""
    body = {k: v for k, v in tx.items() if k != "signature"}
    if "multisig" in body:
        body["multisig"] = {k: v for k, v in body["multisig"].items() if k != "signatures"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


@pytest.fixture
def world(tmp_path):
    node, keys = Node(tmp_path / "n"), [Ed25519PrivateKey.generate() for _ in range(3)]
    policy = multisig_policy(2, [public_hex(k) for k in keys])
    for _ in range(3):
        node.mine_one(policy["address"])
    for _ in range(2):
        node.mine_one(address(keys[0]))
    yield node, keys, policy, tmp_path
    node.close()


def variants(node, keys, policy, dest, amount=UNIT, **kw):
    """The same multisignature payment signed by different subsets of the keys."""
    a, b, c = keys
    base = draft_multisig_transaction(policy, node.balance(policy["address"])["utxos"], dest, amount, FEE, **kw)
    out = []
    for signers in ((a, b), (b, c), (a, c), (a, b, c)):
        tx = copy.deepcopy(base)
        for key in signers:
            add_multisig_signature(tx, key)
        out.append(tx)
    return out


def test_identifier_ignores_signatures_but_covers_everything_else(world):
    node, (a, b, c), policy, _ = world
    dest = address(Ed25519PrivateKey.generate())
    single = build_transaction(a, node.balance(address(a))["utxos"], dest, UNIT, FEE)
    assert transaction_id(single) == independent_id(single)
    resigned = {**single, "signature": "00" * 64}
    assert transaction_id(resigned) == transaction_id(single)                      # the identifier does not move
    with pytest.raises(Invalid, match="Signature invalide"):
        node.submit(resigned)                                                      # ...but the bad signature is still refused
    for field, value in (("outputs", [{"address": dest, "amount": 1}]), ("locktime", 5), ("network", "x")):
        assert transaction_id({**single, field: value}) != transaction_id(single)   # everything else is committed
    multi = variants(node, (a, b, c), policy, dest)
    assert len({transaction_id(t) for t in multi}) == 1 and transaction_id(multi[0]) == independent_id(multi[0])
    other_policy = copy.deepcopy(multi[0])
    other_policy["multisig"]["threshold"] = 3
    assert transaction_id(other_policy) != transaction_id(multi[0])                # the policy itself is committed
    coinbase = node.chain[1]["transactions"][0]
    assert transaction_id(coinbase) == hashlib.sha256(canonical(coinbase)).hexdigest()   # coinbase: whole object
    assert transaction_id("nonsense") and transaction_id(5)                       # never raises on junk


def test_signature_variants_are_one_payment_for_pool_blocks_and_merkle_root(world):
    node, keys, policy, _ = world
    dest = address(Ed25519PrivateKey.generate())
    v1, v2, v3, v4 = variants(node, keys, policy, dest)
    first = node.submit(v1)
    assert node.submit(v2) == first == node.submit(v4) and len(node.pending) == 1   # a re-signed copy is the same payment
    assert merkle_root([v1]) == merkle_root([v2]) == merkle_root([v4])
    block = make_candidate(node.chain, node.utxos, [], address(keys[0]))
    block["transactions"] += [v1, v3]                                              # both variants in one block
    block["merkle_root"] = merkle_root(block["transactions"])
    with pytest.raises(Invalid, match="dupliquée"):
        node.accept_block(solve(block))


def test_a_third_party_re_signing_cannot_break_a_chained_payment(world, tmp_path):
    """Malleability attack: the parent is mined with different signatures; the child spending it stays valid."""
    node, keys, policy, _ = world
    a, b, c = keys
    middle = Ed25519PrivateKey.generate()
    parent = variants(node, keys, policy, address(middle), amount=5 * UNIT)[0]      # signed by a and b
    parent_id = node.submit(parent)
    child = build_transaction(middle, [{"address": address(middle), "txid": parent_id, "index": 0,
                                        "amount": 5 * UNIT, "spendable": True}], address(a), UNIT, FEE)
    child_id = node.submit(child)                                                  # spends an unconfirmed output
    miner = Node(tmp_path / "miner")                                               # an attacker who re-signed the parent
    try:
        assert miner.adopt(copy.deepcopy(node.chain))
        miner.submit(variants(miner, keys, policy, address(middle), amount=5 * UNIT)[1])   # signed by b and c
        miner.mine_one(address(c))
        mined = copy.deepcopy(miner.chain[-1])
        assert transaction_id(mined["transactions"][1]) == parent_id and mined["transactions"][1] != parent
        node.accept_block(mined)                                                   # the honest node takes the other variant
        assert parent_id not in node.pending and child_id in node.pending          # and the child is still good to go
        node.mine_one(address(a))
        assert node.balance(address(a))["confirmed"] >= UNIT
    finally:
        miner.close()
