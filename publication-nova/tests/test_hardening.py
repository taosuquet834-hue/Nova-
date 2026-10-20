"""V6: consensus hardening and node safety policies."""
import copy
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from novacoin.core import (ADJUST_INTERVAL, BLOCK_VERSION, DUST, MAX_FUTURE_SECONDS, MIN_FEE_PER_BYTE,
                           TARGET_SECONDS, Invalid, block_id, canonical, expected_target, genesis,
                           make_candidate, median_index, solve, validate_next)
from novacoin.node import Node
from novacoin.wallet import address, build_transaction


@pytest.fixture
def key():
    return Ed25519PrivateKey.generate()


def grow(chain, coins, key, count, spacing=TARGET_SECONDS, start=None):
    start = start or int(time.time()) - 1_000_000
    for i in range(count):
        height = len(chain)
        block = solve(make_candidate(chain, coins, [], address(key), start + height * spacing))
        coins = validate_next(block, chain, coins)
        chain.append(block)
    return chain, coins


def test_block_version_rules(key):
    chain, coins = [genesis()], {}
    assert genesis()["version"] == BLOCK_VERSION == 2
    base = make_candidate(chain, coins, [], address(key))
    for version, message in [(1, "obsol"), (3, "mettre le logiciel à jour"), (True, "invalide"), ("2", "invalide")]:
        block = copy.deepcopy(base)
        block["version"] = version
        with pytest.raises(Invalid, match=message):
            validate_next(block, chain, coins)


def test_timestamps_must_strictly_increase(key):
    chain, coins = grow([genesis()], {}, key, 12)
    block = make_candidate(chain, coins, [], address(key), chain[-1]["timestamp"] + 5)
    block["timestamp"] = chain[-1]["timestamp"]            # equal to the previous block
    with pytest.raises(Invalid, match="précédent|ancien"):
        validate_next(solve(block), chain, coins)
    # a timestamp older than the previous block but above the median is refused for the same rule
    block = make_candidate(chain, coins, [], address(key), chain[-1]["timestamp"] + 5)
    block["timestamp"] = chain[-1]["timestamp"] - 1
    assert block["timestamp"] > chain[-6]["timestamp"]
    with pytest.raises(Invalid, match="précédent"):
        validate_next(solve(block), chain, coins)


def test_future_limit_is_tight(key):
    assert MAX_FUTURE_SECONDS == 60
    chain, coins = [genesis()], {}
    now = int(time.time())
    block = solve(make_candidate(chain, coins, [], address(key), now + 61))
    with pytest.raises(Invalid, match="futur"):
        validate_next(block, chain, coins, now=now)
    validate_next(solve(make_candidate(chain, coins, [], address(key), now + 60)), chain, coins, now=now)


def test_single_block_timestamp_cannot_swing_difficulty(key):
    """Time-warp attempt: honest 10 s blocks, but the very last block claims a huge delay."""
    chain, c2 = [genesis()], {}
    chain, c2 = grow(chain, c2, key, ADJUST_INTERVAL - 1, spacing=TARGET_SECONDS)
    lying = solve(make_candidate(chain, c2, [], address(key), chain[-1]["timestamp"] + 5_000))
    c2 = validate_next(lying, chain, c2, now=lying["timestamp"] + 1)
    with_lie = chain + [lying]
    honest_chain, c3 = grow([genesis()], {}, key, ADJUST_INTERVAL, spacing=TARGET_SECONDS)
    # The median-block measurement ignores the last block's lie entirely:
    assert expected_target(with_lie) == expected_target(honest_chain)
    start, end = median_index(len(with_lie) - ADJUST_INTERVAL), median_index(len(with_lie) - 1)
    assert end < len(with_lie) - 1 and start >= 1


def test_median_index_is_unbiased_for_early_windows():
    assert median_index(1) == 1
    assert median_index(20) == 15          # blocks 10..20 -> middle is 15
    assert median_index(40) == 35


# ------------------------------------------------------------------ node policies

def test_mempool_fee_and_dust_policy(tmp_path, key):
    node = Node(tmp_path / "n")
    try:
        for _ in range(3):
            node.mine_one(address(key))
        other = Ed25519PrivateKey.generate()
        coins = node.balance(address(key))["utxos"]
        size_hint = len(canonical(build_transaction(key, coins, address(other), 10**8, 100_000)))
        cheap = build_transaction(key, coins, address(other), 10**8, 1)
        with pytest.raises(Invalid, match="Frais trop bas"):
            node.submit(cheap)
        exact = build_transaction(key, coins, address(other), 10**8, MIN_FEE_PER_BYTE * size_hint + 100)
        node.submit(exact)
    finally:
        node.close()


def test_dust_outputs_are_refused_and_wallet_never_creates_dust_change(tmp_path, key):
    node = Node(tmp_path / "n")
    try:
        for _ in range(3):
            node.mine_one(address(key))
        other = Ed25519PrivateKey.generate()
        coins = node.balance(address(key))["utxos"]
        with pytest.raises(Invalid, match="poussière"):
            node.submit(build_transaction(key, coins, address(other), DUST - 1, 100_000))
        total = sum(c["amount"] for c in coins if c["spendable"])
        # leave less than DUST as change: the wallet folds it into the fee instead of creating it
        tx = build_transaction(key, coins[:1], address(other), coins[0]["amount"] - 100_000 - (DUST - 1), 100_000)
        assert len(tx["outputs"]) == 1 and total > 0
        node.submit(tx)
    finally:
        node.close()


def test_blocks_prefer_higher_fee_rates(tmp_path, key):
    node = Node(tmp_path / "n")
    try:
        keys = [Ed25519PrivateKey.generate() for _ in range(3)]
        for k in keys:
            for _ in range(3):
                node.mine_one(address(k))
        dest = address(Ed25519PrivateKey.generate())
        fees = {}
        for k, fee in zip(keys, (50_000, 900_000, 200_000)):
            tx = build_transaction(k, node.balance(address(k))["utxos"], dest, 10**8, fee)
            fees[node.submit(tx)] = fee
        from novacoin.core import make_candidate as candidate, transaction_id
        block = candidate(node.chain, node.utxos, list(node.pending.values()), address(key))
        order = [fees[transaction_id(t)] for t in block["transactions"][1:]]
        assert order == sorted(order, reverse=True)
    finally:
        node.close()


def build_fork(tmp_path, key, shared, main_extra, side_extra):
    """Two nodes sharing `shared` blocks, then diverging."""
    a, b = Node(tmp_path / "a", max_reorg=3), Node(tmp_path / "b")
    for _ in range(shared):
        a.mine_one(address(key))
    assert b.adopt(copy.deepcopy(a.chain))
    for _ in range(main_extra):
        a.mine_one(address(key))
    other = Ed25519PrivateKey.generate()
    for _ in range(side_extra):
        b.mine_one(address(other))
    return a, b


def test_deep_reorganisation_is_refused_by_policy_but_shallow_one_is_accepted(tmp_path, key):
    a, b = build_fork(tmp_path, key, 3, main_extra=5, side_extra=10)    # b is heavier, forks 5 deep
    try:
        assert b.work > a.work
        tip = a.status()["tip"]
        with pytest.raises(Invalid, match="refusée"):
            a.adopt(copy.deepcopy(b.chain))
        assert a.status()["tip"] == tip
        assert any(e["kind"] == "reorg_refused" for e in a.events())
    finally:
        a.close(); b.close()
    a, b = build_fork(tmp_path / "x", key, 3, main_extra=2, side_extra=6)  # only 2 deep: allowed
    try:
        assert a.adopt(copy.deepcopy(b.chain))
        assert a.status()["tip"] == b.status()["tip"]
    finally:
        a.close(); b.close()


def test_reorg_limit_zero_means_unlimited(tmp_path, key):
    a, b = build_fork(tmp_path, key, 2, main_extra=6, side_extra=12)
    try:
        a.max_reorg = 0
        assert a.adopt(copy.deepcopy(b.chain))
    finally:
        a.close(); b.close()


def test_checkpoints_reject_contradicting_chains_and_blocks(tmp_path, key):
    a, b = build_fork(tmp_path, key, 3, main_extra=1, side_extra=3)
    try:
        pinned = {4: block_id(a.chain[4])}                 # a's own block 4
        guarded = Node(tmp_path / "g", checkpoints=pinned, max_reorg=0)
        try:
            assert guarded.adopt(copy.deepcopy(a.chain[:4])) is True     # below the checkpoint: fine
            assert guarded.adopt(copy.deepcopy(a.chain)) is True         # a's block 4 matches it
            with pytest.raises(Invalid, match="point de contrôle"):
                guarded.adopt(copy.deepcopy(b.chain))      # heavier but contradicts height 4
            assert guarded.status()["tip"] == a.status()["tip"]
        finally:
            guarded.close()
        b.close()                                          # release b's data directory
        # a node whose stored chain contradicts a checkpoint refuses to start
        with pytest.raises(Invalid, match="contredit"):
            Node(tmp_path / "b", checkpoints={4: block_id(a.chain[4])})
        with pytest.raises(Invalid):
            Node(tmp_path / "bad", checkpoints={0: "00" * 32})
        with pytest.raises(Invalid):
            Node(tmp_path / "bad2", checkpoints={5: "xyz"})
    finally:
        a.close()


def test_status_announces_protocol_and_policies(tmp_path):
    node = Node(tmp_path / "n", max_reorg=7, checkpoints={3: "ab" * 32})
    try:
        protocol = node.status()["protocol"]
        assert protocol["block_version"] == BLOCK_VERSION and protocol["max_reorg"] == 7
        assert protocol["checkpoints"] == 1
    finally:
        node.close()
