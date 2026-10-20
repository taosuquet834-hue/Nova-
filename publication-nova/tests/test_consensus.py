import copy
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from novacoin.core import (
    ADJUST_INTERVAL, HALVING_INTERVAL, INITIAL_TARGET, MAX_TARGET, MIN_TARGET, TARGET_SECONDS, median_index, INITIAL_REWARD, MAX_MONEY, NETWORK, UNIT,
    Invalid, address_from_public, apply_transaction, block_id, block_work, expected_target,
    format_amount, genesis, make_candidate, merkle_root, parse_amount,
    signing_bytes, solve, subsidy, transaction_id, valid_address, validate_chain,
    validate_next,
)
from novacoin.node import Node, decode_json
from novacoin.wallet import address, build_transaction, create_wallet, load_wallet, public_hex


@pytest.fixture
def keys():
    return Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()


@pytest.fixture
def funded(tmp_path, keys):
    node = Node(tmp_path / "node")
    for _ in range(3):
        node.mine_one(address(keys[0]))
    yield node
    node.close()


def payment(node, keys, amount=10 * UNIT):
    return build_transaction(keys[0], node.balance(address(keys[0]))["utxos"],
                             address(keys[1]), amount, 100_000)


def resign(tx, key):
    tx["signature"] = key.sign(signing_bytes(tx)).hex()
    return tx


def test_signed_payment_rewards_and_conservation(funded, keys):
    total_before = sum(c["amount"] for c in funded.utxos.values())
    tx = payment(funded, keys)
    funded.submit(tx)
    block = funded.mine_one(address(keys[0]))
    assert funded.balance(address(keys[1]))["confirmed"] == 10 * UNIT
    assert funded.balance(address(keys[0]))["confirmed"] == 190 * UNIT
    assert block["transactions"][0]["outputs"][0]["amount"] == 50 * UNIT + 100_000
    assert sum(c["amount"] for c in funded.utxos.values()) == total_before + INITIAL_REWARD
    assert not funded.pending
    with pytest.raises(Invalid, match="déjà dépensée"):
        funded.submit(tx)


def test_tampered_payment_does_not_mutate_state(funded, keys):
    tx = payment(funded, keys)
    tx["outputs"][0]["amount"] += 1
    before = copy.deepcopy(funded.utxos)
    with pytest.raises(Invalid, match="Signature"):
        funded.submit(tx)
    assert funded.utxos == before
    assert not funded.pending


def test_wrong_owner_even_with_valid_signature(funded, keys):
    tx = payment(funded, keys)
    tx["public_key"] = public_hex(keys[1])
    resign(tx, keys[1])
    with pytest.raises(Invalid, match="possède"):
        funded.submit(tx)


def test_conflicting_transactions_rejected(funded, keys):
    first = payment(funded, keys)
    second = payment(funded, keys, 11 * UNIT)
    funded.submit(first)
    with pytest.raises(Invalid, match="déjà dépensée"):
        funded.submit(second)
    assert len(funded.pending) == 1


@pytest.mark.parametrize("amount", [-1, 0, True, 1.5, "100", MAX_MONEY + 1])
def test_invalid_amounts(funded, keys, amount):
    tx = payment(funded, keys)
    tx["outputs"][0]["amount"] = amount
    resign(tx, keys[0])
    with pytest.raises(Invalid):
        funded.submit(tx)


def test_duplicate_input(funded, keys):
    tx = payment(funded, keys)
    tx["inputs"].append(tx["inputs"][0])
    resign(tx, keys[0])
    with pytest.raises(Invalid, match="deux fois"):
        funded.submit(tx)


def test_cross_network_replay(funded, keys):
    tx = payment(funded, keys)
    tx["network"] = "another-network"
    resign(tx, keys[0])
    with pytest.raises(Invalid, match="réseau"):
        funded.submit(tx)


def test_no_overspending(funded, keys):
    tx = payment(funded, keys)
    tx["outputs"][0]["amount"] = 60 * UNIT
    resign(tx, keys[0])
    with pytest.raises(Invalid, match="insuffisant"):
        funded.submit(tx)


def test_reward_maturity(tmp_path, keys):
    node = Node(tmp_path)
    try:
        node.mine_one(address(keys[0]))
        balance = node.balance(address(keys[0]))
        assert balance["confirmed"] == 50 * UNIT
        assert balance["available"] == 0
        coins = balance["utxos"]
        coins[0]["spendable"] = True  # Dishonest wallet cannot bypass consensus.
        tx = build_transaction(keys[0], coins, address(keys[1]), UNIT, 100_000)
        with pytest.raises(Invalid, match="immature"):
            node.submit(tx)
        node.mine_one(address(keys[0]))
        assert node.balance(address(keys[0]))["available"] == 50 * UNIT
        node.submit(tx)
    finally:
        node.close()


@pytest.mark.parametrize("fault", ["reward", "merkle", "parent", "time", "difficulty", "duplicate"])
def test_invalid_blocks_are_atomic(funded, keys, fault):
    tx = payment(funded, keys)
    block = make_candidate(funded.chain, funded.utxos, [tx], address(keys[0]))
    if fault == "reward":
        block["transactions"][0]["outputs"][0]["amount"] += 1
        block["merkle_root"] = merkle_root(block["transactions"])
    elif fault == "merkle":
        block["merkle_root"] = "f" * 64
    elif fault == "parent":
        block["previous"] = "f" * 64
    elif fault == "time":
        block["timestamp"] = int(time.time()) + 1000
    elif fault == "difficulty":
        block["target"] = MAX_TARGET
    elif fault == "duplicate":
        block["transactions"].append(tx)
        block["merkle_root"] = merkle_root(block["transactions"])
    solve(block)
    before = copy.deepcopy(funded.chain), copy.deepcopy(funded.utxos)
    with pytest.raises(Invalid):
        funded.accept_block(block)
    assert (funded.chain, funded.utxos) == before


def test_invalid_pow(funded, keys):
    block = make_candidate(funded.chain, funded.utxos, [], address(keys[0]))
    while int(block_id(block), 16) < block["target"]:
        block["nonce"] += 1
    with pytest.raises(Invalid, match="Preuve"):
        funded.accept_block(block)


def test_reorg_restores_orphaned_payment(funded, keys, tmp_path):
    other = Node(tmp_path / "other")
    try:
        assert other.adopt(copy.deepcopy(funded.chain))
        tx = payment(funded, keys)
        txid = funded.submit(tx)
        funded.mine_one(address(keys[0]))
        assert funded.balance(address(keys[1]))["confirmed"] == 10 * UNIT
        other.mine_one(address(keys[0]))
        other.mine_one(address(keys[0]))
        assert funded.adopt(copy.deepcopy(other.chain))
        assert funded.balance(address(keys[1]))["confirmed"] == 0
        assert txid in funded.pending
        funded.mine_one(address(keys[0]))
        assert funded.balance(address(keys[1]))["confirmed"] == 10 * UNIT
        assert not funded.pending
        assert not funded.adopt(copy.deepcopy(other.chain))
    finally:
        other.close()


def test_conflicting_reorg_drops_old_payment(funded, keys, tmp_path):
    other = Node(tmp_path / "other")
    try:
        other.adopt(copy.deepcopy(funded.chain))
        funded.submit(payment(funded, keys, 10 * UNIT))
        funded.mine_one(address(keys[0]))
        other.submit(payment(other, keys, 20 * UNIT))
        other.mine_one(address(keys[0]))
        other.mine_one(address(keys[0]))
        funded.adopt(copy.deepcopy(other.chain))
        assert not funded.pending
        assert funded.balance(address(keys[1]))["confirmed"] == 20 * UNIT
    finally:
        other.close()


def test_invalid_candidate_chain_never_adopted(funded):
    bad = copy.deepcopy(funded.chain)
    bad[1]["transactions"][0]["outputs"][0]["amount"] += 100
    before = copy.deepcopy(funded.chain)
    with pytest.raises(Invalid):
        funded.adopt(bad)
    assert funded.chain == before


def test_persistence_of_chain_mempool_and_token(tmp_path, keys):
    node = Node(tmp_path)
    for _ in range(3):
        node.mine_one(address(keys[0]))
    txid = node.submit(payment(node, keys))
    token, tip = node.token, node.status()["tip"]
    node.close()
    reopened = Node(tmp_path)
    try:
        assert reopened.token == token
        assert reopened.status()["tip"] == tip
        assert txid in reopened.pending
        reopened.mine_one(address(keys[0]))
        assert reopened.balance(address(keys[1]))["confirmed"] == 10 * UNIT
    finally:
        reopened.close()


def build_window(keys, spacing):
    chain, coins = [genesis()], {}
    start = int(time.time()) - 100_000
    for i in range(1, ADJUST_INTERVAL + 1):
        block = solve(make_candidate(chain, coins, [], address(keys[0]), start + i * spacing))
        coins = validate_next(block, chain, coins)
        chain.append(block)
    return chain, coins, start


def window_span(chain):
    start, end = median_index(len(chain) - ADJUST_INTERVAL), median_index(len(chain) - 1)
    return TARGET_SECONDS * (end - start), chain[end]["timestamp"] - chain[start]["timestamp"]


def test_adjustment_both_directions_clamped_and_chainwork(keys):
    # Much too fast: clamped to a 4x harder target. Much too slow: clamped to 4x easier.
    for spacing, clamp in [(1, "low"), (400, "high")]:
        chain, coins, start = build_window(keys, spacing)
        expected_window, _ = window_span(chain)
        clamped = expected_window // 4 if clamp == "low" else expected_window * 4
        before = chain[-1]["target"]
        assert expected_target(chain) == max(MIN_TARGET, min(MAX_TARGET, before * clamped // expected_window))
        block = solve(make_candidate(chain, coins, [], address(keys[0]), start + 21 * spacing))
        chain.append(block)
        _, work = validate_chain(chain)
        assert work == sum(block_work(b["target"]) for b in chain[1:])
        assert block["target"] == expected_target(chain[:-1])
    # A proportional change inside the clamp is applied exactly, not in coarse steps.
    chain, coins, _ = build_window(keys, 45)
    expected_window, elapsed = window_span(chain)
    assert expected_target(chain) == chain[-1]["target"] * elapsed // expected_window


def test_target_never_leaves_bounds_and_wrong_target_is_refused(keys):
    chain, coins, _ = build_window(keys, 1)
    assert MIN_TARGET <= expected_target(chain) <= MAX_TARGET
    block = make_candidate(chain, coins, [], address(keys[0]))
    block["target"] = block["target"] * 2
    solve(block)
    with pytest.raises(Invalid, match="Difficulté"):
        validate_next(block, chain, coins)


def test_real_network_constants_are_not_the_easy_test_ones():
    import os, subprocess, sys
    env = {k: v for k, v in os.environ.items() if k != "NOVA_EASY"}
    code = ("from novacoin.core import *; import novacoin.core as c;"
            "print(NETWORK, INITIAL_TARGET == 1 << 234, difficulty_bits(INITIAL_TARGET), "
            "difficulty_bits(MAX_TARGET), difficulty_bits(MIN_TARGET))")
    out = subprocess.run([sys.executable, "-c", code], env=env, text=True, capture_output=True,
                         cwd=os.path.dirname(os.path.dirname(__file__))).stdout.split()
    assert out == ["nova-testnet-3", "True", "22.0", "16.0", "96.0"]
    assert NETWORK == "nova-testnet-3-easy"  # tests never mix with the real network


def test_supply_schedule_and_integer_precision():
    assert subsidy(1) == INITIAL_REWARD
    assert subsidy(HALVING_INTERVAL) == INITIAL_REWARD
    assert subsidy(HALVING_INTERVAL + 1) == INITIAL_REWARD // 2
    total = sum(subsidy(1 + epoch * HALVING_INTERVAL) * HALVING_INTERVAL for epoch in range(64))
    assert total <= MAX_MONEY
    assert parse_amount("0.00000001") == 1
    assert format_amount(1) == "0.00000001"
    assert parse_amount("21000000") == MAX_MONEY


@pytest.mark.parametrize("text", ["NaN", "Infinity", "-1", "0.000000001", "21000001", "", "1e999999999"])
def test_bad_decimal_input(text):
    with pytest.raises(Invalid):
        parse_amount(text)


def test_encrypted_wallet_roundtrip_and_no_overwrite(tmp_path):
    path = tmp_path / "wallet.pem"
    key = create_wallet(path, "a-test-password")
    assert b"ENCRYPTED PRIVATE KEY" in path.read_bytes()
    assert address(load_wallet(path, "a-test-password")) == address(key)
    assert path.stat().st_mode & 0o077 == 0
    with pytest.raises(Invalid):
        load_wallet(path, "wrong-password")
    with pytest.raises(FileExistsError):
        create_wallet(path, "a-test-password")
    original = address(key)
    assert valid_address(original)
    assert not valid_address(original[:-1] + ("0" if original[-1] != "0" else "1"))


@pytest.mark.parametrize("data", [b'{"amount":1,"amount":2}', b'{"amount":NaN}', b"\xff", b"[" * 2000])
def test_hostile_json(data):
    with pytest.raises(Invalid):
        decode_json(data)


def test_exclusive_data_directory_and_release(tmp_path):
    node = Node(tmp_path)
    try:
        with pytest.raises(Invalid, match="déjà utilisé"):
            Node(tmp_path)
    finally:
        node.close()
    reopened = Node(tmp_path)
    reopened.close()


def test_corrupted_database_fails_closed(tmp_path, keys):
    node = Node(tmp_path)
    node.mine_one(address(keys[0]))
    with node.db:
        node.db.execute("UPDATE blocks SET payload='{}' WHERE height=1")
    node.close()
    with pytest.raises(Invalid):
        Node(tmp_path)
    # Failed initialization also releases the directory lock.
    with pytest.raises(Invalid, match="Champs"):
        Node(tmp_path)
