"""The chain lives in SQLite: list-like behaviour, bounded memory, and the same answers as a plain list."""
import copy
import threading
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from novacoin import core
from novacoin.attack_bench import SimulatedClock
from novacoin.chainstore import ChainStore
from novacoin.core import Invalid, Tail, block_id, validate_chain
from novacoin.node import Node
from novacoin.wallet import address


@pytest.fixture
def clock(monkeypatch):
    sim = SimulatedClock()
    monkeypatch.setattr(core, "time", sim)
    return sim


def grow(node, key, count, clock):
    for _ in range(count):
        clock.now += core.TARGET_SECONDS
        node.mine_one(address(key))


def test_chainstore_behaves_like_the_list_it_replaces(tmp_path, clock):
    node, key = Node(tmp_path / "n"), Ed25519PrivateKey.generate()
    try:
        grow(node, key, 40, clock)
        plain = list(node.chain)
        assert len(node.chain) == len(plain) == 41
        assert node.chain == plain and plain == list(node.chain)
        for index in (0, 1, 20, 40, -1, -2, -41):
            assert node.chain[index] == plain[index]
        for part in (slice(None), slice(3, 9), slice(-5, None), slice(None, 4), slice(5, 30, 7), slice(50, 60)):
            assert node.chain[part] == plain[part]
        for bad in (41, -42, 1000):
            with pytest.raises(IndexError):
                node.chain[bad]
        copied = copy.deepcopy(node.chain)
        assert isinstance(copied, list) and copied == plain and copied[5] is not plain[5]
        assert [block_id(b) for b in node.chain.iter_from(38)] == node.ids[38:]
        assert node.chain.work_between(1, 41) == node.work and node.chain.work_between(5, 5) == 0
        assert not (node.chain == plain[:-1]) and not (node.chain == 5)
    finally:
        node.close()


def test_only_a_small_window_of_blocks_stays_in_memory(tmp_path, clock):
    node, key = Node(tmp_path / "n"), Ed25519PrivateKey.generate()
    try:
        grow(node, key, 400, clock)
        assert len(node.chain) == 401 and len(node.chain.cache) <= node.chain.window
        for height in (7, 123, 399, 3, 250):                      # random access reads from disk, cache stays bounded
            assert block_id(node.chain[height]) == node.ids[height]
        assert len(node.chain.cache) <= node.chain.window
    finally:
        node.close()
    again = Node(tmp_path / "n")                                   # restart: validation streams through the chain
    try:
        assert len(again.chain) == 401 and len(again.chain.cache) <= again.chain.window
        assert len(again.ids) == 401 and again.status()["height"] == 400
    finally:
        again.close()


def test_small_window_still_returns_correct_blocks(tmp_path, clock):
    node, key = Node(tmp_path / "n"), Ed25519PrivateKey.generate()
    try:
        grow(node, key, 30, clock)
        tiny = ChainStore(tmp_path / "n" / "chain.sqlite3", window=4)
        assert len(tiny) == 31 and tiny[:] == list(node.chain)
        assert len(tiny.cache) <= 4 and tiny[10] == node.chain[10] and tiny[-1] == node.chain[-1]
        tiny.close()
    finally:
        node.close()


def test_reorg_keeps_store_database_and_ids_in_step(tmp_path, clock):
    a, b, key, rival = Node(tmp_path / "a"), Node(tmp_path / "b", max_reorg=0), Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    try:
        grow(a, key, 20, clock)
        assert b.adopt(copy.deepcopy(a.chain))
        base = clock.now
        grow(a, key, 5, clock)
        clock.now = base
        grow(b, rival, 9, clock)
        clock.now += 1000
        assert a.adopt(copy.deepcopy(b.chain))                     # replaces the last 5 blocks
        assert a.chain == b.chain and a.ids == b.ids and len(a.chain) == 30
        assert a.status()["tip"] == b.status()["tip"]
        a.close()
        again = Node(tmp_path / "a")
        try:
            assert again.chain == b.chain and again.work == b.work                        # the disk agrees
        finally:
            again.close()
        a = Node(tmp_path / "a")
    finally:
        a.close(); b.close()


def test_tail_window_supports_validation_without_the_whole_chain(tmp_path, clock):
    node, key = Node(tmp_path / "n"), Ed25519PrivateKey.generate()
    try:
        grow(node, key, 120, clock)
        plain = list(node.chain)
        assert validate_chain(plain) == validate_chain(node.chain) == (node.utxos, node.work)
        partial_utxos, partial_work = validate_chain(node.chain, upto=60)
        assert partial_work == node.chain.work_between(1, 60) and len(partial_utxos) == 59
        with pytest.raises(Invalid):
            validate_chain(node.chain, upto=500)
        with pytest.raises(Invalid):
            validate_chain(node.chain, upto=0)
        tail = Tail(plain[-80:], len(plain))
        assert len(tail) == len(plain) and len(tail.blocks) == Tail.KEEP
        assert tail[-1] == plain[-1] and tail[len(plain) - 3] == plain[-3] and tail[-3:] == plain[-3:]
        with pytest.raises(IndexError):
            tail[5]                                                   # far outside the window
    finally:
        node.close()


def test_reading_while_mining_never_fails(tmp_path, clock):
    node, key = Node(tmp_path / "n"), Ed25519PrivateKey.generate()
    errors, done = [], threading.Event()

    def reader():
        while not done.is_set():
            try:
                height = len(node.chain) - 1
                assert node.chain[height]["height"] == height and node.chain[-1]["height"] >= height
                list(node.chain.iter_from(max(0, height - 5)))
                node.chain.work_between(1, max(1, height))
            except Exception as exc:                                  # any exception is a defect
                errors.append(repr(exc))

    threads = [threading.Thread(target=reader) for _ in range(3)]
    for t in threads:
        t.start()
    try:
        grow(node, key, 80, clock)
    finally:
        done.set()
        for t in threads:
            t.join()
        node.close()
    assert errors == []


def test_chain_replay_is_linear_and_inplace_validation_is_opt_in(tmp_path, clock):
    from novacoin.core import genesis, make_candidate, solve, validate_next
    key = Ed25519PrivateKey.generate()
    chain, coins = [genesis()], {}
    for _ in range(3):
        clock.now += core.TARGET_SECONDS
        block = solve(make_candidate(chain, coins, [], address(key)))
        coins = validate_next(block, chain, coins)
        chain.append(block)
    clock.now += core.TARGET_SECONDS
    nxt = solve(make_candidate(chain, coins, [], address(key)))
    snapshot = copy.deepcopy(coins)
    kept = validate_next(nxt, chain, coins)                      # default: the caller's map is left alone
    assert coins == snapshot and len(kept) == len(coins) + 1
    owned = copy.deepcopy(coins)
    result = validate_next(nxt, chain, owned, inplace=True)      # opt-in: the map is updated in place
    assert result is owned and owned == kept
    # replaying a few hundred blocks must stay fast (it used to copy the whole UTXO set per block)
    node = Node(tmp_path / "n")
    try:
        grow(node, key, 300, clock)
        started = time.time()
        validate_chain(node.chain)
        assert time.time() - started < 5
    finally:
        node.close()
