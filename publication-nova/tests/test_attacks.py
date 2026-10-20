"""V7: the attack bench as a regression suite, plus the defects it found."""
import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from novacoin import attack_bench as bench
from novacoin import node as module
from novacoin.core import MIN_FEE_PER_BYTE, UNIT, Invalid, transaction_id
from novacoin.node import MAX_MEMPOOL, Node
from novacoin.wallet import address, build_transaction


def outcomes(names, **kwargs):
    results, report = bench.run(selected=names, **kwargs)
    return {r.name: r for r in results}, report


def test_double_spends_are_refused():
    results, _ = outcomes({"double_spend_in_pool", "double_spend_in_block"})
    assert len(results) == 2 and all(r.held for r in results.values())


def test_reorg_attacks_behave_as_documented():
    results, report = outcomes({"majority_reorg", "equal_work_does_not_switch", "deep_reorg_policy"})
    by = {name.split(" ")[0]: r for name, r in results.items()}
    assert by["Retournement"].severity == "inhérent" and not by["Retournement"].held     # inherent to PoW
    assert by["Chaîne"].held and by["Réécriture"].held
    assert "modèle exact" in report and "51 %" in report


def test_time_warp_is_bounded():
    results, _ = outcomes({"time_warp_window"})
    assert all(r.held for r in results.values())


def test_fuzzing_never_causes_an_internal_error():
    results, _ = outcomes({"fuzz_consensus"}, fuzz_rounds=600)
    (result,) = results.values()
    assert result.held, result.observed


def test_peer_and_pool_defences_from_the_bench():
    results, _ = outcomes({"mempool_flood", "lying_peer_search_cost"})
    assert len(results) == 2 and all(r.held for r in results.values())


def test_bench_does_not_leave_the_clock_patched():
    import time
    from novacoin import core
    outcomes({"double_spend_in_pool"})
    assert core.time is time


def test_nakamoto_table_matches_known_values():
    # Values published in the Bitcoin white paper (q = 0.1: z=1 -> 0.2045873, z=5 -> 0.0009137)
    assert bench.catch_up_probability(0.1, 1) == pytest.approx(0.2045873, abs=1e-6)
    assert bench.catch_up_probability(0.1, 5) == pytest.approx(0.0009137, abs=1e-6)
    assert bench.catch_up_probability(0.3, 5) == pytest.approx(0.1773523, abs=1e-6)
    assert bench.catch_up_probability(0.51, 6) == 1.0


# ------------------------------------------------------------------ defects found by the bench

@pytest.fixture
def funded(tmp_path):
    node, owners = Node(tmp_path / "n"), [Ed25519PrivateKey.generate() for _ in range(3)]
    for key in owners:
        for _ in range(3):
            node.mine_one(address(key))
    yield node, owners
    node.close()


def test_submit_does_not_revalidate_the_whole_pool(funded, monkeypatch):
    node, (a, b, c) = funded
    dest = address(c)
    node.submit(build_transaction(a, node.balance(address(a))["utxos"], dest, UNIT, 100_000))
    node.submit(build_transaction(b, node.balance(address(b))["utxos"], dest, UNIT, 100_000))
    calls = []
    original = module.apply_transaction
    monkeypatch.setattr(module, "apply_transaction", lambda *args: calls.append(1) or original(*args))
    node.submit(build_transaction(c, node.balance(address(c))["utxos"], address(a), UNIT, 100_000))
    assert len(calls) == 1                           # only the new payment, not the two already pending


def test_pool_view_stays_consistent_after_rejections_blocks_and_restart(funded, tmp_path):
    node, (a, b, c) = funded
    coins = node.balance(address(a))["utxos"]
    good = build_transaction(a, coins, address(b), UNIT, 100_000)
    conflicting = build_transaction(a, coins, address(c), UNIT, 100_000)     # same coins
    node.submit(good)
    with pytest.raises(Invalid):
        node.submit(conflicting)
    assert list(node.pending) == [transaction_id(good)]
    node.mine_one(address(c))                        # confirms the payment; view rebuilt
    assert node.pending == {}
    node.submit(build_transaction(b, node.balance(address(b))["utxos"], address(c), UNIT, 100_000))
    assert len(node.pending) == 1


def test_full_pool_evicts_the_cheapest_payment_for_a_better_one(tmp_path, monkeypatch):
    monkeypatch.setattr(module, "MAX_MEMPOOL", 3)
    node = Node(tmp_path / "n")
    owners = [Ed25519PrivateKey.generate() for _ in range(5)]
    try:
        for key in owners:
            for _ in range(3):
                node.mine_one(address(key))
        dest = address(Ed25519PrivateKey.generate())
        ids = {}
        for key, fee in zip(owners[:3], (300_000, 120_000, 200_000)):
            ids[fee] = node.submit(build_transaction(key, node.balance(address(key))["utxos"], dest, UNIT, fee))
        with pytest.raises(Invalid, match="pleine"):                    # pays no more than the cheapest
            node.submit(build_transaction(owners[3], node.balance(address(owners[3]))["utxos"], dest, UNIT, 120_000))
        better = node.submit(build_transaction(owners[4], node.balance(address(owners[4]))["utxos"], dest, UNIT, 500_000))
        assert ids[120_000] not in node.pending and better in node.pending and len(node.pending) == 3
        assert any(e["kind"] == "evicted" for e in node.events())
    finally:
        node.close()
    reopened = Node(tmp_path / "n")
    try:
        assert set(reopened.pending) == {ids[300_000], ids[200_000], better}      # eviction was persisted
    finally:
        reopened.close()


def test_ancestor_search_is_logarithmic(tmp_path, monkeypatch):
    node = Node(tmp_path / "n")
    key = Ed25519PrivateKey.generate()
    try:
        for _ in range(40):
            node.mine_one(address(key))
        asked = []
        local = list(node.ids)
        remote = local[:25] + ["ab" * 32] * 20                     # honest up to height 24, then different
        monkeypatch.setattr(node, "peer_call", lambda peer, path, **kw: (
            asked.append(path) or {"hashes": [remote[int(path.split("from=")[1].split("&")[0])]]}))
        assert node._find_common("https://127.0.0.1:1", 44, local) == 24
        assert len(asked) <= 1 + 6                                  # genesis + log2(41) probes
    finally:
        node.close()
