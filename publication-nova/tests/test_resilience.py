import copy
import sqlite3

import pytest

from novacoin.core import Invalid, UNIT
from novacoin.node import Node, request_json
from novacoin.wallet import address, build_transaction
from helpers import call
from test_network import network


def fund(nodes, alice):
    for _ in range(3):
        nodes[0].mine_one(address(alice))
    nodes[1].sync_once()
    nodes[0].sync_once()


def test_partition_blocks_incoming_and_outgoing_then_catches_up(network):
    nodes, urls, alice, _ = network
    fund(nodes, alice)
    before = nodes[1].status()["tip"]
    request_json(urls[1] + "/api/network", {"isolated": True}, nodes[1].token)
    nodes[0].mine_one(address(alice))
    nodes[1].sync_once()
    nodes[0].sync_once()
    assert nodes[1].status()["tip"] == before
    assert nodes[1].status()["network_state"] == "isolated"
    for endpoint in ("/p2p/hashes?from=0&limit=1", "/p2p/mempool"):
        with pytest.raises(Invalid, match="isolé"):
            call(nodes[1].p2p_url, endpoint)
    with pytest.raises(Invalid, match="isolé"):
        call(nodes[1].p2p_url, "/p2p/blocks", nodes[0].chain[-1])
    request_json(urls[1] + "/api/network", {"isolated": False}, nodes[1].token)
    nodes[1].sync_once()
    nodes[0].sync_once()
    assert nodes[1].status()["tip"] == nodes[0].status()["tip"]
    assert nodes[1].status()["network_state"] == "connected"
    assert any(e["kind"] == "sync" for e in nodes[1].events())


def test_pending_payment_survives_isolation_and_confirms(network):
    nodes, urls, alice, bob = network
    fund(nodes, alice)
    nodes[0].set_isolated(True)
    txid = nodes[0].demo_send("Alice", address(bob), "10")
    nodes[1].sync_once()
    assert txid not in nodes[1].pending
    nodes[0].set_isolated(False)
    nodes[1].sync_once()
    assert txid in nodes[1].pending
    nodes[1].mine_one(address(alice))
    nodes[0].sync_once()
    assert nodes[0].balance(address(bob))["confirmed"] == 10 * UNIT
    assert nodes[0].status()["tip"] == nodes[1].status()["tip"]


def test_fork_equal_work_waits_then_stronger_branch_wins(network):
    nodes, _, alice, bob = network
    fund(nodes, alice)
    nodes[1].set_isolated(True)
    nodes[0].mine_one(address(alice))
    nodes[1].mine_one(address(bob))
    assert nodes[0].work == nodes[1].work
    tips = [n.status()["tip"] for n in nodes]
    assert tips[0] != tips[1]
    nodes[1].set_isolated(False)
    for n in nodes:
        n.sync_once()
    assert [n.status()["tip"] for n in nodes] == tips
    assert nodes[0].status()["network_state"] == "diverged"
    nodes[1].mine_one(address(bob))
    nodes[0].sync_once()
    nodes[1].sync_once()
    assert nodes[0].status()["tip"] == nodes[1].status()["tip"]
    event = next(e for e in nodes[0].events() if e["kind"] == "reorg")
    assert event["details"]["removed_blocks"] == 1
    assert event["details"]["added_blocks"] == 2


def test_conflicting_payments_during_partition_are_reconciled(network):
    nodes, _, alice, bob = network
    fund(nodes, alice)
    nodes[1].set_isolated(True)
    coins = nodes[0].balance(address(alice))["utxos"]
    left = build_transaction(alice, coins, address(bob), 10 * UNIT, 100_000)
    right = build_transaction(alice, coins, address(bob), 20 * UNIT, 100_000)
    nodes[0].submit(left)
    nodes[1].submit(right)
    nodes[0].mine_one(address(alice))
    nodes[1].mine_one(address(alice))
    nodes[1].mine_one(address(alice))
    nodes[1].set_isolated(False)
    nodes[0].sync_once()
    assert nodes[0].balance(address(bob))["confirmed"] == 20 * UNIT
    assert not nodes[0].pending
    with pytest.raises(Invalid, match="dépensée"):
        nodes[0].submit(left)


def test_inflight_sync_cannot_cross_isolation_barrier(network, monkeypatch):
    nodes, _, alice, _ = network
    nodes[0].mine_one(address(alice))
    from novacoin import node as module
    original = module.peer_request

    def intercepted(url, path, *args, **kwargs):
        response = original(url, path, *args, **kwargs)
        if "/p2p/blocks?" in path:
            nodes[1].set_isolated(True)
            nodes[1].set_isolated(False)
        return response

    monkeypatch.setattr(module, "peer_request", intercepted)
    nodes[1].sync_once()
    assert nodes[1].status()["height"] == 0
    monkeypatch.setattr(module, "peer_request", original)
    nodes[1].sync_once()
    assert nodes[1].status()["height"] == 1


def test_isolation_and_event_log_persist(tmp_path):
    node = Node(tmp_path)
    node.set_isolated(True)
    node.close()
    node = Node(tmp_path)
    try:
        assert node.isolated
        assert node.status()["network_state"] == "isolated"
        assert any(e["kind"] == "isolation" for e in node.events())
        node.set_isolated(False)
        for i in range(220):
            node.record_event("test", str(i))
        assert node.db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 200
        assert len(node.events()) == 30
    finally:
        node.close()


@pytest.mark.parametrize("operation", ["block", "reorg", "submit"])
def test_disk_failure_rolls_back_chain_and_pending(network, operation):
    nodes, _, alice, bob = network
    fund(nodes, alice)
    node = nodes[0]
    tx = build_transaction(alice, node.balance(address(alice))["utxos"],
                           address(bob), UNIT, 100_000)
    if operation != "submit":
        node.submit(tx)
    before = copy.deepcopy(node.chain), copy.deepcopy(node.pending), copy.deepcopy(node.utxos)
    before_disk = list(node.db.execute("SELECT * FROM blocks")), list(node.db.execute("SELECT * FROM pending"))
    node.db.execute("""CREATE TRIGGER simulate_disk_failure BEFORE DELETE ON pending
                       BEGIN SELECT RAISE(ABORT, 'simulated disk failure'); END""")
    if operation == "submit":
        # Trigger an insert failure when the pending table is empty.
        node.db.execute("""CREATE TRIGGER simulate_insert_failure BEFORE INSERT ON pending
                           BEGIN SELECT RAISE(ABORT, 'simulated disk failure'); END""")
    with pytest.raises(sqlite3.DatabaseError):
        if operation == "block":
            node.mine_one(address(alice))
        elif operation == "reorg":
            nodes[1].mine_one(address(bob))
            nodes[1].mine_one(address(bob))
            node.adopt(copy.deepcopy(nodes[1].chain))
        else:
            node.submit(tx)
    assert (node.chain, node.pending, node.utxos) == before
    assert (list(node.db.execute("SELECT * FROM blocks")), list(node.db.execute("SELECT * FROM pending"))) == before_disk


def test_lab_controls_secondary_and_require_admin(network):
    nodes, urls, _, _ = network
    nodes[0].lab_peer = (urls[1], str(nodes[1].data_dir / "admin.token"))
    payload = {"target": "secondary", "action": "isolate"}
    with pytest.raises(Invalid, match="administrateur"):
        request_json(urls[0] + "/api/lab/control", payload)
    request_json(urls[0] + "/api/lab/control", payload, nodes[0].token)
    assert nodes[1].isolated
    dashboard = request_json(urls[0] + "/api/dashboard", token=nodes[0].token)
    assert dashboard["lab"]["secondary"]["isolated"]
    assert nodes[1].token not in str(dashboard)
    payload["action"] = "connect"
    request_json(urls[0] + "/api/lab/control", payload, nodes[0].token)
    assert not nodes[1].isolated
    with pytest.raises(Invalid):
        request_json(urls[1] + "/api/network", {"isolated": "false"}, nodes[1].token)
