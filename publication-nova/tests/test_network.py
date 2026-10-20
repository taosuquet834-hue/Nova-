import copy
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from novacoin.core import Invalid, UNIT
from novacoin.node import Node, NodeServer, PeerServer, request_json
from novacoin.wallet import address, build_transaction


@pytest.fixture
def network(tmp_path):
    alice, bob = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    nodes, servers, threads, urls = [], [], [], []
    for i in range(2):
        node = Node(tmp_path / str(i), demo_keys={"Alice": alice, "Bob": bob} if i == 0 else {})
        server = NodeServer(("127.0.0.1", 0), node)
        peer_server = PeerServer(("127.0.0.1", 0), node)
        for srv in (server, peer_server):
            thread = threading.Thread(target=srv.serve_forever, daemon=True)
            thread.start()
            threads.append(thread)
            servers.append(srv)
        node.p2p_url = f"https://127.0.0.1:{peer_server.server_port}"   # test convenience
        nodes.append(node)
        urls.append(f"http://127.0.0.1:{server.server_port}")
    nodes[0].add_peer(nodes[1].p2p_url)
    nodes[1].add_peer(nodes[0].p2p_url)
    yield nodes, urls, alice, bob
    for server in servers:
        server.shutdown()
        server.server_close()
    for thread in threads:
        thread.join()
    for node in nodes:
        node.close()


def test_two_nodes_propagate_transaction_and_block(network):
    nodes, urls, alice, bob = network
    for _ in range(3):
        nodes[0].mine_one(address(alice))
    nodes[1].sync_once()
    assert nodes[0].status()["tip"] == nodes[1].status()["tip"]
    coins = request_json(urls[0] + "/api/balance?address=" + address(alice))["utxos"]
    tx = build_transaction(alice, coins, address(bob), 10 * UNIT, 100_000)
    txid = request_json(urls[0] + "/api/transactions", tx)["txid"]
    nodes[1].sync_once()
    assert txid in nodes[1].pending
    nodes[1].mine_one(address(bob))
    nodes[0].sync_once()
    assert nodes[0].status()["tip"] == nodes[1].status()["tip"]
    assert nodes[0].balance(address(bob))["confirmed"] == 60 * UNIT + 100_000
    assert not nodes[0].pending


def test_admin_protection_and_cross_site_requests(network):
    nodes, urls, alice, _ = network
    with pytest.raises(Invalid, match="administrateur"):
        request_json(urls[0] + "/api/mine", {"address": address(alice), "count": 1})
    with pytest.raises(Invalid, match="administrateur"):
        request_json(urls[0] + "/api/dashboard")
    assert request_json(urls[0] + "/api/dashboard", token=nodes[0].token)["demo"]
    request = Request(urls[0] + "/api/mine", b'{}',
                      {"Origin": "https://untrusted.example", "X-Nova-Token": nodes[0].token})
    with pytest.raises(HTTPError) as error:
        urlopen(request, timeout=3)
    assert error.value.code == 400


def test_only_one_concurrent_spend_wins(network):
    nodes, urls, alice, bob = network
    node = nodes[0]
    for _ in range(3):
        node.mine_one(address(alice))
    coins = node.balance(address(alice))["utxos"]
    transactions = [build_transaction(alice, coins, address(bob), amount * UNIT, 100_000)
                    for amount in (10, 11)]

    def send(tx):
        try:
            request_json(urls[0] + "/api/transactions", tx)
            return True
        except Invalid:
            return False
    with ThreadPoolExecutor(2) as pool:
        assert sum(pool.map(send, transactions)) == 1
    assert len(node.pending) == 1


def test_peer_disconnect_reported_and_recovery(network):
    nodes, urls, _, _ = network
    nodes[0].add_peer("https://127.0.0.1:1")
    nodes[0].sync_once()
    assert nodes[0].peer_health[nodes[1].p2p_url]["ok"]
    assert nodes[0].peer_health["https://127.0.0.1:1"]["ok"] is False


def test_malformed_request_returns_error_and_node_survives(network):
    _, urls, _, _ = network
    for payload in ({"unexpected": True}, {"inputs": None}, {"version": True}):
        with pytest.raises(Invalid):
            request_json(urls[0] + "/api/transactions", payload)
    assert request_json(urls[0] + "/api/status")["height"] == 0


def test_dashboard_and_security_headers(network):
    _, urls, _, _ = network
    with urlopen(urls[0], timeout=3) as response:
        body = response.read().decode()
        assert '<html lang="fr">' in body
        assert "Miner 3 blocs" in body
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
