import threading
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from novacoin import node as module
from novacoin.core import SYNC_BATCH, Invalid
from novacoin.node import Node, NodeServer, PeerServer, request_json
from novacoin.wallet import address
from helpers import call


def wait_for(condition, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.1)
    return False


@pytest.fixture
def trio(tmp_path):
    """Three nodes; node 2 is configured with node 0 only, and nobody lists node 2."""
    nodes, servers, urls = [], [], []
    for i in range(3):
        node = Node(tmp_path / f"n{i}")
        server = NodeServer(("127.0.0.1", 0), node)
        peer_server = PeerServer(("127.0.0.1", 0), node)
        node.local_url = f"http://127.0.0.1:{server.server_port}"
        for srv in (server, peer_server):
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            servers.append(srv)
        nodes.append(node)
        urls.append(f"https://127.0.0.1:{peer_server.server_port}")   # peer (TLS) addresses
    nodes[0].add_peer(urls[1])
    nodes[1].add_peer(urls[0])
    nodes[2].add_peer(urls[0])
    yield nodes, urls
    for server in servers:
        server.shutdown()
        server.server_close()
    for node in nodes:
        node.close()


def requests_seen(monkeypatch):
    seen = []
    original = module.peer_request

    def spy(url, path, *args, **kwargs):
        seen.append(path)
        return original(url, path, *args, **kwargs)

    monkeypatch.setattr(module, "peer_request", spy)
    return seen


def test_incremental_sync_downloads_only_missing_blocks(trio, monkeypatch):
    nodes, _ = trio
    key = Ed25519PrivateKey.generate()
    monkeypatch.setattr(module, "SYNC_BATCH", 8)   # same module serves and consumes batches
    batch = 8
    for _ in range(3 * batch + 5):
        nodes[0].mine_one(address(key))
    nodes[1].sync_once()
    assert nodes[1].status()["tip"] == nodes[0].status()["tip"]   # several batches
    for _ in range(3):
        nodes[0].mine_one(address(key))
    seen = requests_seen(monkeypatch)
    nodes[1].sync_once()
    assert nodes[1].status()["tip"] == nodes[0].status()["tip"]
    fetched = [u for u in seen if "/p2p/blocks?" in u]
    assert len(fetched) == 1 and f"from={3 * batch + 6}&" in fetched[0]   # only the 3 new blocks


def test_incremental_fork_switch_replays_from_common_ancestor(trio):
    nodes, _ = trio
    a, b = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    for _ in range(4):
        nodes[0].mine_one(address(a))
    nodes[1].sync_once()
    nodes[1].set_isolated(True)
    nodes[0].mine_one(address(a))
    for _ in range(3):
        nodes[1].mine_one(address(b))
    nodes[1].set_isolated(False)
    nodes[0].sync_once()
    assert nodes[0].status()["tip"] == nodes[1].status()["tip"]
    assert nodes[0].status()["height"] == 7
    event = next(e for e in nodes[0].events() if e["kind"] == "reorg")
    assert (event["details"]["removed_blocks"], event["details"]["added_blocks"]) == (1, 3)
    assert nodes[0].balance(address(b))["confirmed"] == 3 * 50 * 10**8


def test_replaced_chain_survives_restart(trio, tmp_path):
    nodes, _ = trio
    a, b = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    nodes[0].mine_one(address(a))
    nodes[1].set_isolated(True)
    nodes[1].mine_one(address(b))
    nodes[1].mine_one(address(b))
    nodes[1].set_isolated(False)
    nodes[0].sync_once()
    tip, work, data = nodes[0].status()["tip"], nodes[0].work, nodes[0].data_dir
    nodes[0].close()
    reopened = Node(data)
    try:
        assert reopened.status()["tip"] == tip and reopened.work == work
    finally:
        reopened.close()
    nodes[0] = Node(data)  # the fixture closes whatever sits in the list


def test_invalid_blocks_from_peer_are_refused(trio, monkeypatch):
    nodes, _ = trio
    key = Ed25519PrivateKey.generate()
    for _ in range(3):
        nodes[0].mine_one(address(key))
    original = module.peer_request

    def forged(url, path, *args, **kwargs):
        data, remote_id = original(url, path, *args, **kwargs)
        if "/p2p/blocks?" in path:
            data["blocks"][1]["transactions"][0]["outputs"][0]["amount"] += 1
        return data, remote_id

    monkeypatch.setattr(module, "peer_request", forged)
    nodes[1].sync_once()
    assert nodes[1].status()["height"] == 0
    assert nodes[1].status()["peers"][0]["ok"] is False


def test_hash_and_block_endpoints_are_bounded_and_respect_isolation(trio):
    nodes, urls = trio
    key = Ed25519PrivateKey.generate()
    nodes[0].mine_one(address(key))
    assert len(call(urls[0], "/p2p/hashes?from=0&limit=2")["hashes"]) == 2
    for bad in ("from=-1&limit=1", "from=0&limit=0", f"from=0&limit={SYNC_BATCH + 1}", "from=x"):
        with pytest.raises(Invalid):
            call(urls[0], "/p2p/blocks?" + bad)
    nodes[0].set_isolated(True)
    with pytest.raises(Invalid, match="isolé"):
        call(urls[0], "/p2p/hashes?from=0&limit=1")


def test_automatic_mining_starts_stops_and_persists(tmp_path):
    key = Ed25519PrivateKey.generate()
    node = Node(tmp_path / "auto")
    node.start_sync()
    try:
        node.set_automine(True, address(key))
        assert wait_for(lambda: node.status()["height"] >= 3)
        assert node.status()["automine"]["enabled"] is True
        node.set_automine(False)
        time.sleep(0.5)
        height = node.status()["height"]
        time.sleep(1)
        assert node.status()["height"] == height
        with pytest.raises(Invalid):
            node.set_automine(True, "adresse-invalide")
        with pytest.raises(Invalid):
            node.set_automine("oui")
        node.set_automine(True, address(key))
    finally:
        node.close()
    reopened = Node(tmp_path / "auto")
    try:
        assert reopened.status()["automine"]["enabled"] is True
    finally:
        reopened.close()


def test_automine_endpoint_needs_admin_and_nodes_converge(trio):
    nodes, urls = trio
    key = Ed25519PrivateKey.generate()
    for node in nodes:
        node.start_sync()
    local = nodes[1].local_url
    with pytest.raises(Invalid, match="administrateur"):
        request_json(local + "/api/automine", {"enabled": True, "address": address(key)})
    request_json(local + "/api/automine", {"enabled": True, "address": address(key)}, nodes[1].token)
    assert wait_for(lambda: all(n.status()["height"] >= 4 for n in nodes), 40)
    request_json(local + "/api/automine", {"enabled": False}, nodes[1].token)
    time.sleep(1)
    assert wait_for(lambda: len({n.status()["tip"] for n in nodes}) == 1)


def test_competing_automatic_miners_converge_on_one_chain(trio):
    nodes, urls = trio
    keys = [Ed25519PrivateKey.generate() for _ in range(3)]
    for node in nodes:
        node.max_reorg = 0          # this test is about mining convergence, not the reorganisation-evidence policy
        node.start_sync()
    nodes[0].add_peer(urls[2])
    nodes[1].add_peer(urls[2])
    nodes[2].add_peer(urls[1])
    for node, key in zip(nodes, keys):
        node.set_automine(True, address(key))
    assert wait_for(lambda: all(n.status()["height"] >= 12 for n in nodes), 60)
    for node in nodes:
        node.set_automine(False)
    time.sleep(1)
    tips = lambda: {n.status()["tip"] for n in nodes}
    if not wait_for(lambda: len(tips()) == 1, 10):
        # The only legitimate reason not to converge: two branches with exactly the same, maximal
        # work (two miners found a block at the same height just before stopping). Each node
        # keeps the first branch it saw; one more block on either branch settles everyone.
        top = max(n.work for n in nodes)
        leaders = [i for i, n in enumerate(nodes) if n.work == top]
        assert len({nodes[i].status()["tip"] for i in leaders}) > 1, "pas d'égalité : vraie divergence"
        nodes[leaders[0]].mine_one(address(keys[leaders[0]]))
    assert wait_for(lambda: len(tips()) == 1, 20)
    assert nodes[0].work == nodes[1].work == nodes[2].work
    issued = sum(n.balance(address(k))["confirmed"] for n in nodes[:1] for k in keys)
    assert issued == nodes[0].status()["height"] * 50 * 10**8   # no coin created or lost in forks


def test_peer_discovery_announcement_and_self_detection(trio):
    nodes, urls = trio
    for node in nodes:
        node.start_sync()
    # Node 2 knows only node 0. Node 1 and node 0 must learn node 2, node 2 must learn node 1.
    assert wait_for(lambda: urls[1] in nodes[2].peers and urls[2] in nodes[0].peers
                    and urls[2] in nodes[1].peers)
    # Nobody keeps its own address as a peer, even though others list it.
    assert wait_for(lambda: all(u not in n.peers for n, u in zip(nodes, urls)))
    assert wait_for(lambda: all(len(n.status()["peers"]) == 2 and all(p["ok"] for p in n.status()["peers"])
                                for n in nodes))
    key = Ed25519PrivateKey.generate()
    nodes[2].mine_one(address(key))
    assert wait_for(lambda: len({n.status()["tip"] for n in nodes}) == 1)
    assert nodes[0].status()["height"] == 1


def test_discovery_ignores_public_and_malformed_addresses(trio):
    nodes, _ = trio
    node = nodes[0]
    before = dict(node.peers)
    some_id = "ab" * 32
    node.learn_announced("8.8.8.8", 18441, some_id)
    node.learn_announced("127.0.0.1", 80, some_id)
    node.learn_announced("::1", 18441, some_id)
    node.learn_announced("not-an-ip", 18441, some_id)
    node.learn_announced("127.0.0.1", 28441, "not-hex")
    node.learn_announced("127.0.0.1", 28441, node.node_id)   # ourselves
    assert node.peers == before
    node.learn_announced("192.168.1.20", 28441, some_id)
    assert node.peers["https://192.168.1.20:28441"] == some_id
    node.learn_announced("192.168.1.21", 28441, some_id)      # same identity, other address
    assert "https://192.168.1.21:28441" not in node.peers
