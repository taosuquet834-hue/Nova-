import threading
import urllib.error
import urllib.request

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from novacoin.core import UNIT, Invalid, subsidy
from novacoin.node import Node, NodeServer, request_json
from novacoin.wallet import address, build_transaction


@pytest.fixture
def chain(tmp_path):
    node = Node(tmp_path / "n")
    server = NodeServer(("127.0.0.1", 0), node)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    alice, bob = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    for _ in range(3):
        node.mine_one(address(alice))
    tx = build_transaction(alice, node.balance(address(alice))["utxos"], address(bob), 10 * UNIT, 150_000)
    txid = node.submit(tx)
    node.mine_one(address(alice))
    yield node, f"http://127.0.0.1:{server.server_port}", alice, bob, txid
    server.shutdown()
    server.server_close()
    node.close()


def get(url):
    return request_json(url)


def test_block_view_reconciles_rewards_fees_and_links(chain):
    node, url, alice, bob, txid = chain
    block = get(url + "/api/explorer/block?key=4")
    assert block["height"] == 4 and block["hash"] == node.ids[4] and block["previous"] == node.ids[3]
    assert block["miner"] == address(alice) and block["tx_count"] == 2
    assert block["fees"] == 150_000 and block["reward"] == subsidy(4) + 150_000
    assert block["next"] is None and block["confirmations"] == 1
    assert get(url + "/api/explorer/block?key=" + node.ids[2])["height"] == 2          # by hash
    genesis = get(url + "/api/explorer/block?key=0")
    assert genesis["height"] == 0 and genesis["miner"] is None and genesis["next"] == node.ids[1]
    payment = [t for t in block["transactions"] if not t["coinbase"]][0]
    assert payment["txid"] == txid and payment["fee"] == 150_000
    assert payment["inputs"][0]["address"] == address(alice) and payment["inputs"][0]["amount"] == 50 * UNIT


def test_block_list_is_paged_newest_first(chain):
    node, url, *_ = chain
    page = get(url + "/api/explorer/blocks?start=0&limit=3")
    assert [b["height"] for b in page["blocks"]] == [4, 3, 2] and page["height"] == 4
    assert [b["height"] for b in get(url + "/api/explorer/blocks?start=3&limit=10")["blocks"]] == [1, 0]
    for bad in ("limit=0", "limit=101", "start=-1", "start=x"):
        with pytest.raises(Invalid):
            get(url + "/api/explorer/blocks?" + bad)


def test_transaction_and_address_views(chain):
    node, url, alice, bob, txid = chain
    tx = get(url + "/api/explorer/tx?id=" + txid)
    assert tx["height"] == 4 and tx["confirmations"] == 1 and tx["fee"] == 150_000 and tx["confirmed"]
    bob_view = get(url + "/api/explorer/address?address=" + address(bob))
    assert bob_view["received"] == 10 * UNIT and bob_view["sent"] == 0 and bob_view["confirmed"] == 10 * UNIT
    alice_view = get(url + "/api/explorer/address?address=" + address(alice))
    assert alice_view["sent"] == 50 * UNIT                     # the coin she spent
    assert alice_view["received"] == 4 * 50 * UNIT + 150_000 + (50 * UNIT - 10 * UNIT - 150_000)
    assert alice_view["history"][0]["height"] == 4            # newest first
    assert get(url + "/api/explorer/address?address=" + address(Ed25519PrivateKey.generate()))["events"] == 0


def test_pending_transaction_is_visible_before_confirmation(chain):
    node, url, alice, bob, _ = chain
    coins = node.balance(address(alice))["utxos"]
    pending = node.submit(build_transaction(alice, coins, address(bob), UNIT, 150_000))
    view = get(url + "/api/explorer/tx?id=" + pending)
    assert view["confirmed"] is False and view["height"] is None and view["fee"] == 150_000


def test_search_dispatch_and_errors(chain):
    node, url, alice, bob, txid = chain
    assert get(url + "/api/explorer/search?q=3") == {"type": "block", "key": 3}
    assert get(url + "/api/explorer/search?q=" + node.ids[1].upper())["type"] == "block"
    assert get(url + "/api/explorer/search?q=" + txid) == {"type": "tx", "key": txid}
    assert get(url + "/api/explorer/search?q=" + address(bob))["type"] == "address"
    for bad in ("999", "zzz", "0" * 64, "", "x" * 200):
        with pytest.raises(Invalid):
            get(url + "/api/explorer/search?q=" + bad)
    for bad in ("block?key=999", "block?key=" + "0" * 64, "tx?id=zz", "tx?id=" + "0" * 64, "address?address=bad"):
        with pytest.raises(Invalid):
            get(url + "/api/explorer/" + bad)


def test_page_is_served_and_never_injects_html(chain):
    node, url, *_ = chain
    with urllib.request.urlopen(url + "/explorer") as response:
        body = response.read().decode()
        assert response.headers["Content-Security-Policy"].startswith("default-src 'none'")
    assert "Explorateur" in body and "innerHTML" not in body and "document.write" not in body
    assert "eval(" not in body


def test_peer_port_does_not_serve_the_explorer(chain):
    node, url, *_ = chain
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(url.replace("http", "http") + "/api/explorer/nothing")
    assert exc.value.code == 404 or exc.value.code == 400
