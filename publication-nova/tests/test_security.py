"""V4 peer transport: encryption, identity pinning, signed requests, abuse control."""
import socket
import ssl
import stat
import threading
import time
from urllib.parse import urlsplit

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from helpers import call, identity
from novacoin import node as module
from novacoin.core import Invalid
from novacoin.node import Node, NodeServer, PeerServer, decode_json
from novacoin.p2p import (NonceMemory, RateLimiter, Reputation, client_context, parse_peer,
                          sign_request, signing_payload)
from novacoin.wallet import address
from test_network import network  # noqa: F401  (fixture)
from pathlib import Path as _P
ROOT_DIR = _P(__file__).resolve().parents[1]


def raw(url, request, context=None):
    """Plain TLS client: send bytes, return (status, decoded JSON or raw text)."""
    parts = urlsplit(url)
    sock = (context or client_context()).wrap_socket(socket.create_connection((parts.hostname, parts.port), 5))
    try:
        sock.sendall(request)
        data = b""
        while chunk := sock.recv(65536):
            data += chunk
    except (ConnectionResetError, ssl.SSLError):
        pass
    finally:
        sock.close()
    head, _, body = data.partition(b"\r\n\r\n")
    status = int(head.split()[1]) if head.startswith(b"HTTP/") else None
    try:
        return status, decode_json(body)
    except Invalid:
        return status, body


def send(url, method, path, headers, body=b""):
    text = f"{method} {path} HTTP/1.1\r\nHost: x\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers.items())
    text += f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    return raw(url, text.encode() + body)


# ------------------------------------------------------------------ transport

def test_peer_port_speaks_only_tls13_with_the_node_identity(network):
    nodes, _, _, _ = network
    url = nodes[0].p2p_url
    parts = urlsplit(url)
    sock = client_context().wrap_socket(socket.create_connection((parts.hostname, parts.port), 5))
    try:
        assert sock.version() == "TLSv1.3"
        from novacoin.p2p import certificate_id
        assert certificate_id(sock.getpeercert(True)) == nodes[0].node_id
    finally:
        sock.close()
    # An older protocol version is refused.
    old = client_context()
    old.minimum_version, old.maximum_version = ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2
    with pytest.raises(ssl.SSLError):
        old.wrap_socket(socket.create_connection((parts.hostname, parts.port), 5))
    # Plain HTTP on the peer port yields nothing readable.
    plain = socket.create_connection((parts.hostname, parts.port), 5)
    plain.sendall(b"GET /p2p/status HTTP/1.0\r\n\r\n")
    plain.settimeout(5)
    try:
        data = plain.recv(4096)
    except (ConnectionResetError, socket.timeout):
        data = b""
    plain.close()
    assert b"chainwork" not in data and not data.startswith(b"HTTP/")


def test_identity_is_pinned_and_wrong_identity_is_refused_before_sending(network):
    nodes, _, _, _ = network
    url, real = nodes[0].p2p_url, nodes[0].node_id
    assert call(url, "/p2p/status", expected=real)["network"]
    sent_before = len(nodes[0].nonces.seen)
    with pytest.raises(Invalid, match="Identité du pair différente"):
        call(url, "/p2p/status", expected="00" * 32)
    assert len(nodes[0].nonces.seen) == sent_before          # nothing was sent to the impostor


def test_first_contact_remembers_identity_and_later_mismatch_blocks_sync(network):
    nodes, _, _, _ = network
    assert nodes[0].peers[nodes[1].p2p_url] is None
    nodes[0].sync_once()
    assert nodes[0].peers[nodes[1].p2p_url] == nodes[1].node_id
    assert any(e["kind"] == "peer_identity" for e in nodes[0].events())
    nodes[0].peers[nodes[1].p2p_url] = "ab" * 32            # as if the peer's key had changed
    nodes[1].mine_one(address(Ed25519PrivateKey.generate()))
    nodes[0].sync_once()
    health = nodes[0].peer_health[nodes[1].p2p_url]
    assert health["ok"] is False and "Identité" in health["error"]
    assert nodes[0].status()["height"] == 0                  # nothing accepted from the impostor


def test_pinned_identity_survives_restart(tmp_path):
    first = Node(tmp_path / "a")
    other = "cd" * 32
    first.add_peer(f"https://127.0.0.1:29999#{other}")
    node_id, key_file = first.node_id, tmp_path / "a" / "node.key"
    first.close()
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600
    again = Node(tmp_path / "a")
    try:
        assert again.node_id == node_id
        assert again.peers == {"https://127.0.0.1:29999": other}
    finally:
        again.close()


def test_peer_address_syntax():
    assert parse_peer("https://127.0.0.1:2000") == ("https://127.0.0.1:2000", None)
    assert parse_peer("https://127.0.0.1:2000#" + "a" * 64) == ("https://127.0.0.1:2000", "a" * 64)
    for bad in ("http://127.0.0.1:2000", "https://127.0.0.1", "https://user@127.0.0.1:2000",
                "https://127.0.0.1:2000/x", "https://127.0.0.1:2000#xyz", "https://127.0.0.1:2000?a=1", 5):
        with pytest.raises(Invalid):
            parse_peer(bad)


# ------------------------------------------------------------------ signed requests

def test_unsigned_tampered_replayed_and_misaddressed_requests_are_refused(network):
    nodes, _, _, _ = network
    url, nid = nodes[0].p2p_url, nodes[0].node_id
    key, my_id = identity()
    assert raw(url, b"GET /p2p/status HTTP/1.0\r\n\r\n")[0] == 401                   # no signature
    headers = sign_request(key, my_id, nid, "GET", "/p2p/status", b"", None)
    assert send(url, "GET", "/p2p/status", headers)[0] == 200
    status, body = send(url, "GET", "/p2p/status", headers)                           # replay
    assert status == 401 and "rejouée" in body["error"]
    fresh = sign_request(key, my_id, nid, "GET", "/p2p/status", b"", None)
    assert send(url, "GET", "/p2p/mempool", fresh)[0] == 401                          # other path
    other_node = sign_request(key, my_id, nodes[1].node_id, "GET", "/p2p/status", b"", None)
    assert send(url, "GET", "/p2p/status", other_node)[0] == 401                      # meant for someone else
    old, nonce = int(time.time()) - 1000, "0" * 24
    from novacoin.p2p import find_identity_nonce
    stale = {"X-Nova-Id": my_id, "X-Nova-Time": str(old), "X-Nova-Nonce": nonce,
             "X-Nova-Work": str(find_identity_nonce(my_id)),
             "X-Nova-Sig": key.sign(signing_payload("GET", "/p2p/status", b"", old, nonce, my_id, nid, None)).hex()}
    status, body = send(url, "GET", "/p2p/status", stale)
    assert status == 401 and "Horloge" in body["error"]
    forged = sign_request(key, my_id, nid, "GET", "/p2p/status", b"", None)
    forged["X-Nova-Id"] = identity()[1]                                               # someone else's name
    assert send(url, "GET", "/p2p/status", forged)[0] == 401


def test_body_is_covered_by_the_signature(network):
    nodes, _, _, _ = network
    url, nid = nodes[0].p2p_url, nodes[0].node_id
    key, my_id = identity()
    headers = sign_request(key, my_id, nid, "POST", "/p2p/transactions", b'{"a":1}', None)
    status, _ = send(url, "POST", "/p2p/transactions", headers, b'{"a":2}')            # body swapped
    assert status == 401


def test_admin_and_wallet_routes_do_not_exist_on_the_peer_port(network):
    nodes, urls, _, _ = network
    for path in ("/api/dashboard", "/api/mine", "/api/automine", "/api/status", "/"):
        with pytest.raises(Invalid, match="inconnue"):
            call(nodes[0].p2p_url, path)
    for path in ("/p2p/status", "/p2p/blocks?from=0&limit=1", "/p2p/peers"):
        status, _ = raw_local(urls[0], path)
        assert status == 404                                  # peer routes are not on the local port


def raw_local(url, path):
    import urllib.error
    import urllib.request
    try:
        with urllib.request.urlopen(url + path, timeout=3) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


# ------------------------------------------------------------------ abuse control

def test_oversized_peer_body_is_refused(network):
    nodes, _, _, _ = network
    with pytest.raises(Invalid):
        call(nodes[0].p2p_url, "/p2p/transactions", {"x": "y" * 400_000})


def test_invalid_objects_lead_to_a_ban_and_then_to_refusal(network):
    nodes, _, _, _ = network
    url = nodes[0].p2p_url
    who = identity()
    banned_at = None
    for i in range(60):
        try:
            call(url, "/p2p/transactions", {"junk": i}, who=who)
        except Invalid as exc:
            if "banni" in str(exc):
                banned_at = i
                break
    assert banned_at is not None and banned_at > 10        # tolerated for a while, then cut off
    assert any(e["kind"] == "peer_banned" for e in nodes[0].events())
    assert nodes[0].status()["security"]["bans"][0]["key"] == who[1]
    with pytest.raises(Invalid, match="banni"):
        call(url, "/p2p/status", who=who)
    call(url, "/p2p/status")                               # an unrelated identity is unaffected


def test_flooding_is_rate_limited_per_identity_and_per_address(network):
    nodes, _, _, _ = network
    url, node = nodes[0].p2p_url, nodes[0]
    # Deterministic: tiny buckets that practically never refill during the test.
    node.id_limiter = RateLimiter(capacity=5, per_second=0.001)
    who = identity()
    answers = []
    for _ in range(8):
        try:
            answers.append(call(url, "/p2p/status", who=who)["network"])
        except Invalid as exc:
            answers.append(str(exc))
    assert answers[:5] == [answers[0]] * 5 and "Trop de requêtes" in answers[5]
    call(url, "/p2p/status")                                  # another identity is unaffected
    node.id_limiter = RateLimiter(capacity=60, per_second=15)
    node.ip_limiter = RateLimiter(capacity=3, per_second=0.001)
    refused = 0
    for _ in range(6):
        try:
            call(url, "/p2p/status")
        except Invalid as exc:
            refused += "Trop de requêtes" in str(exc)
    assert refused >= 3                                       # unauthenticated floods stop earlier
    assert node.status()["height"] == 0                       # the node itself stays healthy


def test_a_stalled_handshake_does_not_block_other_peers_and_connections_are_capped(network):
    nodes, _, _, _ = network
    parts = urlsplit(nodes[0].p2p_url)
    idle = [socket.create_connection((parts.hostname, parts.port)) for _ in range(8)]  # never speak
    try:
        started = time.monotonic()
        extra = socket.create_connection((parts.hostname, parts.port))
        extra.settimeout(3)
        try:
            assert extra.recv(1) == b""                      # over the per-address cap: dropped
        except (ConnectionResetError, socket.timeout):
            pass
        extra.close()
        assert time.monotonic() - started < 3
    finally:
        for sock in idle:
            sock.close()
    time.sleep(0.5)
    assert call(nodes[0].p2p_url, "/p2p/status")["network"]    # slots are released afterwards


def test_forged_blocks_from_a_peer_get_it_banned_by_us(network, monkeypatch):
    nodes, _, alice, _ = network
    for _ in range(2):
        nodes[0].mine_one(address(alice))
    original = module.peer_request

    def forged(url, path, *args, **kwargs):
        data, remote_id = original(url, path, *args, **kwargs)
        if "/p2p/blocks?" in path:
            data["blocks"][0]["transactions"][0]["outputs"][0]["amount"] += 1
        return data, remote_id

    monkeypatch.setattr(module, "peer_request", forged)
    for _ in range(4):
        nodes[1].sync_once()
    assert nodes[1].status()["height"] == 0
    assert nodes[1].is_banned(None, nodes[0].node_id)
    assert nodes[1].peer_health[nodes[0].p2p_url]["error"].startswith("Pair banni")
    monkeypatch.setattr(module, "peer_request", original)
    nodes[1].sync_once()
    assert nodes[1].status()["height"] == 0                  # still banned, nothing fetched


def test_closed_node_only_talks_to_pinned_identities(tmp_path):
    inner, outsider = Node(tmp_path / "closed", closed=True), Node(tmp_path / "friend")
    friend_server = PeerServer(("127.0.0.1", 0), outsider)
    closed_server = PeerServer(("127.0.0.1", 0), inner)
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (friend_server, closed_server)]
    for t in threads:
        t.start()
    try:
        url = f"https://127.0.0.1:{closed_server.server_port}"
        with pytest.raises(Invalid, match="fermé"):
            call(url, "/p2p/status")
        inner.add_peer(f"https://127.0.0.1:{friend_server.server_port}#{outsider.node_id}")
        # The pinned identity is accepted; discovery is switched off.
        key = outsider.key
        assert peer_ok(url, key, outsider.node_id)
        assert call(url, "/p2p/peers", who=(key, outsider.node_id))["peers"] == []
    finally:
        for server in (friend_server, closed_server):
            server.shutdown()
            server.server_close()
        inner.close()
        outsider.close()


def peer_ok(url, key, node_id):
    return call(url, "/p2p/status", who=(key, node_id))["network"]


# ------------------------------------------------------------------ unit tests of the guards

def test_reputation_decays_and_bans_expire():
    rep = Reputation(threshold=100, ban_seconds=900, half_life=60)
    key = ("id", "x")
    assert not rep.penalize(key, 60, now=0)
    assert not rep.penalize(key, 60, now=600)                # ten half-lives later: almost forgotten
    assert rep.penalize(key, 90, now=601)                    # but a burst bans
    assert rep.banned(key, now=700)
    assert rep.snapshot(now=700) == [{"kind": "id", "key": "x", "seconds_left": 801}]
    assert not rep.banned(key, now=601 + 901)


def test_rate_limiter_refills():
    limiter = RateLimiter(capacity=3, per_second=1)
    assert [limiter.allow("k", now=0) for _ in range(4)] == [True, True, True, False]
    assert limiter.allow("k", now=1.1) and not limiter.allow("k", now=1.2)
    assert limiter.allow("other", now=0)


def test_nonce_memory_refuses_reuse_and_stays_bounded(monkeypatch):
    memory = NonceMemory()
    memory.check("a", "n1", 100)
    with pytest.raises(Invalid, match="rejouée"):
        memory.check("a", "n1", 101)
    monkeypatch.setattr("novacoin.p2p.NONCE_MEMORY", 5)
    memory = NonceMemory()
    for i in range(5):
        memory.check("b", f"n{i}", 100)
    with pytest.raises(Invalid, match="Trop"):
        memory.check("c", "z", 101)
    memory.check("c", "z", 100 + 1000)                       # old entries expire


# ------------------------------------------------------------------ identity cost (V11)

def test_identity_without_proof_of_work_is_refused_and_a_proven_one_accepted(network):
    from novacoin.p2p import find_identity_nonce, identity_ok, IDENTITY_BITS
    nodes, _, _, _ = network
    url, nid = nodes[0].p2p_url, nodes[0].node_id
    key, ident = identity()
    # a missing, wrong or malformed proof is refused before anything else
    for work in (None, "x", "999999999999"):
        headers = sign_request(key, ident, nid, "GET", "/p2p/status", b"", None, work=0)
        if work is None:
            del headers["X-Nova-Work"]
        else:
            headers["X-Nova-Work"] = work
        if work == "999999999999" and identity_ok(ident, int(work)):
            continue                                            # astronomically unlikely: this nonce happens to be valid
        status, body = send(url, "GET", "/p2p/status", headers)
        assert status == 401 and "preuve" in body["error"].lower(), body
    good = find_identity_nonce(ident)
    assert identity_ok(ident, good) and IDENTITY_BITS >= 1
    assert send(url, "GET", "/p2p/status", sign_request(key, ident, nid, "GET", "/p2p/status", b"", None, work=good))[0] == 200
    # a proof made for another identity is worthless
    other_key, other_ident = identity()
    stolen = sign_request(other_key, other_ident, nid, "GET", "/p2p/status", b"", None, work=good)
    if not identity_ok(other_ident, good):
        assert send(url, "GET", "/p2p/status", stolen)[0] == 401


def test_node_computes_stores_and_reuses_its_identity_proof(tmp_path):
    import json
    from novacoin.p2p import identity_ok
    node = Node(tmp_path / "n")
    nonce = node.identity_nonce
    node.close()
    stored = json.loads((tmp_path / "n" / "identity.work").read_text())
    assert stored["nonce"] == nonce and identity_ok(stored["id"], nonce) and (tmp_path / "n" / "identity.work").stat().st_mode & 0o077 == 0
    (tmp_path / "n" / "identity.work").write_text(json.dumps({**stored, "nonce": nonce + 1}))   # invalid nonce: recomputed
    again = Node(tmp_path / "n")
    try:
        assert identity_ok(again.node_id, again.identity_nonce)
    finally:
        again.close()


def test_real_network_identity_cost_is_meaningful():
    import os
    import subprocess
    import sys
    env = {k: v for k, v in os.environ.items() if k != "NOVA_EASY"}
    out = subprocess.run([sys.executable, "-c", "from novacoin.p2p import IDENTITY_BITS; print(IDENTITY_BITS)"],
                         cwd=ROOT_DIR, env=env, text=True, capture_output=True).stdout.strip()
    assert out == "22"                                         # about 4 million hashes per identity on average
