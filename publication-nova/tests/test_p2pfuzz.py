"""Network-layer fuzzing: garbage, malformed HTTP and fuzzed signed requests must never crash the peer server."""
import logging
import random
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit

import pytest

from helpers import identity
from novacoin import node as module
from novacoin.p2p import RateLimiter, client_context, sign_request
from test_network import network  # noqa: F401  (fixture)

HEADER_NAMES = ["Host", "Content-Length", "Transfer-Encoding", "X-Nova-Id", "X-Nova-Sig", "X-Nova-Time",
                "X-Nova-Nonce", "X-Nova-Listen", "Connection", "Expect", "Cookie", "Range", "\x00bad"]
VALUES = ["", "0", "-1", "99999999999999999999", "chunked", "ab" * 32, "z" * 500, "\xff\xfe", "1" * 70_000,
          "bytes=0-", "100-continue", "'; DROP TABLE blocks;--", "../../etc/passwd", "\x00", "NaN"]
PATHS = ["/", "/p2p", "/p2p/status", "/p2p/blocks?from=-1&limit=1", "/p2p/blocks?from=99999999999999999999&limit=1",
         "/p2p/hashes?from=NaN&limit=%00", "/p2p/hashes?from=0&limit=1&limit=2", "/p2p/%2e%2e/%2e%2e/etc/passwd",
         "/p2p/peers?" + "a=1&" * 5000, "/api/dashboard", "//p2p/status", "/p2p/mempool#frag", "*", "http://x/p2p/status",
         "/p2p/status\x00", "/p2p/blocks?from=0&limit=" + "9" * 400, "/p2p/transactions", "/p2p/blocks"]
BODIES = [b"", b"{}", b"[]", b"null", b"[" * 20000, b'{"a":' * 5000, b"\xff\xfe\x00", b'{"a":1,"a":2}', b'{"x":NaN}',
          b'{"inputs":"x"}', b"1" * 5000, b'{"version":1,"network":"x"}', b'"' + b"x" * 100_000 + b'"']


def raw_exchange(url, payload, timeout=3):
    parts = urlsplit(url)
    try:
        sock = client_context().wrap_socket(socket.create_connection((parts.hostname, parts.port), timeout))
    except (OSError, ssl.SSLError):
        return b""
    try:
        sock.settimeout(timeout)
        sock.sendall(payload)
        data = b""
        while chunk := sock.recv(65536):
            data += chunk
            if len(data) > 200_000:
                break
        return data
    except (OSError, ssl.SSLError):
        return b""
    finally:
        sock.close()


def test_malformed_and_signed_garbage_never_crash_the_peer_server(network, caplog):
    nodes, _, _, _ = network
    node, url = nodes[0], nodes[0].p2p_url
    node.ip_limiter = RateLimiter(10 ** 6, 10 ** 6)                 # let the fuzzer through to the parsers
    node.id_limiter = RateLimiter(10 ** 6, 10 ** 6)
    rng = random.Random(11)
    threads_before = threading.active_count()
    statuses = {}
    with caplog.at_level(logging.ERROR, logger="nova"):
        for i in range(260):
            kind = i % 4
            if kind == 0:                                           # pure noise
                payload = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 1500)))
            elif kind == 1:                                         # malformed HTTP
                headers = "".join(f"{rng.choice(HEADER_NAMES)}: {rng.choice(VALUES)}\r\n" for _ in range(rng.randrange(0, 8)))
                line = f"{rng.choice(['GET','POST','PUT','DELETE','BREW','G\\x00T',''])} {rng.choice(PATHS)} HTTP/{rng.choice(['1.0','1.1','9.9','x'])}\r\n"
                payload = (line + headers + rng.choice(["\r\n", "\n", "", "\r\n\r\n"])).encode("utf-8", "surrogatepass") + rng.choice(BODIES)[:3000]
            else:                                                   # correctly signed, hostile content
                key, ident = identity()
                path = rng.choice([p for p in PATHS if p.startswith("/p2p")])
                body = rng.choice(BODIES) if kind == 3 else b""
                method = "POST" if kind == 3 else "GET"
                headers = sign_request(key, ident, node.node_id, method, path, body, None)
                text = f"{method} {path} HTTP/1.1\r\nHost: x\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers.items())
                payload = (text + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode("utf-8", "surrogatepass") + body
            data = raw_exchange(url, payload[:200_000])
            if data.startswith(b"HTTP/"):
                code = int(data.split()[1])
                statuses[code] = statuses.get(code, 0) + 1
                assert code != 500, data[:200]
    assert not [r for r in caplog.records if "Unexpected error" in r.getMessage()]
    assert statuses and set(statuses) <= {200, 201, 400, 401, 403, 404, 413, 414, 429, 431, 501, 505}
    time.sleep(1)
    key, ident = identity()
    reply = raw_exchange(url, (f"GET /p2p/status HTTP/1.1\r\nHost: x\r\nConnection: close\r\n" + "".join(
        f"{k}: {v}\r\n" for k, v in sign_request(key, ident, node.node_id, "GET", "/p2p/status", b"", None).items())
        + "\r\n").encode())
    assert reply.startswith(b"HTTP/1.0 200") or reply.startswith(b"HTTP/1.1 200")                # still serving
    assert threading.active_count() <= threads_before + 30                                       # nothing leaked
    assert node.status()["height"] == 0 and node.pending == {}                                   # and nothing got in


def test_slow_drip_connection_is_cut_by_the_total_deadline(network, monkeypatch):
    nodes, _, _, _ = network
    monkeypatch.setattr(module, "PEER_REQUEST_DEADLINE", 1.2)
    parts = urlsplit(nodes[0].p2p_url)
    sock = client_context().wrap_socket(socket.create_connection((parts.hostname, parts.port), 5))
    started = time.time()
    closed = False
    try:
        for byte in b"GET /p2p/status HTTP/1.1\r\nHost: x\r\n":
            sock.sendall(bytes([byte]))
            time.sleep(0.35)                                        # each read is fast, the whole request is not
            if time.time() - started > 6:
                break
    except (OSError, ssl.SSLError):
        closed = True
    finally:
        sock.close()
    assert closed and time.time() - started < 5
