"""V9: operator tooling and the hardening found by the internal audit."""
import os
import re
import socket
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from novacoin.core import Invalid
from novacoin.doctor import checks
from novacoin.node import Node, NodeServer, request_json

ROOT = Path(__file__).resolve().parents[1]


def cli(*args, **env):
    return subprocess.run([sys.executable, "-m", "novacoin", *args], cwd=ROOT, text=True, capture_output=True,
                          env={**os.environ, **env}, timeout=30)


@pytest.fixture
def local(tmp_path):
    node = Node(tmp_path / "n")
    server = NodeServer(("127.0.0.1", 0), node)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield node, server.server_port
    server.shutdown()
    server.server_close()
    node.close()


def raw_get(port, path, host):
    with socket.create_connection(("127.0.0.1", port), 5) as sock:
        sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        data = b""
        while chunk := sock.recv(65536):
            data += chunk
    return int(data.split()[1]), data.split(b"\r\n\r\n", 1)[1]


def test_dns_rebinding_host_names_are_refused(local):
    node, port = local
    for good in (f"127.0.0.1:{port}", f"localhost:{port}"):
        assert raw_get(port, "/api/status", good)[0] == 200
    for bad in ("evil.example.com", f"evil.example.com:{port}", "10.0.0.5", ""):
        status, body = raw_get(port, "/api/status", bad)
        assert status == 400 and b"Nom d" in body
    assert raw_get(port, "/api/explorer/blocks", "evil.example.com")[0] == 400


def test_remote_local_port_requires_explicit_consent(tmp_path):
    result = cli("node", "--data", str(tmp_path / "x"), "--host", "0.0.0.0", "--port", "1")
    assert result.returncode == 1 and "127.0.0.1" in result.stderr and "chiffré" in result.stderr
    assert not (tmp_path / "x" / "chain.sqlite3").exists()          # refused before anything was created


def test_peers_file_is_parsed_with_comments(tmp_path):
    peers = tmp_path / "peers.txt"
    ident = "ab" * 32
    peers.write_text(f"# seeds\nhttps://127.0.0.1:2001#{ident}  # first\n\nhttps://127.0.0.1:2002\n")
    result = cli("node", "--data", str(tmp_path / "d"), "--host", "0.0.0.0", "--port", "1",
                 "--peers-file", str(peers))
    assert "127.0.0.1" in result.stderr                              # refused for the host, peers file was fine
    bad = tmp_path / "bad.txt"
    bad.write_text("http://127.0.0.1:2001\n")
    result = cli("node", "--data", str(tmp_path / "d2"), "--port", "1", "--peers-file", str(bad))
    assert result.returncode == 1 and "https" in result.stderr


def test_doctor_reports_each_check(tmp_path):
    rows = list(checks(tmp_path / "data", 18441, 28441))
    labels = " ".join(label for _, label, _ in rows)
    assert "TLS 1.3" in labels and "Ed25519" in labels and "Espace disque" in labels
    assert all(status in ("OK", "WARN", "FAIL") for status, _, _ in rows)
    # insecure permissions on the key are a blocking finding
    data = tmp_path / "data"
    data.mkdir()
    key = data / "node.key"
    key.write_text("x")
    key.chmod(0o644)
    assert any(status == "FAIL" and "node.key" in label for status, label, _ in checks(data, 18441, 28441))
    occupied = socket.socket()
    occupied.bind(("127.0.0.1", 0))
    port = occupied.getsockname()[1]
    try:
        assert any(status == "WARN" and "occupé" in label for status, label, _ in checks(data, port, 28441))
    finally:
        occupied.close()
    done = cli("doctor", "--data", str(tmp_path / "ok"), "--port", "39111")
    assert "Résultat" in done.stdout


# ------------------------------------------------------------------ static audit guard

FORBIDDEN = {
    r"\beval\(": "eval", r"\bexec\(": "exec", r"\bpickle\b": "pickle", r"\bmarshal\b": "marshal",
    r"shell\s*=\s*True": "shell=True", r"os\.system": "os.system", r"yaml\.load": "yaml.load",
    r"innerHTML": "innerHTML", r"document\.write": "document.write",
}


def test_no_dangerous_constructs_in_the_shipped_code():
    offenders = []
    for path in list((ROOT / "novacoin").glob("*.py")) + list((ROOT / "novacoin").glob("*.html")):
        text = path.read_text()
        for pattern, name in FORBIDDEN.items():
            if name and re.search(pattern, text):
                offenders.append(f"{path.name}: {name}")
    assert offenders == []


def test_subprocess_is_only_used_by_the_launcher_and_verifier():
    users = {p.name for p in (ROOT / "novacoin").glob("*.py") if "import subprocess" in p.read_text()}
    assert users <= {"demo.py", "verify.py"}


def test_secrets_are_created_with_private_permissions(tmp_path):
    node = Node(tmp_path / "n")
    try:
        for name in ("node.key", "admin.token"):
            assert (tmp_path / "n" / name).stat().st_mode & 0o077 == 0, name
        assert (tmp_path / "n").stat().st_mode & 0o077 == 0
    finally:
        node.close()


def test_wallet_and_secrets_never_appear_in_logs_or_status(local):
    node, port = local
    blob = str(request_json(f"http://127.0.0.1:{port}/api/status")) + str(node.events())
    assert node.token not in blob
    assert node.key.private_bytes_raw().hex() not in blob


def test_soak_tool_runs_briefly_without_errors():
    sys.path.insert(0, str(ROOT / "tools"))
    import soak
    result = soak.run(0.2, 3, 5, report=lambda *_: None)
    assert result["settled"] and result["errors"] == []


# ------------------------------------------------------------------ reorg limit as an operator concern

def test_blocked_reorg_is_reported_once_and_can_be_lifted(tmp_path):
    import copy
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from novacoin.wallet import address
    a, b = Node(tmp_path / "a", max_reorg=2), Node(tmp_path / "b")
    key, other = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    try:
        for _ in range(5):
            a.mine_one(address(key))
        for _ in range(9):
            b.mine_one(address(other))
        for _ in range(4):                                      # a peer keeps offering the heavier chain
            with pytest.raises(Invalid, match="refusée"):
                a.adopt(copy.deepcopy(b.chain))
        assert [e["kind"] for e in a.events()].count("reorg_refused") == 1
        assert a.status()["reorg_blocked"] == {"removed_blocks": 5, "limit": 2}
        a.set_max_reorg(0)
        assert a.status()["reorg_blocked"] is None
        assert a.adopt(copy.deepcopy(b.chain)) and a.status()["tip"] == b.status()["tip"]
        with pytest.raises(Invalid):
            a.set_max_reorg(-1)
    finally:
        a.close()
        b.close()


def test_reorg_limit_endpoint_requires_the_admin_token(local):
    node, port = local
    url = f"http://127.0.0.1:{port}/api/max-reorg"
    with pytest.raises(Invalid, match="administrateur"):
        request_json(url, {"limit": 0})
    assert request_json(url, {"limit": 7}, node.token) == {"limit": 7} and node.max_reorg == 7


def test_node_stops_cleanly_on_sigterm_and_when_sigint_was_inherited_as_ignored(tmp_path):
    """Service managers send SIGTERM; background jobs inherit an ignored SIGINT. Both must shut down cleanly."""
    import signal
    import time
    for number, signum in enumerate((signal.SIGTERM, signal.SIGINT)):
        port = 41000 + number * 5 + os.getpid() % 500
        command = [sys.executable, "-m", "novacoin", "node", "--data", str(tmp_path / f"d{number}"),
                   "--port", str(port), "--p2p-port", str(port + 1)]
        ignoring = lambda: signal.signal(signal.SIGINT, signal.SIG_IGN)       # runs in the child before exec
        process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                   env={**os.environ, "NOVA_EASY": "1"}, preexec_fn=ignoring)
        deadline = time.time() + 20
        while time.time() < deadline:
            try:
                request_json(f"http://127.0.0.1:{port}/api/status")
                break
            except Invalid:
                time.sleep(0.2)
        started = time.time()
        process.send_signal(signum)
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            pytest.fail(f"{signum.name} ignored")
        assert process.returncode == 0 and time.time() - started < 15, process.stderr.read()[-300:]
