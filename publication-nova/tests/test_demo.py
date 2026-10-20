"""Exercise the shipped launcher with three real node subprocesses and a restart."""
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

from novacoin.core import Invalid
from novacoin.node import request_json


def wait_for(predicate, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            value = predicate()
            if value:
                return value
        except (Invalid, OSError):
            pass
        time.sleep(0.1)
    raise AssertionError("The two-process demo did not reach the expected state")


def free_ports():
    """A base port such that base..base+2 and base+10000..base+10002 are all free."""
    import random
    for _ in range(100):
        base = random.randint(20000, 40000)
        sockets = []
        try:
            for port in (*range(base, base + 3), *range(base + 10000, base + 10003)):
                sock = socket.socket()
                sockets.append(sock)
                sock.bind(("127.0.0.1", port))
            return base
        except OSError:
            continue
        finally:
            for sock in sockets:
                sock.close()
    raise AssertionError("Could not find free test ports")


def test_shipped_demo_payment_and_immediate_restart(tmp_path):
    port = free_ports()
    base = f"http://127.0.0.1:{port}"
    peer = f"http://127.0.0.1:{port + 1}"
    third = f"http://127.0.0.1:{port + 2}"
    project = Path(__file__).resolve().parents[1]
    command = [sys.executable, "-m", "novacoin.demo", "--data", str(tmp_path / "demo"),
               "--port", str(port), "--no-browser"]
    token = None
    tip = None
    for run in range(2):
        with (tmp_path / f"launcher-{run}.log").open("w") as log:
            process = subprocess.Popen(command, cwd=project, stdout=log, stderr=log)
            try:
                wait_for(lambda: request_json(base + "/api/status"))
                wait_for(lambda: request_json(peer + "/api/status"))
                wait_for(lambda: request_json(third + "/api/status"))
                new_token = (tmp_path / "demo/node-1/admin.token").read_text().strip()
                if run == 1:
                    assert token == new_token
                token = new_token
                dashboard = request_json(base + "/api/dashboard", token=token)
                alice, bob = dashboard["wallets"]
                if run == 0:
                    request_json(base + "/api/mine", {"address": alice["address"], "count": 3}, token)
                    wait_for(lambda: request_json(base + "/api/status")["height"] == 3)
                    wait_for(lambda: not request_json(base + "/api/status")["mining"]["running"])
                    request_json(base + "/api/demo/send",
                                 {"sender": "Alice", "recipient": bob["address"], "amount": "10"}, token)
                    request_json(base + "/api/mine", {"address": alice["address"], "count": 1}, token)
                    wait_for(lambda: request_json(base + "/api/status")["height"] == 4)
                    tip = request_json(base + "/api/status")["tip"]
                else:
                    assert request_json(base + "/api/status")["tip"] == tip
                wait_for(lambda: request_json(peer + "/api/status")["tip"] == tip)
                wait_for(lambda: request_json(third + "/api/status")["tip"] == tip)
                # Everyone found everyone, over authenticated peers only.
                for url in (base, peer, third):
                    wait_for(lambda: sum(1 for p in request_json(url + "/api/status")["peers"]
                                         if p["ok"] and p["id"]) == 2)
                assert request_json(base + "/api/balance?address=" + bob["address"])["confirmed_nova"] == "10.00000000"
                assert request_json(peer + "/api/balance?address=" + bob["address"])["confirmed_nova"] == "10.00000000"
            finally:
                process.send_signal(signal.SIGINT)
                try:
                    process.wait(timeout=45)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            assert process.returncode == 0
