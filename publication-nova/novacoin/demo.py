"""Launch three independent node processes, with demo wallets on the first node."""
from __future__ import annotations

import argparse
import os
import secrets
import signal
import socket
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

from .core import Invalid
from .node import request_json
from .wallet import create_wallet


def main():
    parser = argparse.ArgumentParser(description="Lancer le laboratoire Nova à trois nœuds")
    parser.add_argument("--data", default=".local/demo")
    parser.add_argument("--port", type=int, default=18441)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--lab", action="store_true",
                        help="Réseau de laboratoire (difficulté minimale, blocs instantanés) : pour essayer sans attendre")
    args = parser.parse_args()
    if args.lab:
        os.environ["NOVA_EASY"] = "1"          # inherited by the node processes; a separate "-easy" network
    root = Path(args.data).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    for port in (*range(args.port, args.port + 3), *range(args.port + 10000, args.port + 10003)):
        with socket.socket() as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("127.0.0.1", port))
            except OSError:
                raise SystemExit(f"Le port {port} est occupé. Fermez la démonstration existante "
                                 "ou choisissez --port 19441.")
    wallets = root / "wallets"
    wallets.mkdir(mode=0o700, exist_ok=True)
    password_path = wallets / "demo.password"
    if not password_path.exists():
        fd = os.open(password_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(secrets.token_urlsafe(32))
    demo_password = password_path.read_text()
    for name in ("alice", "bob"):
        if not (wallets / f"{name}.pem").exists():
            create_wallet(wallets / f"{name}.pem", demo_password)
    children, logs = [], []

    def interrupted(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)      # also when inherited as ignored (background job)
    try:
        # Node 3 is only told about node 1: it must discover node 2 (and be discovered) by itself.
        for index in range(3):
            port = args.port + index
            peer = args.port + (1 if index == 0 else 0)
            # Peers are given by address only: the first contact pins each identity (TOFU).
            cmd = [sys.executable, "-m", "novacoin", "node", "--data", str(root / f"node-{index + 1}"),
                   "--port", str(port), "--p2p-port", str(port + 10000),
                   "--peer", f"https://127.0.0.1:{peer + 10000}"]
            if index == 0:
                cmd += ["--demo-wallets", str(wallets), "--lab-peer-token",
                        str(root / "node-2" / "admin.token"),
                        "--lab-peer-url", f"http://127.0.0.1:{args.port + 1}"]
            log = (root / f"node-{index + 1}.log").open("a")
            logs.append(log)
            children.append(subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT))
        base = f"http://127.0.0.1:{args.port}"
        deadline = time.monotonic() + 120
        while True:
            if any(child.poll() is not None for child in children):
                raise Invalid(f"Un nœud s'est arrêté. Consulter les journaux dans {root}.")
            try:
                request_json(base + "/api/status")
                request_json(f"http://127.0.0.1:{args.port + 1}/api/status")
                request_json(f"http://127.0.0.1:{args.port + 2}/api/status")
                break
            except Invalid:
                if time.monotonic() > deadline:
                    raise Invalid("Le démarrage des nœuds a dépassé 2 minutes")
                time.sleep(0.2)
        token = (root / "node-1" / "admin.token").read_text().strip()
        url = base + "/#token=" + token
        # URL is written locally; do not expose the control token in routine logs.
        access_path = root / "dashboard.url"
        fd = os.open(access_path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(url)
        print(f"Nova V13 fonctionne sur {base}", flush=True)
        print(f"Accès administrateur local : {access_path}", flush=True)
        print("Trois nœuds actifs. Ctrl+C pour arrêter. Les données seront conservées.", flush=True)
        if not args.no_browser:
            webbrowser.open(url)
        while all(child.poll() is None for child in children):
            time.sleep(0.5)
        raise Invalid(f"Un nœud s'est arrêté. Consulter les journaux dans {root}.")
    except KeyboardInterrupt:
        print("\nArrêt des trois nœuds…", flush=True)
    except Invalid as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        raise SystemExit(1)
    finally:
        for child in children:
            if child.poll() is None:
                child.send_signal(signal.SIGINT)
        for child in children:
            try:
                child.wait(timeout=15)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        for log in logs:
            log.close()


if __name__ == "__main__":
    main()
