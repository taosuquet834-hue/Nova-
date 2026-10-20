#!/usr/bin/env python3
"""Long-running soak test: several in-process nodes, random mining, payments and network cuts.

Checks invariants all along (no worker thread crash, money supply = sum of block subsidies, chains
agree after the network is allowed to settle). Uses the easy lab network.

Usage: python tools/soak.py [--minutes 5] [--nodes 4] [--seed 1]
"""
import argparse
import os
import random
import sys
import tempfile
import threading
import time

os.environ["NOVA_EASY"] = "1"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from novacoin.core import Invalid, subsidy  # noqa: E402
from novacoin.node import Node, NodeServer, PeerServer  # noqa: E402
from novacoin.wallet import address, build_transaction  # noqa: E402


def supply(node):
    with node.lock:
        return sum(c["amount"] for c in node.utxos.values()), sum(subsidy(h) for h in range(1, len(node.chain)))


def run(minutes, count, seed, report=print, max_reorg=0):
    rng = random.Random(seed)
    errors, servers, nodes, keys = [], [], [], [Ed25519PrivateKey.generate() for _ in range(count)]
    hook, threading.excepthook = threading.excepthook, lambda a: errors.append(f"{a.thread.name}: {a.exc_value!r}")
    with tempfile.TemporaryDirectory() as tmp:
        for i in range(count):
            node = Node(f"{tmp}/n{i}", max_reorg=max_reorg)
            peer_server = PeerServer(("127.0.0.1", 0), node)
            threading.Thread(target=peer_server.serve_forever, daemon=True).start()
            servers.append(peer_server)
            nodes.append(node)
        for i, node in enumerate(nodes):                        # a ring, the rest is discovered
            node.add_peer(f"https://127.0.0.1:{servers[(i + 1) % count].server_port}")
        for node in nodes:
            node.start_sync()
        stats = {"payments": 0, "refused": 0, "cuts": 0, "automine_switches": 0}
        deadline = time.monotonic() + minutes * 60
        try:
            while time.monotonic() < deadline:
                i = rng.randrange(count)
                action = rng.choice(("mine", "mine", "pay", "pay", "pay", "cut", "heal", "auto"))
                node = nodes[i]
                if action == "mine" and not node.mining["running"]:
                    node.start_mining(address(keys[i]), rng.randint(1, 3))
                elif action == "pay":
                    try:
                        coins = node.balance(address(keys[i]))["utxos"]
                        dest = address(keys[rng.randrange(count)])
                        node.submit(build_transaction(keys[i], coins, dest, rng.randint(1, 5) * 10 ** 8, 200_000))
                        stats["payments"] += 1
                    except Invalid:
                        stats["refused"] += 1
                elif action == "cut" and rng.random() < 0.5:
                    node.set_isolated(True)
                    stats["cuts"] += 1
                elif action == "heal":
                    node.set_isolated(False)
                elif action == "auto":
                    node.set_automine(rng.random() < 0.5, address(keys[i]))
                    stats["automine_switches"] += 1
                total, expected = supply(node)
                if total != expected:
                    errors.append(f"offre monétaire incohérente sur le nœud {i} : {total} ≠ {expected}")
                time.sleep(rng.uniform(0.05, 0.4))
            for node in nodes:                                   # quiesce
                node.set_automine(False)
                node.set_isolated(False)
            time.sleep(4)
            settled = False
            for _ in range(30):
                tips = {n.status()["tip"] for n in nodes}
                if len(tips) == 1:
                    settled = True
                    break
                time.sleep(1)
            if not settled:                                      # equal-work tie: one block settles it
                best = max(nodes, key=lambda n: n.work)
                best.mine_one(address(keys[0]))
                for _ in range(30):
                    if len({n.status()["tip"] for n in nodes}) == 1:
                        settled = True
                        break
                    time.sleep(1)
            for node in nodes:
                total, expected = supply(node)
                if total != expected:
                    errors.append(f"offre monétaire finale incohérente : {total} ≠ {expected}")
            heights = [n.status()["height"] for n in nodes]
            diagnostics = []
            if not settled:
                for i, n in enumerate(nodes):
                    kinds = {}
                    for e in n.events():
                        kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
                    refused = [e["details"] for e in n.events() if e["kind"] == "reorg_refused"][:1]
                    health = [(p["url"][-5:], p.get("ok"), (p.get("error") or "")[:60]) for p in n.status()["peers"]]
                    diagnostics.append(f"nœud {i} : hauteur {n.status()['height']}, événements {kinds}, "
                                       f"réorg refusée {refused}, pairs {health}, bans {n.status()['security']['bans']}")
                for line in diagnostics:
                    report(line)
            events = sum(len(n.events()) for n in nodes)
            report(f"{minutes} min, {count} nœuds : hauteurs finales {heights}, convergence : {settled}, "
                   f"paiements {stats['payments']} (refusés {stats['refused']}), coupures {stats['cuts']}, "
                   f"événements journalisés {events}")
            return {"settled": settled, "errors": errors, "heights": heights, "diagnostics": diagnostics, **stats}
        finally:
            threading.excepthook = hook
            for server in servers:
                server.shutdown()
                server.server_close()
            for node in nodes:
                node.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--minutes", type=float, default=5)
    parser.add_argument("--nodes", type=int, default=4)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--max-reorg", type=int, default=0, help="0 = sans limite (défaut de l'essai)")
    args = parser.parse_args()
    result = run(args.minutes, args.nodes, args.seed, max_reorg=args.max_reorg)
    for error in result["errors"]:
        print("ERREUR :", error)
    sys.exit(0 if result["settled"] and not result["errors"] else 1)
