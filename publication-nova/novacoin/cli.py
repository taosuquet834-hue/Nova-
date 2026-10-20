from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import sys
from pathlib import Path

from .core import Invalid, format_amount, parse_amount
from .node import Node, NodeServer, PeerServer, peer_url, request_json
from .p2p import parse_peer
from .hdwallet import HDWallet
from .wallet import address, build_transaction, create_wallet, load_wallet


def password():
    return os.environ.get("NOVA_WALLET_PASSWORD") or getpass.getpass("Mot de passe du portefeuille : ")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="nova", description="Nova V13 — monnaie de test indépendante")
    sub = parser.add_subparsers(dest="command", required=True)
    node_cmd = sub.add_parser("node", help="Démarrer un nœud")
    node_cmd.add_argument("--data", required=True)
    node_cmd.add_argument("--host", default="127.0.0.1")
    node_cmd.add_argument("--port", type=int, default=18441)
    node_cmd.add_argument("--p2p-port", type=int, help="Port TLS des pairs (défaut : port + 10000)")
    node_cmd.add_argument("--p2p-host", help="Adresse d'écoute des pairs (défaut : --host)")
    node_cmd.add_argument("--peer", action="append", default=[],
                          help="Pair : https://adresse:port ou https://adresse:port#identifiant")
    node_cmd.add_argument("--closed", action="store_true",
                          help="Nœud fermé : seuls les pairs configurés avec identifiant sont acceptés")
    node_cmd.add_argument("--max-reorg", type=int, default=50,
                          help="Plus grande réorganisation acceptée, en blocs (0 = sans limite)")
    node_cmd.add_argument("--checkpoint", action="append", default=[], metavar="HAUTEUR:EMPREINTE",
                          help="Point de contrôle : toute chaîne différente à cette hauteur est refusée")
    node_cmd.add_argument("--peers-file", help="Fichier de pairs (une adresse par ligne, # pour commenter)")
    node_cmd.add_argument("--allow-remote-local-port", action="store_true",
                          help="Autoriser --host hors de cette machine (port local NON chiffré : déconseillé)")
    node_cmd.add_argument("--checkpoints-file", help="Fichier JSON {hauteur: empreinte} de points de contrôle officiels")
    node_cmd.add_argument("--lab-peer-url", help=argparse.SUPPRESS)
    for name in ("key-protect", "key-unprotect"):
        kp = sub.add_parser(name, help="Chiffrer / déchiffrer la clé d'identité du nœud (mot de passe par variable d'environnement)")
        kp.add_argument("--data", required=True)
    verify_release = sub.add_parser("verify-release", help="Vérifier la signature d'une archive publiée")
    verify_release.add_argument("--file", required=True)
    verify_release.add_argument("--sig", required=True)
    verify_release.add_argument("--pubkey", required=True, help="Clé publique de publication (64 hexadécimaux)")
    for name in ("hd-backup", "hd-check-backup"):
        hb = sub.add_parser(name)
        hb.add_argument("--wallet", required=True)
        hb.add_argument("--backup", required=True)
    rotate = sub.add_parser("token-rotate", help="Remplacer le jeton administrateur (nœud arrêté)")
    rotate.add_argument("--data", required=True)
    pub = sub.add_parser("hd-pubkey", help="Clé publique d'une adresse du portefeuille (pour une multisignature)")
    pub.add_argument("--wallet", required=True)
    pub.add_argument("--index", type=int, default=0)
    ms = sub.add_parser("multisig-address", help="Adresse d'une politique m parmi n clés")
    ms.add_argument("--threshold", type=int, required=True)
    ms.add_argument("--keys", required=True, help="Clés publiques séparées par des virgules")
    md = sub.add_parser("multisig-draft", help="Préparer un paiement multisignature non signé")
    for flag in ("--threshold", "--keys", "--to", "--amount", "--out"):
        md.add_argument(flag, required=True, type=int if flag == "--threshold" else str)
    md.add_argument("--fee", default="0.001")
    md.add_argument("--locktime", type=int, default=0)
    md.add_argument("--node", default="http://127.0.0.1:18441")
    mg = sub.add_parser("multisig-sign", help="Ajouter sa signature à un brouillon")
    mg.add_argument("--draft", required=True)
    mg.add_argument("--wallet", required=True, help="Portefeuille récupérable (.json)")
    mg.add_argument("--index", type=int, default=0)
    mm = sub.add_parser("multisig-submit", help="Envoyer un brouillon suffisamment signé")
    mm.add_argument("--draft", required=True)
    mm.add_argument("--node", default="http://127.0.0.1:18441")
    rk = sub.add_parser("release-keygen", help="Créer la clé de publication (à garder HORS LIGNE) ; affiche la clé publique")
    rk.add_argument("--out", required=True)
    rs = sub.add_parser("release-sign", help="Signer une archive avec la clé de publication")
    rs.add_argument("--key", required=True)
    rs.add_argument("--file", required=True)
    rs.add_argument("--sig")
    sub.add_parser("version", help="Afficher la version et l'identifiant du réseau")
    doctor = sub.add_parser("doctor", help="Vérifier cette machine avant de lancer un nœud")
    doctor.add_argument("--data", default=".local/noeud")
    doctor.add_argument("--port", type=int, default=18441)
    doctor.add_argument("--p2p-port", type=int)
    node_cmd.add_argument("--demo-wallets", help=argparse.SUPPRESS)
    node_cmd.add_argument("--lab-peer-token", help=argparse.SUPPRESS)
    node_cmd.add_argument("--verbose", action="store_true")
    create = sub.add_parser("wallet-create", help="Créer un portefeuille chiffré")
    create.add_argument("--wallet", required=True)
    addr = sub.add_parser("wallet-address", help="Afficher l'adresse du portefeuille")
    addr.add_argument("--wallet", required=True)
    hd = sub.add_parser("hd-create", help="Créer un portefeuille récupérable (phrase de 12 mots)")
    hd.add_argument("--wallet", required=True)
    hd = sub.add_parser("hd-restore", help="Restaurer un portefeuille depuis sa phrase")
    hd.add_argument("--wallet", required=True)
    for name in ("hd-address", "hd-balance", "hd-send", "hd-contact"):
        hd = sub.add_parser(name)
        hd.add_argument("--wallet", required=True)
        if name != "hd-address" or True:
            hd.add_argument("--node", default="http://127.0.0.1:18441")
        if name == "hd-send":
            hd.add_argument("--to", required=True, help="Adresse ou nom d'un contact")
            hd.add_argument("--amount", required=True)
            hd.add_argument("--fee", default="0.001")
        if name == "hd-contact":
            hd.add_argument("--name", required=True)
            hd.add_argument("--address", required=True)
    for name in ("status", "balance", "send", "mine", "automine", "peer-add", "reorg-limit"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--node", default="http://127.0.0.1:18441")
        if name == "balance":
            cmd.add_argument("--address", required=True)
        elif name == "send":
            cmd.add_argument("--wallet", required=True)
            cmd.add_argument("--to", required=True)
            cmd.add_argument("--amount", required=True)
            cmd.add_argument("--fee", default="0.001")
        elif name == "mine":
            cmd.add_argument("--address", required=True)
            cmd.add_argument("--count", type=int, default=1)
            cmd.add_argument("--token-file", required=True)
        elif name == "automine":
            cmd.add_argument("--address", help="Adresse qui reçoit les récompenses")
            cmd.add_argument("--off", action="store_true", help="Arrêter le minage automatique")
            cmd.add_argument("--token-file", required=True)
        elif name == "reorg-limit":
            cmd.add_argument("--value", type=int, required=True, help="Blocs (0 = sans limite)")
            cmd.add_argument("--token-file", required=True)
        elif name == "peer-add":
            cmd.add_argument("--peer", required=True)
            cmd.add_argument("--token-file", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "node":
            logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING)
            demo_keys = {}
            if args.demo_wallets:
                root = Path(args.demo_wallets)
                demo_password = (root / "demo.password").read_text()
                demo_keys = {name: load_wallet(root / f"{name.lower()}.pem", demo_password)
                             for name in ("Alice", "Bob")}
            import ipaddress
            try:
                local_only = ipaddress.ip_address(args.host).is_loopback or args.host == "localhost"
            except ValueError:
                local_only = args.host == "localhost"
            if not local_only and not args.allow_remote_local_port:
                raise Invalid("Le port local (tableau de bord, administration) n'est pas chiffré : il doit "
                              "rester sur 127.0.0.1. Seul --p2p-host ouvre le réseau (TLS). "
                              "Si vous savez ce que vous faites : --allow-remote-local-port.")
            peers = list(args.peer)
            if args.peers_file:
                for line in Path(args.peers_file).read_text().splitlines():
                    line = line.split("#", 1)[0].strip()
                    if line:
                        peers.append(line)
            checkpoints = {}
            if args.checkpoints_file:
                checkpoints.update({int(h): d for h, d in json.loads(Path(args.checkpoints_file).read_text()).items()})
            for item in args.checkpoint:
                height, _, digest = item.partition(":")
                checkpoints[int(height)] = digest
            node = Node(args.data, peers, demo_keys, closed=args.closed,
                        max_reorg=args.max_reorg, checkpoints=checkpoints)
            if args.lab_peer_token and args.lab_peer_url:
                from urllib.parse import urlsplit
                if urlsplit(args.lab_peer_url).hostname != "127.0.0.1":
                    raise Invalid("Le laboratoire commande seulement un nœud local")
                node.lab_peer = (peer_url(args.lab_peer_url), args.lab_peer_token)
            try:
                server = NodeServer((args.host, args.port), node)
                p2p_port = args.p2p_port if args.p2p_port is not None else args.port + 10000
                peer_server = PeerServer((args.p2p_host or args.host, p2p_port), node)
            except Exception:
                node.close()
                raise
            import signal
            import threading
            # Stop cleanly on Ctrl+C and on SIGTERM (service managers), even when started from a
            # background job that inherited an ignored SIGINT.
            for signum in (signal.SIGINT, signal.SIGTERM):
                signal.signal(signum, signal.default_int_handler)
            threading.Thread(target=peer_server.serve_forever, kwargs={"poll_interval": 0.3},
                             daemon=True, name="nova-peers").start()
            node.start_sync()
            print(f"Nova : http://{args.host}:{args.port} — réseau {node.status()['network']}", flush=True)
            print(f"Pairs (TLS) : https://{args.p2p_host or args.host}:{p2p_port}#{node.node_id}", flush=True)
            print(f"Jeton administrateur : {Path(args.data).resolve() / 'admin.token'}", flush=True)
            try:
                server.serve_forever(poll_interval=0.3)
            except KeyboardInterrupt:
                pass
            finally:
                node.stop.set()          # background threads start leaving before the servers close
                server.server_close()
                peer_server.shutdown()
                peer_server.server_close()
                node.close()
            return
        if args.command in ("key-protect", "key-unprotect"):
            from .p2p import key_is_encrypted, protect_key
            old = os.environ.get("NOVA_NODE_PASSWORD") if key_is_encrypted(args.data) else None
            if args.command == "key-protect":
                new = os.environ.get("NOVA_NEW_NODE_PASSWORD") or getpass.getpass("Nouveau mot de passe de la clé du nœud : ")
                if not os.environ.get("NOVA_NEW_NODE_PASSWORD") and new != getpass.getpass("Confirmer : "):
                    raise Invalid("Les deux mots de passe ne correspondent pas")
                if len(new) < 12:
                    raise Invalid("Mot de passe de la clé du nœud : 12 caractères au moins")
                protect_key(args.data, new, old)
                print("Clé chiffrée. Lancer ensuite le nœud avec NOVA_NODE_PASSWORD (ou NOVA_NODE_PASSWORD_FILE).")
            else:
                protect_key(args.data, None, old)
                print("Clé déchiffrée (déconseillé).")
            return
        if args.command in ("hd-pubkey", "multisig-address", "multisig-draft", "multisig-sign", "multisig-submit"):
            from .wallet import (add_multisig_signature, draft_multisig_transaction, multisig_policy,
                                 multisig_ready, public_hex)
            from urllib.parse import urlencode
            if args.command == "hd-pubkey":
                print(public_hex(HDWallet.load(args.wallet, password()).key(args.index)))
            elif args.command == "multisig-address":
                print(json.dumps(multisig_policy(args.threshold, args.keys.split(",")), indent=2))
            elif args.command == "multisig-draft":
                policy = multisig_policy(args.threshold, args.keys.split(","))
                node_url = peer_url(args.node)
                coins = request_json(node_url + "/api/balance?" + urlencode({"address": policy["address"]}))["utxos"]
                draft = draft_multisig_transaction(policy, coins, args.to, parse_amount(args.amount),
                                                   parse_amount(args.fee, allow_zero=True), locktime=args.locktime)
                Path(args.out).write_text(json.dumps(draft, indent=2))
                print(json.dumps({"draft": args.out, "address": policy["address"], "needs": policy["threshold"]}))
            elif args.command == "multisig-sign":
                draft = json.loads(Path(args.draft).read_text())
                add_multisig_signature(draft, HDWallet.load(args.wallet, password()).key(args.index))
                Path(args.draft).write_text(json.dumps(draft, indent=2))
                print(json.dumps({"signatures": len(draft["multisig"]["signatures"]),
                                  "needs": draft["multisig"]["threshold"], "ready": multisig_ready(draft)}))
            else:
                draft = json.loads(Path(args.draft).read_text())
                if not multisig_ready(draft):
                    raise Invalid("Pas assez de signatures pour envoyer ce paiement")
                print(json.dumps(request_json(peer_url(args.node) + "/api/transactions", draft)))
            return
        if args.command == "token-rotate":
            import secrets as _secrets
            token_path = Path(args.data) / "admin.token"
            if not token_path.exists():
                raise Invalid("Pas de jeton à remplacer dans ce dossier")
            if (Path(args.data) / "node.lock").exists():
                import fcntl
                with (Path(args.data) / "node.lock").open("a+b") as lock:
                    try:
                        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except OSError as exc:
                        raise Invalid("Arrêter le nœud avant de remplacer son jeton") from exc
            fd = os.open(token_path.with_name("admin.token.new"), os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "w") as stream:
                stream.write(_secrets.token_urlsafe(32))
            os.replace(token_path.with_name("admin.token.new"), token_path)
            print("Jeton remplacé. Relancer le nœud ; les anciens accès ne fonctionnent plus.")
            return
        if args.command == "release-keygen":
            from .release_sign import generate_release_key
            new = os.environ.get("NOVA_RELEASE_KEY_PASSWORD") or getpass.getpass("Mot de passe de la clé de publication (12 caractères ou plus) : ")
            if not os.environ.get("NOVA_RELEASE_KEY_PASSWORD") and new != getpass.getpass("Confirmer : "):
                raise Invalid("Les deux mots de passe ne correspondent pas")
            public = generate_release_key(args.out, new)
            print(json.dumps({"key_file": str(Path(args.out).resolve()), "public_key": public}, indent=2))
            print("\nGardez ce fichier HORS LIGNE (clé USB chiffrée, jamais dans le dépôt) et sauvegardez-le en deux "
                  "endroits.\nPubliez la clé publique ci-dessus à plusieurs endroits indépendants : c'est elle que les "
                  "utilisateurs comparent.", file=sys.stderr)
            return
        if args.command == "release-sign":
            from .release_sign import sign_file
            secret = os.environ.get("NOVA_RELEASE_KEY_PASSWORD") or getpass.getpass("Mot de passe de la clé de publication : ")
            print(sign_file(args.key, secret, args.file, args.sig))
            return
        if args.command == "verify-release":
            from .release_sign import verify_file
            print("Signature valide : " + verify_file(args.file, args.sig, args.pubkey))
            return
        if args.command in ("hd-backup", "hd-check-backup"):
            wallet = HDWallet.load(args.wallet, password())
            backup_password = os.environ.get("NOVA_BACKUP_PASSWORD") or getpass.getpass("Mot de passe de la sauvegarde : ")
            if args.command == "hd-backup":
                addresses = wallet.backup(args.backup, backup_password)
                print(json.dumps({"backup": str(Path(args.backup).resolve()), "verified": True,
                                  "addresses": len(addresses)}))
            else:
                copy = HDWallet.load(args.backup, backup_password)
                same = copy.seed == wallet.seed
                print(json.dumps({"backup_matches_wallet": same, "addresses": len(copy.addresses())}))
                if not same:
                    raise Invalid("La sauvegarde ne correspond pas à ce portefeuille")
            return
        if args.command == "version":
            from . import __version__
            from .core import NETWORK
            print(json.dumps({"version": __version__, "network": NETWORK}))
            return
        if args.command == "doctor":
            from .doctor import run_doctor
            raise SystemExit(run_doctor(args.data, args.port, args.p2p_port or args.port + 10000))
        if args.command == "wallet-create":
            result = {"address": address(create_wallet(args.wallet, password())),
                      "wallet": str(Path(args.wallet).resolve())}
        elif args.command == "wallet-address":
            result = {"address": address(load_wallet(args.wallet, password()))}
        elif args.command == "hd-create":
            wallet, phrase = HDWallet.create(args.wallet, password())
            print("PHRASE DE RÉCUPÉRATION — à écrire sur papier, maintenant, et à ne montrer à personne.")
            print("Elle ne sera plus jamais affichée ; elle seule permet de retrouver les pièces.\n")
            print("    " + phrase + "\n")
            result = {"first_address": wallet.new_address(), "wallet": str(Path(args.wallet).resolve())}
        elif args.command == "hd-restore":
            phrase = os.environ.get("NOVA_PHRASE") or getpass.getpass("Phrase de 12 mots : ")
            wallet, _ = HDWallet.create(args.wallet, password(), phrase=phrase)
            result = {"restored": True, "next": "Lancer hd-balance : les adresses utilisées seront retrouvées"}
        elif args.command in ("hd-address", "hd-balance", "hd-send", "hd-contact"):
            wallet = HDWallet.load(args.wallet, password())
            node_url = peer_url(args.node)
            from urllib.parse import urlencode
            fetch = lambda a: request_json(node_url + "/api/balance?" + urlencode({"address": a}))
            if args.command == "hd-address":
                result = {"address": wallet.new_address()}
            elif args.command == "hd-balance":
                found = wallet.balance(fetch)
                result = {"confirmed_nova": format_amount(found["confirmed"]),
                          "available_nova": format_amount(found["available"]),
                          "addresses": len(wallet.addresses()), "contacts": wallet.state["contacts"]}
            elif args.command == "hd-contact":
                wallet.add_contact(args.name, args.address)
                result = {"contacts": wallet.state["contacts"]}
            else:
                result = {"txids": wallet.send(fetch, lambda tx: request_json(node_url + "/api/transactions", tx)["txid"],
                                               args.to, parse_amount(args.amount),
                                               parse_amount(args.fee, allow_zero=True))}
        else:
            node_url = peer_url(args.node)
            if args.command == "status":
                result = request_json(node_url + "/api/status")
            elif args.command == "balance":
                from urllib.parse import urlencode
                result = request_json(node_url + "/api/balance?" + urlencode({"address": args.address}))
            elif args.command == "send":
                key = load_wallet(args.wallet, password())
                coins = request_json(node_url + "/api/balance?address=" + address(key))["utxos"]
                tx = build_transaction(key, coins, args.to, parse_amount(args.amount),
                                       parse_amount(args.fee, allow_zero=True))
                result = request_json(node_url + "/api/transactions", tx)
            elif args.command == "mine":
                result = request_json(node_url + "/api/mine",
                                      {"address": args.address, "count": args.count},
                                      Path(args.token_file).read_text().strip())
            elif args.command == "automine":
                if not args.off and not args.address:
                    raise Invalid("Indiquer --address ou --off")
                result = request_json(node_url + "/api/automine",
                                      {"enabled": not args.off, "address": args.address},
                                      Path(args.token_file).read_text().strip())
            elif args.command == "reorg-limit":
                result = request_json(node_url + "/api/max-reorg", {"limit": args.value},
                                      Path(args.token_file).read_text().strip())
            elif args.command == "peer-add":
                spec = parse_peer(args.peer)
                result = request_json(node_url + "/api/peers", {"url": spec[0] + ("#" + spec[1] if spec[1] else "")},
                                      Path(args.token_file).read_text().strip())
        print(json.dumps(result, indent=2, ensure_ascii=False))
    except (Invalid, OSError) as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
