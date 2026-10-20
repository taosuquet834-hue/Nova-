"""Persistent full node, bounded HTTP transport, polling peer synchronization."""
from __future__ import annotations

import copy
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import secrets
import socket
import sqlite3
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, ProxyHandler, build_opener

from . import __version__
from .chainstore import ChainStore
from .selftest import run_selftest
from .p2p import (IDENTITY_BITS, find_identity_nonce, identity_ok, key_is_encrypted, NonceMemory, RateLimiter, Reputation, load_identity,
                  parse_peer, peer_request, private_address, server_context, verify_request)
from .core import (Tail, MAX_FUTURE_SECONDS, subsidy, validate_transaction_shape, BLOCK_VERSION, DEFAULT_MAX_REORG, DUST, MIN_FEE_PER_BYTE,
                   NETWORK, MAX_CHAIN_BLOCKS, COINBASE_MATURITY, SYNC_BATCH, UNIT, Invalid,
                   apply_transaction, block_id, block_work, canonical, difficulty_bits,
                   format_amount, genesis, hex_string,
                   make_candidate, parse_amount, require, solve, transaction_id,
                   valid_address, validate_chain, validate_next, integer)
from .wallet import address as wallet_address, build_transaction

LOG = logging.getLogger("nova")
MAX_HTTP_BYTES = 8_000_000
MAX_MEMPOOL = 1_000
MAX_MEMPOOL_BYTES = 2_000_000


def decode_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "Clé JSON dupliquée")
            result[key] = value
        return result

    def bad_constant(value):
        raise Invalid("Constante JSON invalide")

    try:
        return json.loads(data, object_pairs_hook=unique, parse_constant=bad_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise Invalid("Document JSON invalide") from exc


def peer_url(url):
    require(isinstance(url, str), "Adresse de nœud invalide")
    try:
        parts = urlsplit(url)
        require(parts.scheme == "http" and parts.hostname and parts.port,
                "Utiliser http://adresse:port")
        require(parts.username is None and parts.password is None
                and parts.path in ("", "/") and not parts.query and not parts.fragment,
                "Adresse de nœud invalide")
        require(1 <= parts.port <= 65535, "Port invalide")
    except ValueError as exc:
        raise Invalid("Adresse de nœud invalide") from exc
    return url.rstrip("/")


def request_json(url, payload=None, token=None, timeout=3):
    headers = {"Accept": "application/json"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["X-Nova-Token"] = token
    request = Request(url, data=canonical(payload) if payload is not None else None,
                      headers=headers)
    try:
        with build_opener(ProxyHandler({})).open(request, timeout=timeout) as response:
            data = response.read(MAX_HTTP_BYTES + 1)
        require(len(data) <= MAX_HTTP_BYTES, "Réponse réseau trop volumineuse")
        return decode_json(data)
    except HTTPError as exc:
        try:
            message = decode_json(exc.read(4096)).get("error", str(exc))
        except Invalid:
            message = str(exc)
        raise Invalid(message) from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise Invalid(f"Nœud injoignable : {urlsplit(url).netloc}") from exc


def _env_password():
    """Node key password from the environment (value or file), never from the command line."""
    if os.environ.get("NOVA_NODE_PASSWORD_FILE"):
        return Path(os.environ["NOVA_NODE_PASSWORD_FILE"]).read_text().strip() or None
    return os.environ.get("NOVA_NODE_PASSWORD") or None


class SelfPeer(Invalid):
    """A peer address turned out to be this very node."""


class Node:
    def __init__(self, data_dir, peers=(), demo_keys=None, closed=False,
                 max_reorg=DEFAULT_MAX_REORG, checkpoints=None, key_password=None):
        self.closed = closed
        self.key_password = key_password if key_password is not None else _env_password()
        self.max_reorg = max_reorg            # 0 = unlimited
        self.checkpoints = dict(checkpoints or {})
        for height, digest in self.checkpoints.items():
            require(type(height) is int and height >= 1, "Point de contrôle invalide")
            hex_string(digest, 64)
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._directory_lock = (self.data_dir / "node.lock").open("a+b")
        try:
            if os.name == "nt":
                import msvcrt
                self._directory_lock.seek(0)
                if not self._directory_lock.read(1):
                    self._directory_lock.write(b"0")
                    self._directory_lock.flush()
                self._directory_lock.seek(0)
                msvcrt.locking(self._directory_lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._directory_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self._directory_lock.close()
            raise Invalid("Ce dossier de données est déjà utilisé par un autre nœud") from exc
        try:
            self._initialize(peers, demo_keys)
        except Exception:
            if hasattr(self, "db"):
                self.db.close()
            self._directory_lock.close()
            raise

    def _load_identity_work(self):
        """Nonce proving this node's identity cost (computed once, a few seconds on the real network)."""
        path = self.data_dir / "identity.work"
        try:
            saved = json.loads(path.read_text())
            if saved.get("network") == NETWORK and saved.get("id") == self.node_id and identity_ok(self.node_id, saved["nonce"]):
                return saved["nonce"]
        except (OSError, ValueError, KeyError, TypeError):
            pass
        nonce = find_identity_nonce(self.node_id)
        fd = os.open(path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump({"network": NETWORK, "id": self.node_id, "bits": IDENTITY_BITS, "nonce": nonce}, stream)
        return nonce

    def _repair_permissions(self):
        """Secrets must never be readable by others: tighten silently and leave a trace."""
        fixed = []
        if os.name == "posix":
            for path, wanted in ((self.data_dir, 0o700), (self.data_dir / "node.key", 0o600),
                                 (self.data_dir / "admin.token", 0o600)):
                if path.exists() and path.stat().st_mode & 0o077:
                    path.chmod(wanted)
                    fixed.append(path.name)
        return fixed

    def _initialize(self, peers, demo_keys):
        run_selftest()
        repaired = self._repair_permissions()
        self.lock = threading.RLock()
        self.stop = threading.Event()
        self.threads = []
        self.demo_keys = demo_keys or {}
        self.peer_health = {}
        self.last_sync_error = None
        self.syncing = False
        self.network_epoch = 0
        self.sync_guard = threading.Lock()
        self.lab_peer = None
        self.rejected_peers = set()
        self.discovered = set()
        self.reorg_blocked = None      # set while a heavier chain is refused by the reorg limit
        self.newer_seen = set()
        self.p2p_port = None
        self.reputation, self.nonces = Reputation(), NonceMemory()
        self.ip_limiter = RateLimiter(capacity=120, per_second=40)   # before authentication
        self.id_limiter = RateLimiter(capacity=60, per_second=15)    # per authenticated peer
        self.bandwidth_limiter = RateLimiter(capacity=16_000_000, per_second=2_000_000)   # bytes of blocks served
        self.auto_mined = 0
        self.wake = threading.Event()
        self.mining = {"running": False, "completed": 0, "requested": 0, "error": None}
        self.db = sqlite3.connect(self.data_dir / "chain.sqlite3", check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS blocks(height INTEGER PRIMARY KEY, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS pending(txid TEXT PRIMARY KEY, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS settings(name TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS events(
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL,
                kind TEXT NOT NULL, message TEXT NOT NULL, details TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS bans(kind TEXT NOT NULL, key TEXT NOT NULL, until INTEGER NOT NULL,
                PRIMARY KEY(kind, key));
            CREATE TABLE IF NOT EXISTS autocp(height INTEGER PRIMARY KEY, hash TEXT NOT NULL);
        """)
        for column in ("prev", "hash"):          # tamper-evident journal (older databases are upgraded)
            try:
                self.db.execute(f"ALTER TABLE events ADD COLUMN {column} TEXT")
            except sqlite3.OperationalError:
                pass
        saved_discovered = self.db.execute("SELECT value FROM settings WHERE name='discovered'").fetchone()
        self.discovered = set(decode_json(saved_discovered[0])) if saved_discovered else set()
        self.auto_checkpoints = {h: d for h, d in self.db.execute("SELECT height, hash FROM autocp")}
        self.reputation.restore(list(self.db.execute("SELECT kind, key, until FROM bans")))
        self._journal_cache = None
        saved_isolation = self.db.execute("SELECT value FROM settings WHERE name='isolated'").fetchone()
        self.isolated = bool(decode_json(saved_isolation[0])) if saved_isolation else False
        self.key, self.node_id = load_identity(self.data_dir, self.key_password)
        self.key_encrypted = key_is_encrypted(self.data_dir)
        self.identity_nonce = self._load_identity_work()
        saved_auto = self.db.execute("SELECT value FROM settings WHERE name='automine'").fetchone()
        self.automine = decode_json(saved_auto[0]).get("address") if saved_auto else None
        require(self.automine is None or valid_address(self.automine), "Adresse de minage enregistrée invalide")
        if self.db.execute("SELECT 1 FROM blocks LIMIT 1").fetchone() is None:
            with self.db:
                self.db.execute("INSERT INTO blocks VALUES(0, ?)", (canonical(genesis()).decode(),))
        self.chain = ChainStore(self.data_dir / "chain.sqlite3")      # blocks stay on disk, recent ones are cached
        self.utxos, self.work = validate_chain(self.chain)           # streams through the whole chain once
        self.ids = [block_id(b) for b in self.chain]
        for height, digest in self.checkpoints.items():
            require(height >= len(self.ids) or self.ids[height] == digest,
                    f"La chaîne locale contredit le point de contrôle {height}")
        self._view = None
        self.pending = {}
        self._rebuild_pending([decode_json(row[0]) for row in
                               self.db.execute("SELECT payload FROM pending ORDER BY rowid")])
        saved_peers = self.db.execute("SELECT value FROM settings WHERE name='peers'").fetchone()
        stored = decode_json(saved_peers[0]) if saved_peers else {}
        self.peers = {}   # https://host:port -> pinned node id (None until first contact)
        if isinstance(stored, dict):  # pre-V4 lists of plain http addresses are dropped
            for url, peer_id in stored.items():
                try:
                    self.peers[parse_peer(url)[0]] = parse_peer(url + "#" + peer_id)[1] if peer_id else None
                except Invalid:
                    continue
        for spec in peers:
            url, peer_id = parse_peer(spec)
            if peer_id or url not in self.peers:
                self.peers[url] = peer_id
        require(len(self.peers) <= 16, "Maximum 16 pairs")
        token_path = self.data_dir / "admin.token"
        try:
            fd = os.open(token_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            self.token = token_path.read_text().strip()
        else:
            self.token = secrets.token_urlsafe(32)
            with os.fdopen(fd, "w") as stream:
                stream.write(self.token)
        require(len(self.token) >= 32, "Jeton administrateur invalide")
        self._save_pending()
        self._save_peers()
        self.record_event("startup", "Nœud redémarré, historique vérifié",
                          {"height": len(self.chain) - 1, "isolated": self.isolated})
        if repaired:
            self.record_event("permissions_fixed", "Droits de fichiers trop larges corrigés", {"files": repaired})

    @property
    def pending(self):
        return self._pending

    @pending.setter
    def pending(self, value):
        self._pending = value
        self._view = None          # cached "chain + pending" view must be rebuilt

    def _pool_view(self):
        """UTXO set with every pending payment applied; built once, then updated per payment."""
        if self._view is None:
            view, info = dict(self.utxos), {}
            for txid, tx in self._pending.items():
                info[txid] = (apply_transaction(tx, view, len(self.chain)), len(canonical(tx)))
            self._view, self._info = view, info
        return self._view

    @staticmethod
    def _event_hash(previous, timestamp, kind, message, details):
        return hashlib.sha256(canonical([previous or "", timestamp, kind, message, details])).hexdigest()

    def record_event(self, kind, message, details=None):
        with self.lock, self.db:
            last = self.db.execute("SELECT hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
            previous, now, text = (last[0] if last else None), int(time.time()), canonical(details or {}).decode()
            self.db.execute("INSERT INTO events(timestamp,kind,message,details,prev,hash) VALUES(?,?,?,?,?,?)",
                            (now, kind, message, text, previous or "", self._event_hash(previous, now, kind, message, text)))
            self.db.execute("DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 200)")
            self._journal_cache = None

    def journal_state(self):
        """Verify the event journal's hash chain and sign its head with the node identity."""
        with self.lock:
            if self._journal_cache:
                return self._journal_cache
            rows = list(self.db.execute("SELECT id,timestamp,kind,message,details,prev,hash FROM events ORDER BY id"))
            ok, expected_prev, bad = True, None, None
            for index, (rid, ts, kind, message, details, prev, digest) in enumerate(rows):
                if digest is None:                      # rows written before the chain existed
                    expected_prev = None
                    continue
                if (index and expected_prev is not None and prev != expected_prev) \
                        or digest != self._event_hash(prev or None, ts, kind, message, details):
                    ok, bad = False, rid
                    break
                expected_prev = digest
            head = rows[-1][6] if rows and rows[-1][6] else ""
            self._journal_cache = {"ok": ok, "first_bad": bad, "entries": len(rows), "head": head,
                                   "signature": self.key.sign(head.encode()).hex() if head else ""}
            return self._journal_cache

    def events(self):
        with self.lock:
            return [{"id": row[0], "timestamp": row[1], "kind": row[2],
                     "message": row[3], "details": decode_json(row[4])}
                    for row in self.db.execute(
                        "SELECT id,timestamp,kind,message,details FROM events ORDER BY id DESC LIMIT 30")]

    def set_isolated(self, value):
        require(type(value) is bool, "État d'isolement invalide")
        with self.lock:
            if self.isolated != value:
                with self.db:
                    self.db.execute("INSERT OR REPLACE INTO settings VALUES('isolated',?)",
                                    (canonical(value).decode(),))
                self.isolated = value
                self.network_epoch += 1
                self.peer_health.clear()
                self.record_event("isolation" if value else "reconnection",
                                  "Nœud isolé : échanges entre nœuds suspendus" if value
                                  else "Nœud reconnecté : recherche des blocs manquants")

    def alerts(self):
        """Things an operator should look at now, most serious first. Called with the lock held."""
        out, now = [], int(time.time())
        ok_peers = [p for p in self.peer_health.values() if p.get("ok")]
        if self.isolated:
            out.append(("info", "Ce nœud est volontairement isolé du réseau"))
        elif self.peers and not ok_peers and self.peer_health:
            out.append(("critical", "Aucun pair joignable : le nœud ne voit pas le réseau"))
        elif len(self.peers) >= 2 and len(ok_peers) == 1:
            out.append(("warning", "Un seul pair joignable : faible protection contre un pair hostile"))
        if self.reorg_blocked:
            out.append(("critical", f"Une chaîne plus lourde est refusée par la limite de réorganisation "
                                    f"({self.reorg_blocked['removed_blocks']} blocs)"))
        skews = sorted(p["skew"] for p in ok_peers if p.get("skew") is not None)
        if skews and abs(skews[len(skews) // 2]) > 30:
            out.append(("warning", f"Horloge décalée de {skews[len(skews) // 2]} s par rapport aux pairs "
                                   f"(les échanges refusent plus de 60 s)"))
        if len(self.chain) > 1 and now - self.chain[-1]["timestamp"] > 30 * 10 and ok_peers:
            out.append(("warning", f"Aucun nouveau bloc depuis {(now - self.chain[-1]['timestamp']) // 60} min"))
        if self.newer_seen:
            out.append(("warning", "Un pair utilise une version plus récente du protocole : mettre à jour"))
        groups = {self._network_group(urlsplit(p).hostname) for p in self.peers}
        if len(self.peers) >= 3 and len(groups) == 1 and None not in groups:
            out.append(("warning", "Tous vos pairs sont dans le même réseau : risque d'éclipse"))
        if not self.journal_state()["ok"]:
            out.append(("critical", "Le journal d'événements a été altéré"))
        if not self.key_encrypted:
            out.append(("info", "La clé d'identité du nœud n'est pas chiffrée (commande key-protect)"))
        if self.reputation.snapshot():
            out.append(("info", f"{len(self.reputation.snapshot())} pair(s) banni(s) temporairement"))
        order = {"critical": 0, "warning": 1, "info": 2}
        return [{"level": lv, "message": m} for lv, m in sorted(out, key=lambda x: order[x[0]])]

    def network_state(self):
        if self.isolated:
            return "isolated"
        if self.syncing:
            return "syncing"
        health = list(self.peer_health.values())
        if not self.peers:
            return "alone"
        if not health:
            return "connecting"
        if any(p.get("ok") and p.get("tip") != block_id(self.chain[-1]) for p in health):
            return "diverged"
        if any(not p.get("ok") for p in health):
            return "error"
        return "connected"

    def lab_status(self):
        result = {"enabled": bool(self.lab_peer), "secondary": None}
        if self.lab_peer:
            try:
                token = Path(self.lab_peer[1]).read_text().strip()
                result["secondary"] = request_json(self.lab_peer[0] + "/api/dashboard", token=token, timeout=1)
            except (Invalid, OSError) as exc:
                result["error"] = str(exc)
        return result

    def lab_control(self, target, action, miner="Alice", count=1):
        require(target in ("primary", "secondary"), "Nœud inconnu")
        require(action in ("isolate", "connect", "mine"), "Action inconnue")
        require(bool(self.demo_keys), "Commandes disponibles dans le laboratoire uniquement")
        if action == "mine":
            require(miner in self.demo_keys, "Portefeuille inconnu")
            integer(count, 1, 20, "Nombre de blocs")
            body = {"address": wallet_address(self.demo_keys[miner]), "count": count}
            endpoint = "/api/mine"
        else:
            body = {"isolated": action == "isolate"}
            endpoint = "/api/network"
        if target == "primary":
            if action == "mine":
                self.start_mining(body["address"], count)
            else:
                self.set_isolated(body["isolated"])
            return {"accepted": True}
        require(self.lab_peer is not None, "Second nœud non configuré")
        remote_url, token_file = self.lab_peer
        try:
            token = Path(token_file).read_text().strip()
        except OSError as exc:
            raise Invalid("Accès au second nœud indisponible") from exc
        return request_json(remote_url + endpoint, body, token, timeout=2)

    def _save_peers(self):
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO settings VALUES('peers', ?)",
                            (canonical(self.peers).decode(),))

    def _write_pending(self, pending):
        self.db.execute("DELETE FROM pending")
        self.db.executemany("INSERT INTO pending VALUES(?, ?)",
                            [(key, canonical(tx).decode()) for key, tx in pending.items()])

    def _save_pending(self):
        with self.db:
            self._write_pending(self.pending)

    def _rebuild_pending(self, candidates):
        self.pending = self._filter_pending(candidates, self.utxos, len(self.chain))

    def _filter_pending(self, candidates, utxos, height):
        available = dict(utxos)
        pending, size = {}, 0
        for tx in candidates:
            if len(pending) >= MAX_MEMPOOL:
                break
            try:
                encoded = canonical(tx)
                if size + len(encoded) > MAX_MEMPOOL_BYTES:
                    continue
                txid = transaction_id(tx)
                if txid in pending:
                    continue
                apply_transaction(tx, available, height)
                pending[txid] = tx
                size += len(encoded)
            except (Invalid, TypeError, ValueError, RecursionError):
                continue
        return pending

    def add_peer(self, spec):
        url, peer_id = parse_peer(spec)
        with self.lock:
            require(len(self.peers) < 16 or url in self.peers, "Maximum 16 pairs")
            if peer_id or url not in self.peers:
                self.peers[url] = peer_id
            self._save_peers()

    # ------------------------------------------------------------ peer trust and abuse control

    def _ban_keys(self, ip, peer_id):
        keys = [("id", peer_id)] if peer_id else []
        if ip and not ipaddress.ip_address(ip).is_loopback:  # local nodes share one address
            keys.append(("ip", ip))
        return keys

    def is_banned(self, ip=None, peer_id=None):
        return any(self.reputation.banned(key) for key in self._ban_keys(ip, peer_id))

    def penalize(self, ip, peer_id, points, reason):
        for key in self._ban_keys(ip, peer_id):
            if self.reputation.penalize(key, points):
                with self.lock, self.db:
                    self.db.executemany("INSERT OR REPLACE INTO bans VALUES(?,?,?)", self.reputation.export())
                    self.db.execute("DELETE FROM bans WHERE until < ?", (int(time.time()),))
                self.record_event("peer_banned", "Pair banni temporairement",
                                  {"kind": key[0], "key": key[1], "reason": reason})

    def punish(self, peer, points, reason):
        with self.lock:
            peer_id = self.peers.get(peer)
        self.penalize(urlsplit(peer).hostname, peer_id, points, reason)

    def peer_call(self, peer, path, payload=None, timeout=4):
        """Signed request to a peer over pinned TLS; remembers the identity on first contact."""
        with self.lock:
            expected = self.peers.get(peer)
        if self.stop.is_set():
            raise Invalid("Nœud en cours d'arrêt")          # never start a new exchange while closing
        data, remote_id = peer_request(peer, path, self.key, self.node_id, expected, payload,
                                       self.p2p_port, min(timeout, 3), self.identity_nonce)
        if remote_id == self.node_id:
            raise SelfPeer("Ce pair est ce nœud")
        with self.lock:
            if peer in self.peers and self.peers[peer] is None:
                self.peers[peer] = remote_id
                self._save_peers()
                self.record_event("peer_identity", "Identité du pair mémorisée",
                                  {"peer": peer, "id": remote_id})
        return data

    def submit(self, tx):
        with self.lock:
            require(isinstance(tx, dict), "Transaction invalide")
            original = self._pending
            try:
                txid = transaction_id(tx)
                if txid in self._pending:
                    return txid
                validate_transaction_shape(tx)              # signature etc., for this payment only
                size = len(canonical(tx))
                view = self._pool_view()
                try:
                    paid = sum(view[(i["txid"], i["index"])]["amount"] for i in tx["inputs"])
                except KeyError as exc:
                    raise Invalid("Pièce absente ou déjà dépensée") from exc
                fee = paid - sum(o["amount"] for o in tx["outputs"])
                require(fee >= 0, "Solde insuffisant")
                require(fee >= MIN_FEE_PER_BYTE * size,
                        f"Frais trop bas : au moins {MIN_FEE_PER_BYTE * size} unités pour {size} octets")
                require(all(o["amount"] >= DUST for o in tx["outputs"]),
                        f"Montant sous le seuil de poussière ({DUST} unités)")
                evicted = None
                if (len(self._pending) >= MAX_MEMPOOL
                        or sum(i[1] for i in self._info.values()) + size > MAX_MEMPOOL_BYTES):
                    evicted = self._evictable(tx, fee, size)
                    self._pending = {k: v for k, v in original.items() if k != evicted}
                    self._view = None
                    view = self._pool_view()                  # rebuilt without the evicted payment
                apply_transaction(tx, view, len(self.chain))   # full validation; updates the view
                with self.db:
                    if evicted:
                        self.db.execute("DELETE FROM pending WHERE txid=?", (evicted,))
                    self.db.execute("INSERT OR REPLACE INTO pending VALUES(?, ?)", (txid, canonical(tx).decode()))
                self._info[txid] = (fee, size)
                self._pending[txid] = copy.deepcopy(tx)
            except Exception:
                self._pending = original                     # disk or rule failure: nothing changes
                self._view = None                            # never keep a half-updated view
                raise
            if evicted:
                self.record_event("evicted", "Paiement le moins rémunéré remplacé", {"txid": evicted})
            self.record_event("transaction", "Paiement signé accepté", {"txid": txid})
            return txid

    def _evictable(self, tx, fee, size):
        """Cheapest pending payment nobody depends on, if the new one pays strictly more per byte."""
        needed = {i["txid"] for t in self._pending.values() for i in t["inputs"]}
        needed |= {i["txid"] for i in tx["inputs"]}
        rates = [(f / sz, txid) for txid, (f, sz) in self._info.items() if txid not in needed]
        require(bool(rates) and fee / size > min(rates)[0], "File de transactions pleine")
        return min(rates)[1]

    def accept_block(self, block):
        with self.lock:
            require(len(self.chain) < MAX_CHAIN_BLOCKS, "Limite de blocs atteinte")
            updated = validate_next(block, self.chain, self.utxos)
            expected_hash = self._checkpoint(block["height"])
            require(expected_hash is None or block_id(block) == expected_hash,
                    "Bloc contraire à un point de contrôle")
            pending = self._filter_pending(list(self.pending.values()), updated, len(self.chain) + 1)
            with self.db:
                self.db.execute("INSERT INTO blocks VALUES(?, ?)",
                                (len(self.chain), canonical(block).decode()))
                self._write_pending(pending)
            self.chain.append(copy.deepcopy(block))
            self.ids.append(block_id(block))
            self.utxos = updated
            self.work += block_work(block["target"])
            self.pending = pending
            self.record_event("block", "Nouveau bloc confirmé",
                              {"height": block["height"], "hash": block_id(block)})
            self._update_auto_checkpoints()

    def adopt(self, candidate):
        # Expensive validation runs outside the state lock; comparison is inside.
        updated, work = validate_chain(candidate)
        with self.lock:
            if work <= self.work:
                return False
            previous_tip = block_id(self.chain[-1])
            common = 0
            for position, right in enumerate(candidate):
                if position >= len(self.ids) or self.ids[position] != block_id(right):
                    break
                common += 1
            removed = len(self.chain) - common
            self._check_reorg(removed, [block_id(b) for b in candidate[common:]], common, work,
                              self.chain.work_between(1, common))
            confirmed = {transaction_id(tx) for b in candidate for tx in b["transactions"]}
            old = [tx for b in self.chain.iter_from(common) for tx in b["transactions"][1:]
                   if transaction_id(tx) not in confirmed]
            remaining = list(self.pending.values())
            pending = self._filter_pending(old + remaining, updated, len(candidate))
            with self.db:
                self.db.execute("DELETE FROM blocks")
                self.db.executemany("INSERT INTO blocks VALUES(?, ?)",
                                    [(i, canonical(b).decode()) for i, b in enumerate(candidate)])
                self._write_pending(pending)
            self.chain.reload()                          # the blocks table now holds the candidate
            self.ids = [block_id(b) for b in candidate]
            self.utxos, self.work, self.pending = updated, work, pending
            self.record_event("reorg" if removed else "sync",
                              "Historique concurrent adopté" if removed else "Blocs manquants récupérés",
                              {"previous_tip": previous_tip, "tip": block_id(candidate[-1]),
                               "removed_blocks": removed, "added_blocks": len(candidate) - common,
                               "pending": len(self.pending)})
            self._update_auto_checkpoints()
            return True

    def adopt_suffix(self, common, blocks, utxos, work, snapshot_tip):
        """Replace everything after height `common` with already validated blocks."""
        with self.lock:
            require(self.ids[-1] == snapshot_tip, "La chaîne locale a changé pendant la synchronisation")
            if work <= self.work:
                return False
            previous_tip = self.ids[-1]
            removed = len(self.chain) - 1 - common
            self._check_reorg(removed, [block_id(b) for b in blocks], common + 1, work,
                              self.chain.work_between(1, common + 1))
            confirmed = {transaction_id(tx) for b in blocks for tx in b["transactions"]}
            old = [tx for b in self.chain.iter_from(common + 1) for tx in b["transactions"][1:]
                   if transaction_id(tx) not in confirmed]
            pending = self._filter_pending(old + list(self.pending.values()), utxos,
                                           common + 1 + len(blocks))
            with self.db:
                self.db.execute("DELETE FROM blocks WHERE height > ?", (common,))
                self.db.executemany("INSERT INTO blocks VALUES(?, ?)",
                                    [(common + 1 + i, canonical(b).decode()) for i, b in enumerate(blocks)])
                self._write_pending(pending)
            self.chain.truncate(common + 1)
            del self.ids[common + 1:]
            self.reorg_blocked = None
            self.chain.extend(copy.deepcopy(blocks))
            self.ids.extend(block_id(b) for b in blocks)
            self.utxos, self.work, self.pending = utxos, work, pending
            self.record_event("reorg" if removed else "sync",
                              "Historique concurrent adopté" if removed else "Blocs manquants récupérés",
                              {"previous_tip": previous_tip, "tip": self.ids[-1],
                               "removed_blocks": removed, "added_blocks": len(blocks),
                               "pending": len(self.pending)})
            self._update_auto_checkpoints()
            return True

    def _checkpoint(self, height):
        """Expected block hash at a height: operator checkpoints always, automatic ones unless the
        administrator lifted the reorganisation limit (limit 0 = explicit override)."""
        if height in self.checkpoints:
            return self.checkpoints[height]
        return self.auto_checkpoints.get(height) if self.max_reorg else None

    def _update_auto_checkpoints(self):
        """Remember every 100th block once it is buried 50 deep; forget ones the chain no longer has."""
        with self.lock:
            tip = len(self.ids) - 1
            stale = [h for h, d in self.auto_checkpoints.items() if h > tip or self.ids[h] != d]
            kept = {h for h in self.auto_checkpoints if h not in stale}
            new = [h for h in range(100, tip - 49, 100) if h not in kept]
            if not stale and not new:
                return
            with self.db:
                for h in stale:
                    self.db.execute("DELETE FROM autocp WHERE height=?", (h,))
                    del self.auto_checkpoints[h]
                for h in new:
                    self.db.execute("INSERT OR REPLACE INTO autocp VALUES(?,?)", (h, self.ids[h]))
                    self.auto_checkpoints[h] = self.ids[h]
            if stale:
                self.record_event("autocheckpoint_reset", "Points de contrôle automatiques réinitialisés",
                                  {"heights": stale})

    def _check_reorg(self, removed, new_ids, first_height, new_work=None, base_work=0):
        """Local safety policy against rewriting history; called with the lock held."""
        if self.max_reorg and removed > 6 and new_work is not None:
            margin = 125 if removed > 20 else 110          # more proof needed to erase more history
            # Compare only the competing branches (what is erased against what replaces it): the shared
            # prefix is identical and must not dilute the margin on a long chain.
            if (new_work - base_work) * 100 < (self.work - base_work) * margin:
                self.record_event("reorg_refused", "Chaîne concurrente pas assez lourde pour effacer autant de blocs",
                                  {"removed_blocks": removed, "required_margin_percent": margin - 100})
                raise Invalid(f"Effacer {removed} blocs exige un travail supérieur d'au moins {margin - 100} %")
        if self.max_reorg and removed > self.max_reorg:
            state = {"removed_blocks": removed, "limit": self.max_reorg}
            if self.reorg_blocked != state:           # log a persistent refusal once, not every 2 seconds
                self.reorg_blocked = state
                self.record_event("reorg_refused", "Réorganisation trop profonde refusée", state)
            raise Invalid(f"Réorganisation de {removed} blocs refusée (limite {self.max_reorg})")
        for offset, digest in enumerate(new_ids):
            wanted = self._checkpoint(first_height + offset)
            if wanted is not None and digest != wanted:
                self.record_event("reorg_refused", "Chaîne contraire à un point de contrôle refusée",
                                  {"height": first_height + offset})
                raise Invalid("Chaîne contraire à un point de contrôle")

    def set_max_reorg(self, value):
        """Administrator decision: accept (or limit again) deep reorganisations."""
        integer(value, 0, MAX_CHAIN_BLOCKS, "Limite de réorganisation")
        with self.lock:
            self.max_reorg = value
            self.reorg_blocked = None
        self.record_event("max_reorg", "Limite de réorganisation modifiée", {"limit": value})

    def _find_common(self, peer, remote_height, ids):
        """Binary search for the last shared block: about log2(height) requests, whatever a peer claims."""
        def remote_hash(height):
            data = self.peer_call(peer, f"/p2p/hashes?from={height}&limit=1", timeout=3)
            hashes = data.get("hashes") if isinstance(data, dict) else None
            try:
                require(isinstance(hashes, list) and len(hashes) == 1, "Réponse de pair invalide")
                hex_string(hashes[0], 64)
            except Invalid:
                self.punish(peer, 20, "Réponse mal formée")
                raise
            return hashes[0]

        if remote_hash(0) != ids[0]:
            self.punish(peer, 50, "Genesis différent")
            raise Invalid("Genesis incompatible")
        low, high = 0, min(len(ids) - 1, remote_height)
        while low < high:
            middle = (low + high + 1) // 2
            if remote_hash(middle) == ids[middle]:
                low = middle
            else:
                high = middle - 1
        return low

    def sync_from(self, peer, remote_height, epoch):
        """Find the last shared block, then download and validate only what is missing."""
        require(isinstance(remote_height, int) and 0 <= remote_height < MAX_CHAIN_BLOCKS,
                "Hauteur de pair invalide")
        with self.lock:
            ids = list(self.ids)
        common = self._find_common(peer, remote_height, ids)
        with self.lock:
            require(self.ids[:common + 1] == ids[:common + 1], "La chaîne locale a changé pendant la synchronisation")
            snapshot_tip = self.ids[-1]
            prefix = Tail(self.chain[max(0, common + 1 - Tail.KEEP):common + 1], common + 1)
            utxos = dict(self.utxos) if common == len(self.chain) - 1 else None
        try:
            if utxos is None:
                utxos, _ = validate_chain(self.chain, upto=common + 1)   # replay the shared prefix from disk
            work = self.chain.work_between(1, common + 1)
        except (IndexError, ValueError) as exc:
            raise Invalid("La chaîne locale a changé pendant la synchronisation") from exc
        blocks, nxt = [], common + 1
        while nxt <= remote_height:
            with self.lock:
                if self.stop.is_set() or self.isolated or epoch != self.network_epoch:
                    return False
            data = self.peer_call(peer, f"/p2p/blocks?from={nxt}&limit={SYNC_BATCH}", timeout=8)
            batch = data.get("blocks") if isinstance(data, dict) else None
            if not (isinstance(batch, list) and 1 <= len(batch) <= SYNC_BATCH):
                self.punish(peer, 20, "Réponse mal formée")
                raise Invalid("Réponse de pair invalide")
            for block in batch:
                try:
                    wanted = self._checkpoint(block.get("height") if isinstance(block, dict) else None)
                    require(wanted is None or block_id(block) == wanted, "Bloc contraire à un point de contrôle")
                    utxos = validate_next(block, prefix, utxos, inplace=True)   # `utxos` is this sync's own copy
                except Invalid as exc:
                    self.punish(peer, 50, "Bloc invalide : " + str(exc)[:80])
                    raise
                prefix.append(block)
                blocks.append(block)
                work += block_work(block["target"])
            nxt += len(batch)
        with self.lock:
            if self.isolated or epoch != self.network_epoch:
                return False
        return self.adopt_suffix(common, blocks, utxos, work, snapshot_tip)

    # ------------------------------------------------------------ explorer (read-only views)

    def _explorer_index(self):
        """Index of transactions and address history, rebuilt only when the tip changes."""
        tip = self.ids[-1]
        cached = getattr(self, "_explorer_cache", None)
        if cached and cached["tip"] == tip:
            return cached
        txs, outs, history, by_hash = {}, {}, {}, {}
        for block in self.chain:
            by_hash[block_id(block)] = block["height"]
            for position, tx in enumerate(block["transactions"]):
                txid = transaction_id(tx)
                txs[txid] = (block["height"], position)
                if tx.get("type") != "coinbase":
                    for item in tx["inputs"]:
                        owner = outs.get((item["txid"], item["index"]))
                        if owner:
                            history.setdefault(owner[0], []).append(
                                {"height": block["height"], "txid": txid, "received": 0, "sent": owner[1]})
                for index, out in enumerate(tx["outputs"]):
                    outs[(txid, index)] = (out["address"], out["amount"])
                    history.setdefault(out["address"], []).append(
                        {"height": block["height"], "txid": txid, "received": out["amount"], "sent": 0})
        self._explorer_cache = {"tip": tip, "txs": txs, "outs": outs, "history": history, "by_hash": by_hash}
        return self._explorer_cache

    def _tx_view(self, tx, index, confirmed):
        txid = transaction_id(tx)
        coinbase = tx.get("type") == "coinbase"
        inputs = []
        if not coinbase:
            for item in tx["inputs"]:
                owner = index["outs"].get((item["txid"], item["index"]))
                inputs.append({"txid": item["txid"], "index": item["index"],
                               "address": owner[0] if owner else None, "amount": owner[1] if owner else None})
        total_out = sum(o["amount"] for o in tx["outputs"])
        fee = None if coinbase or any(i["amount"] is None for i in inputs) else sum(i["amount"] for i in inputs) - total_out
        return {"txid": txid, "coinbase": coinbase, "inputs": inputs, "outputs": tx["outputs"],
                "total_out": total_out, "fee": fee, "confirmed": confirmed}

    def explorer_block(self, key):
        with self.lock:
            index = self._explorer_index()
            if isinstance(key, str) and len(key) == 64:
                require(key in index["by_hash"], "Bloc inconnu")
                key = index["by_hash"][key]
            require(type(key) is int and 0 <= key < len(self.chain), "Bloc inconnu")
            block = self.chain[key]
            txs = [self._tx_view(tx, index, True) for tx in block["transactions"]]
            reward = sum(o["amount"] for o in block["transactions"][0]["outputs"]) if key else 0
            return {"height": key, "hash": self.ids[key], "previous": block["previous"],
                    "timestamp": block["timestamp"], "version": block["version"], "nonce": block["nonce"],
                    "difficulty_bits": difficulty_bits(block["target"]), "merkle_root": block["merkle_root"],
                    "size": len(canonical(block)), "tx_count": len(txs), "transactions": txs,
                    "miner": block["transactions"][0]["outputs"][0]["address"]
                    if key and block["transactions"][0]["outputs"] else None,
                    "reward": reward, "fees": max(0, reward - subsidy(key)) if key else 0,
                    "confirmations": len(self.chain) - key,
                    "next": self.ids[key + 1] if key + 1 < len(self.chain) else None}

    def explorer_blocks(self, start, limit):
        with self.lock:
            top = len(self.chain) - 1 - start
            rows = []
            for h in range(top, max(-1, top - limit), -1):
                b = self.chain[h]
                rows.append({"height": h, "hash": self.ids[h], "timestamp": b["timestamp"],
                             "tx_count": len(b["transactions"]), "size": len(canonical(b)),
                             "difficulty_bits": difficulty_bits(b["target"])})
            return {"blocks": rows, "height": len(self.chain) - 1}

    def explorer_tx(self, txid):
        with self.lock:
            hex_string(txid, 64)
            index = self._explorer_index()
            if txid in index["txs"]:
                height, position = index["txs"][txid]
                view = self._tx_view(self.chain[height]["transactions"][position], index, True)
                return {**view, "height": height, "position": position,
                        "block": self.ids[height], "confirmations": len(self.chain) - height}
            require(txid in self.pending, "Transaction inconnue")
            view = self._tx_view(self.pending[txid], index, False)
            return {**view, "height": None, "confirmations": 0}

    def explorer_address(self, address, limit=50):
        require(valid_address(address), "Adresse invalide")
        with self.lock:
            index = self._explorer_index()
            events = index["history"].get(address, [])
            info = self.balance(address)
            return {"address": address, "confirmed": info["confirmed"], "available": info["available"],
                    "received": sum(e["received"] for e in events), "sent": sum(e["sent"] for e in events),
                    "events": len(events), "history": list(reversed(events[-limit:]))}

    def explorer_search(self, query):
        query = (query or "").strip()
        require(1 <= len(query) <= 100, "Recherche vide")
        with self.lock:
            index = self._explorer_index()
            if query.isdecimal() and len(query) <= 9 and int(query) < len(self.chain):   # a 64-digit hash is not a height
                return {"type": "block", "key": int(query)}
            if len(query) == 64 and all(c in "0123456789abcdef" for c in query.lower()):
                query = query.lower()
                if query in index["by_hash"]:
                    return {"type": "block", "key": query}
                if query in index["txs"] or query in self.pending:
                    return {"type": "tx", "key": query}
            if valid_address(query):
                return {"type": "address", "key": query}
        raise Invalid("Rien trouvé : saisir une hauteur, une empreinte de bloc, un identifiant de transaction ou une adresse")

    def _used_addresses(self):
        """Every address that ever received coins (rebuilt only when the tip changes)."""
        tip = self.ids[-1]
        if getattr(self, "_used_cache", (None, None))[0] != tip:
            used = {out["address"] for b in self.chain for tx in b["transactions"] for out in tx["outputs"]}
            self._used_cache = (tip, used)
        return self._used_cache[1]

    def balance(self, address):
        require(valid_address(address), "Adresse invalide")
        with self.lock:
            reserved = {(i["txid"], i["index"]) for tx in self.pending.values() for i in tx["inputs"]}
            coins = []
            for (txid, index), coin in self.utxos.items():
                if coin["address"] != address:
                    continue
                mature = not coin["coinbase"] or len(self.chain) - coin["height"] >= COINBASE_MATURITY
                coins.append({**coin, "txid": txid, "index": index,
                              "spendable": mature and (txid, index) not in reserved,
                              "mature": mature})
            total = sum(c["amount"] for c in coins)
            spendable = sum(c["amount"] for c in coins if c["spendable"])
            return {"address": address, "used": address in self._used_addresses(),
                    "confirmed": total, "available": spendable,
                    "confirmed_nova": format_amount(total), "available_nova": format_amount(spendable),
                    "utxos": coins}

    def status(self, detail=False):
        with self.lock:
            result = {"name": "Nova", "version": __version__, "network": NETWORK,
                      "height": len(self.chain) - 1, "tip": block_id(self.chain[-1]),
                      "chainwork": str(self.work), "difficulty_bits": difficulty_bits(self.chain[-1]["target"]),
                      "node_id": self.node_id, "reorg_blocked": self.reorg_blocked,
                      "protocol": {"block_version": BLOCK_VERSION, "software": __version__,
                                   "max_reorg": self.max_reorg, "checkpoints": len(self.checkpoints)},
                      "security": {"transport": "TLS 1.3, identités Ed25519 épinglées, requêtes signées",
                                   "closed": self.closed, "bans": self.reputation.snapshot(),
                                   "key_encrypted": self.key_encrypted,
                                   "auto_checkpoints": len(self.auto_checkpoints),
                                   "journal": dict(self.journal_state())},
                      "automine": {"enabled": bool(self.automine), "address": self.automine,
                                   "blocks": self.auto_mined},
                      "pending": len(self.pending), "unit": UNIT,
                      "peers": [{"url": p, "id": self.peers[p], **self.peer_health.get(p, {"ok": None})}
                                for p in sorted(self.peers)],
                      "p2p_port": self.p2p_port,
                      "mining": copy.deepcopy(self.mining), "test_network": True,
                      "demo": bool(self.demo_keys)}
            result.update({"isolated": self.isolated, "network_state": self.network_state(),
                           "now": int(time.time()), "alerts": self.alerts()})
            if detail:
                result["issued_nova"] = format_amount(sum(c["amount"] for c in self.utxos.values()))
                result["blocks"] = [{"height": b["height"], "hash": block_id(b),
                                     "previous": b["previous"], "timestamp": b["timestamp"],
                                     "transactions": len(b["transactions"]),
                                     "bits": difficulty_bits(b["target"]), "nonce": b["nonce"]}
                                    for b in reversed(self.chain[-12:])]
                result["pending_transactions"] = [
                    {"txid": transaction_id(t), "outputs": t["outputs"]}
                    for t in list(self.pending.values())[:20]]
                result["wallets"] = [
                    {"name": name, **self.balance(wallet_address(key))}
                    for name, key in self.demo_keys.items()]
                result["events"] = self.events()
            return result

    def mine_one(self, address, auto=False):
        while True:
            with self.lock:
                block = make_candidate(self.chain, self.utxos, list(self.pending.values()), address)
            # Timestamps strictly increase and may be at most MAX_FUTURE_SECONDS ahead of real time,
            # so a long burst of blocks cannot outrun the clock: wait instead of mining a refused block.
            ahead = block["timestamp"] - (int(time.time()) + MAX_FUTURE_SECONDS)
            if ahead <= 0:
                break
            if self.stop.wait(min(ahead + 0.2, 5)):
                raise Invalid("Minage interrompu")
        height = block["height"]
        # Give up as soon as a peer extends the chain: the work would be wasted.
        cancelled = lambda: (self.stop.is_set() or len(self.chain) != height
                             or (auto and self.automine != address))
        solve(block, cancelled)
        self.accept_block(block)
        return block

    def set_automine(self, enabled, address=None):
        require(type(enabled) is bool, "Valeur invalide")
        if enabled:
            require(valid_address(address), "Adresse de minage invalide")
        with self.lock:
            with self.db:
                if enabled:
                    self.db.execute("INSERT OR REPLACE INTO settings VALUES('automine',?)",
                                    (canonical({"address": address}).decode(),))
                else:
                    self.db.execute("DELETE FROM settings WHERE name='automine'")
            changed = self.automine != (address if enabled else None)
            self.automine = address if enabled else None
        if changed:
            self.record_event("automine", "Minage automatique activé" if enabled
                              else "Minage automatique arrêté")
        self.wake.set()

    def _automine_loop(self):
        while not self.stop.is_set():
            address = self.automine
            if not address or self.mining["running"]:
                self.wake.wait(1)
                self.wake.clear()
                continue
            try:
                self.mine_one(address, auto=True)
                with self.lock:
                    self.auto_mined += 1
            except Invalid:
                self.stop.wait(0.05)  # stale candidate or cancelled: start again on the new tip
            except Exception:
                LOG.exception("Automatic mining failed; retrying")
                self.stop.wait(2)

    def start_mining(self, address, count):
        require(valid_address(address), "Adresse de minage invalide")
        integer(count, 1, 20, "Nombre de blocs (1 à 20)")
        with self.lock:
            require(not self.mining["running"], "Un minage est déjà en cours")
            self.mining = {"running": True, "completed": 0, "requested": count, "error": None}

        def worker():
            try:
                for _ in range(count):
                    if self.stop.is_set():
                        break
                    # Refresh candidate if a peer has advanced our chain in the meantime.
                    for attempt in range(20):
                        try:
                            self.mine_one(address)
                            break
                        except Invalid as exc:
                            if self.stop.is_set() or not any(
                                    word in str(exc) for word in ("parent", "Hauteur", "interrompu")):
                                raise
                            if attempt == 19:
                                raise
                    with self.lock:
                        self.mining["completed"] += 1
            except Exception as exc:
                LOG.exception("Mining stopped")
                with self.lock:
                    self.mining["error"] = str(exc)
            finally:
                with self.lock:
                    self.mining["running"] = False

        thread = threading.Thread(target=worker, daemon=True, name="nova-miner")
        self.threads.append(thread)
        thread.start()

    def demo_send(self, sender, recipient, amount):
        require(sender in self.demo_keys, "Portefeuille de démonstration inconnu")
        key = self.demo_keys[sender]
        with self.lock:
            coins = self.balance(wallet_address(key))["utxos"]
            tx = build_transaction(key, coins, recipient, parse_amount(amount), parse_amount("0.001"))
            return self.submit(tx)

    def sync_once(self):
        if not self.sync_guard.acquire(blocking=False):
            return
        try:
            with self.lock:
                if self.isolated:
                    return
                peers, epoch = list(self.peers), self.network_epoch
            for peer in peers:
                with self.lock:
                    if self.stop.is_set() or self.isolated or epoch != self.network_epoch:
                        return
                    peer_id = self.peers.get(peer)
                if self.is_banned(urlsplit(peer).hostname, peer_id):
                    with self.lock:
                        self.peer_health[peer] = {"ok": False, "error": "Pair banni temporairement",
                                                  "checked_at": int(time.time())}
                    continue
                discover = False
                try:
                    remote = self.peer_call(peer, "/p2p/status", timeout=2)
                    require(isinstance(remote, dict) and remote.get("network") == NETWORK,
                            "Réseau incompatible")
                    newer = (remote.get("protocol") or {}).get("block_version")
                    if type(newer) is int and newer > BLOCK_VERSION and peer not in self.newer_seen:
                        self.newer_seen.add(peer)
                        self.record_event("peer_newer", "Un pair utilise une version plus récente du protocole",
                                          {"peer": peer, "block_version": newer, "ours": BLOCK_VERSION})
                    require(not remote.get("isolated", False), "Le pair est volontairement isolé")
                    remote_work = remote.get("chainwork")
                    require(isinstance(remote_work, str) and len(remote_work) <= 32
                            and remote_work.isdecimal(), "Travail cumulé invalide")
                    with self.lock:
                        need_chain = int(remote_work) > self.work
                        self.syncing = need_chain
                    if need_chain:
                        self.sync_from(peer, remote.get("height"), epoch)
                    pending = self.peer_call(peer, "/p2p/mempool", timeout=2)["transactions"]
                    require(isinstance(pending, list) and len(pending) <= MAX_MEMPOOL, "File invalide")
                    with self.lock:
                        if self.isolated or epoch != self.network_epoch:
                            return
                        for tx in pending:
                            try:
                                self.submit(tx)
                            except Invalid:
                                pass
                        old_health = self.peer_health.get(peer, {})
                        remote_now = remote.get("now")
                        self.peer_health[peer] = {"ok": True, "height": remote["height"],
                            "skew": remote_now - int(time.time()) if type(remote_now) is int else None,
                            "tip": remote["tip"], "chainwork": remote_work,
                            "checked_at": int(time.time())}
                        if not old_health.get("ok"):
                            self.record_event("peer_connected", "Connexion à un pair établie", {"peer": peer})
                    discover = not self.closed
                except SelfPeer:
                    with self.lock:  # we have been given our own address: forget it
                        self.peers.pop(peer, None)
                        self.rejected_peers.add(peer)
                        self.peer_health.pop(peer, None)
                        self._save_peers()
                except (Invalid, KeyError, TypeError, ValueError, RecursionError) as exc:
                    with self.lock:
                        if self.isolated or epoch != self.network_epoch:
                            return
                        old_health = self.peer_health.get(peer, {})
                        self.peer_health[peer] = {"ok": False, "error": str(exc)[:180],
                                                  "checked_at": int(time.time())}
                        if old_health.get("ok") is not False or old_health.get("error") != str(exc)[:180]:
                            self.record_event("peer_error", "Échange avec un pair interrompu",
                                              {"peer": peer, "reason": str(exc)[:180]})
                finally:
                    with self.lock:
                        self.syncing = False
                if discover:
                    self._discover(peer)
        finally:
            self.sync_guard.release()

    def _may_add_peer(self, url, peer_id):
        """Common rules for peers we were told about (called with the lock held)."""
        host = urlsplit(url).hostname
        # Open discovery needs more than authentication (nothing stops a flood of identities);
        # until then, stay on loopback and private networks. Anti-eclipse limits: half of the table
        # stays reserved for peers the operator chose, and at most two peers per /16 network.
        if (self.closed or self.isolated or not private_address(host) or url in self.peers
                or url in self.rejected_peers or len(self.peers) >= 16
                or peer_id == self.node_id or peer_id in self.peers.values()
                or len(self.discovered) >= 8):
            return False
        group = self._network_group(host)
        if group and sum(1 for p in self.peers if self._network_group(urlsplit(p).hostname) == group) >= 2:
            return False
        return True

    @staticmethod
    def _network_group(host):
        try:
            if ipaddress.ip_address(host).is_loopback:
                return None                     # the local laboratory runs everything on one address
        except ValueError:
            return None
        return ".".join(host.split(".")[:2])

    def _remember_discovered(self, url):
        self.discovered.add(url)
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO settings VALUES('discovered',?)",
                            (canonical(sorted(self.discovered)).decode(),))

    def learn_announced(self, host, port, peer_id):
        """An authenticated peer told us where it listens."""
        try:
            integer(port, 1024, 65535, "Port")
            url = parse_peer(f"https://{host}:{port}")[0]
            hex_string(peer_id, 64)
        except Invalid:
            return
        with self.lock:
            if url in self.peers and self.peers[url] is None and peer_id != self.node_id:
                self.peers[url] = peer_id
                self._save_peers()
                return
            if not self._may_add_peer(url, peer_id):
                return
            self.peers[url] = peer_id
            self._save_peers()
            self._remember_discovered(url)
            self.record_event("peer_discovered", "Un pair s'est annoncé", {"peer": url, "id": peer_id})

    def _discover(self, peer):
        """Learn private-network peers, with their identities, from a peer."""
        try:
            known = self.peer_call(peer, "/p2p/peers", timeout=2).get("peers", [])
        except (Invalid, AttributeError):
            return
        if not isinstance(known, list):
            return
        with self.lock:
            for spec in known[:16]:
                try:
                    url, peer_id = parse_peer(spec)
                except Invalid:
                    continue
                if peer_id and self._may_add_peer(url, peer_id):
                    self.peers[url] = peer_id
                    self._save_peers()
                    self._remember_discovered(url)
                    self.record_event("peer_discovered", "Nouveau pair découvert",
                                      {"peer": url, "id": peer_id, "via": peer})

    def start_sync(self):
        def worker():
            while not self.stop.is_set():
                try:
                    self.sync_once()
                except Exception:
                    LOG.exception("Peer sync failed; retrying")
                self.stop.wait(2)
        thread = threading.Thread(target=worker, daemon=True, name="nova-sync")
        self.threads.append(thread)
        thread.start()
        miner = threading.Thread(target=self._automine_loop, daemon=True, name="nova-automine")
        self.threads.append(miner)
        miner.start()

    def close(self):
        self.stop.set()
        self.wake.set()
        for thread in self.threads:
            thread.join(timeout=12)
        with self.lock:
            self.chain.close()
            self.db.close()
            self._directory_lock.close()


class NodeServer(ThreadingHTTPServer):
    """Local server: dashboard, wallet API and administration. Not a peer interface."""
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, bind, node):
        self.node = node
        self.slots = threading.BoundedSemaphore(24)
        super().__init__(bind, Handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class Handler(BaseHTTPRequestHandler):
    server_version = "NovaTest/0.3"

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, fmt, *args):
        LOG.debug("%s %s", self.client_address[0], fmt % args)

    @property
    def node(self):
        return self.server.node

    def respond(self, value, status=200, html=False):
        body = value if html else canonical(value)
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8" if html else "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                         "connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def admin(self):
        require(hmac.compare_digest(self.headers.get("X-Nova-Token", ""), self.node.token),
                "Accès administrateur requis")

    def check_origin(self):
        # DNS rebinding: a hostile page can make its own name resolve to 127.0.0.1. Only the names
        # of this very machine (or the explicitly bound address) are served.
        bound = self.server.server_address[0]
        host = urlsplit("http://" + self.headers.get("Host", "")).hostname
        require(host in ("127.0.0.1", "localhost", "::1", bound), "Nom d'hôte refusé")
        origin = self.headers.get("Origin")
        if origin:
            require(origin == "http://" + self.headers.get("Host", ""), "Origine refusée")
        require(self.headers.get("Sec-Fetch-Site") not in ("cross-site",),
                "Requête provenant d'un autre site refusée")

    def do_GET(self):
        try:
            self.check_origin()
            path = urlsplit(self.path)
            if path.path == "/":
                return self.respond(Path(__file__).with_name("dashboard.html").read_bytes(), html=True)
            if path.path == "/api/status":
                return self.respond(self.node.status())
            if path.path == "/explorer":
                return self.respond(Path(__file__).with_name("explorer.html").read_bytes(), html=True)
            if path.path.startswith("/api/explorer/"):
                query = parse_qs(path.query)
                one = lambda name, default="": query.get(name, [default])[0]
                kind = path.path[len("/api/explorer/"):]
                if kind == "block":
                    key = one("key")
                    return self.respond(self.node.explorer_block(int(key) if key.isdecimal() and len(key) <= 9 else key))
                if kind == "blocks":
                    start, limit = int(one("start", "0")), int(one("limit", "20"))
                    integer(start, 0, MAX_CHAIN_BLOCKS, "Début")
                    integer(limit, 1, 100, "Limite")
                    return self.respond(self.node.explorer_blocks(start, limit))
                if kind == "tx":
                    return self.respond(self.node.explorer_tx(one("id")))
                if kind == "address":
                    return self.respond(self.node.explorer_address(one("address")))
                if kind == "search":
                    return self.respond(self.node.explorer_search(one("q")))
            if path.path == "/api/dashboard":
                self.admin()
                data = self.node.status(detail=True)
                data["lab"] = self.node.lab_status()
                return self.respond(data)
            if path.path == "/api/balance":
                address = parse_qs(path.query).get("address", [""])[0]
                return self.respond(self.node.balance(address))
            return self.respond({"error": "Page inconnue"}, 404)
        except (Invalid, ValueError, TypeError, RecursionError) as exc:
            self.respond({"error": str(exc)}, 400)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self):
        try:
            self.check_origin()
            require(not self.headers.get("Transfer-Encoding"), "Encodage non accepté")
            size = int(self.headers.get("Content-Length", "0"))
            require(0 < size <= 300_000, "Taille de requête invalide")
            body = decode_json(self.rfile.read(size))
            require(isinstance(body, dict), "Objet JSON attendu")
            path = urlsplit(self.path).path
            if path == "/api/transactions":
                with self.node.lock:
                    require(not self.node.isolated, "Nœud isolé : échanges suspendus")
                    return self.respond({"txid": self.node.submit(body)}, 201)
            self.admin()
            if path == "/api/network":
                self.node.set_isolated(body.get("isolated"))
                return self.respond({"isolated": self.node.isolated})
            if path == "/api/lab/control":
                return self.respond(self.node.lab_control(body.get("target"), body.get("action"),
                                                         body.get("miner", "Alice"), body.get("count", 1)))
            if path == "/api/mine":
                self.node.start_mining(body.get("address"), body.get("count", 1))
                return self.respond({"started": True}, 202)
            if path == "/api/automine":
                self.node.set_automine(body.get("enabled"), body.get("address"))
                return self.respond({"enabled": bool(self.node.automine)})
            if path == "/api/max-reorg":
                self.node.set_max_reorg(body.get("limit"))
                return self.respond({"limit": self.node.max_reorg})
            if path == "/api/peers":
                self.node.add_peer(body.get("url"))
                return self.respond({"added": True}, 201)
            if path == "/api/demo/send":
                require(bool(self.node.demo_keys), "Mode démonstration désactivé")
                return self.respond({"txid": self.node.demo_send(
                    body.get("sender"), body.get("recipient"), body.get("amount"))}, 201)
            return self.respond({"error": "Commande inconnue"}, 404)
        except (Invalid, ValueError, TypeError, KeyError, RecursionError) as exc:
            self.respond({"error": str(exc)}, 400)
        except (BrokenPipeError, ConnectionResetError):
            pass


PEER_BODY_LIMIT = 300_000
ROUTE_BODY_LIMITS = {"/p2p/transactions": 20_000, "/p2p/blocks": 300_000}
PEER_REQUEST_DEADLINE = 15      # seconds for a whole request, however slowly the client drips bytes
MAX_CONNECTIONS_PER_IP = 8


class PeerServer(ThreadingHTTPServer):
    """Peer interface: TLS 1.3 only, every request signed by a node identity, rate limited."""
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, bind, node):
        self.node = node
        self.context = server_context(node.data_dir, node.key_password)
        self.slots = threading.BoundedSemaphore(24)
        self.per_ip, self.ip_lock = {}, threading.Lock()
        super().__init__(bind, PeerHandler)
        node.p2p_port = self.server_port

    def process_request(self, request, client_address):
        ip = client_address[0]
        with self.ip_lock:
            if self.per_ip.get(ip, 0) >= MAX_CONNECTIONS_PER_IP or not self.slots.acquire(blocking=False):
                self.shutdown_request(request)
                return
            self.per_ip[ip] = self.per_ip.get(ip, 0) + 1
        try:
            super().process_request(request, client_address)
        except Exception:
            self._release(ip)
            raise

    def _release(self, ip):
        with self.ip_lock:
            self.per_ip[ip] -= 1
            if not self.per_ip[ip]:
                del self.per_ip[ip]
        self.slots.release()

    def process_request_thread(self, request, client_address):
        # The TLS handshake runs here, in the worker thread and under a timeout, so that a client
        # that never finishes it cannot stall the accept loop.
        try:
            try:
                request.settimeout(5)
                tls = self.context.wrap_socket(request, server_side=True, do_handshake_on_connect=False)
                tls.do_handshake()
            except (ssl.SSLError, OSError):
                try:
                    request.close()
                except OSError:
                    pass
                return
            # A client that drips one byte every few seconds never trips the per-read timeout:
            # the connection is cut after a total deadline instead.
            def cut():
                for action in (lambda: tls.shutdown(socket.SHUT_RDWR), tls.close):
                    try:
                        action()
                    except (OSError, ssl.SSLError, ValueError):
                        pass
            watchdog = threading.Timer(PEER_REQUEST_DEADLINE, cut)
            watchdog.daemon = True
            watchdog.start()
            try:
                super().process_request_thread(tls, client_address)
            finally:
                watchdog.cancel()
        finally:
            self._release(client_address[0])

    def handle_error(self, request, client_address):
        # Broken or cut connections are routine; anything else is a defect worth a stack trace.
        error = sys.exc_info()[1]
        if isinstance(error, (OSError, ssl.SSLError)):
            LOG.debug("Peer connection ended: %s", error)
            return
        LOG.exception("Unexpected error while serving a peer")


class PeerHandler(BaseHTTPRequestHandler):
    server_version = "NovaPeer/0.4"
    protocol_version = "HTTP/1.0"

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, fmt, *args):
        LOG.debug("%s %s", self.client_address[0], fmt % args)

    @property
    def node(self):
        return self.server.node

    def respond(self, value, status=200):
        body = canonical(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.handle_peer("GET")

    def do_POST(self):
        self.handle_peer("POST")

    def handle_peer(self, method):
        node, ip = self.node, self.client_address[0]
        sender = None
        try:
            if node.is_banned(ip, None):
                return self.respond({"error": "Pair banni temporairement"}, 403)
            if not node.ip_limiter.allow(ip):
                node.penalize(ip, None, 2, "Trop de requêtes")
                return self.respond({"error": "Trop de requêtes"}, 429)
            body = b""
            if method == "POST":
                require(not self.headers.get("Transfer-Encoding"), "Encodage non accepté")
                size = int(self.headers.get("Content-Length", "0"))
                limit = ROUTE_BODY_LIMITS.get(urlsplit(self.path).path, 2_000)   # unknown routes get a tiny budget
                require(0 < size <= min(limit, PEER_BODY_LIMIT), "Taille de requête invalide")
                body = self.rfile.read(size)
            try:
                sender, listen = verify_request(self.headers, method, self.path, body,
                                                node.node_id, node.nonces)
            except Invalid as exc:
                node.penalize(ip, None, 10, "Requête non authentifiée")
                return self.respond({"error": str(exc)}, 401)
            if node.is_banned(ip, sender):
                return self.respond({"error": "Pair banni temporairement"}, 403)
            if node.closed:
                with node.lock:
                    known = sender in node.peers.values()
                if not known:
                    return self.respond({"error": "Nœud fermé : identité inconnue"}, 403)
            if not node.id_limiter.allow(sender):
                node.penalize(ip, sender, 2, "Trop de requêtes")
                return self.respond({"error": "Trop de requêtes"}, 429)
            if listen:
                node.learn_announced(ip, listen, sender)
            path = urlsplit(self.path)
            with node.lock:
                require(not node.isolated, "Nœud isolé : échanges suspendus")
            return self.route(method, path, body, ip, sender)
        except (Invalid, ValueError, TypeError, KeyError, RecursionError) as exc:
            self.respond({"error": str(exc)}, 400)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass

    def route(self, method, path, body, ip, sender):
        node = self.node
        if method == "GET" and path.path == "/p2p/status":
            return self.respond(node.status())
        if method == "GET" and path.path in ("/p2p/hashes", "/p2p/blocks"):
            query = parse_qs(path.query)
            start = int(query.get("from", ["0"])[0])
            limit = int(query.get("limit", [str(SYNC_BATCH)])[0])
            integer(start, 0, MAX_CHAIN_BLOCKS, "Début")
            integer(limit, 1, SYNC_BATCH, "Limite")
            with node.lock:
                if path.path == "/p2p/hashes":
                    return self.respond({"hashes": node.ids[start:start + limit]})
                answer = {"blocks": copy.deepcopy(node.chain[start:start + limit])}
            require(len(canonical(answer)) <= MAX_HTTP_BYTES, "Lot trop volumineux")
            if not node.bandwidth_limiter.allow(sender, cost=len(canonical(answer))):
                node.penalize(ip, sender, 1, "Débit de téléchargement excessif")
                return self.respond({"error": "Débit de téléchargement dépassé : réessayer plus tard"}, 429)
            return self.respond(answer)
        if method == "GET" and path.path == "/p2p/mempool":
            with node.lock:
                return self.respond({"transactions": list(node.pending.values())})
        if method == "GET" and path.path == "/p2p/peers":
            with node.lock:
                return self.respond({"peers": [f"{url}#{peer_id}" for url, peer_id in sorted(node.peers.items())
                                               if peer_id and not node.closed]})
        if method == "POST" and path.path in ("/p2p/transactions", "/p2p/blocks"):
            payload = decode_json(body)
            require(isinstance(payload, dict), "Objet JSON attendu")
            try:
                with node.lock:
                    if path.path == "/p2p/transactions":
                        return self.respond({"txid": node.submit(payload)}, 201)
                    node.accept_block(payload)
                    return self.respond({"hash": block_id(payload)}, 201)
            except Invalid:
                node.penalize(ip, sender, 3 if path.path.endswith("transactions") else 15,
                              "Objet invalide transmis")
                raise
        return self.respond({"error": "Page inconnue"}, 404)
