"""Peer transport (V4): TLS 1.3 with pinned node identities, signed requests, abuse limits.

Every node owns an Ed25519 identity key. Its public key *is* the node id, and it is also the
key of the node's self-signed TLS certificate. A peer is therefore authenticated twice:
the TLS handshake proves who answers (the certificate key must match the pinned id), and each
request carries a signature that proves who asks and binds the request to one recipient.
"""
from __future__ import annotations

import datetime
import hashlib
import http.client
import ipaddress
import os
import secrets
import socket
import ssl
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.x509.oid import NameOID

from .core import EASY, NETWORK, Invalid, canonical, hex_string, require

# Identity cost (anti-Sybil): a node id is only accepted from a peer that found a nonce such that
# SHA-256("NOVA-ID" || network || id || nonce) starts with IDENTITY_BITS zero bits. One honest node
# pays a few seconds once; a thousand fake identities cost a thousand times that.
IDENTITY_BITS = 6 if EASY else 22
_NONCES = {}
MAX_HTTP_BYTES = 8_000_000
CLOCK_SKEW = 60            # seconds of tolerated clock difference for signed requests
NONCE_MEMORY = 20_000
PREFIX = b"NOVA-P2P-V4\0"


# ---------------------------------------------------------------- identity and TLS

def _raw_public(public_key):
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _encryption(password):
    return (serialization.BestAvailableEncryption(password.encode()) if password
            else serialization.NoEncryption())


def key_is_encrypted(data_dir):
    path = Path(data_dir) / "node.key"
    return path.exists() and b"ENCRYPTED" in path.read_bytes()[:64]


def load_identity(data_dir, password=None):
    """Return (private key, node id hex), creating key and certificate on first start.
    With a password the key file is stored encrypted (scrypt-based PKCS8)."""
    data_dir = Path(data_dir)
    key_path, cert_path = data_dir / "node.key", data_dir / "node.crt"
    try:
        fd = os.open(key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        encrypted = key_is_encrypted(data_dir)
        require(not encrypted or password, "La clé du nœud est chiffrée : fournir NOVA_NODE_PASSWORD "
                                           "(ou NOVA_NODE_PASSWORD_FILE)")
        try:
            key = serialization.load_pem_private_key(key_path.read_bytes(),
                                                     password.encode() if encrypted else None)
        except (ValueError, TypeError) as exc:
            raise Invalid("Mot de passe de la clé du nœud incorrect" if encrypted
                          else "Clé d'identité du nœud illisible") from exc
        require(isinstance(key, Ed25519PrivateKey), "Clé d'identité du nœud invalide")
    else:
        key = Ed25519PrivateKey.generate()
        with os.fdopen(fd, "wb") as stream:
            stream.write(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8, _encryption(password)))
    node_id = _raw_public(key.public_key()).hex()
    if not cert_path.exists() or certificate_id(
            x509.load_pem_x509_certificate(cert_path.read_bytes()).public_bytes(serialization.Encoding.DER)) != node_id:
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "nova-node")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=3650)).sign(key, None))
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key, node_id


def certificate_id(der):
    """Node id carried by a TLS certificate: its raw Ed25519 public key."""
    try:
        public = x509.load_der_x509_certificate(der).public_key()
        require(isinstance(public, Ed25519PublicKey), "Certificat de pair non Ed25519")
        return _raw_public(public).hex()
    except ValueError as exc:
        raise Invalid("Certificat de pair illisible") from exc


def server_context(data_dir, password=None):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(Path(data_dir) / "node.crt", Path(data_dir) / "node.key", password=password)
    return context


def protect_key(data_dir, new_password=None, old_password=None):
    """Encrypt (new_password set) or decrypt (new_password None) the node key, atomically."""
    data_dir = Path(data_dir)
    key, _ = load_identity(data_dir, old_password)
    path = data_dir / "node.key"
    temporary = path.with_name("node.key.tmp")
    fd = os.open(temporary, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       _encryption(new_password)))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def client_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = False      # identity is checked by pinning, not by host name
    context.verify_mode = ssl.CERT_NONE
    return context


# ---------------------------------------------------------------- peer addresses

def parse_peer(spec):
    """'https://host:port' or 'https://host:port#<64 hex node id>' -> (url, id or None)."""
    require(isinstance(spec, str) and len(spec) <= 300, "Adresse de pair invalide")
    try:
        parts = urlsplit(spec)
        require(parts.scheme == "https" and parts.hostname and parts.port,
                "Utiliser https://adresse:port (ou https://adresse:port#identifiant)")
        require(parts.username is None and parts.password is None
                and parts.path in ("", "/") and not parts.query, "Adresse de pair invalide")
        require(1 <= parts.port <= 65535, "Port invalide")
    except Invalid:
        raise
    except ValueError as exc:
        raise Invalid("Adresse de pair invalide") from exc
    peer_id = parts.fragment or None
    if peer_id is not None:
        hex_string(peer_id, 64)
    host = parts.hostname
    host = f"[{host}]" if ":" in host else host
    return f"https://{host}:{parts.port}", peer_id


def private_address(host):
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.version == 4 and (ip.is_loopback or ip.is_private)


# ---------------------------------------------------------------- signed requests

def signing_payload(method, target, body, when, nonce, sender, recipient, listen):
    return PREFIX + canonical({"network": NETWORK, "method": method, "target": target,
                               "body": hashlib.sha256(body).hexdigest(), "time": when,
                               "nonce": nonce, "from": sender, "to": recipient,
                               "listen": listen})


def identity_digest(node_id, nonce):
    return hashlib.sha256(b"NOVA-ID\0" + NETWORK.encode() + b"\0" + bytes.fromhex(node_id)
                          + nonce.to_bytes(8, "big")).digest()


def identity_ok(node_id, nonce, bits=None):
    bits = IDENTITY_BITS if bits is None else bits
    return type(nonce) is int and 0 <= nonce < 2 ** 64 and \
        int.from_bytes(identity_digest(node_id, nonce), "big") >> (256 - bits) == 0


def find_identity_nonce(node_id, bits=None):
    bits = IDENTITY_BITS if bits is None else bits
    cached = _NONCES.get((node_id, bits))
    if cached is not None:
        return cached
    nonce = 0
    while not identity_ok(node_id, nonce, bits):
        nonce += 1
    _NONCES[(node_id, bits)] = nonce
    return nonce


def sign_request(key, sender, recipient, method, target, body, listen, work=None):
    work = find_identity_nonce(sender) if work is None else work
    when, nonce = int(time.time()), secrets.token_hex(12)
    signature = key.sign(signing_payload(method, target, body, when, nonce, sender, recipient, listen))
    headers = {"X-Nova-Id": sender, "X-Nova-Time": str(when), "X-Nova-Nonce": nonce,
               "X-Nova-Sig": signature.hex(), "X-Nova-Work": str(work)}
    if listen:
        headers["X-Nova-Listen"] = str(listen)
    return headers


class NonceMemory:
    """Remember recent nonces so that a captured request cannot be replayed."""

    def __init__(self):
        self.seen, self.lock = {}, threading.Lock()

    def check(self, sender, nonce, now):
        with self.lock:
            if len(self.seen) >= NONCE_MEMORY:
                self.seen = {k: v for k, v in self.seen.items() if v > now}
                require(len(self.seen) < NONCE_MEMORY, "Trop de requêtes récentes")
            key = (sender, nonce)
            require(key not in self.seen, "Requête rejouée")
            self.seen[key] = now + 2 * CLOCK_SKEW


def verify_request(headers, method, target, body, own_id, nonces, now=None):
    """Return (sender id, announced listen port or None); raise Invalid when anything is off."""
    now = int(time.time()) if now is None else now
    sender, nonce = headers.get("X-Nova-Id", ""), headers.get("X-Nova-Nonce", "")
    require(bool(sender and headers.get("X-Nova-Sig")), "Requête non signée")
    hex_string(sender, 64)
    require(len(nonce) == 24 and all(c in "0123456789abcdef" for c in nonce), "Nonce invalide")
    try:
        when = int(headers.get("X-Nova-Time", ""))
        listen = int(headers["X-Nova-Listen"]) if headers.get("X-Nova-Listen") else None
    except ValueError as exc:
        raise Invalid("En-tête invalide") from exc
    try:
        work = int(headers.get("X-Nova-Work", ""))
    except ValueError as exc:
        raise Invalid("Preuve d'identité absente ou illisible") from exc
    require(identity_ok(sender, work), "Identité sans preuve de travail suffisante")
    require(abs(when - now) <= CLOCK_SKEW, "Horloge du pair trop éloignée")
    require(listen is None or 1024 <= listen <= 65535, "Port annoncé invalide")
    signature = headers.get("X-Nova-Sig", "")
    hex_string(signature, 128)
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(sender)).verify(
            bytes.fromhex(signature),
            signing_payload(method, target, body, when, nonce, sender, own_id, listen))
    except (InvalidSignature, ValueError) as exc:
        raise Invalid("Signature de pair invalide") from exc
    nonces.check(sender, nonce, now)
    return sender, listen


# ---------------------------------------------------------------- abuse control

class RateLimiter:
    """Token bucket per key (ip or node id)."""

    def __init__(self, capacity=80, per_second=25):
        self.capacity, self.rate = capacity, per_second
        self.buckets, self.lock = {}, threading.Lock()

    def allow(self, key, now=None, cost=1):
        now = time.monotonic() if now is None else now
        with self.lock:
            tokens, last = self.buckets.get(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - last) * self.rate)
            if len(self.buckets) > 5000:
                self.buckets = {k: v for k, v in self.buckets.items() if v[0] < self.capacity}
            if tokens < min(cost, self.capacity):
                self.buckets[key] = (tokens, now)
                return False
            self.buckets[key] = (tokens - min(cost, self.capacity), now)
            return True


class Reputation:
    """Misbehaviour score with decay; crossing the threshold bans the key for a while."""

    def __init__(self, threshold=100, ban_seconds=900, half_life=60):
        self.threshold, self.ban_seconds, self.half_life = threshold, ban_seconds, half_life
        self.scores, self.bans, self.lock = {}, {}, threading.Lock()

    def banned(self, key, now=None):
        now = time.time() if now is None else now
        with self.lock:
            until = self.bans.get(key)
            if until and until > now:
                return True
            self.bans.pop(key, None)
            return False

    def penalize(self, key, points, now=None):
        """Add points; return True when this call banned the key."""
        now = time.time() if now is None else now
        with self.lock:
            score, last = self.scores.get(key, (0.0, now))
            score = score * 0.5 ** ((now - last) / self.half_life) + points
            self.scores[key] = (score, now)
            if len(self.scores) > 2000:
                self.scores = {k: v for k, v in self.scores.items() if v[0] >= 1}
            if score >= self.threshold and key not in self.bans:
                self.bans[key] = now + self.ban_seconds
                self.scores.pop(key, None)
                return True
            return False

    def export(self, now=None):
        now = time.time() if now is None else now
        with self.lock:
            return [(k[0], k[1], int(until)) for k, until in self.bans.items() if until > now]

    def restore(self, rows, now=None):
        now = time.time() if now is None else now
        with self.lock:
            for kind, key, until in rows:
                if until > now:
                    self.bans[(kind, key)] = until

    def snapshot(self, now=None):
        now = time.time() if now is None else now
        with self.lock:
            return [{"kind": k[0], "key": k[1], "seconds_left": int(until - now)}
                    for k, until in self.bans.items() if until > now]


# ---------------------------------------------------------------- client side

def peer_request(url, path, key, own_id, expected_id=None, payload=None, listen=None, timeout=4, work=None):
    """Signed request over pinned TLS. Returns (decoded JSON, remote node id)."""
    from .node import decode_json  # local import: node imports this module
    parts = urlsplit(url)
    try:
        raw = socket.create_connection((parts.hostname, parts.port), timeout=timeout)
        sock = client_context().wrap_socket(raw)
    except (OSError, ssl.SSLError) as exc:
        raise Invalid(f"Nœud injoignable : {parts.netloc}") from exc
    try:
        remote_id = certificate_id(sock.getpeercert(True))
        require(expected_id is None or remote_id == expected_id,
                "Identité du pair différente de celle attendue : connexion refusée")
        body = canonical(payload) if payload is not None else b""
        method = "POST" if payload is not None else "GET"
        headers = {"Accept": "application/json", "Connection": "close",
                   **sign_request(key, own_id, remote_id, method, path, body, listen, work)}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        connection = http.client.HTTPSConnection(parts.hostname, parts.port, timeout=timeout)
        connection.sock = sock
        try:
            connection.request(method, path, body=body or None, headers=headers)
            response = connection.getresponse()
            data = response.read(MAX_HTTP_BYTES + 1)
        finally:
            connection.close()
        require(len(data) <= MAX_HTTP_BYTES, "Réponse réseau trop volumineuse")
        if response.status >= 400:
            try:
                message = decode_json(data).get("error", f"Erreur {response.status}")
            except (Invalid, AttributeError):
                message = f"Erreur {response.status}"
            raise Invalid(message)
        return decode_json(data), remote_id
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        raise Invalid(f"Nœud injoignable : {parts.netloc}") from exc
    finally:
        sock.close()
