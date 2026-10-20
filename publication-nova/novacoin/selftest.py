"""Known-answer tests run at every start: a broken or tampered crypto library must stop the node."""
from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .core import Invalid

# RFC 8032, section 7.1, test 1 (empty message) and NIST SHA-256("abc")
ED_SECRET = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
ED_PUBLIC = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
ED_SIGNATURE = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                             "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
SHA256_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def run_selftest():
    if hashlib.sha256(b"abc").hexdigest() != SHA256_ABC:
        raise Invalid("Auto-test : SHA-256 incorrect, environnement cryptographique défaillant")
    key = Ed25519PrivateKey.from_private_bytes(ED_SECRET)
    raw = key.public_key().public_bytes_raw()
    if raw != ED_PUBLIC or key.sign(b"") != ED_SIGNATURE:
        raise Invalid("Auto-test : Ed25519 incorrect, environnement cryptographique défaillant")
    try:
        Ed25519PublicKey.from_public_bytes(ED_PUBLIC).verify(ED_SIGNATURE, b"")
        Ed25519PublicKey.from_public_bytes(ED_PUBLIC).verify(ED_SIGNATURE, b"x")
    except Exception:
        pass
    else:
        raise Invalid("Auto-test : une fausse signature a été acceptée")
    box = AESGCM(b"\x01" * 32)
    if box.decrypt(b"\x02" * 12, box.encrypt(b"\x02" * 12, b"nova", b"aad"), b"aad") != b"nova":
        raise Invalid("Auto-test : AES-GCM incorrect")
