from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from novacoin.p2p import peer_request


def identity():
    key = Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return key, raw.hex()


def call(url, path, payload=None, who=None, expected=None, listen=None):
    """Signed peer request from an arbitrary (by default fresh) identity; returns the JSON."""
    key, node_id = who or identity()
    return peer_request(url, path, key, node_id, expected, payload, listen)[0]
