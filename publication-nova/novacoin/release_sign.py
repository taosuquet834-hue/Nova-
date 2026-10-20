"""Sign and verify release archives with an Ed25519 release key (kept offline by the maintainer)."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .core import Invalid, require

PREFIX = b"NOVA-RELEASE-V1\0"


def generate_release_key(path, password):
    require(password and len(password) >= 12, "Mot de passe de la clé de publication : 12 caractères au moins")
    key = Ed25519PrivateKey.generate()
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.BestAvailableEncryption(password.encode())))
    return public_hex(key)


def public_hex(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def file_digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def sign_file(key_path, password, file_path, signature_path=None):
    try:
        key = serialization.load_pem_private_key(Path(key_path).read_bytes(), password.encode())
    except (ValueError, TypeError) as exc:
        raise Invalid("Clé de publication illisible ou mot de passe incorrect") from exc
    require(isinstance(key, Ed25519PrivateKey), "Clé de publication invalide")
    digest = file_digest(file_path)
    name = Path(file_path).name
    signature = key.sign(PREFIX + canonical_statement(name, digest)).hex()
    out = Path(signature_path or str(file_path) + ".sig")
    out.write_text(json.dumps({"file": name, "sha256": digest, "signature": signature,
                               "public_key": public_hex(key)}, indent=2) + "\n")
    return out


def canonical_statement(name, digest):
    return json.dumps({"file": name, "sha256": digest}, sort_keys=True, separators=(",", ":")).encode()


def verify_file(file_path, signature_path, trusted_public_key):
    """Raise Invalid unless the file matches a signature made by the *trusted* key (not the one in the file)."""
    try:
        blob = json.loads(Path(signature_path).read_text())
        name, digest, signature = blob["file"], blob["sha256"], bytes.fromhex(blob["signature"])
        public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(trusted_public_key))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise Invalid("Signature ou clé publique illisible") from exc
    require(name == Path(file_path).name, "La signature concerne un autre fichier")
    require(file_digest(file_path) == digest, "Le fichier a été modifié : empreinte différente")
    try:
        public.verify(signature, PREFIX + canonical_statement(name, digest))
    except InvalidSignature as exc:
        raise Invalid("Signature invalide pour la clé de publication de confiance") from exc
    return digest
