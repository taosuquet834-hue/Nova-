"""Encrypted local wallets, selection of confirmed coins, offline signing."""
from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .core import (multisig_address, DUST, NETWORK, MAX_INPUTS, MAX_MONEY, Invalid, address_from_public,
                   integer, require, signing_bytes, valid_address)


def public_hex(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def address(key):
    return address_from_public(public_hex(key))


def create_wallet(path, password):
    require(isinstance(password, str) and len(password) >= 10,
            "Choisir un mot de passe d'au moins 10 caractères")
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    data = key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.BestAvailableEncryption(password.encode()))
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
    return key


def load_wallet(path, password):
    try:
        key = serialization.load_pem_private_key(Path(path).read_bytes(),
                                                password=password.encode())
    except (ValueError, TypeError) as exc:
        raise Invalid("Mot de passe ou portefeuille incorrect") from exc
    require(isinstance(key, Ed25519PrivateKey), "Type de clé incorrect")
    return key


def build_transaction(key, coins, recipient, amount, fee, change_address=None, locktime=None):
    require(valid_address(recipient), "Adresse du destinataire invalide")
    integer(amount, 1, MAX_MONEY, "Montant")
    integer(fee, 0, MAX_MONEY, "Frais")
    require(amount + fee <= MAX_MONEY, "Montant trop élevé")
    owner = address(key)
    selected, total = [], 0
    for coin in sorted(coins, key=lambda c: (c["amount"], c["txid"], c["index"])):
        if coin["address"] != owner or not coin["spendable"]:
            continue
        selected.append({"txid": coin["txid"], "index": coin["index"]})
        total += coin["amount"]
        if total >= amount + fee or len(selected) >= MAX_INPUTS:
            break
    require(total >= amount + fee, "Solde disponible insuffisant (ou trop de petites pièces)")
    outputs = [{"address": recipient, "amount": amount}]
    if total - amount - fee >= DUST:   # smaller leftovers would be dust: they go to the fee
        change_address = change_address or owner
        require(valid_address(change_address), "Adresse de monnaie invalide")
        outputs.append({"address": change_address, "amount": total - amount - fee})
    if locktime is None:
        tx = {"version": 1, "network": NETWORK, "inputs": selected, "outputs": outputs,
              "public_key": public_hex(key), "signature": ""}
    else:      # version 2: the payment cannot be included in a block before height `locktime`
        integer(locktime, 0, 2 ** 31 - 1, "Verrouillage")
        tx = {"version": 2, "network": NETWORK, "inputs": selected, "outputs": outputs, "locktime": locktime,
              "public_key": public_hex(key), "signature": ""}
    tx["signature"] = key.sign(signing_bytes(tx)).hex()
    return tx


# ---------------------------------------------------------------- m-of-n multisignature

def multisig_policy(threshold, public_keys):
    keys = sorted(set(public_keys))
    return {"threshold": threshold, "keys": keys, "address": multisig_address(threshold, keys)}


def draft_multisig_transaction(policy, coins, recipient, amount, fee, change_address=None, locktime=0):
    """Unsigned payment from a multisig address; each signer then calls add_multisig_signature."""
    require(valid_address(recipient), "Adresse du destinataire invalide")
    integer(amount, 1, MAX_MONEY, "Montant")
    integer(fee, 0, MAX_MONEY, "Frais")
    integer(locktime, 0, 2 ** 31 - 1, "Verrouillage")
    owner = multisig_address(policy["threshold"], policy["keys"])
    selected, total = [], 0
    for coin in sorted(coins, key=lambda c: (c["amount"], c["txid"], c["index"])):
        if coin["address"] != owner or not coin["spendable"]:
            continue
        selected.append({"txid": coin["txid"], "index": coin["index"]})
        total += coin["amount"]
        if total >= amount + fee or len(selected) >= MAX_INPUTS:
            break
    require(total >= amount + fee, "Solde disponible insuffisant (ou trop de petites pièces)")
    outputs = [{"address": recipient, "amount": amount}]
    if total - amount - fee >= DUST:
        outputs.append({"address": change_address or owner, "amount": total - amount - fee})
    return {"version": 2, "network": NETWORK, "inputs": selected, "outputs": outputs, "locktime": locktime,
            "multisig": {"threshold": policy["threshold"], "keys": list(policy["keys"]), "signatures": []}}


def add_multisig_signature(tx, key):
    """Add this signer's signature (idempotent). Returns the payment; check multisig_ready()."""
    mine = public_hex(key)
    policy = tx["multisig"]
    require(mine in policy["keys"], "Cette clé ne fait pas partie de la politique multisignature")
    if not any(item["key"] == mine for item in policy["signatures"]):
        policy["signatures"].append({"key": mine, "signature": key.sign(signing_bytes(tx)).hex()})
        policy["signatures"].sort(key=lambda item: item["key"])
    return tx


def multisig_ready(tx):
    return len(tx["multisig"]["signatures"]) >= tx["multisig"]["threshold"]
