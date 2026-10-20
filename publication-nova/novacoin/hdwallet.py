"""Recoverable wallet (V5): 12-word phrase, one fresh address per receipt, contacts.

The phrase encodes 128 bits of entropy plus a 4-bit checksum. It is *not* BIP39: the word list
is Nova's own (2048 four-letter words), so phrases are not interchangeable with other wallets.
Keys are derived from the phrase with PBKDF2-HMAC-SHA512 then HMAC-SHA512 per index, and every
payment signs with a single key (a consensus rule), so a payment from several addresses is sent
as several transactions.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .core import EASY, MAX_INPUTS, Invalid, require, valid_address
from .wallet import address as key_address, build_transaction

GAP_LIMIT = 20
WORDS = 12
_FIRST = [c + v for c in "bdfghjklmnprstvz" for v in "aeio"]      # 64 syllables
_SECOND = [c + v for c in "bdklmnst" for v in "aeio"]             # 32 syllables
WORDLIST = [a + b for a in _FIRST for b in _SECOND]                # 2048 words
_INDEX = {word: i for i, word in enumerate(WORDLIST)}
PBKDF2_ROUNDS = 1_000 if EASY else 200_000
SCRYPT_N = 2 ** 8 if EASY else 2 ** 15


# ---------------------------------------------------------------- phrase

def entropy_to_phrase(entropy):
    require(len(entropy) == 16, "Entropie invalide")
    bits = int.from_bytes(entropy, "big") << 4 | hashlib.sha256(entropy).digest()[0] >> 4
    return " ".join(WORDLIST[(bits >> (11 * (WORDS - 1 - i))) & 2047] for i in range(WORDS))


def new_phrase():
    return entropy_to_phrase(secrets.token_bytes(16))


def phrase_to_entropy(phrase):
    words = phrase.lower().split() if isinstance(phrase, str) else []
    require(len(words) == WORDS, f"La phrase doit contenir {WORDS} mots")
    bits = 0
    for position, word in enumerate(words, 1):
        require(word in _INDEX, f"Mot inconnu en position {position}")
        bits = bits << 11 | _INDEX[word]
    entropy = (bits >> 4).to_bytes(16, "big")
    require(hashlib.sha256(entropy).digest()[0] >> 4 == bits & 15,
            "Phrase incorrecte : la somme de contrôle ne correspond pas (mot erroné ou mal placé)")
    return entropy


def seed_from_phrase(phrase, passphrase=""):
    phrase_to_entropy(phrase)
    return hashlib.pbkdf2_hmac("sha512", " ".join(phrase.lower().split()).encode(),
                               b"nova-wallet-v5" + passphrase.encode(), PBKDF2_ROUNDS)


def derive_key(seed, index):
    require(isinstance(index, int) and 0 <= index < 2 ** 31, "Index invalide")
    return Ed25519PrivateKey.from_private_bytes(
        hmac.new(seed, b"nova/key/" + str(index).encode(), hashlib.sha512).digest()[:32])


# ---------------------------------------------------------------- wallet file

class HDWallet:
    """Encrypted wallet file (scrypt + AES-GCM) holding the seed, the next index and contacts."""

    def __init__(self, path, password, seed, state, salt, lock_after=None):
        self.path, self.seed, self.state, self._salt = Path(path), seed, state, salt
        self.lock_after, self._last_use = lock_after, time.monotonic()
        self._box = AESGCM(Scrypt(salt=salt, length=32, n=SCRYPT_N, r=8, p=1).derive(password.encode()))

    # -- creation / loading
    @classmethod
    def create(cls, path, password, phrase=None, passphrase=""):
        """New wallet; returns (wallet, phrase). The phrase is shown once and never stored."""
        require(isinstance(password, str) and len(password) >= 10,
                "Choisir un mot de passe d'au moins 10 caractères")
        path = Path(path)
        require(not path.exists(), "Ce fichier de portefeuille existe déjà")
        phrase = phrase or new_phrase()
        wallet = cls(path, password, seed_from_phrase(phrase, passphrase),
                     {"next_index": 0, "contacts": {}}, secrets.token_bytes(16))
        wallet.save(first=True)
        return wallet, " ".join(phrase.lower().split())

    @classmethod
    def load(cls, path, password):
        try:
            blob = json.loads(Path(path).read_text())
            salt = bytes.fromhex(blob["salt"])
            wallet = cls(path, password, b"", {}, salt)
            plain = wallet._box.decrypt(bytes.fromhex(blob["nonce"]), bytes.fromhex(blob["data"]), b"nova-hd-v5")
            data = json.loads(plain)
            wallet.seed = bytes.fromhex(data["seed"])
            wallet.state = {"next_index": int(data["next_index"]), "contacts": dict(data["contacts"])}
        except (OSError, ValueError, KeyError, TypeError, InvalidTag) as exc:
            raise Invalid("Mot de passe ou portefeuille incorrect") from exc
        return wallet

    def save(self, first=False):
        nonce = secrets.token_bytes(12)
        plain = json.dumps({"seed": self.seed.hex(), **self.state}).encode()
        blob = {"version": 1, "salt": self._salt.hex(), "nonce": nonce.hex(),
                "data": self._box.encrypt(nonce, plain, b"nova-hd-v5").hex()}
        if first:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "w") as stream:
                json.dump(blob, stream)
            return
        temporary = self.path.with_name(self.path.name + ".tmp")
        fd = os.open(temporary, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(blob, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, self.path)

    # -- addresses
    def key(self, index):
        require(self.seed, "Portefeuille verrouillé : le déverrouiller avec son mot de passe")
        if self.lock_after is not None and time.monotonic() - self._last_use > self.lock_after:
            self.lock()
            raise Invalid("Portefeuille verrouillé après une période d'inactivité")
        self._last_use = time.monotonic()
        return derive_key(self.seed, index)

    # -- locking: the seed is dropped from memory until the password is given again
    def lock(self):
        self.seed = b""

    def unlock(self, password):
        fresh = HDWallet.load(self.path, password)
        self.seed, self._last_use = fresh.seed, time.monotonic()

    # -- backup: an independent encrypted copy, checked by restoring it
    def backup(self, path, backup_password):
        require(self.seed, "Portefeuille verrouillé")
        require(backup_password and len(backup_password) >= 10, "Mot de passe de sauvegarde : 10 caractères au moins")
        copy = HDWallet(path, backup_password, self.seed, json.loads(json.dumps(self.state)), secrets.token_bytes(16))
        copy.save(first=True)
        verified = HDWallet.load(path, backup_password)             # a backup nobody has opened is not a backup
        require(verified.seed == self.seed and verified.state == self.state, "La sauvegarde ne correspond pas")
        return verified.addresses()

    def address(self, index):
        return key_address(self.key(index))

    def new_address(self):
        """A never-used receiving address; the index is saved before it is shown."""
        index = self.state["next_index"]
        self.state["next_index"] = index + 1
        self.save()
        return self.address(index)

    def addresses(self):
        return [self.address(i) for i in range(self.state["next_index"])]

    # -- contacts
    def add_contact(self, name, address):
        require(isinstance(name, str) and 1 <= len(name) <= 40 and name.strip() == name, "Nom invalide")
        require(valid_address(address), "Adresse invalide")
        self.state["contacts"][name] = address
        self.save()

    def resolve(self, name_or_address):
        return self.state["contacts"].get(name_or_address, name_or_address)

    # -- chain interaction (fetch(address) -> node balance dict, with "used" and "utxos")
    def scan(self, fetch):
        """Find used addresses with a gap limit; raises next_index to cover them. Returns balances."""
        found, index, quiet = {}, 0, 0
        while quiet < GAP_LIMIT or index < self.state["next_index"]:
            info = fetch(self.address(index))
            if info["used"] or info["confirmed"]:
                quiet = 0
                found[index] = info
            else:
                quiet += 1
            index += 1
            require(index < 5_000, "Analyse interrompue : trop d'adresses")
        used_end = max(found, default=-1) + 1
        if used_end > self.state["next_index"]:
            self.state["next_index"] = used_end
            self.save()
        return found

    def balance(self, fetch):
        found = self.scan(fetch)
        return {"confirmed": sum(i["confirmed"] for i in found.values()),
                "available": sum(i["available"] for i in found.values()),
                "addresses": {self.address(i): info["available"] for i, info in found.items()}}

    def send(self, fetch, submit, recipient, amount, fee, locktime=None):
        """Pay `amount`, split over as many transactions as needed (one signing key each).
        Change goes to a fresh address. Returns the list of transaction ids."""
        recipient = self.resolve(recipient)
        require(valid_address(recipient), "Destinataire inconnu (ni adresse ni contact)")
        found = self.scan(fetch)
        plan, remaining = [], amount
        for index, info in sorted(found.items(), key=lambda kv: -kv[1]["available"]):
            usable = sum(c["amount"] for c in info["utxos"] if c["spendable"])
            part = min(remaining, usable - fee)
            if part > 0:
                plan.append((index, info, part))
                remaining -= part
            if remaining == 0:
                break
        require(remaining == 0, "Solde disponible insuffisant")
        require(len(plan) <= 10, "Paiement trop fragmenté : regrouper d'abord les petites sommes")
        txs = []
        for index, info, part in plan:
            change = self.new_address()
            txs.append(build_transaction(self.key(index), info["utxos"], recipient, part, fee, change, locktime))
        return [submit(tx) for tx in txs]
