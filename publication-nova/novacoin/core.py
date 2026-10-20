"""Deterministic consensus rules. All amounts are integer smallest units."""
from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import time
from decimal import Decimal, DecimalException

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# Laboratory switch: NOVA_EASY=1 selects a separate, trivially easy network for automated tests.
EASY = os.environ.get("NOVA_EASY") == "1"
NETWORK = "nova-testnet-3-easy" if EASY else "nova-testnet-3"
BLOCK_VERSION = 2          # consensus version of blocks
ACCEPTED_BLOCK_VERSIONS = (2,)
TX_VERSION = 1              # single-key payment without extra fields
TX_VERSION_2 = 2            # adds `locktime` and optional m-of-n multisignature
MAX_MULTISIG_KEYS = 5
UNIT = 100_000_000
MAX_MONEY = 21_000_000 * UNIT
INITIAL_REWARD = 50 * UNIT
HALVING_INTERVAL = 210_000
COINBASE_MATURITY = 2
# Difficulty is a continuous 256-bit target: a block id (as a number) must be strictly below it.
# "Bits" below only describe the target in the familiar unit (2**bits attempts on average).
INITIAL_BITS = 6 if EASY else 22      # about 60 s per block for one Python miner
EASIEST_BITS = 4 if EASY else 16      # lowest difficulty the chain can fall back to
HARDEST_BITS = 96                     # ceiling far beyond any local power
INITIAL_TARGET = 1 << (256 - INITIAL_BITS)
MAX_TARGET = 1 << (256 - EASIEST_BITS)
MIN_TARGET = 1 << (256 - HARDEST_BITS)
ADJUST_INTERVAL = 20
MAX_ADJUST_FACTOR = 4
# Relay policy (not consensus): what a node is willing to keep and relay.
MIN_FEE_PER_BYTE = 10      # smallest units per byte
DUST = 1_000               # smallest output a node relays (0.00001 NOVA)
DEFAULT_MAX_REORG = 50     # deepest chain reorganisation a node accepts by itself
TARGET_SECONDS = 60   # 10 s forks too often on a real network (see RAPPORT-SIMULATIONS.md)
MAX_FUTURE_SECONDS = 60
MAX_BLOCK_BYTES = 256_000
MAX_TX_BYTES = 16_000
MAX_BLOCK_TXS = 200
MAX_INPUTS = 64
MAX_OUTPUTS = 64
MAX_CHAIN_BLOCKS = 500_000  # Blocks live in SQLite; memory holds the tip window, ids and the UTXO set.
SYNC_BATCH = 100            # Blocks per incremental synchronization request.


class Invalid(ValueError):
    """Untrusted data violates protocol or local policy."""


def require(condition, message):
    if not condition:
        raise Invalid(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def exact_keys(obj, keys):
    require(isinstance(obj, dict) and set(obj) == set(keys), "Champs invalides")


def integer(value, low, high, label="Nombre"):
    require(type(value) is int and low <= value <= high, f"{label} invalide")


def hex_string(value, length):
    require(isinstance(value, str) and len(value) == length
            and all(c in "0123456789abcdef" for c in value), "Encodage hexadécimal invalide")


def address_from_public(public_hex):
    hex_string(public_hex, 64)
    body = hashlib.sha256(bytes.fromhex(public_hex)).hexdigest()[:40]
    checksum = hashlib.sha256((NETWORK + body).encode()).hexdigest()[:8]
    return "nv1" + body + checksum


def multisig_address(threshold, public_keys):
    """Address of an m-of-n policy: `nm1` + hash of (m, sorted distinct keys) + network checksum."""
    require(type(threshold) is int and isinstance(public_keys, list)
            and 1 <= threshold <= len(public_keys) <= MAX_MULTISIG_KEYS, "Politique multisignature invalide")
    for key in public_keys:
        hex_string(key, 64)
    require(public_keys == sorted(set(public_keys)), "Clés multisignature : triées et sans doublon")
    body = hashlib.sha256(canonical({"m": threshold, "keys": public_keys})).hexdigest()[:40]
    return "nm1" + body + hashlib.sha256((NETWORK + body).encode()).hexdigest()[:8]


def valid_address(address):
    if not isinstance(address, str) or len(address) != 51 or address[:3] not in ("nv1", "nm1"):
        return False
    body = address[3:43]
    return (all(c in "0123456789abcdef" for c in body)
            and address[43:] == hashlib.sha256((NETWORK + body).encode()).hexdigest()[:8])


def parse_amount(text, allow_zero=False):
    try:
        amount = Decimal(str(text)) * UNIT
        require(amount.is_finite() and amount == amount.to_integral_value(),
                "Le montant doit avoir au maximum 8 décimales")
        result = int(amount)
        integer(result, 0 if allow_zero else 1, MAX_MONEY, "Montant")
        return result
    except (DecimalException, ValueError, OverflowError) as exc:
        raise Invalid("Montant invalide (maximum 8 décimales)") from exc


def format_amount(amount):
    return f"{Decimal(amount) / UNIT:.8f}"


def transaction_id(tx):
    """Identifier of a payment: its hash *without* signatures, so nobody can change it by re-signing
    (malleability). Signatures are still checked and still part of the block's bytes."""
    if isinstance(tx, dict) and tx.get("type") != "coinbase":       # anything else is hashed as is and refused later
        tx = {k: v for k, v in tx.items() if k != "signature"}
        if isinstance(tx.get("multisig"), dict):
            tx["multisig"] = {k: v for k, v in tx["multisig"].items() if k != "signatures"}
    return digest(tx)


def signing_bytes(tx):
    if tx.get("version") == TX_VERSION_2:
        unsigned = {k: v for k, v in tx.items() if k != "signature"}
        if "multisig" in unsigned:                       # the policy is signed, the signatures are not
            unsigned["multisig"] = {k: v for k, v in unsigned["multisig"].items() if k != "signatures"}
        return b"NOVA-TX-V2\0" + canonical(unsigned)
    return b"NOVA-TX-V1\0" + canonical({k: v for k, v in tx.items() if k != "signature"})


def validate_outputs(outputs):
    require(isinstance(outputs, list) and 1 <= len(outputs) <= MAX_OUTPUTS,
            "Nombre de destinataires invalide")
    total = 0
    for output in outputs:
        exact_keys(output, ("address", "amount"))
        require(valid_address(output["address"]), "Adresse invalide")
        integer(output["amount"], 1, MAX_MONEY, "Montant")
        total += output["amount"]
    require(total <= MAX_MONEY, "Montant total trop élevé")
    return total


def tx_owner(tx):
    """Address that must own every coin this (already shape-checked) payment spends."""
    if "multisig" in tx:
        return multisig_address(tx["multisig"]["threshold"], tx["multisig"]["keys"])
    return address_from_public(tx["public_key"])


def validate_transaction_shape(tx):
    require(isinstance(tx, dict) and type(tx.get("version")) is int, "Transaction invalide")
    if tx["version"] == TX_VERSION:
        exact_keys(tx, ("version", "network", "inputs", "outputs", "public_key", "signature"))
    else:
        integer(tx["version"], TX_VERSION_2, TX_VERSION_2, "Version")
        require(isinstance(tx, dict) and ("multisig" in tx) != ("public_key" in tx), "Un seul type de signataire")
        exact_keys(tx, ("version", "network", "inputs", "outputs", "locktime") +
                   (("multisig",) if "multisig" in tx else ("public_key", "signature")))
        integer(tx["locktime"], 0, 2 ** 31 - 1, "Verrouillage")
    require(tx["network"] == NETWORK, "Mauvais réseau")
    require(len(canonical(tx)) <= MAX_TX_BYTES, "Transaction trop volumineuse")
    require(isinstance(tx["inputs"], list) and 1 <= len(tx["inputs"]) <= MAX_INPUTS,
            "Nombre d'entrées invalide")
    seen = set()
    for item in tx["inputs"]:
        exact_keys(item, ("txid", "index"))
        hex_string(item["txid"], 64)
        integer(item["index"], 0, MAX_OUTPUTS - 1, "Index")
        key = (item["txid"], item["index"])
        require(key not in seen, "Entrée utilisée deux fois")
        seen.add(key)
    validate_outputs(tx["outputs"])
    if "multisig" in tx:
        policy = tx["multisig"]
        exact_keys(policy, ("threshold", "keys", "signatures"))
        multisig_address(policy["threshold"], policy["keys"])          # validates m, n, ordering, hex
        require(isinstance(policy["signatures"], list) and policy["threshold"] <= len(policy["signatures"])
                <= len(policy["keys"]), "Signatures insuffisantes ou trop nombreuses")
        message, signers = signing_bytes(tx), set()
        for item in policy["signatures"]:
            exact_keys(item, ("key", "signature"))
            require(item["key"] in policy["keys"] and item["key"] not in signers, "Signataire inconnu ou en double")
            hex_string(item["signature"], 128)
            try:
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(item["key"])).verify(
                    bytes.fromhex(item["signature"]), message)
            except (InvalidSignature, ValueError) as exc:
                raise Invalid("Signature invalide") from exc
            signers.add(item["key"])
        return
    hex_string(tx["public_key"], 64)
    hex_string(tx["signature"], 128)
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(tx["public_key"])).verify(
            bytes.fromhex(tx["signature"]), signing_bytes(tx))
    except (InvalidSignature, ValueError) as exc:
        raise Invalid("Signature invalide") from exc


def apply_transaction(tx, utxos, height):
    """Validate fully before mutating the supplied UTXO map. `height` is the height of the block
    that would contain the payment."""
    validate_transaction_shape(tx)
    require(tx.get("locktime", 0) <= height, f"Paiement verrouillé jusqu'au bloc {tx.get('locktime')}")
    owner = tx_owner(tx)
    total_in = 0
    keys = []
    for item in tx["inputs"]:
        key = (item["txid"], item["index"])
        coin = utxos.get(key)
        require(coin is not None, "Pièce absente ou déjà dépensée")
        require(coin["address"] == owner, "Cette clé ne possède pas la pièce")
        require(not coin["coinbase"] or height - coin["height"] >= COINBASE_MATURITY,
                "Récompense de minage encore immature")
        total_in += coin["amount"]
        keys.append(key)
    total_out = sum(output["amount"] for output in tx["outputs"])
    require(total_in >= total_out, "Solde insuffisant")
    txid = transaction_id(tx)
    require(not any((txid, i) in utxos for i in range(len(tx["outputs"]))),
            "Transaction déjà présente")
    for key in keys:
        del utxos[key]
    add_outputs(tx, utxos, height, False)
    return total_in - total_out


def add_outputs(tx, utxos, height, coinbase):
    txid = transaction_id(tx)
    for i, output in enumerate(tx["outputs"]):
        utxos[(txid, i)] = {**output, "height": height, "coinbase": coinbase}


def subsidy(height):
    return INITIAL_REWARD >> ((height - 1) // HALVING_INTERVAL)


def coinbase(height, address, reward):
    return {"type": "coinbase", "network": NETWORK, "height": height,
            "outputs": [{"address": address, "amount": reward}] if reward else []}


def merkle_root(transactions):
    layer = [transaction_id(tx) for tx in transactions]
    if not layer:
        return hashlib.sha256(b"").hexdigest()
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        layer = [hashlib.sha256(bytes.fromhex(layer[i] + layer[i + 1])).hexdigest()
                 for i in range(0, len(layer), 2)]
    return layer[0]


def header(block):
    return {k: block[k] for k in ("version", "network", "height", "previous",
                                 "timestamp", "target", "nonce", "merkle_root")}


def block_id(block):
    return digest(header(block))


def genesis():
    return {"version": BLOCK_VERSION, "network": NETWORK, "height": 0, "previous": "0" * 64,
            "timestamp": 1_700_000_000, "target": INITIAL_TARGET, "nonce": 0,
            "merkle_root": merkle_root([]), "transactions": []}


def block_work(target):
    """Expected number of attempts needed to find a block below this target."""
    return (1 << 256) // (target + 1)


def difficulty_bits(target):
    """Human-readable difficulty: 20.0 means about 2**20 attempts per block."""
    return round(256 - math.log2(target), 2)


def median_index(i):
    """Index of the median block of the (up to) 11 mined blocks ending at index i.
    Timestamps are strictly increasing, so the median by time is the median by position."""
    low = max(1, i - 10)
    return low + (i - low + 1) // 2


def expected_target(chain):
    target = chain[-1]["target"]
    # Block 1 is the first measurement; genesis is not a mined time sample.
    if len(chain) > ADJUST_INTERVAL and (len(chain) - 1) % ADJUST_INTERVAL == 0:
        # Time is measured between two *median* blocks, so that the timestamp of any single
        # block, in particular the last one, cannot swing the next difficulty.
        start, end = median_index(len(chain) - ADJUST_INTERVAL), median_index(len(chain) - 1)
        expected = TARGET_SECONDS * (end - start)
        elapsed = chain[end]["timestamp"] - chain[start]["timestamp"]
        elapsed = max(expected // MAX_ADJUST_FACTOR, min(expected * MAX_ADJUST_FACTOR, elapsed))
        target = target * elapsed // expected
    return max(MIN_TARGET, min(MAX_TARGET, target))


def median_time(chain):
    stamps = sorted(b["timestamp"] for b in chain[-11:])
    return stamps[len(stamps) // 2]


def validate_next(block, chain, utxos, now=None, inplace=False):
    exact_keys(block, ("version", "network", "height", "previous", "timestamp",
                       "target", "nonce", "merkle_root", "transactions"))
    require(len(canonical(block)) <= MAX_BLOCK_BYTES, "Bloc trop volumineux")
    require(type(block["version"]) is int, "Version de bloc invalide")
    require(block["version"] in ACCEPTED_BLOCK_VERSIONS,
            f"Version de bloc inconnue ({block['version']}) : mettre le logiciel à jour"
            if block["version"] > max(ACCEPTED_BLOCK_VERSIONS) else "Version de bloc obsolète")
    integer(block["height"], len(chain), len(chain), "Hauteur")
    require(block["network"] == NETWORK, "Mauvais réseau")
    require(block["previous"] == block_id(chain[-1]), "Bloc parent inconnu")
    integer(block["timestamp"], 0, 2**63 - 1, "Horodatage")
    require(block["timestamp"] > median_time(chain), "Horodatage trop ancien")
    require(block["timestamp"] > chain[-1]["timestamp"], "Horodatage antérieur au bloc précédent")
    require(block["timestamp"] <= (int(time.time()) if now is None else now)
            + MAX_FUTURE_SECONDS, "Horodatage trop futur")
    integer(block["target"], MIN_TARGET, MAX_TARGET, "Difficulté")
    require(block["target"] == expected_target(chain), "Difficulté incorrecte")
    integer(block["nonce"], 0, 2**64 - 1, "Nonce")
    require(int(block_id(block), 16) < block["target"],
            "Preuve de travail invalide")
    transactions = block["transactions"]
    require(isinstance(transactions, list) and 1 <= len(transactions) <= MAX_BLOCK_TXS,
            "Nombre de transactions invalide")
    require(block["merkle_root"] == merkle_root(transactions), "Racine Merkle incorrecte")
    require(len({transaction_id(tx) for tx in transactions}) == len(transactions),
            "Transaction dupliquée dans le bloc")
    reward_tx = transactions[0]
    exact_keys(reward_tx, ("type", "network", "height", "outputs"))
    require(reward_tx["type"] == "coinbase" and reward_tx["network"] == NETWORK,
            "Récompense invalide")
    integer(reward_tx["height"], len(chain), len(chain), "Hauteur de récompense")
    require(isinstance(reward_tx["outputs"], list) and len(reward_tx["outputs"]) <= 1,
            "Récompense invalide")
    claimed = validate_outputs(reward_tx["outputs"]) if reward_tx["outputs"] else 0
    # Coins are never modified in place (they are removed and created), so a shallow copy of the map is enough.
    # `inplace` lets a caller that owns the UTXO map (chain replay) skip even that; on failure that map is spoiled.
    updated = utxos if inplace else dict(utxos)
    fees = sum(apply_transaction(tx, updated, len(chain)) for tx in transactions[1:])
    require(claimed == subsidy(len(chain)) + fees, "Création monétaire incorrecte")
    add_outputs(reward_tx, updated, len(chain), True)
    return updated


class Tail:
    """The last blocks of a chain, indexable by absolute height like the full list. Validation only ever needs
    the recent past (median time, difficulty window), so very long chains can be checked in constant memory."""

    KEEP = 64

    def __init__(self, blocks=(), total=0):
        self.blocks, self.total = list(blocks)[-self.KEEP:], total

    def __len__(self):
        return self.total

    def _at(self, index):
        if index < 0:
            index += self.total
        offset = self.total - len(self.blocks)
        if not offset <= index < self.total:
            raise IndexError("Bloc hors de la fenêtre récente")
        return self.blocks[index - offset]

    def __getitem__(self, index):
        if isinstance(index, slice):
            return [self._at(i) for i in range(*index.indices(self.total))]
        return self._at(index)

    def append(self, block):
        self.blocks.append(block)
        self.total += 1
        if len(self.blocks) > self.KEEP:
            del self.blocks[0]


def validate_chain(chain, now=None, upto=None):
    """Validate the first `upto` blocks (default: all) of a list-like chain, streaming through it."""
    count = len(chain) if upto is None else upto
    require(1 <= count <= len(chain) and count <= MAX_CHAIN_BLOCKS, "Historique absent ou limite de blocs atteinte")
    require(canonical(chain[0]) == canonical(genesis()), "Genesis incompatible")
    utxos, work = {}, 0
    tail = Tail([chain[0]], 1)
    for height in range(1, count):
        block = chain[height]
        utxos = validate_next(block, tail, utxos, now, inplace=True)
        work += block_work(block["target"])
        tail.append(block)
    return utxos, work


def make_candidate(chain, utxos, pending, address, now=None):
    require(valid_address(address), "Adresse de minage invalide")
    require(len(chain) < MAX_CHAIN_BLOCKS, "Limite de blocs de cette version atteinte")
    height = len(chain)
    selected, fees, size = [], 0, 1000
    available = dict(utxos)

    def feerate(tx):  # best-paying first; payments spending unconfirmed coins sort after their parents
        try:
            paid = sum(utxos[(i["txid"], i["index"])]["amount"] for i in tx["inputs"])
        except (KeyError, TypeError):
            return 0
        return (paid - sum(o["amount"] for o in tx["outputs"])) / max(1, len(canonical(tx)))

    for tx in sorted(pending, key=feerate, reverse=True):
        if len(selected) >= MAX_BLOCK_TXS - 1 or size + len(canonical(tx)) > MAX_BLOCK_BYTES:
            continue
        try:
            fee = apply_transaction(tx, available, height)
        except Invalid:
            continue
        fees += fee
        selected.append(tx)
        size += len(canonical(tx))
    transactions = [coinbase(height, address, subsidy(height) + fees)] + selected
    return {"version": BLOCK_VERSION, "network": NETWORK, "height": height,
            "previous": block_id(chain[-1]),
            "timestamp": max(int(time.time()) if now is None else now, median_time(chain) + 1,
                             chain[-1]["timestamp"] + 1),
            "target": expected_target(chain), "nonce": 0,
            "merkle_root": merkle_root(transactions), "transactions": transactions}


def solve(block, cancelled=lambda: False):
    target = block["target"]
    while int(block_id(block), 16) >= target:
        block["nonce"] += 1
        if block["nonce"] % 1024 == 0 and cancelled():
            raise Invalid("Minage interrompu")
    return block
