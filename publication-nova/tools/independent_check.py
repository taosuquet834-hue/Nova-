#!/usr/bin/env python3
"""Independent verifier of a Nova chain, written from PROTOCOLE.md only (no import of novacoin).

Usage: [NOVA_EASY=1] python tools/independent_check.py path/to/chain.sqlite3
"""
import hashlib
import json
import os
import sqlite3
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

EASY = os.environ.get("NOVA_EASY") == "1"
NETWORK = "nova-testnet-3-easy" if EASY else "nova-testnet-3"
INITIAL_BITS, EASIEST_BITS, HARDEST_BITS = (6, 4, 96) if EASY else (22, 16, 96)
UNIT, MAX_MONEY, WINDOW, TARGET_SECONDS, MATURITY = 10 ** 8, 21_000_000 * 10 ** 8, 20, 60, 2


class Bad(Exception):
    pass


def need(ok, message):
    if not ok:
        raise Bad(message)


def canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canon(value)).hexdigest()


def txid_of(tx):
    """Payment identifier: hash of the payment without its signatures (coinbase: the whole object)."""
    if tx.get("type") != "coinbase":
        tx = {k: v for k, v in tx.items() if k != "signature"}
        if isinstance(tx.get("multisig"), dict):
            tx["multisig"] = {k: v for k, v in tx["multisig"].items() if k != "signatures"}
    return digest(tx)


def block_id(b):
    return digest({k: b[k] for k in ("version", "network", "height", "previous", "timestamp", "target",
                                      "nonce", "merkle_root")})


def merkle(txids):
    layer = list(txids)
    if not layer:
        return hashlib.sha256(b"").hexdigest()
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        layer = [hashlib.sha256(bytes.fromhex(layer[i] + layer[i + 1])).hexdigest() for i in range(0, len(layer), 2)]
    return layer[0]


def address_of(public_hex):
    body = hashlib.sha256(bytes.fromhex(public_hex)).hexdigest()[:40]
    return "nv1" + body + hashlib.sha256((NETWORK + body).encode()).hexdigest()[:8]


def subsidy(h):
    return 5_000_000_000 >> ((h - 1) // 210_000)


def middle(i):
    low = max(1, i - 10)
    return low + (i - low + 1) // 2


def expected_target(chain):
    t, n = chain[-1]["target"], len(chain)
    if n > WINDOW and (n - 1) % WINDOW == 0:
        start, end = middle(n - WINDOW), middle(n - 1)
        expected = TARGET_SECONDS * (end - start)
        elapsed = chain[end]["timestamp"] - chain[start]["timestamp"]
        elapsed = max(expected // 4, min(expected * 4, elapsed))
        t = t * elapsed // expected
    return max(1 << (256 - HARDEST_BITS), min(1 << (256 - EASIEST_BITS), t))


def genesis():
    return {"version": 2, "network": NETWORK, "height": 0, "previous": "0" * 64, "timestamp": 1_700_000_000,
            "target": 1 << (256 - INITIAL_BITS), "nonce": 0, "merkle_root": hashlib.sha256(b"").hexdigest(),
            "transactions": []}


def multisig_address_of(m, keys):
    need(type(m) is int and isinstance(keys, list) and 1 <= m <= len(keys) <= 5, "multisignature : politique")
    need(all(isinstance(k, str) and len(k) == 64 for k in keys) and keys == sorted(set(keys)), "multisignature : clés")
    body = hashlib.sha256(canon({"m": m, "keys": keys})).hexdigest()[:40]
    return "nm1" + body + hashlib.sha256((NETWORK + body).encode()).hexdigest()[:8]


def check_outputs(outputs, limit=64):
    need(isinstance(outputs, list) and 1 <= len(outputs) <= limit, "sorties : nombre invalide")
    total = 0
    for o in outputs:
        need(set(o) == {"address", "amount"}, "sortie : champs")
        a = o["address"]
        need(isinstance(a, str) and len(a) == 51 and a[:3] in ("nv1", "nm1"), "adresse invalide")
        body = a[3:43]
        need(a[43:] == hashlib.sha256((NETWORK + body).encode()).hexdigest()[:8], "somme de contrôle d'adresse")
        need(type(o["amount"]) is int and 1 <= o["amount"] <= MAX_MONEY, "montant invalide")
        total += o["amount"]
    return total


def verify_signatures(tx):
    """Return the address that must own the coins; raise Bad when a signature or the shape is wrong."""
    v2 = tx.get("version") == 2
    if v2:
        need(("multisig" in tx) != ("public_key" in tx), "un seul type de signataire")
        need(set(tx) == {"version", "network", "inputs", "outputs", "locktime"} | ({"multisig"} if "multisig" in tx
             else {"public_key", "signature"}), "paiement v2 : champs")
        need(type(tx["locktime"]) is int and 0 <= tx["locktime"] < 2 ** 31, "verrouillage invalide")
    else:
        need(set(tx) == {"version", "network", "inputs", "outputs", "public_key", "signature"}, "paiement : champs")
        need(tx["version"] == 1, "version de paiement")
    need(tx["network"] == NETWORK, "paiement : réseau")
    if not v2:
        prefix, body = b"NOVA-TX-V1\0", {k: v for k, v in tx.items() if k != "signature"}
    elif "multisig" in tx:
        policy = tx["multisig"]
        need(set(policy) == {"threshold", "keys", "signatures"}, "multisignature : champs")
        owner = multisig_address_of(policy["threshold"], policy["keys"])
        need(isinstance(policy["signatures"], list)
             and policy["threshold"] <= len(policy["signatures"]) <= len(policy["keys"]), "signatures insuffisantes")
        unsigned = {k: v for k, v in tx.items() if k != "multisig"}
        unsigned["multisig"] = {k: v for k, v in policy.items() if k != "signatures"}
        message, seen = b"NOVA-TX-V2\0" + canon(unsigned), set()
        for item in policy["signatures"]:
            need(set(item) == {"key", "signature"} and item["key"] in policy["keys"] and item["key"] not in seen,
                 "signataire inconnu ou en double")
            seen.add(item["key"])
            try:
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(item["key"])).verify(bytes.fromhex(item["signature"]), message)
            except (InvalidSignature, ValueError):
                raise Bad("signature multisignature invalide")
        return owner
    else:
        prefix, body = b"NOVA-TX-V2\0", {k: v for k, v in tx.items() if k != "signature"}
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(tx["public_key"])).verify(
            bytes.fromhex(tx["signature"]), prefix + canon(body))
    except (InvalidSignature, ValueError):
        raise Bad("signature invalide")
    return address_of(tx["public_key"])


def apply_payment(tx, utxos, height):
    need(len(canon(tx)) <= 16_000, "paiement trop gros")
    need(isinstance(tx["inputs"], list) and 1 <= len(tx["inputs"]) <= 64, "entrées : nombre")
    owner = verify_signatures(tx)
    need(tx.get("locktime", 0) <= height, "paiement verrouillé")
    seen, total_in, keys = set(), 0, []
    for item in tx["inputs"]:
        key = (item["txid"], item["index"])
        need(key not in seen and key in utxos, "pièce absente, dépensée ou entrée en double")
        seen.add(key)
        coin = utxos[key]
        need(coin["address"] == owner, "mauvais propriétaire")
        need(not coin["coinbase"] or height - coin["height"] >= MATURITY, "récompense immature")
        total_in += coin["amount"]
        keys.append(key)
    total_out = check_outputs(tx["outputs"])
    need(total_in >= total_out, "solde insuffisant")
    for key in keys:
        del utxos[key]
    txid = txid_of(tx)
    for i, o in enumerate(tx["outputs"]):
        utxos[(txid, i)] = {**o, "height": height, "coinbase": False}
    return total_in - total_out


def verify(chain):
    need(canon(chain[0]) == canon(genesis()), "genesis différent")
    utxos, work = {}, 0
    for h in range(1, len(chain)):
        b, prefix = chain[h], chain[:h]
        need(set(b) == {"version", "network", "height", "previous", "timestamp", "target", "nonce",
                        "merkle_root", "transactions"}, f"bloc {h} : champs")
        need(b["version"] == 2 and b["network"] == NETWORK and b["height"] == h, f"bloc {h} : version/réseau/hauteur")
        need(b["previous"] == block_id(chain[h - 1]), f"bloc {h} : parent")
        stamps = sorted(x["timestamp"] for x in prefix[-11:])
        need(b["timestamp"] > stamps[len(stamps) // 2] and b["timestamp"] > prefix[-1]["timestamp"], f"bloc {h} : horodatage")
        need(b["target"] == expected_target(prefix), f"bloc {h} : cible attendue")
        need(int(block_id(b), 16) < b["target"], f"bloc {h} : preuve de travail")
        need(len(canon(b)) <= 256_000 and 1 <= len(b["transactions"]) <= 200, f"bloc {h} : taille")
        txids = [txid_of(t) for t in b["transactions"]]
        need(len(set(txids)) == len(txids) and b["merkle_root"] == merkle(txids), f"bloc {h} : Merkle")
        reward = b["transactions"][0]
        need(set(reward) == {"type", "network", "height", "outputs"} and reward["type"] == "coinbase"
             and reward["network"] == NETWORK and reward["height"] == h and len(reward["outputs"]) <= 1,
             f"bloc {h} : récompense")
        fees = sum(apply_payment(t, utxos, h) for t in b["transactions"][1:])
        claimed = check_outputs(reward["outputs"], 1) if reward["outputs"] else 0
        need(claimed == subsidy(h) + fees, f"bloc {h} : montant de la récompense")
        for i, o in enumerate(reward["outputs"]):
            utxos[(txids[0], i)] = {**o, "height": h, "coinbase": True}
        work += (1 << 256) // (b["target"] + 1)
    return work


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    db = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
    chain = [json.loads(row[0]) for row in db.execute("SELECT payload FROM blocks ORDER BY height")]
    try:
        work = verify(chain)
    except Bad as exc:
        print(f"INVALIDE : {exc}")
        return 1
    print(f"VALIDE : hauteur {len(chain) - 1}, dernier bloc {block_id(chain[-1])}, travail cumulé {work}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
