import json
import stat

import pytest

from novacoin.core import Invalid, UNIT
from novacoin.hdwallet import (GAP_LIMIT, WORDLIST, HDWallet, derive_key, entropy_to_phrase,
                               new_phrase, phrase_to_entropy, seed_from_phrase)
from novacoin.node import Node
from novacoin.wallet import address as key_address

PASSWORD = "un mot de passe solide"


def test_wordlist_is_2048_unique_four_letter_words():
    assert len(WORDLIST) == 2048 == len(set(WORDLIST))
    assert all(len(w) == 4 and w.isalpha() and w.islower() for w in WORDLIST)


def test_phrase_roundtrip_checksum_and_errors():
    entropy = bytes(range(16))
    phrase = entropy_to_phrase(entropy)
    assert len(phrase.split()) == 12 and phrase_to_entropy(phrase) == entropy
    assert phrase_to_entropy("  " + phrase.upper().replace(" ", "   ") + " ") == entropy   # forgiving input
    words = phrase.split()
    swapped = words[:]
    swapped[0], swapped[1] = words[1], words[0]
    wrong = words[:]
    wrong[5] = WORDLIST[(WORDLIST.index(words[5]) + 1) % 2048]
    detected = 0
    for bad in (swapped, wrong):
        try:
            phrase_to_entropy(" ".join(bad))
        except Invalid as exc:
            assert "somme de contrôle" in str(exc)
            detected += 1
    assert detected >= 1                              # a checksum has 1/16 chance of missing an error
    with pytest.raises(Invalid, match="position 3"):
        phrase_to_entropy(" ".join(words[:2] + ["zzzz"] + words[3:]))
    with pytest.raises(Invalid, match="12 mots"):
        phrase_to_entropy(" ".join(words[:11]))
    assert len({new_phrase() for _ in range(20)}) == 20


def test_derivation_is_deterministic_and_phrase_specific():
    phrase = entropy_to_phrase(b"\x01" * 16)
    seed = seed_from_phrase(phrase)
    assert key_address(derive_key(seed, 0)) == key_address(derive_key(seed_from_phrase(phrase), 0))
    assert key_address(derive_key(seed, 0)) != key_address(derive_key(seed, 1))
    assert seed != seed_from_phrase(phrase, passphrase="option")
    assert seed != seed_from_phrase(entropy_to_phrase(b"\x02" * 16))


def test_wallet_file_is_encrypted_persistent_and_password_protected(tmp_path):
    path = tmp_path / "w.json"
    wallet, phrase = HDWallet.create(path, PASSWORD)
    first = wallet.new_address()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    raw = path.read_text()
    assert wallet.seed.hex() not in raw and phrase.split()[0] not in raw and first not in raw
    again = HDWallet.load(path, PASSWORD)
    assert again.addresses() == [first] and again.seed == wallet.seed
    assert again.new_address() != first and HDWallet.load(path, PASSWORD).state["next_index"] == 2
    with pytest.raises(Invalid, match="incorrect"):
        HDWallet.load(path, "mauvais mot de passe")
    blob = json.loads(raw)
    blob["data"] = blob["data"][:-2] + ("00" if blob["data"][-2:] != "00" else "11")
    path.write_text(json.dumps(blob))
    with pytest.raises(Invalid):
        HDWallet.load(path, PASSWORD)                 # tampering is detected
    with pytest.raises(Invalid, match="10 caractères"):
        HDWallet.create(tmp_path / "x.json", "court")
    with pytest.raises(Invalid, match="existe"):
        HDWallet.create(path, PASSWORD)


def test_contacts(tmp_path):
    wallet, _ = HDWallet.create(tmp_path / "w.json", PASSWORD)
    other = HDWallet.create(tmp_path / "o.json", PASSWORD)[0].address(0)
    wallet.add_contact("Bob", other)
    assert HDWallet.load(tmp_path / "w.json", PASSWORD).resolve("Bob") == other
    for bad in (("", other), (" x", other), ("Eve", "pas-une-adresse")):
        with pytest.raises(Invalid):
            wallet.add_contact(*bad)


@pytest.fixture
def chain(tmp_path):
    node = Node(tmp_path / "node")
    yield node
    node.close()


def fetch_from(node):
    return lambda a: node.balance(a)


def test_receive_send_split_change_and_full_recovery(tmp_path, chain):
    node = chain
    alice, phrase = HDWallet.create(tmp_path / "a.json", PASSWORD)
    bob, _ = HDWallet.create(tmp_path / "b.json", PASSWORD)
    a0, a1 = alice.new_address(), alice.new_address()
    for address in (a0, a0, a1, a1, a1):               # coins on two different addresses
        node.mine_one(address)
    node.mine_one(bob.new_address())                    # maturity for Alice's last blocks
    node.mine_one(bob.new_address())
    fetch = fetch_from(node)
    before = alice.balance(fetch)
    assert before["confirmed"] == before["available"] == 5 * 50 * UNIT
    # 200 NOVA exceeds any single address's balance (100 and 150) -> two transactions, one per key.
    submit = lambda tx: node.submit(tx)
    fee = UNIT // 1000
    txids = alice.send(fetch, submit, bob.address(0), 200 * UNIT, fee)
    assert len(txids) == 2 and len(set(txids)) == 2
    node.mine_one(bob.new_address())
    after = alice.balance(fetch)
    assert after["confirmed"] == 250 * UNIT - 200 * UNIT - 2 * fee      # change came back, fees left
    assert node.balance(bob.address(0))["confirmed"] == 200 * UNIT + 50 * UNIT   # payment + a block he mined there
    assert alice.state["next_index"] >= 4                # two fresh change addresses were allocated
    with pytest.raises(Invalid, match="insuffisant"):
        alice.send(fetch, submit, bob.address(0), 10_000 * UNIT, fee)
    # Lose everything but the phrase: a brand-new wallet finds addresses, change included.
    restored, _ = HDWallet.create(tmp_path / "restored.json", PASSWORD, phrase=phrase)
    assert restored.state["next_index"] == 0
    found = restored.balance(fetch)
    assert found["confirmed"] == alice.balance(fetch)["confirmed"]
    assert restored.state["next_index"] == alice.state["next_index"]
    assert restored.addresses()[:2] == [a0, a1]


def test_scan_respects_gap_limit(tmp_path, chain):
    wallet, _ = HDWallet.create(tmp_path / "w.json", PASSWORD)
    chain.mine_one(wallet.address(GAP_LIMIT - 1))        # last index still inside the gap
    assert wallet.balance(fetch_from(chain))["confirmed"] == 50 * UNIT
    other, _ = HDWallet.create(tmp_path / "x.json", PASSWORD)
    chain.mine_one(other.address(GAP_LIMIT + 5))         # beyond the gap: not discovered (documented)
    assert other.balance(fetch_from(chain))["confirmed"] == 0
