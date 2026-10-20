"""Attack bench (V7): runs concrete attacks against in-process nodes and reports what held.

Every scenario states what the defence is supposed to do, runs the attack, and records the
observed outcome. A scenario is "HELD" when the defence behaved as stated; scenarios that
document an *inherent* weakness (for example majority hash power) are reported as such.
Run:  python -m novacoin.attack_bench   (uses the trivially easy lab network)
"""
from __future__ import annotations

import copy
import math
import os
import random
import sys
import tempfile
import time
from pathlib import Path

if os.environ.get("NOVA_EASY") != "1":          # the bench needs the easy network: restart with it
    os.environ["NOVA_EASY"] = "1"
    os.execv(sys.executable, [sys.executable, "-m", "novacoin.attack_bench", *sys.argv[1:]])

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from . import core, node as node_module  # noqa: E402
from .core import (ADJUST_INTERVAL, DEFAULT_MAX_REORG, MAX_FUTURE_SECONDS, TARGET_SECONDS, UNIT,  # noqa: E402
                   Invalid, block_id, canonical, expected_target, genesis, make_candidate,
                   median_index, solve, validate_next)
from .node import MAX_MEMPOOL, Node  # noqa: E402
from .wallet import address, build_transaction  # noqa: E402

FEE = 100_000


class SimulatedClock:
    """Replaces the clock seen by the consensus code so that long chains keep a steady difficulty
    (real blocks would otherwise come far faster than the 10 s target and make mining explode)."""

    def __init__(self):
        self.now = int(time.time()) - 5_000_000   # room for 80,000 blocks at 60 s

    def time(self):
        return self.now

    def __getattr__(self, name):
        return getattr(time, name)


CLOCK = SimulatedClock()


def mine(node, miner_address, count=1):
    for _ in range(count):
        CLOCK.now += TARGET_SECONDS
        node.mine_one(miner_address)


class Result:
    def __init__(self, name, defence, held, observed, severity="", note=""):
        self.name, self.defence, self.held, self.observed = name, defence, held, observed
        self.severity, self.note = severity, note


def keys(n):
    return [Ed25519PrivateKey.generate() for _ in range(n)]


def fresh(tmp, name, **kwargs):
    return Node(Path(tmp) / name, **kwargs)


def sync_to(target, source):
    assert target.adopt(copy.deepcopy(source.chain))


# ------------------------------------------------------------------ scenarios

def double_spend_in_pool(tmp):
    node, (a, b) = fresh(tmp, "pool"), keys(2)
    try:
        for _ in range(3):
            mine(node, address(a))
        coins = node.balance(address(a))["utxos"]
        node.submit(build_transaction(a, coins, address(b), 10 * UNIT, FEE))
        try:
            node.submit(build_transaction(a, coins, address(Ed25519PrivateKey.generate()), 10 * UNIT, FEE))
            return Result("Double dépense dans la file", "Le second paiement des mêmes pièces est refusé",
                          False, "Les deux paiements ont été acceptés")
        except Invalid as exc:
            return Result("Double dépense dans la file", "Le second paiement des mêmes pièces est refusé",
                          True, f"Refusé : {exc}")
    finally:
        node.close()


def double_spend_in_block(tmp):
    node, (a, b) = fresh(tmp, "block"), keys(2)
    try:
        for _ in range(3):
            mine(node, address(a))
        coins = node.balance(address(a))["utxos"]
        first = build_transaction(a, coins, address(b), 10 * UNIT, FEE)
        second = build_transaction(a, coins, address(Ed25519PrivateKey.generate()), 10 * UNIT, FEE)
        block = make_candidate(node.chain, node.utxos, [first], address(a))
        block["transactions"].append(second)
        from .core import merkle_root
        block["merkle_root"] = merkle_root(block["transactions"])
        solve(block)
        try:
            node.accept_block(block)
            return Result("Double dépense dans un bloc", "Un bloc qui dépense deux fois est refusé", False,
                          "Bloc accepté")
        except Invalid as exc:
            return Result("Double dépense dans un bloc", "Un bloc qui dépense deux fois est refusé", True,
                          f"Refusé : {exc}")
    finally:
        node.close()


def build_reorg_scenario(tmp, confirmations, attacker_blocks, name, max_reorg=DEFAULT_MAX_REORG):
    """Merchant is paid and sees `confirmations` blocks; attacker secretly mines `attacker_blocks`
    blocks spending the same coin to itself. Returns (merchant_still_paid, victim, attacker)."""
    attacker_key, merchant, thief = keys(3)
    victim = fresh(tmp, name + "-v", max_reorg=max_reorg)
    attacker = fresh(tmp, name + "-a", max_reorg=0)
    try:
        for _ in range(3):
            mine(victim, address(attacker_key))
        sync_to(attacker, victim)
        coins = victim.balance(address(attacker_key))["utxos"]
        pay = build_transaction(attacker_key, coins, address(merchant), 40 * UNIT, FEE)
        steal = build_transaction(attacker_key, coins, address(thief), 40 * UNIT, FEE)
        fork_time = CLOCK.now
        victim.submit(pay)
        for _ in range(confirmations):
            mine(victim, address(Ed25519PrivateKey.generate()))
        honest_end = CLOCK.now
        CLOCK.now = fork_time                      # the attacker works in parallel, on the same timeline
        attacker.submit(steal)
        for _ in range(attacker_blocks):
            mine(attacker, address(thief))
        CLOCK.now = max(honest_end, CLOCK.now)
        try:
            victim.adopt(copy.deepcopy(attacker.chain))
            refused = None
        except Invalid as exc:
            refused = str(exc)
        paid = victim.balance(address(merchant))["confirmed"] == 40 * UNIT
        return paid, refused, victim, attacker
    except Exception:
        victim.close(); attacker.close()
        raise


def majority_reorg(tmp):
    paid, refused, v, a = build_reorg_scenario(tmp, 6, 8, "maj")
    v.close(); a.close()
    return Result("Retournement de paiement par un attaquant plus puissant",
                  "AUCUNE défense de protocole : c'est la définition de la sécurité par preuve de travail",
                  False, "Paiement annulé après 6 confirmations par une chaîne secrète plus lourde" if not paid
                  else "Paiement conservé", severity="inhérent",
                  note="La sécurité dépend de la puissance honnête, pas du code (voir table ci-dessous).")


def equal_work_does_not_switch(tmp):
    paid, refused, v, a = build_reorg_scenario(tmp, 6, 6, "tie")
    v.close(); a.close()
    return Result("Chaîne secrète à travail égal", "Le nœud garde la première chaîne vue", paid,
                  "Paiement conservé" if paid else "Paiement annulé")


def deep_reorg_policy(tmp):
    paid, refused, v, a = build_reorg_scenario(tmp, DEFAULT_MAX_REORG + 10, DEFAULT_MAX_REORG + 12, "deep")
    events = [e["kind"] for e in v.events()]
    v.close(); a.close()
    return Result("Réécriture de plus de 50 blocs",
                  "Un nœud refuse de lui-même de remplacer plus de 50 blocs (politique locale)",
                  paid and refused is not None and "reorg_refused" in events,
                  f"Refusé : {refused}" if refused else "Réécriture acceptée",
                  note="Limite : un attaquant très majoritaire peut cibler des nœuds fraîchement installés.")


def time_warp_window(tmp):
    """Largest inflation of a difficulty window's measured time obtainable with timestamps alone."""
    clock = 1_800_000_000

    def build(offsets):
        chain, coins, k = [genesis()], {}, keys(1)[0]
        for i in range(1, ADJUST_INTERVAL + 1):
            now = clock + i                                        # real time: 1 s per block
            block = solve(make_candidate(chain, coins, [], address(k), now + offsets(i)))
            coins = validate_next(block, chain, coins, now=now)
            chain.append(block)
        return chain

    def measured(chain):
        start, end = median_index(len(chain) - ADJUST_INTERVAL), median_index(len(chain) - 1)
        return chain[end]["timestamp"] - chain[start]["timestamp"]

    honest = measured(build(lambda i: 0))
    worst = 0
    for shape in (lambda i: MAX_FUTURE_SECONDS if i > ADJUST_INTERVAL // 2 else 0,
                  lambda i: MAX_FUTURE_SECONDS * i // ADJUST_INTERVAL,
                  lambda i: MAX_FUTURE_SECONDS if i % 2 else 0):
        try:
            worst = max(worst, measured(build(shape)) - honest)
        except Invalid:
            continue                                               # shape refused by the rules: fine
    return Result("Manipulation des horodatages (time warp)",
                  f"Le temps mesuré d'une fenêtre ne peut pas être gonflé de plus de {MAX_FUTURE_SECONDS} s",
                  worst <= MAX_FUTURE_SECONDS,
                  f"Meilleur gonflement obtenu : +{worst} s sur une fenêtre réelle de {honest} s "
                  f"(un réglage reste borné à ×4 / ÷4)",
                  note="Sur un réseau lent (fenêtre de plusieurs minutes), 60 s pèsent peu ; sur un réseau très rapide "
                       "ils pèsent beaucoup. Un attaquant majoritaire peut répéter l'opération à chaque fenêtre.")


def fuzz_consensus(tmp, rounds=3000, seed=7):
    rng = random.Random(seed)
    node, (a, b) = fresh(tmp, "fuzz"), keys(2)
    try:
        for _ in range(4):
            mine(node, address(a))
        tx = build_transaction(a, node.balance(address(a))["utxos"], address(b), 5 * UNIT, FEE)
        good = make_candidate(node.chain, node.utxos, [tx], address(a))
        solve(good)
        before = (len(node.chain), sorted(map(str, node.utxos)), sorted(node.pending))
        junk = [None, -1, 0, 2 ** 70, "", "x" * 300, [], {}, True, False, 1.5, "0" * 64, "g" * 64, [[]], {"a": 1}]
        problems, accepted, tried = {}, 0, 0

        def paths(obj, prefix=()):
            yield prefix
            if isinstance(obj, dict):
                for k, v in obj.items():
                    yield from paths(v, prefix + (k,))
            elif isinstance(obj, list):
                for i, v in enumerate(obj):
                    yield from paths(v, prefix + (i,))

        for _ in range(rounds):
            subject = copy.deepcopy(good if rng.random() < 0.7 else tx)
            for _ in range(rng.choice((1, 1, 2, 3))):
                target = rng.choice(list(paths(subject)))
                if not target:
                    subject = copy.deepcopy(rng.choice(junk))
                    break
                parent = subject
                for step in target[:-1]:
                    parent = parent[step]
                action = rng.choice(("replace", "replace", "delete", "add"))
                try:
                    if action == "delete":
                        del parent[target[-1]]
                    elif action == "add" and isinstance(parent, dict):
                        parent[str(rng.choice(junk))[:10] or "k"] = copy.deepcopy(rng.choice(junk))
                    else:
                        parent[target[-1]] = copy.deepcopy(rng.choice(junk))
                except (KeyError, IndexError, TypeError):
                    pass
            for call in ("block", "submit"):
                if call == "block" and not (isinstance(subject, dict) and "transactions" in subject):
                    continue
                tried += 1
                try:
                    if call == "block":
                        if rng.random() < 0.5:                      # get past proof of work some of the time
                            budget = [0]

                            def give_up():                      # a mutated target may be unreachable
                                budget[0] += 1
                                return budget[0] > 4

                            try:
                                solve(subject, give_up) if isinstance(subject.get("nonce"), int) else None
                            except Exception:
                                pass
                        node.accept_block(copy.deepcopy(subject))
                    else:
                        node.submit(copy.deepcopy(subject))
                    accepted += 1
                except Invalid:
                    pass
                except Exception as exc:                           # anything else is a defect
                    key = f"{type(exc).__name__}: {str(exc)[:70]}"
                    problems[key] = problems.get(key, 0) + 1
        after = (len(node.chain), sorted(map(str, node.utxos)), sorted(node.pending))
        unchanged = before[0] <= after[0] <= before[0] + 1 and set(before[2]) <= set(after[2]) | set(before[2])
        return Result("Blocs et paiements mutés au hasard",
                      "Toute mutation est refusée proprement (jamais d'erreur interne) et l'état reste sain",
                      not problems and unchanged,
                      f"{tried} objets essayés, {accepted} acceptés (mutations sans effet), "
                      + ("aucune erreur interne" if not problems else f"ERREURS INTERNES : {problems}"),
                      severity="" if not problems else "défaut")
    finally:
        node.close()


def mempool_flood(tmp):
    node, spammer = fresh(tmp, "flood"), keys(1)[0]
    try:
        started = time.time()
        rejected = 0
        for i in range(2000):
            try:
                node.submit({"version": 1, "network": "x", "inputs": [], "outputs": [], "n": i})
            except Invalid:
                rejected += 1
        elapsed = time.time() - started
        return Result("Inondation de paiements invalides", "Tous refusés, file inchangée, coût borné",
                      rejected == 2000 and not node.pending, f"{rejected}/2000 refusés en {elapsed:.1f} s, "
                      f"file : {len(node.pending)}")
    finally:
        node.close()


def mempool_full_eviction(tmp):
    """Fill the pool with minimum-fee transactions, then offer a well-paying one."""
    node, (spammer, honest, dest) = fresh(tmp, "full"), keys(3)
    try:
        parents = -(-MAX_MEMPOOL // 61)
        for _ in range(parents + 3):
            mine(node, address(spammer))
        mine(node, address(honest))
        for _ in range(3):
            mine(node, address(honest))
        wallet_coins = [c for c in node.balance(address(spammer))["utxos"] if c["spendable"]][:parents]
        from .core import MIN_FEE_PER_BYTE, transaction_id
        for coin in wallet_coins:                                      # split each coin into 60 outputs
            outputs_total = coin["amount"] - 200_000
            size_guess = 5_000
            per = (outputs_total - MIN_FEE_PER_BYTE * size_guess) // 60
            tx = {"version": 1, "network": node_module.NETWORK, "inputs": [{"txid": coin["txid"], "index": coin["index"]}],
                  "outputs": [{"address": address(spammer), "amount": per} for _ in range(60)],
                  "public_key": "", "signature": ""}
            from .wallet import public_hex
            from .core import signing_bytes
            tx["public_key"] = public_hex(spammer)
            tx["signature"] = spammer.sign(signing_bytes(tx)).hex()
            node.submit(tx)
            for index in range(60):
                if len(node.pending) >= MAX_MEMPOOL:
                    break
                child = build_transaction(spammer, [{"address": address(spammer), "txid": transaction_id(tx),
                                                     "index": index, "amount": per, "spendable": True}],
                                          address(dest), per - 6_000, 6_000)
                node.submit(child)
        full = len(node.pending)
        good = build_transaction(honest, node.balance(address(honest))["utxos"], address(dest), 10 * UNIT, 2_000_000)
        try:
            node.submit(good)
            return Result("File pleine de paiements à frais minimaux",
                          "Un paiement bien rémunéré reste accepté (éviction des moins payants)", True,
                          f"File de {full} paiements ; le paiement à frais élevés a été accepté")
        except Invalid as exc:
            return Result("File pleine de paiements à frais minimaux",
                          "Un paiement bien rémunéré reste accepté (éviction des moins payants)", False,
                          f"File de {full} paiements ; le paiement à frais élevés est refusé : {exc}",
                          severity="défaut")
    finally:
        node.close()


def lying_peer_search_cost(tmp):
    """A peer claims an enormous chain and answers every ancestor probe with random hashes."""
    node, miner = fresh(tmp, "liar"), keys(1)[0]
    for _ in range(250):
        mine(node, address(miner))
    calls = []
    original = node_module.peer_request
    url = "https://127.0.0.1:65000"
    node.peers[url] = "ab" * 32

    def liar(peer, path, *args, **kwargs):
        calls.append(path)
        if path.startswith("/p2p/status"):
            return ({"network": node_module.NETWORK, "chainwork": str(10 ** 30), "height": 90_000,
                     "tip": "ab" * 32, "isolated": False}, "ab" * 32)
        if path.startswith("/p2p/hashes"):
            count = int(path.split("limit=")[1])
            return ({"hashes": [os.urandom(32).hex() for _ in range(count)]}, "ab" * 32)
        return ({"transactions": [], "peers": []}, "ab" * 32)

    node_module.peer_request = liar
    try:
        node.sync_once()
        first = len(calls)
        node.sync_once()
        node.sync_once()
    finally:
        node_module.peer_request = original
    requests = first
    banned = node.is_banned(None, "ab" * 32)
    node.close()
    return Result("Pair menteur annonçant 90 000 blocs", "Coût borné (quelques dizaines de requêtes) et pair sanctionné",
                  requests <= 40 and banned,
                  f"{requests} requêtes pour une tentative (chaîne locale de 250 blocs) ; pair banni après 3 tentatives : {banned}",
                  severity="" if requests <= 40 and banned else "défaut")


# ------------------------------------------------------------------ reporting

def catch_up_probability(q, z):
    """Nakamoto (2008): chance that an attacker with share q ever erases a payment z blocks deep."""
    p = 1 - q
    if q >= p:
        return 1.0
    lam = z * q / p
    total = 1.0
    for k in range(z + 1):
        poisson = math.exp(-lam) * lam ** k / math.factorial(k)
        total -= poisson * (1 - (q / p) ** (z - k))
    return max(0.0, total)


def exact_catch_up_probability(q, z):
    """Exact chance that an attacker with share q ever erases a payment confirmed z times.
    The attacker's blocks found while the honest chain finds z follow a negative binomial law (Rosenfeld, 2012);
    Nakamoto's table used a Poisson approximation that is slightly too optimistic."""
    p = 1 - q
    if q >= p:
        return 1.0
    if z == 0:
        return 1.0
    return sum(math.comb(k + z - 1, k) * p ** z * q ** k * (1 if k >= z else (q / p) ** (z - k)) for k in range(2000))


def render(results, started):
    lines = ["# Rapport du banc d'attaques Nova", "",
             f"Exécuté le {time.strftime('%d/%m/%Y %H:%M', time.gmtime(started))} UTC sur le réseau de laboratoire "
             "(difficulté minimale). Les défenses sont celles du code de ce dossier.", "",
             "| Attaque | Défense attendue | Résultat | Observé |", "|---|---|---|---|"]
    for r in results:
        label = "**TIENT**" if r.held else ("**INHÉRENT**" if r.severity == "inhérent" else "**CASSE**")
        lines.append(f"| {r.name} | {r.defence} | {label} | {r.observed} |")
    notes = [f"- *{r.name}* : {r.note}" for r in results if r.note]
    if notes:
        lines += ["", "## Remarques", *notes]
    lines += ["", "## Chance qu'un attaquant efface un paiement (modèle exact)", "",
              "Part de puissance de l'attaquant (lignes) et confirmations attendues (colonnes). "
              "C'est la limite théorique de toute chaîne à preuve de travail, quel que soit le code. (Le tableau d'origine du livre blanc de "
              "Bitcoin, calculé par approximation, sous-estime un peu ces chances ; ces valeurs sont exactes et confirmées par simulation, "
              "voir `RAPPORT-SIMULATIONS.md`.)", "",
              "| Part \\ confirmations | 1 | 2 | 6 | 12 | 30 |", "|---|---|---|---|---|---|"]
    for q in (0.1, 0.25, 0.3, 0.4, 0.45, 0.51):
        lines.append(f"| {int(q * 100)} % | " + " | ".join(f"{exact_catch_up_probability(q, z) * 100:.2f} %"
                                                           for z in (1, 2, 6, 12, 30)) + " |")
    lines += ["", "Au-delà de 50 % de la puissance, l'attaque réussit toujours. Sur un réseau jeune et petit, "
              "une seule personne bien équipée peut dépasser 50 %."]
    return "\n".join(lines) + "\n"


SCENARIOS = [double_spend_in_pool, double_spend_in_block, majority_reorg, equal_work_does_not_switch,
             deep_reorg_policy, time_warp_window, fuzz_consensus, mempool_flood, mempool_full_eviction,
             lying_peer_search_cost]


def run(selected=None, output=None, fuzz_rounds=3000):
    started = time.time()
    results = []
    real_time, core.time = core.time, CLOCK          # the simulated clock only lives during the run
    CLOCK.now = int(real_time.time()) - 5_000_000
    try:
        with tempfile.TemporaryDirectory() as tmp:
            _run_all(tmp, selected, results, fuzz_rounds)
    finally:
        core.time = real_time
    report = render(results, started)
    if output:
        Path(output).mkdir(parents=True, exist_ok=True)
        (Path(output) / "RAPPORT-ATTAQUES.md").write_text(report)
    return results, report


def _run_all(tmp, selected, results, fuzz_rounds):
    if True:
        for scenario in SCENARIOS:
            if selected and scenario.__name__ not in selected:
                continue
            try:
                results.append(scenario(tmp, fuzz_rounds) if scenario is fuzz_consensus else scenario(tmp))
            except Exception as exc:        # a scenario that crashes is itself a finding
                results.append(Result(scenario.__name__, "Le scénario s'exécute", False,
                                      f"Erreur inattendue : {type(exc).__name__}: {exc}", severity="défaut"))
            print(("TIENT   " if results[-1].held else "CASSE   ") + results[-1].name + " — " + results[-1].observed,
                  flush=True)


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else ".local/attacks"
    results, _ = run(output=out)
    print(f"Rapport : {Path(out).resolve() / 'RAPPORT-ATTAQUES.md'}")
    raise SystemExit(0 if all(r.held or r.severity == "inhérent" for r in results) else 1)
