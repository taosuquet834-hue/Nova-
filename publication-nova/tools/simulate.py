#!/usr/bin/env python3
"""Monte-Carlo simulations of proof-of-work attacks, checked against published formulas.

  selfish   : selfish mining (Eyal & Sirer, 2014) - revenue share of a pool that withholds blocks
  doublespend: probability that a secret chain erases a payment confirmed z times (Nakamoto, 2008)
  forks     : how often two blocks compete because of propagation delay (block time vs latency)

Usage: python tools/simulate.py [--blocks 400000] [--seed 1] [--out RAPPORT-SIMULATIONS.md]
No node is started: these are models of the protocol's rules (longest-work chain wins), not of the code.
"""
import argparse
import math
import os
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def selfish_revenue(alpha, gamma, blocks, rng):
    """Fraction of main-chain blocks won by a selfish pool with hash share alpha."""
    lead, tie, pool, honest = 0, False, 0, 0
    for _ in range(blocks):
        if rng.random() < alpha:                       # the pool finds a block
            if tie:
                pool, tie = pool + 2, False            # it extends its branch and publishes: wins the race
            else:
                lead += 1
        else:                                          # honest miners find a block
            if tie:
                if rng.random() < gamma:               # a share gamma of honest power builds on the pool's branch
                    pool, honest = pool + 1, honest + 1
                else:
                    honest += 2
                tie = False
            elif lead == 0:
                honest += 1
            elif lead == 1:
                tie, lead = True, 0                    # the pool publishes: two equal branches compete
            elif lead == 2:
                pool, lead = pool + 2, 0               # publishes both and wins
            else:
                pool, lead = pool + 1, lead - 1        # reveals one block at a time, keeps the lead
    return pool / max(1, pool + honest)


def selfish_formula(alpha, gamma):
    """Eyal & Sirer, equation 8."""
    a = alpha
    return (a * (1 - a) ** 2 * (4 * a + gamma * (1 - 2 * a)) - a ** 3) / (1 - a * (1 + (2 - a) * a))


def double_spend_probability(q, z, trials, rng):
    """Simulated chance of ever catching up, with the attacker mining in secret while the honest chain gets z blocks."""
    p, wins = 1 - q, 0
    for _ in range(trials):
        attacker = 0
        honest = 0
        while honest < z:                              # race until the honest chain has z confirmations
            if rng.random() < q:
                attacker += 1
            else:
                honest += 1
        deficit = z - attacker
        while 0 < deficit < 60:                        # then a random walk until caught up (or hopeless)
            deficit += -1 if rng.random() < q else 1
        wins += deficit <= 0
    return wins / trials


def fork_rate(block_seconds, delay, blocks, rng):
    """Fraction of blocks that have a competitor found before they could be heard (inter-arrival < delay)."""
    competing = sum(1 for _ in range(blocks) if rng.expovariate(1 / block_seconds) < delay)
    return competing / blocks


def difficulty_response(factor, windows, rng, start_seconds=None):
    """Block spacing, window after window, when the network hash power is multiplied by `factor` at time zero.
    Uses the protocol's real retarget code (`core.expected_target`) on a synthetic chain."""
    os.environ.setdefault("NOVA_EASY", "1")
    from novacoin import core
    start_seconds = core.TARGET_SECONDS if start_seconds is None else start_seconds
    # The laboratory network sits at its easiest bound already; use the real network's start and bounds.
    saved = (core.INITIAL_TARGET, core.MAX_TARGET, core.MIN_TARGET)
    core.INITIAL_TARGET, core.MAX_TARGET, core.MIN_TARGET = 1 << 236, 1 << 240, 1 << 160
    try:
        return _difficulty_response(core, factor, windows, rng, start_seconds)
    finally:
        core.INITIAL_TARGET, core.MAX_TARGET, core.MIN_TARGET = saved


def _difficulty_response(core, factor, windows, rng, start_seconds):
    interval, chain, now = core.ADJUST_INTERVAL, [{"target": core.INITIAL_TARGET, "timestamp": 1_700_000_000}], 1_700_000_000
    seconds_per_work = start_seconds / core.block_work(core.INITIAL_TARGET)      # calibrated so the first window is on target
    spacings = []
    for _ in range(windows):
        times = []
        for _ in range(interval):
            mean = seconds_per_work * core.block_work(chain[-1]["target"]) / factor
            now += max(1, round(rng.expovariate(1 / mean)))                       # timestamps strictly increase
            chain.append({"target": chain[-1]["target"], "timestamp": now})
            times.append(now)
            if (len(chain) - 1) % interval == 0:
                chain[-1]["target"] = core.expected_target(chain)                # the next window's difficulty
        spacings.append((times[-1] - (times[0] - 0)) / interval)
    return spacings


def render(results, blocks, seed):
    lines = ["# Simulations d'attaques sur la preuve de travail", "",
             f"Générées par `python tools/simulate.py` (graine {seed}, {blocks:,} blocs par cas). Ce sont des **modèles des règles du "
             "protocole** (la chaîne au plus grand travail l'emporte), pas des essais du code ; ils sont comparés aux formules publiées.".replace(",", " "), "",
             "## 1. Minage égoïste (Eyal et Sirer)", "",
             "Un groupe de mineurs retient ses blocs pour gagner plus que sa part. `γ` est la part des autres mineurs qui "
             "suivent le groupe en cas d'égalité. Un résultat **au-dessus de la puissance du groupe** signifie que tricher paie.", "",
             "| Puissance α | γ | Part des blocs (simulée) | Formule publiée | Tricher paie ? |", "|---|---|---|---|---|"]
    for alpha, gamma, simulated, formula in results["selfish"]:
        lines.append(f"| {alpha:.0%} | {gamma} | {simulated:.3f} | {formula:.3f} | {'**oui**' if simulated > alpha + 0.005 else 'non'} |")
    lines += ["", "Seuil : avec γ = 0 le minage égoïste commence à payer vers **un tiers** de la puissance ; avec γ = 0,5 vers **un quart** ; "
              "avec γ = 1, dès qu'on a de la puissance. **Aucune règle de Nova ne l'empêche** : c'est une propriété de la preuve de travail.", "",
              "## 2. Effacer un paiement confirmé", "",
              "| Puissance de l'attaquant | Confirmations | Simulé | Modèle exact |", "|---|---|---|---|"]
    for q, z, simulated, formula in results["double"]:
        lines.append(f"| {q:.0%} | {z} | {simulated:.3f} | {formula:.3f} |")
    lines += ["", "## 3. Blocs concurrents selon la latence du réseau", "",
              "Part des blocs qui ont un concurrent trouvé avant d'avoir pu être connu : du travail perdu, et un réseau plus facile à diviser.", "",
              "| Temps de bloc | Latence de propagation | Simulé | Formule 1 − e^(−Δ/T) |", "|---|---|---|---|"]
    for block_seconds, delay, simulated, formula in results["forks"]:
        lines.append(f"| {block_seconds} s | {delay} s | {simulated:.3f} | {formula:.3f} |")
    lines += ["", "## 4. Si la puissance de calcul change brutalement", "",
              "Temps moyen entre deux blocs, fenêtre après fenêtre (20 blocs), avec la **vraie règle d'ajustement** du protocole. "
              "Cible : 60 s. Moyenne sur 200 essais.", "",
              "| Puissance | Fenêtre 1 | Fenêtre 2 | Fenêtre 3 | Fenêtre 4 | Fenêtre 5 | Fenêtre 6 | Temps total perdu au-dessus de la cible |",
              "|---|---|---|---|---|---|---|---|"]
    for label, row, lost in results["difficulty"]:
        lines.append(f"| {label} | " + " | ".join(f"{v:.1f} s" for v in row) + f" | {lost / 60:.0f} min |")
    lines += ["", "Si 90 % des mineurs partent, les blocs deviennent 10 fois plus lents et il faut plusieurs fenêtres (chacune limitée à ×4) "
              "pour revenir à 60 s : le réseau reste **très lent pendant plusieurs dizaines de minutes**, puis redevient normal sans intervention. "
              "À l'inverse, une arrivée massive accélère les blocs (donc plus de blocs concurrents) jusqu'à l'ajustement suivant.", ""]
    lines += ["", "**Lecture** : avec 10 secondes par bloc (versions 3 à 12), une latence réaliste sur Internet (1 à 2 s) produisait 10 à 18 % de blocs concurrents. "
              "**Depuis la V13, le temps de bloc est de 60 s** : 2 s de latence donnent environ 3 % de blocs concurrents. Bitcoin, à 600 s, reste sous 1 %.", ""]
    return "\n".join(lines)


def run(blocks=400_000, seed=1):
    rng = random.Random(seed)
    selfish = [(a, g, selfish_revenue(a, g, blocks, rng), selfish_formula(a, g))
               for a, g in ((0.10, 0.5), (0.25, 0.0), (0.25, 0.5), (0.30, 0.5), (0.33, 0.0), (0.35, 0.0), (0.40, 0.0), (0.45, 0.5))]
    from novacoin.attack_bench import exact_catch_up_probability as catch_up_probability
    trials = max(20_000, blocks // 5)
    double = [(q, z, double_spend_probability(q, z, trials, rng), catch_up_probability(q, z))
              for q, z in ((0.10, 6), (0.25, 3), (0.25, 6), (0.30, 6), (0.40, 6), (0.40, 12))]
    forks = [(t, d, fork_rate(t, d, blocks, rng), 1 - math.exp(-d / t)) for t, d in ((10, 1), (10, 2), (60, 1), (60, 2), (60, 5), (600, 2))]
    difficulty = []
    for label, factor in (("÷10 (90 % des mineurs partent)", 0.1), ("÷2", 0.5), ("×4", 4), ("×10", 10)):
        runs = [difficulty_response(factor, 6, rng) for _ in range(200)]
        row = [sum(r[i] for r in runs) / len(runs) for i in range(6)]
        lost = sum(max(0, v - 10) * 20 for v in row)
        difficulty.append((label, row, lost))
    return {"selfish": selfish, "double": double, "forks": forks, "difficulty": difficulty}


if __name__ == "__main__":
    import os
    os.environ.setdefault("NOVA_EASY", "1")
    parser = argparse.ArgumentParser()
    parser.add_argument("--blocks", type=int, default=400_000)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--out", default="RAPPORT-SIMULATIONS.md")
    args = parser.parse_args()
    report = render(run(args.blocks, args.seed), args.blocks, args.seed)
    Path(args.out).write_text(report)
    print(report)
