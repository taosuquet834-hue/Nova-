import os
import random
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import simulate  # noqa: E402


def test_selfish_mining_matches_the_published_formula():
    rng = random.Random(5)
    for alpha, gamma in ((0.25, 0.5), (0.35, 0.0), (0.40, 0.5)):
        measured = simulate.selfish_revenue(alpha, gamma, 400_000, rng)
        assert measured == pytest.approx(simulate.selfish_formula(alpha, gamma), abs=0.01), (alpha, gamma)


def test_selfish_mining_threshold_behaviour():
    rng = random.Random(9)
    assert simulate.selfish_formula(1 / 3, 0) == pytest.approx(1 / 3, abs=1e-9)            # break-even at one third, gamma 0
    assert simulate.selfish_revenue(0.2, 0.0, 300_000, rng) < 0.2                          # cheating does not pay below it
    assert simulate.selfish_revenue(0.40, 0.0, 300_000, rng) > 0.40 + 0.01                 # and pays well above it
    assert simulate.selfish_revenue(0.0, 0.5, 1000, rng) == 0


def test_double_spend_simulation_agrees_with_the_exact_model_and_nakamoto_is_optimistic():
    from novacoin.attack_bench import catch_up_probability, exact_catch_up_probability
    rng = random.Random(7)
    for q, z in ((0.10, 6), (0.30, 6), (0.40, 6)):
        assert simulate.double_spend_probability(q, z, 40_000, rng) == pytest.approx(exact_catch_up_probability(q, z), abs=0.012), (q, z)
    # the white paper's Poisson approximation understates the risk (30 %, 6 confirmations: 13 % against 16 %)
    assert catch_up_probability(0.3, 6) < exact_catch_up_probability(0.3, 6) - 0.02
    assert exact_catch_up_probability(0.51, 6) == 1.0 and exact_catch_up_probability(0.3, 0) == 1.0


def test_fork_rate_follows_the_latency_formula_and_explains_the_block_time():
    import math
    rng = random.Random(3)
    assert simulate.fork_rate(10, 2, 200_000, rng) == pytest.approx(1 - math.exp(-0.2), abs=0.006)
    assert simulate.fork_rate(600, 2, 200_000, rng) < 0.01                                   # Bitcoin's block time
    assert simulate.fork_rate(10, 2, 200_000, rng) > 0.15                                    # the old 10 s block time on a 2 s network
    assert simulate.fork_rate(60, 2, 200_000, rng) < 0.04                                    # the V13 block time on the same network


def test_difficulty_recovers_after_a_hash_power_shock_using_the_real_retarget_code():
    rng = random.Random(2)
    from novacoin.core import TARGET_SECONDS as T
    stable = [sum(simulate.difficulty_response(1.0, 4, rng)[i] for _ in range(60)) / 60 for i in range(4)]
    assert all(0.7 * T < v < 1.4 * T for v in stable)                        # a steady network stays near the target
    drop = [sum(simulate.difficulty_response(0.1, 6, rng)[i] for _ in range(80)) / 80 for i in range(6)]
    assert drop[0] > 7 * T                                                   # first window: about ten times too slow
    assert drop[1] < drop[0] / 2.5 and drop[2] < drop[1] * 1.2               # each window recovers, capped at x4 per window
    assert drop[-1] < 2 * T                                                  # and it ends near the target
    surge = [sum(simulate.difficulty_response(10, 4, rng)[i] for _ in range(80)) / 80 for i in range(4)]
    assert surge[0] < 0.2 * T and surge[-1] > surge[0]                       # too fast at first, then pulled back


def test_simulations_are_reproducible_and_the_report_renders(tmp_path):
    assert simulate.run(20_000, 4) == simulate.run(20_000, 4)
    out = tmp_path / "r.md"
    done = subprocess.run([sys.executable, str(ROOT / "tools" / "simulate.py"), "--blocks", "30000", "--out", str(out)],
                          text=True, capture_output=True, env={**os.environ, "NOVA_EASY": "1"})
    assert done.returncode == 0
    text = out.read_text()
    assert "Minage égoïste" in text and "Modèle exact" in text and "latence" in text.lower() and "un tiers" in text
