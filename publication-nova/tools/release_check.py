#!/usr/bin/env python3
"""Pre-publication check. Runs everything that can be checked by machine and writes RELEASE-CHECKLIST.md.

It never publishes, uploads or contacts anything. The decisions only a person can take are listed at the end.
Usage: python tools/release_check.py [--soak-minutes 1]
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))
import build_release  # noqa: E402

REQUIRED_DOCS = ["README.md", "README.en.md", "LISEZ-MOI.md", "PROTOCOLE.md", "TESTNET.md", "SECURITY.md",
                 "CHANGELOG.md", "VALIDATION.md", "RAPPORT-ATTAQUES.md", "AUDIT-INTERNE.md",
                 "CAHIER-AUDIT-EXTERNE.md", "LIMITES-ET-AVERTISSEMENTS.md", "JURIDIQUE-A-VALIDER.md",
                 "LICENSE", "CONTRIBUTING.md", "DURCISSEMENT-V11.md", "AMELIORATIONS-V12.md", "AMELIORATIONS-V13.md", "RAPPORT-SIMULATIONS.md", "seeds.txt", "requirements.txt", "pyproject.toml"]
SENSITIVE = re.compile(r"(\.token$|\.pem$|\.key$|\.crt$|\.sqlite3|\.password$|/\.local/|__pycache__|\.pytest_cache|\.DS_Store)")


def run(command, **kwargs):
    started = time.time()
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, **kwargs)
    return result, time.time() - started


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--soak-minutes", type=float, default=1)
    args = parser.parse_args()
    py, rows = sys.executable, []

    def record(name, ok, detail):
        rows.append((name, ok, detail))
        print(("OK    " if ok else "ÉCHEC ") + name + " — " + detail, flush=True)

    result, took = run([py, "-m", "novacoin.verify"])
    tail = [line for line in result.stdout.splitlines() if "passed" in line or "failed" in line]
    record("Suite de tests complète", result.returncode == 0, (tail[-1] if tail else "aucune sortie") + f" ({took:.0f} s)")

    result, took = run([py, "-m", "novacoin.attack_bench", ".local/attacks"])
    held = result.stdout.count("TIENT")
    broke = [l for l in result.stdout.splitlines() if l.startswith("CASSE")]
    inherent = [l for l in broke if "plus puissant" in l]
    record("Banc d'attaques", len(broke) == len(inherent) and held >= 9,
           f"{held} tiennent, {len(broke) - len(inherent)} cassent, {len(inherent)} inhérent (puissance majoritaire)")

    result, took = run([py, "tools/soak.py", "--minutes", str(args.soak_minutes), "--nodes", "4", "--seed", "21"])
    record("Essai de longue durée", result.returncode == 0, result.stdout.strip().splitlines()[-1][:160]
           if result.stdout.strip() else result.stderr[-200:])

    with tempfile.TemporaryDirectory() as one, tempfile.TemporaryDirectory() as two:
        first, second = build_release.build(ROOT, one), build_release.build(ROOT, two)
        record("Archive reproductible", first["sha256"] == second["sha256"],
               f"deux constructions : {first['sha256'][:16]}… identiques" if first["sha256"] == second["sha256"]
               else "empreintes différentes")
        names = zipfile.ZipFile(Path(one) / first["archive"]).namelist()
        leaks = [n for n in names if SENSITIVE.search(n)]
        record("Aucun secret ni cache dans l'archive", not leaks, f"{len(names)} fichiers" if not leaks else str(leaks[:5]))

    missing = [d for d in REQUIRED_DOCS if not (ROOT / d).exists()]
    record("Documents requis présents", not missing, "tous présents" if not missing else f"manquent : {missing}")

    version = build_release.version()
    pyproject = re.search(r'version = "([^"]+)"', (ROOT / "pyproject.toml").read_text()).group(1)
    record("Version cohérente", pyproject == version and version in (ROOT / "README.md").read_text(), version)

    network = re.search(r'NETWORK = "([^"]+)-easy" if EASY else "([^"]+)"', (ROOT / "novacoin/core.py").read_text()).group(2)
    stale = [p.name for p in ROOT.rglob("*") if p.is_file() and p.suffix in (".py", ".md", ".html")
             and "nova-independent-test" in p.read_text(errors="ignore")
             and p.name not in ("CHANGELOG.md", "LISEZ-MOI.md", "release_check.py", "test_release.py")]
    record("Identifiant de réseau cohérent", not stale and network in (ROOT / "PROTOCOLE.md").read_text(),
           network if not stale else f"ancien identifiant dans {stale}")

    placeholders = sorted({p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*.md") if "A_COMPLETER" in p.read_text()}
                          - {"RELEASE-CHECKLIST.md"})
    record("Champs à compléter signalés", True, f"{len(placeholders)} fichier(s) : {', '.join(placeholders) or 'aucun'}")
    license_text = (ROOT / "LICENSE").read_text() if (ROOT / "LICENSE").exists() else ""
    record("Licence", "GNU AFFERO GENERAL PUBLIC LICENSE" in license_text and "Version 3" in license_text,
           "AGPL-3.0 présente" if license_text else "LICENSE absent")

    lines = ["# Liste de contrôle avant publication", "",
             f"Générée par `tools/release_check.py` le {time.strftime('%d/%m/%Y %H:%M', time.gmtime())} UTC "
             f"pour la version **{version}**, réseau **{network}**. Rien n'a été publié, envoyé ni téléversé.", "",
             "## Contrôles automatiques", "", "| Contrôle | Résultat | Détail |", "|---|---|---|"]
    lines += [f"| {n} | {'OK' if ok else '**ÉCHEC**'} | {d} |" for n, ok, d in rows]
    lines += ["", "## Décisions et actions qui reviennent à une personne", "",
              "- [ ] **Renseigner le contact de sécurité** dans `SECURITY.md` (champ `A_COMPLETER`).",
              "- [ ] **Faire valider les points juridiques** de `JURIDIQUE-A-VALIDER.md` par un juriste, et vérifier que le nom « Nova » est utilisable.",
              "- [ ] **Décider où et comment publier** (dépôt de code, page, annonce) et relire les textes publics : aucune promesse de valeur.",
              "- [ ] **Faire relire par des humains compétents** `PROTOCOLE.md` et le code (`CAHIER-AUDIT-EXTERNE.md`) ; idéalement un audit avant d'ouvrir le réseau à des inconnus.",
              "- [ ] **Renseigner `seeds.txt`** avec les nœuds que vous exploiterez vraiment, après vérification de leurs identifiants.",
              "- [ ] **Exploiter au moins 3 nœuds sur des machines et des réseaux différents** pendant plusieurs jours avant l'ouverture (les essais faits ici durent quelques minutes sur une seule machine).",
              "- [ ] **Vérifier l'archive finale** (`dist/SHA256SUMS`) sur une machine propre : `python -m novacoin doctor`, `python -m novacoin.demo`.",
              "- [ ] **Annoncer une durée de vie** du réseau d'essai et le droit de le réinitialiser.", ""]
    (ROOT / "RELEASE-CHECKLIST.md").write_text("\n".join(lines))
    failed = [n for n, ok, _ in rows if not ok]
    print("\nRésultat :", "ÉCHEC : " + ", ".join(failed) if failed else "tous les contrôles automatiques passent")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
