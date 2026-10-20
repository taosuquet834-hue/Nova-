"""Run the actual tests and save a reproducible validation report."""
import argparse
import hashlib
import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path


def source_digest(root):
    digest = hashlib.sha256()
    paths = sorted(list((root / "novacoin").glob("*.py")) +
                   list((root / "novacoin").glob("*.html")) +
                   list((root / "tests").glob("*.py")) +
                   [root / "pyproject.toml", root / "requirements.txt", root / "requirements-dev.txt"])
    for path in paths:
        digest.update(str(path.relative_to(root)).encode() + b"\0" + path.read_bytes())
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description="Vérifier Nova V13 et produire un rapport")
    parser.add_argument("--output", default=".local/validation")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    xml = output / "tests.xml"
    xml.unlink(missing_ok=True)
    before = source_digest(root)
    print("Vérification du consensus, des coupures, des reprises et du lanceur…", flush=True)
    result = subprocess.run([sys.executable, "-m", "pytest", "-q", "--junitxml=" + str(xml)],
                            cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    (output / "tests.log").write_text(result.stdout)
    suites = list(ET.parse(xml).getroot().iter("testsuite")) if xml.exists() else []
    totals = {key: sum(int(s.get(key, "0")) for s in suites)
              for key in ("tests", "failures", "errors", "skipped")}
    after = source_digest(root)
    passed = result.returncode == 0 and totals["tests"] > 0 and totals["skipped"] == 0 and before == after
    report = {"version": "1.0.0rc1", "timestamp_utc": datetime.now(timezone.utc).isoformat(),
              "source_sha256": after, "sources_unchanged": before == after,
              "passed": passed, "exit_code": result.returncode, **totals}
    (output / "report.json").write_text(json.dumps(report, indent=2))
    (output / "RAPPORT.md").write_text(
        "# Vérification Nova V13\n\n"
        f"Résultat : **{'RÉUSSI' if passed else 'ÉCHEC'}**\n\n"
        f"- Tests : {totals['tests']}\n- Échecs : {totals['failures']}\n"
        f"- Erreurs : {totals['errors']}\n- Ignorés : {totals['skipped']}\n"
        f"- Date UTC : {report['timestamp_utc']}\n- Empreinte des sources : `{after}`\n\n"
        "Les tests utilisent des dossiers temporaires et des ports locaux dédiés. "
        "Ils ne modifient pas les portefeuilles de la démonstration.\n\n"
        "Ce résultat valide les scénarios automatisés présents ; il ne constitue pas un audit indépendant.\n")
    print(result.stdout[-2000:], end="")
    print(f"Rapport : {output / 'RAPPORT.md'}")
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
