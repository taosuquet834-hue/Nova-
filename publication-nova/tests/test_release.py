"""V10: the release package is reproducible, clean and complete; undecided matters stay undecided."""
import json
import re
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import build_release  # noqa: E402

SENSITIVE = re.compile(r"(\.token$|\.pem$|\.key$|\.crt$|\.sqlite3|\.password$|/\.local/|__pycache__|\.pytest_cache|\.DS_Store|\.zip$)")


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    one, two = tmp_path_factory.mktemp("a"), tmp_path_factory.mktemp("b")
    return build_release.build(ROOT, one), build_release.build(ROOT, two), one, two


def test_build_is_reproducible(built):
    first, second, one, two = built
    assert first == second
    assert (one / first["archive"]).read_bytes() == (two / second["archive"]).read_bytes()
    assert (one / "SHA256SUMS").read_text() == f"{first['sha256']}  {first['archive']}\n"
    release = json.loads((one / "RELEASE.json").read_text())
    assert release["version"] == "1.3.0rc1" and release["network"].startswith("nova-testnet-3")


def test_archive_is_clean_and_normalised(built):
    first, _, one, _ = built
    with zipfile.ZipFile(one / first["archive"]) as zf:
        names = zf.namelist()
        assert names == sorted(names) and not [n for n in names if SENSITIVE.search(n)]
        assert all(i.date_time == build_release.FIXED_DATE for i in zf.infolist())
        modes = {i.filename.rsplit("/", 1)[-1]: i.external_attr >> 16 for i in zf.infolist()}
        assert modes["Lancer Nova.command"] == 0o755 and modes["node.py"] == 0o644
        assert zf.testzip() is None
    assert f"nova-{first['version']}/novacoin/core.py" in names


def test_required_documents_exist_and_are_not_empty():
    for name in ("README.md", "README.en.md", "LISEZ-MOI.md", "PROTOCOLE.md", "TESTNET.md", "SECURITY.md",
                 "CHANGELOG.md", "VALIDATION.md", "RAPPORT-ATTAQUES.md", "AUDIT-INTERNE.md",
                 "CAHIER-AUDIT-EXTERNE.md", "LIMITES-ET-AVERTISSEMENTS.md", "JURIDIQUE-A-VALIDER.md",
                 "LICENSE", "CONTRIBUTING.md", "DURCISSEMENT-V11.md", "AMELIORATIONS-V12.md", "AMELIORATIONS-V13.md", "RAPPORT-SIMULATIONS.md", "seeds.txt"):
        assert (ROOT / name).stat().st_size > 200, name


def test_licence_is_chosen_and_other_decisions_stay_open():
    licence = (ROOT / "LICENSE").read_text()                                          # chosen by the owner: AGPL-3.0
    assert "GNU AFFERO GENERAL PUBLIC LICENSE" in licence and "Version 3, 19 November 2007" in licence
    assert 'license = {text = "AGPL-3.0-only"}' in (ROOT / "pyproject.toml").read_text()
    assert "A_COMPLETER" in (ROOT / "SECURITY.md").read_text()                       # contact is not invented
    assert "pas un avis juridique" in (ROOT / "JURIDIQUE-A-VALIDER.md").read_text()
    seeds = [l for l in (ROOT / "seeds.txt").read_text().splitlines() if l.split("#")[0].strip()]
    assert seeds == []                                                               # no fake public nodes


def test_public_texts_carry_the_warnings():
    for name in ("README.md", "README.en.md", "LIMITES-ET-AVERTISSEMENTS.md"):
        text = (ROOT / name).read_text().lower()
        assert "aucune valeur" in text or "no value" in text, name
    assert "aucun audit indépendant" in (ROOT / "LIMITES-ET-AVERTISSEMENTS.md").read_text().lower()
    limits = (ROOT / "LIMITES-ET-AVERTISSEMENTS.md").read_text()
    assert "préminage" in limits and "16 %" in limits                      # figure checked against the bench


def test_versions_and_network_are_consistent_everywhere():
    from novacoin import __version__, core
    text = (ROOT / "pyproject.toml").read_text()
    assert f'version = "{__version__}"' in text and __version__ in (ROOT / "README.md").read_text()
    assert core.NETWORK.startswith("nova-testnet-3")
    assert "nova-testnet-3" in (ROOT / "PROTOCOLE.md").read_text()
    stale = [p.name for p in ROOT.rglob("*") if p.is_file() and p.suffix in (".py", ".html")
             and ".local" not in p.parts and p.name not in ("test_release.py", "release_check.py")
             and "nova-independent-test" in p.read_text(errors="ignore")]
    assert stale == []
    out = subprocess.run([sys.executable, "-m", "novacoin", "version"], cwd=ROOT, text=True, capture_output=True)
    assert json.loads(out.stdout)["version"] == __version__


def test_changelog_covers_every_version():
    text = (ROOT / "CHANGELOG.md").read_text()
    for version in ["V1", "V2", "V3", "V4", "V5", "V6", "V7", "V8", "V9", "V10", "V11", "V12", "V13"]:
        assert f"| {version}" in text, version


def test_figures_in_the_warnings_match_the_model():
    from novacoin.attack_bench import exact_catch_up_probability
    assert round(exact_catch_up_probability(0.3, 6) * 100) == 16


def test_every_data_file_of_the_package_is_declared_for_installation():
    text = (ROOT / "pyproject.toml").read_text()
    for page in (ROOT / "novacoin").glob("*.html"):
        assert f'"{page.name}"' in text, f"{page.name} would be missing from a pip installation"
    assert 'packages = ["novacoin"]' in text
