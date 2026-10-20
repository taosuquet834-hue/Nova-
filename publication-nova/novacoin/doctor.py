"""Pre-flight check for node operators: `python -m novacoin doctor`."""
from __future__ import annotations

import os
import shutil
import socket
import ssl
import stat
import sys
import tempfile
from pathlib import Path


def _port_free(port, host="127.0.0.1"):
    with socket.socket() as sock:
        try:
            sock.bind((host, port))
            return True
        except OSError:
            return False


def checks(data_dir, port, p2p_port):
    """Yield (status, label, advice); status is OK, WARN or FAIL."""
    yield ("OK" if sys.version_info >= (3, 11) else "FAIL", f"Python {sys.version.split()[0]}",
           "Python 3.11 ou plus récent est nécessaire")
    yield ("OK" if ssl.HAS_TLSv1_3 else "FAIL", f"TLS 1.3 disponible ({ssl.OPENSSL_VERSION})",
           "Les échanges entre nœuds exigent TLS 1.3 : mettre à jour Python / OpenSSL")
    try:
        import cryptography
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        Ed25519PrivateKey.generate().sign(b"test")
        yield "OK", f"cryptography {cryptography.__version__}, Ed25519 fonctionnel", ""
    except Exception as exc:  # pragma: no cover - environment dependent
        yield "FAIL", "Bibliothèque cryptography absente ou défaillante", str(exc)
    try:
        from .selftest import run_selftest
        run_selftest()
        yield "OK", "Auto-test cryptographique (SHA-256, Ed25519, AES-GCM)", ""
    except Exception as exc:  # pragma: no cover - environment dependent
        yield "FAIL", "Auto-test cryptographique échoué", str(exc)
    for label, number in (("local", port), ("des pairs", p2p_port)):
        free = _port_free(number)
        yield ("OK" if free else "WARN", f"Port {label} {number} " + ("libre" if free else "occupé"),
               "Un autre programme (ou un nœud déjà lancé) l'utilise : choisir un autre port")
    data = Path(data_dir)
    parent = data if data.exists() else data.parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=parent):
            pass
        yield "OK", f"Écriture possible dans {parent}", ""
    except OSError as exc:
        yield "FAIL", f"Écriture impossible dans {parent}", str(exc)
    free = shutil.disk_usage(parent).free / 2 ** 30
    yield ("OK" if free >= 1 else "WARN", f"Espace disque libre : {free:.1f} Go", "Prévoir au moins 1 Go")
    if data.exists():
        mode = stat.S_IMODE(data.stat().st_mode)
        yield ("OK" if mode & 0o077 == 0 else "WARN", f"Droits du dossier de données : {oct(mode)}",
               "Le dossier contient la clé d'identité du nœud : chmod 700")
        key = data / "node.key"
        if key.exists() and b"ENCRYPTED" not in key.read_bytes()[:64]:
            yield "WARN", "La clé d'identité du nœud n'est pas chiffrée", "python -m novacoin key-protect --data " + str(data)
        if key.exists():
            kmode = stat.S_IMODE(key.stat().st_mode)
            yield ("OK" if kmode & 0o077 == 0 else "FAIL", f"Droits de node.key : {oct(kmode)}", "chmod 600 node.key")
    if os.environ.get("NOVA_EASY") == "1":
        yield "WARN", "NOVA_EASY=1 : réseau de laboratoire sans difficulté", "À ne jamais utiliser sur un réseau partagé"
    yield "WARN", "Horloge système", ("Les échanges refusent plus de 60 s d'écart : activer la synchronisation "
                                       "automatique de l'heure (non vérifiable ici)")


def run_doctor(data_dir, port, p2p_port):
    worst = 0
    for status, label, advice in checks(data_dir, port, p2p_port):
        print(f"[{status:<4}] {label}" + (f"\n         → {advice}" if status != "OK" and advice else ""))
        worst = max(worst, {"OK": 0, "WARN": 0, "FAIL": 1}[status])
    print("\nRésultat : " + ("des problèmes bloquants" if worst else "prêt (vérifier les avertissements)"))
    return worst
