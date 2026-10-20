# Cahier des charges pour un audit externe de Nova

À remettre à des auditeurs indépendants avant d'ouvrir le réseau à des tiers. Nova est un
**projet expérimental sans valeur monétaire** ; l'objectif est de savoir si ses garanties tiennent
face à un attaquant déterminé.

## Périmètre

- Code : dossier fourni (Python, environ 5 000 lignes de code applicatif, 1 dépendance : `cryptography`).
- Spécification : `PROTOCOLE.md` (la référence) et `tools/independent_check.py`.
- Travaux déjà faits : `AUDIT-INTERNE.md`, `RAPPORT-ATTAQUES.md`, `VALIDATION.md`.
- Hors périmètre : le système d'exploitation, Python, OpenSSL, le matériel.

## Actifs à protéger

1. L'intégrité de la chaîne (aucune création de pièces hors règles, aucune double dépense confirmée
   par une chaîne honnête).
2. Les clés des portefeuilles (fichiers chiffrés, phrase de récupération).
3. La disponibilité des nœuds honnêtes face à des pairs hostiles.
4. La confidentialité et l'authenticité des échanges entre nœuds.

## Questions précises

1. Les règles de consensus de `PROTOCOLE.md` ont-elles des ambiguïtés ou des cas limites qui
   permettraient à deux implémentations de diverger (fourche accidentelle) ?
2. Y a-t-il une façon de créer des pièces, de dépenser les pièces d'autrui ou de contourner la
   maturité des récompenses ?
3. L'ajustement de difficulté (cible continue, blocs médians, plafond ×4) est-il exploitable (time
   warp, oscillations, blocage) au-delà de ce qui est décrit ?
4. Le transport (TLS 1.3 avec clés Ed25519 épinglées, signatures de requêtes liées au destinataire,
   nonces) résiste-t-il au rejeu, au relais, à l'attaque de l'homme du milieu au premier contact ?
5. Les défenses contre les abus (débit, connexions, bannissement) peuvent-elles être contournées ou
   retournées contre des pairs honnêtes ?
6. Le portefeuille (scrypt, AES-GCM, dérivation PBKDF2/HMAC, phrase de 12 mots, liste de 2048 mots
   propre à Nova) est-il correctement conçu ? Entropie, somme de contrôle, fuite d'information.
7. Exhaustion de ressources : mémoire (ensemble des pièces non dépensées, index de l'explorateur ; les blocs sont sur disque depuis la V12), disque (SQLite WAL), CPU
   (validation de signatures), connexions.
8. Cohérence après arrêt brutal ou disque plein à chaque étape d'écriture.

## Livrables attendus

Un rapport classant les constats par gravité avec, pour chacun, une reproduction minimale ; une
liste de ce qui a été examiné et de ce qui ne l'a pas été ; une relecture des corrections.

## Comment reproduire l'état de l'art du projet

```sh
python -m pip install -r requirements-dev.txt
python -m novacoin.verify                    # tests (plus de 140), rapport reproductible
python -m novacoin.attack_bench              # banc d'attaques
python tools/soak.py --minutes 10            # essai de longue durée
NOVA_EASY=1 python tools/independent_check.py chain.sqlite3
```
