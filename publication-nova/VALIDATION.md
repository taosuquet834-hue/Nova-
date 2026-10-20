# Validation de Nova V13 (1.3.0rc1, réseau nova-testnet-3) — version gelée

Validation du 20 octobre 2026 par `python tools/release_check.py` (empreinte des sources `c6346b4a…d6723af2`).
Les versions V1 à V12 restent intactes dans leurs dossiers. Détail des changements : [AMELIORATIONS-V13.md](AMELIORATIONS-V13.md).

- Python 3.12.10, OpenSSL 3.0.16, cryptography 50.0.0, pytest 9.1.1.
- **208 tests réussis, 0 échec, 0 erreur, 0 ignoré** (205 en V12 ; 3 nouveaux sur l'identifiant de paiement), fuzzing du réseau
  et coupures brutales compris.
- **Banc d'attaques** : 9 scénarios tiennent, 0 cassent, 1 inhérent à la preuve de travail.
- **Essais de longue durée** : 3 minutes (4 nœuds) pendant le contrôle, puis **7 minutes, 5 nœuds, 17 coupures, 105 paiements :
  hauteur finale identique (153) sur les 5 nœuds, offre monétaire exacte à chaque étape.**
- **Démarrage réel** (vraie difficulté 22 bits, blocs de 60 s) : prêt en 14 s, trois nœuds d'accord, un premier bloc en
  150 s (le temps moyen visé est d'environ une minute par bloc ; un seul bloc ne mesure pas le rythme).
- **Mode laboratoire** (`--lab`, défaut du lanceur) : prêt en 1 s, paiement de 10 NOVA confirmé (Alice 240, Bob 10).
- **Vérificateur indépendant** et spécification mis à jour pour les nouveaux identifiants, le temps de bloc de 60 s et la
  difficulté de départ ; il accepte les chaînes du nœud (paiements simples, multisignatures, verrouillages) et rejette les falsifications testées.
- **Archive** reproductible (deux constructions identiques), 75 fichiers, manifeste inclus, aucun secret ni cache.

Défauts trouvés et corrigés pendant ce travail :
1. Le fuzzing a trouvé en quelques secondes une erreur interne dans mon nouveau calcul d'identifiant (entrée qui n'est pas un objet) : corrigé.
2. Mes horloges simulées de test ne remontaient que de 10 000 s : suffisant à 10 s par bloc, pas à 60 s (les mineurs attendaient alors
   le temps réel) ; marge portée à plusieurs millions de secondes. Dix minutes de test perdues à comprendre pourquoi, aucun défaut du nœud.
3. Plusieurs tests supposaient 10 s par bloc (pas de 10 s, fenêtres, difficulté de départ) : rendus indépendants de la constante.

Limites : un seul bloc réel observé sur le vrai réseau (150 s) ; essais de quelques minutes sur une seule machine ; paramètres
secondaires (fenêtre d'ajustement, tolérance d'horloge, limites de réorganisation en blocs) non réévalués pour 60 s ; aucune clé de
publication créée ; aucun audit indépendant ni relecture humaine. Tout ce qui précède est une validation par l'auteur du code.
