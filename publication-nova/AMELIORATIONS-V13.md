# Améliorations V13 (1.3.0rc1) — nouveau réseau `nova-testnet-3`

**Changement de règles de la chaîne : la V13 ne parle pas aux versions précédentes** (nouvel identifiant de réseau, nouveau
genesis, identifiants de paiement différents). La V12 et les précédentes restent intactes dans leurs dossiers.
Ces deux changements viennent de ce que les simulations de la V12 avaient montré.

## 1. 60 secondes par bloc au lieu de 10
- `TARGET_SECONDS = 60`. Avec 10 s par bloc, 1 à 2 s de latence sur Internet produisaient **10 à 18 %** de blocs
  concurrents (du travail perdu, un réseau plus facile à diviser). À 60 s, 2 s de latence donnent **environ 3 %**
  (`RAPPORT-SIMULATIONS.md`). Bitcoin, à 600 s, reste sous 1 %.
- Difficulté de départ **22 bits** (au lieu de 20) pour viser ~60 s avec un mineur Python sur un cœur. Les autres bornes
  sont inchangées (16 à 96 bits, fenêtre de 20 blocs, facteur ×4, blocs médians).
- Conséquences : maturité des récompenses (2 blocs) = 2 minutes ; une fenêtre d'ajustement = 20 minutes ; si 90 % des
  mineurs partent, le retour à la normale prend plusieurs dizaines de minutes (simulation 4 du rapport).
- **Pour essayer sans attendre : le lanceur utilise maintenant le réseau de laboratoire** (`python -m novacoin.demo --lab`,
  et `Lancer Nova.command`). Le tableau de bord affiche « laboratoire ». Sans `--lab`, le lanceur démarre le vrai réseau
  d'essai, où un bloc prend environ une minute.

## 2. L'identifiant d'un paiement ne dépend plus des signatures
- `transaction_id` = empreinte du paiement **sans** `signature` (et sans `multisig.signatures`). Re-signer un paiement ne change
  plus son identifiant : fin de la malléabilité (un tiers ne peut plus invalider un paiement enchaîné en le re-signant).
- Les signatures restent vérifiées et font partie des octets du bloc, mais **ne sont pas engagées par la racine de Merkle** :
  deux variantes signées différemment du même paiement ne peuvent pas figurer dans le même bloc (identifiant dupliqué).
- Mis à jour et testé contre le vérificateur indépendant (`tools/independent_check.py`) et la spécification (`PROTOCOLE.md`).

## Défaut trouvé pendant ce travail
Le fuzzing du banc d'attaques a trouvé, dès la première exécution, que mon nouveau calcul d'identifiant plantait (erreur interne)
quand « le paiement » était un entier ou du texte au lieu d'un objet : il est maintenant refusé proprement comme avant.

## Limites
Un temps de bloc de 60 s ralentit les confirmations (6 confirmations ≈ 6 minutes) ; les paramètres de mise en œuvre
(fenêtre d'ajustement, tolérance d'horloge de 60 s, limites de réorganisation exprimées en blocs) n'ont pas été
réévalués finement pour ce nouveau rythme. Toujours aucun audit indépendant.
