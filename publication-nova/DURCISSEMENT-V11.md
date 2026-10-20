# Durcissement V11 — ce qui a été fait, et ce qui ne l'est pas

Version **1.1.0rc1**, réseau **`nova-testnet-2`**. L'objectif : renforcer Nova **sans aide extérieure**.
Chaque ligne indique le fichier concerné, le test qui la protège, et ses limites. « Sur le papier » ne veut pas dire
« sûr » : rien ici n'a été audité par un tiers.

## Réseau et nœuds
| Protection | Où | Test | Limite honnête |
|---|---|---|---|
| Clé d'identité du nœud **chiffrée** (mot de passe par variable d'environnement ou fichier, commandes `key-protect` / `key-unprotect`) | `p2p.py`, `cli.py` | `test_v11` | Le mot de passe doit être fourni à chaque démarrage ; la clé reste en mémoire pendant l'exécution |
| **Bannissements conservés** après redémarrage | `node.py` | `test_v11` | Un attaquant qui change d'identité repart de zéro |
| **Au plus 2 pairs par réseau /16** et la moitié de la table réservée aux pairs choisis par l'opérateur (anti-éclipse) | `node.py` | `test_v11` | Le laboratoire local (127.0.0.1) est exempté ; ne remplace pas un vrai réseau varié |
| **Alertes** à l'opérateur : isolement, aucun/un seul pair, horloge décalée, aucun bloc récent, version plus récente chez un pair, risque d'éclipse, journal altéré, clé non chiffrée, bannissements | `node.py`, tableau de bord | `test_v11` | Visibles seulement si quelqu'un regarde |
| **Journal chaîné par empreintes et signé** par la clé du nœud | `node.py` | `test_v11` | Détecte l'altération, ne l'empêche pas ; seuls les 200 derniers événements sont gardés |
| **Budget de débit** par pair pour les blocs servis, **limites de taille par route**, **échéance globale** de 15 s par requête | `node.py` | `test_v11b`, `test_p2pfuzz` | Réglages à ajuster selon l'usage réel |
| **Coût d'identité** (anti-Sybil) : une identité de nœud n'est acceptée qu'avec une preuve de travail (22 bits, quelques secondes une fois ; mille fausses identités coûtent des heures) | `p2p.py`, `node.py` | `test_security` | Ne bloque pas un attaquant qui dispose de beaucoup de calcul ; pas de limite sur la durée de vie d'une identité |
| **Fuzzing du réseau** (bruit, HTTP malformé, requêtes signées hostiles) | `tests/test_p2pfuzz.py` | idem | 260 entrées par exécution, pas des heures |
| **Auto-test cryptographique** au démarrage (vecteurs SHA-256 et Ed25519 connus, AES-GCM) : le nœud refuse de démarrer si une primitive est défaillante | `selftest.py` | `test_v11b` | Ne détecte que les défaillances grossières |
| **Réparation des droits de fichiers** (dossier, clé, jeton) et trace dans le journal | `node.py` | `test_v11b` | Systèmes de type Unix |
| **Rotation du jeton administrateur** (`token-rotate`, nœud arrêté) | `cli.py` | `test_v11b` | Manuelle |

## Chaîne
| Protection | Où | Test | Limite honnête |
|---|---|---|---|
| **Points de contrôle automatiques** (un bloc sur cent, enterré à 50 blocs ou plus), conservés ; fichier officiel chargeable (`--checkpoints-file`, outil `tools/make_checkpoints.py`) | `node.py` | `test_v11` | Une levée explicite de la limite de réorganisation (`reorg-limit 0`) les met de côté |
| **Plus de preuve pour effacer plus de blocs** : au-delà de 6 blocs, la branche concurrente doit porter 10 % de travail de plus que la branche effacée (25 % au-delà de 20) | `node.py` | `test_v11` | Politique locale ; peut retarder la réunion de deux moitiés d'un réseau coupé |
| **Test de coupure brutale** : `kill -9` répété d'un nœud qui mine et paie ; la base reste cohérente et passe le vérificateur indépendant | `tests/test_crash.py` | idem | Simule l'arrêt du processus, pas la perte d'alimentation du disque |

## Portefeuille
| Protection | Où | Test | Limite honnête |
|---|---|---|---|
| **Multisignature m-parmi-n** (n ≤ 5) et **paiements verrouillés par date** — **changement de règles : nouveau réseau `nova-testnet-2`** | `core.py`, `wallet.py`, `cli.py`, `PROTOCOLE.md`, `tools/independent_check.py` | `test_multisig` | Identifiant de transaction malléable par les signataires ; clés à gérer par des personnes différentes pour que cela serve |
| **Sauvegarde chiffrée vérifiée** (`hd-backup`, `hd-check-backup`) | `hdwallet.py` | `test_v11` | Une sauvegarde au même endroit que l'original ne protège pas d'un incendie |
| **Verrouillage du portefeuille** (manuel et après inactivité) | `hdwallet.py` | `test_v11` | En mémoire seulement, pas d'effacement garanti en Python |

## Livraison
| Protection | Où | Test | Limite honnête |
|---|---|---|---|
| **Signature des archives** par une clé de publication (Ed25519), vérifiée avec une clé **de confiance** et non celle du fichier | `release_sign.py`, `tools/build_release.py` | `test_v11` | La clé de publication doit être générée et gardée hors ligne par le propriétaire : **aucune n'a été créée** |
| **Manifeste des fichiers** dans l'archive et `tools/verify_install.py` (sans dépendance au paquet vérifié) | `tools/` | `test_v11b` | Ne vaut que si le manifeste lui-même vient d'une archive dont la signature est vérifiée |
| Archive reproductible | `tools/build_release.py` | `test_release` | — |

## Ce qui n'a PAS été fait (par choix ou faute de moyen)
- ~~Chaîne hors mémoire~~ : **faite en V12** (voir [AMELIORATIONS-V12.md](AMELIORATIONS-V12.md)) ; restent en mémoire l'ensemble des pièces non dépensées, la liste des empreintes et, à la demande, l'index de l'explorateur.
- **Anti-Sybil réel** : rien n'empêche de créer des milliers d'identités ; les limites par réseau et par adresse aident, sans suffire.
- **Preuve de travail résistante à une attaque majoritaire** : aucune astuce de code ne remplace la puissance de calcul honnête.
- **Audit indépendant**, **relecture humaine** de la spécification, **essais de plusieurs jours** sur plusieurs machines.
- **Garde de la clé de publication** : les commandes `release-keygen` et `release-sign` existent depuis la V12, mais la clé doit être créée et gardée par le propriétaire, hors ligne : **aucune n'a été créée**.
- **Chiffrement du port local** (reste en HTTP sur 127.0.0.1) et **protection contre un système d'exploitation compromis**.
