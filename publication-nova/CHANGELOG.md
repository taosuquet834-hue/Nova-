# Historique des versions

Les tests comptent la suite automatisée complète au moment de chaque version.

| Version | Apport principal | Tests |
|---|---|---|
| V1 | Chaîne indépendante : preuve de travail, UTXO, signatures Ed25519, portefeuilles chiffrés, SQLite, deux nœuds, tableau de bord | 48 |
| V2 | Laboratoire de résilience : isoler un nœud, deux historiques, journal d'événements | 58 |
| V3 | Difficulté continue (cible 256 bits, départ 20 bits), minage automatique, synchronisation incrémentale, 3 nœuds, découverte de pairs | 70 |
| V4 | Transport TLS 1.3, identités épinglées, requêtes signées, limites de débit, bannissements, mode fermé | 87 |
| V5 | Portefeuille récupérable : 12 mots, adresses neuves, contacts, restauration | 94 |
| V6 | Consensus durci (nouveau réseau) : version de bloc, horodatages croissants, difficulté sur blocs médians ; politiques de réorganisation, points de contrôle, frais minimaux | 106 |
| V7 | Banc d'attaques ; correction de trois défauts (coût quadratique de la file, file bloquée, recherche d'ancêtre) | 117 |
| V8 | Explorateur de blocs, spécification du protocole, vérificateur indépendant | 132 |
| V9 | Audit interne, durcissement du port local, `doctor`, fichier de pairs, essai de longue durée | 143 |
| V10 / 1.0.0rc1 | Réseau public d'essai `nova-testnet-1`, archive reproductible, documents de publication, liste de contrôle | 152 |

| V11 / 1.1.0rc1 | Durcissement sans aide extérieure (clé chiffrée, bannissements durables, alertes, points de contrôle, journal signé, fuzzing réseau, test de coupure, signature des archives) ; multisignature et verrouillage par date (nouveau réseau `nova-testnet-2`) | voir VALIDATION.md |

| V12 / 1.2.0rc1 | Chaîne dans la base (mémoire bornée, 500 000 blocs), démarrage linéaire, commandes de clé de publication, simulations d'attaques, tables de risque exactes | voir VALIDATION.md |

| V13 / 1.3.0rc1 | Nouveau réseau `nova-testnet-3` : blocs de 60 s, difficulté de départ 22 bits, identifiant de paiement indépendant des signatures ; lanceur en réseau de laboratoire | voir VALIDATION.md |

Compatibilité : la V3 a créé un nouveau réseau, la V6 un autre, la V10 un autre encore (changement
d'identifiant seulement : mêmes règles que la V6), la V11 un autre (nouveaux types de paiements) ; la V12 garde le réseau de la V11 ; la V13 en crée un nouveau (règles de temps et identifiants). Les chaînes d'un réseau ne sont pas lisibles par un autre.
