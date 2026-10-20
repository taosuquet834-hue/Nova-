# Nova V13 — notre blockchain expérimentale

Nova est une monnaie de test sur une blockchain indépendante. Elle fonctionne avec
de vrais blocs, des signatures cryptographiques, une preuve de travail et plusieurs
nœuds qui vérifient le même historique. Le nom est provisoire. Ce projet n'est pas
le réseau Bitcoin et n'est affilié à aucune monnaie existante.

**Version livrée (V13) : laboratoire local fonctionnel, pas réseau financier de production.**
Les pièces sont des unités d'essai. Aucun prix, échange en euros ou rendement n'est prévu.

## Nouveautés de la V13 : 60 secondes par bloc, identifiants de paiement stables

**Nouveau réseau `nova-testnet-3`**, incompatible avec les précédents. Détail : [AMELIORATIONS-V13.md](AMELIORATIONS-V13.md).
Les blocs passent à **60 s** (10 s produisait trop de blocs concurrents sur un vrai réseau) et l'identifiant d'un paiement ne dépend
plus de ses signatures (pas de malléabilité). Le lanceur (`Lancer Nova.command`, `python -m novacoin.demo --lab`) utilise le réseau de
laboratoire pour rester instantané ; sans `--lab`, un bloc prend environ une minute.

## Nouveautés de la V12 : chaîne sur disque, simulations

Même réseau que la V11. Détail : [AMELIORATIONS-V12.md](AMELIORATIONS-V12.md). La chaîne est stockée dans la base et
seuls les 128 derniers blocs sont en mémoire ; le démarrage est linéaire (9,9 s → 0,2 s pour 2 000 blocs) ; les commandes
`release-keygen` / `release-sign` préparent la signature des archives ; `tools/simulate.py` simule le minage égoïste, l'effacement
d'un paiement et les blocs concurrents ([RAPPORT-SIMULATIONS.md](RAPPORT-SIMULATIONS.md)).

## Nouveautés de la V11 : durcissement sans aide extérieure

**Nouveau réseau `nova-testnet-2`** (les paiements de version 2 changent les règles de validation ; les chaînes
précédentes ne sont pas lisibles). Le détail, avec les limites de chaque protection et ce qui n'a pas été fait,
est dans [DURCISSEMENT-V11.md](DURCISSEMENT-V11.md). En bref :

- **Paiements** : multisignature m-parmi-n (adresses `nm1…`, commandes `multisig-address`, `multisig-draft`,
  `multisig-sign`, `multisig-submit`) et paiements **verrouillés jusqu'à une hauteur de bloc** (`locktime`).
- **Nœud** : clé d'identité chiffrable (`key-protect`), bannissements conservés, coût d'identité (preuve de travail
  de 22 bits par identité), limites de pairs par réseau, alertes dans le tableau de bord, journal chaîné et signé,
  budget de débit et limites de taille par route, échéance globale par requête, auto-test cryptographique au
  démarrage, réparation des droits de fichiers, rotation du jeton (`token-rotate`).
- **Chaîne** : points de contrôle automatiques (et fichier officiel `--checkpoints-file`), preuve supplémentaire
  exigée pour effacer beaucoup de blocs.
- **Portefeuille** : sauvegarde chiffrée vérifiée (`hd-backup`), verrouillage.
- **Livraison** : signature des archives (`verify-release`), manifeste des fichiers (`tools/verify_install.py`).
- **Essais** : fuzzing du réseau, test de coupure brutale (`kill -9` répété), 200+ tests.

## Nouveautés de la V9 : préparer un réseau de test fermé

Même réseau et mêmes règles que les V6 à V8 (elles se parlent).

- **Audit interne** : [AUDIT-INTERNE.md](AUDIT-INTERNE.md) (méthode, surfaces, défauts trouvés,
  limites) et [CAHIER-AUDIT-EXTERNE.md](CAHIER-AUDIT-EXTERNE.md) pour confier un vrai audit à des tiers.
  Ce n'est **pas** un audit indépendant.
- **Corrections** : le port local refuse d'écouter hors de la machine sans option explicite ; il
  vérifie le nom d'hôte (protection contre le DNS rebinding) ; le mineur attend au lieu de produire
  des blocs trop avancés dans le temps.
- **Outils d'opérateur** : `python -m novacoin doctor` (contrôle de la machine avant lancement),
  `--peers-file` (liste de pairs avec identités), `--closed` (seules les identités listées).
  Guide complet : [TESTNET.md](TESTNET.md).
- **Essai de longue durée** : `python tools/soak.py --minutes 10` (nœuds, mineurs, paiements, coupures
  aléatoires ; vérifie l'offre monétaire et la convergence).

## Nouveautés de la V8 : un explorateur et une spécification

Même réseau et mêmes règles que la V6 et la V7 : elles se parlent.

- **Explorateur de blocs** : `http://127.0.0.1:18441/explorer` (lien « Explorateur » à ajouter aux
  favoris). Recherche par hauteur, empreinte de bloc, identifiant de transaction ou adresse ;
  pages bloc (précédent, suivant, mineur, récompense, frais, confirmations), transaction (origine
  des pièces, frais, état en attente ou confirmé) et adresse (solde, total reçu et envoyé,
  historique). Lecture seule, sans jeton, sur le port local uniquement ; la page n'injecte jamais de
  HTML. Les routes sont `/api/explorer/{block,blocks,tx,address,search}`.
- **Spécification du protocole** : [PROTOCOLE.md](PROTOCOLE.md) décrit toutes les règles de
  consensus, le format des données et le transport entre nœuds, avec les constantes.
- **Vérificateur indépendant** : `tools/independent_check.py` revalide une chaîne en ne s'appuyant
  que sur la spécification (il n'importe pas le code du nœud). Il est testé contre une vraie chaîne
  (paiements, plusieurs ajustements de difficulté) et rejette les falsifications testées : c'est la
  preuve que la spécification suffit à écrire un autre nœud. Pour un nœud en marche, copier d'abord
  la base avec `sqlite3 chain.sqlite3 ".backup copie.sqlite3"`.
- Défaut trouvé en construisant l'explorateur : une empreinte composée uniquement de chiffres était
  lue comme une hauteur de bloc. Corrigé et testé.

## Nouveautés de la V7 : un banc d'attaques

Même réseau et mêmes règles de consensus que la V6 (`nova-testnet-2`) : une V7 et une V6
se parlent. Le banc attaque le code et dit ce qui tient :

```sh
python -m novacoin.attack_bench            # écrit .local/attacks/RAPPORT-ATTAQUES.md
```

Dix scénarios : double dépense (file et bloc), retournement de paiement par chaîne secrète plus
lourde (avec la table de probabilité de Nakamoto), travail égal, réécriture de plus de 50 blocs,
manipulation d'horodatages, fuzzing (blocs et paiements mutés), inondation, file pleine, pair
menteur. **Résultat : tout tient, sauf l'attaque par puissance majoritaire, qui est inhérente à la
preuve de travail.** Le banc a aussi trouvé et fait corriger trois défauts (coût quadratique de
la file, file bloquée par des paiements à frais minimaux, recherche d'ancêtre linéaire) : voir
`RAPPORT-ATTAQUES.md`. Le banc tourne sur le réseau de laboratoire avec une horloge simulée
pour garder une difficulté stable.

## Nouveautés de la V6 : un consensus durci

**C'est un nouveau réseau** (`nova-testnet-2`) : les règles de validation des blocs
changent, donc les chaînes V3 à V5 ne sont pas valides ici et ne se convertissent pas. Le
transport (V4) et le portefeuille (V5) sont inchangés ; les adresses et phrases de récupération
restent valables (mêmes clés), seules les pièces de test sont à recréer.

Règles de consensus (communes à tous les nœuds) :
- **Version de bloc 2.** Une version plus récente est refusée avec le message « mettre le
  logiciel à jour » ; une version plus ancienne est obsolète. Le nœud note dans son journal
  quand un pair annonce un protocole plus récent.
- **Horodatages strictement croissants** : un bloc doit être plus récent que son prédécesseur
  (et que la médiane des 11 derniers). Limite dans le futur ramenée de 120 à **60 secondes**.
- **Difficulté mesurée sur les blocs médians.** Le temps écoulé se mesure entre le bloc médian
  du début et celui de la fin de la fenêtre (et non plus entre deux blocs précis) : mentir sur
  l'horodatage du dernier bloc, ou d'un seul bloc, ne change plus le prochain réglage
  (attaque dite « time warp »). Le résultat est borné à ×4 / ÷4 comme avant.

Politiques locales de chaque nœud (réglables, pas du consensus) :
- **Réorganisation maximale** : un nœud refuse, de lui-même, de remplacer plus de 50 blocs
  (`--max-reorg N`, `0` = sans limite). Cela protège contre une chaîne secrète très longue,
  mais un nœud isolé plus de 50 blocs devra être réglé à la main pour rejoindre le réseau.
- **Points de contrôle** : `--checkpoint HAUTEUR:EMPREINTE` (répétable) ; toute chaîne qui
  diffère à cette hauteur est refusée, et un nœud dont la base les contredit ne démarre pas.
- **Frais minimaux** (10 unités par octet) et **seuil de poussière** (0,00001 NOVA) pour
  qu'une transaction soit acceptée dans la file ; les blocs privilégient les frais les plus
  élevés par octet. Le portefeuille ne crée jamais de monnaie sous le seuil (elle va aux frais).

Ces protections réduisent des attaques précises ; **aucune ne remplace la puissance de calcul
honnête**. Une personne qui disposerait de la majorité de la puissance restera en mesure de
réécrire l'histoire récente.

## Nouveautés de la V5 : un portefeuille qu'on peut retrouver

Le consensus et le réseau sont **identiques à la V4** (même identifiant, mêmes échanges chiffrés) :
une V5 et une V4 se parlent. Les nouveautés sont dans le portefeuille.

- **Phrase de récupération de 12 mots** : `python -m novacoin hd-create --wallet MON.json`
  affiche la phrase **une seule fois** (à écrire sur papier, à ne jamais photographier ni
  enregistrer) puis ne la garde pas. 128 bits d'entropie et une somme de contrôle : un mot
  erroné est repéré dans 15 cas sur 16.
- **Restauration** : `NOVA_PHRASE="…" python -m novacoin hd-restore --wallet NEUF.json`
  (ou saisie masquée), puis `hd-balance` : les adresses utilisées sont retrouvées par analyse
  de la chaîne (marge de 20 adresses vides consécutives). Une adresse située plus de 20 rangs
  après la dernière utilisée ne serait pas retrouvée automatiquement.
- **Une adresse neuve à chaque réception** (`hd-address`) et la **monnaie rendue** va sur une
  adresse neuve. Une transaction n'a qu'une seule clé signataire (règle de consensus) : un
  paiement qui dépasse le solde d'une adresse est donc envoyé en plusieurs transactions.
- **Carnet de contacts** (`hd-contact --name Bob --address …`, puis `hd-send --to Bob`).
- Fichier de portefeuille chiffré (scrypt + AES-GCM, droits 0600), écriture atomique,
  falsification détectée ; mot de passe d'au moins 10 caractères.
- Le nœud indique désormais si une adresse a déjà reçu des pièces (`used`).

**Pas fait dans cette version** : l'application de bureau avec fenêtre (cette installation de
Python n'a pas d'interface graphique native) ; tout passe par la ligne de commande et le tableau
de bord. Les portefeuilles Alice et Bob de la démonstration restent des clés simples.
**La liste de 2048 mots est celle de Nova, pas celle de BIP39** : une phrase Nova ne se
restaure pas dans un autre logiciel, et réciproquement. Ce portefeuille n'a pas été audité :
ne pas y mettre de valeur réelle. Perdre la phrase **et** le fichier = perdre les pièces.

## Nouveautés de la V4 : des échanges entre nœuds chiffrés et authentifiés

Les **règles de consensus ne changent pas** (même chaîne, même difficulté qu'en V3).
La V4 sécurise la façon dont les nœuds se parlent. **Un nœud V3 et un nœud V4 ne peuvent
plus communiquer** (le transport est différent) ; les données d'une chaîne V3 se reprennent
en copiant son dossier de nœud, sans la liste de pairs, qui est ignorée.

- **Deux portes séparées.** Le port local (`--port`, par défaut 18441) sert le tableau de bord,
  les portefeuilles et l'administration, en HTTP sur `127.0.0.1`. Le **port des pairs**
  (`--p2p-port`, par défaut port + 10 000) n'offre que les routes `/p2p/…` de synchronisation
  et **aucune commande d'administration**. Les deux ne partagent aucune route.
- **Chiffrement TLS 1.3 obligatoire** sur le port des pairs (une version plus ancienne ou du
  HTTP en clair est refusé).
- **Identité de nœud.** Chaque nœud a une clé Ed25519 (`node.key`, droits 0600) ; sa clé
  publique est son identifiant et celle de son certificat TLS. Un pair est **épinglé** : on
  peut donner son identifiant (`--peer https://adresse:port#identifiant`) ; sinon le premier
  contact le mémorise et toute identité différente ensuite est refusée avant l'envoi de la
  moindre donnée.
- **Requêtes signées.** Chaque requête porte une signature Ed25519 de l'expéditeur couvrant la
  méthode, le chemin, le contenu, l'heure, un nombre à usage unique et **le destinataire**.
  Une requête modifiée, rejouée, périmée (plus de 60 s d'écart d'horloge) ou destinée à un
  autre nœud est refusée.
- **Mode fermé** (`--closed`) : seuls les pairs dont l'identifiant est configuré sont acceptés,
  sans découverte automatique.
- **Défenses contre les abus** : limite de débit par adresse et par identité, 8 connexions
  simultanées au plus par adresse, poignée de main TLS limitée à 5 secondes (un client qui
  traîne ne bloque personne), taille de requête bornée, **points de mauvaise conduite** avec
  décroissance et **bannissement temporaire** (15 minutes) pour les objets invalides ou les
  blocs falsifiés, dans les deux sens. Les bannissements s'affichent dans le tableau de bord.
- **Découverte avec identités** : les adresses apprises auprès d'un pair arrivent avec
  l'identifiant épinglé. Elle reste limitée aux adresses privées ou locales.
- Le tableau de bord affiche l'identité du nœud, le chiffrement et l'identité de chaque pair.

Commandes utiles :

```sh
python -m novacoin node --data .local/noeud-a --port 19441 --p2p-port 29441 \
  --peer https://127.0.0.1:29442
python -m novacoin node --data .local/noeud-b --port 19442 --p2p-port 29442 \
  --peer https://127.0.0.1:29441#<identifiant-du-noeud-a>
```

Au démarrage, le nœud affiche son adresse de pair complète, avec son identifiant,
à communiquer à ses futurs pairs. `--p2p-host 0.0.0.0` ouvre le port des pairs au réseau.

## Rappel V3 : une chaîne qui vit seule, plus difficile à miner

**La V3 a introduit le réseau `nova-independent-test-v3`** (format de bloc et difficulté
nouveaux). Les chaînes V1 et V2 n'y sont pas lisibles. La V4 garde les mêmes règles de
consensus et le même identifiant : une chaîne V3 reste valide en V4.

- **Difficulté continue.** L'en-tête de bloc contient une *cible* de 256 bits (un bloc est
  valide si son empreinte est inférieure à la cible), comme dans Bitcoin, au lieu d'un
  nombre entier de bits. L'ajustement se fait tous les 20 blocs, proportionnellement au temps
  réellement écoulé (objectif : 10 s par bloc en V3 à V12, 60 s depuis la V13), avec un facteur limité à ×4 ou ÷4 par
  ajustement. Plus de sauts d'un bit.
- **Difficulté de départ : 20 bits** (environ un million d'essais par bloc, 10 à 15 secondes
  sur ce Mac) au lieu de 10. Plancher 16 bits, plafond 96 bits : la chaîne pourra monter bien
  plus haut sans changer de règles. Pour comparaison, Bitcoin est autour de 79 bits.
- **Minage automatique** (bouton du tableau de bord, ou `python -m novacoin automine`) :
  le nœud mine en continu, abandonne un bloc dès qu'un pair a trouvé le suivant, et
  l'option survit au redémarrage. Il consomme un cœur du processeur tant qu'il est actif.
- **Synchronisation incrémentale** : un nœud cherche le dernier bloc commun, puis ne télécharge
  que les blocs manquants, par lots de 100, en les validant au fur et à mesure.
  Plus de limite de 8 Mo ni de 5 000 blocs ; la nouvelle limite est de 100 000 blocs
  (la chaîne entière est gardée en mémoire).
- **Découverte de pairs** : un nœud apprend les adresses des pairs de ses pairs et s'annonce
  à eux. Le lanceur démarre **trois nœuds** (tableau de bord 18441 à 18443, pairs 28441 à 28443) ; le troisième n'est
  relié au départ qu'au premier et trouve le deuxième tout seul. Chaque nœud reconnaît sa
  propre adresse (identifiant de nœud) et l'écarte. Pour l'instant, seules les adresses du
  réseau local ou privé sont acceptées (voir les limites).
- Le laboratoire de résilience de la V2 est conservé (isoler, miner sur A ou B, reconnecter).

Les tests automatisés tournent sur un réseau séparé et très facile (`NOVA_EASY=1`,
identifiant `…-v3-easy`) pour rester rapides ; un test vérifie que le vrai réseau garde bien
ses constantes (20 bits au départ, bornes 16 à 96).

## Lancer la démonstration sur ce Mac

Double-cliquer sur **Lancer Nova.command**. Laisser la fenêtre du terminal ouverte.
Le lanceur démarre deux processus indépendants et ouvre le tableau de bord.
Les dépendances nécessaires sont déjà présentes sur le Mac où cette version a été construite.

1. Choisir Alice, puis cliquer sur **Miner 3 blocs**.
2. Envoyer **10 NOVA** d'Alice à Bob.
3. Cliquer sur **Miner 1 bloc** pour confirmer le paiement.
4. Les soldes confirmés sont alors **190 NOVA pour Alice et 10 pour Bob**.
   Alice reçoit aussi la récompense du quatrième bloc et les frais du paiement.
5. Observer les trois nœuds : ils rejoignent le même historique en quelques secondes.

Une nouvelle installation depuis l'archive commence avec zéro pièce.

- Tableau de bord : `http://127.0.0.1:18441`.
- Autres nœuds : `http://127.0.0.1:18442/api/status` et `http://127.0.0.1:18443/api/status`.
- Ports des pairs (TLS) : 28441, 28442, 28443.
- Arrêter : `Ctrl+C` dans la fenêtre du lanceur.
- Redémarrer : relancer le même fichier ; les blocs et portefeuilles sont conservés.
- Données : `.local/demo/` dans le dossier du projet.
- Si le port est occupé, arrêter le lanceur précédent avant d'en ouvrir un autre.
- Si la page demande un jeton, ouvrir l'adresse contenue dans
  `.local/demo/dashboard.url`, ou saisir le contenu de `.local/demo/node-1/admin.token`.
  Ce jeton autorise les commandes locales ; le conserver privé.

Les portefeuilles Alice et Bob sont gérés par le serveur de démonstration.
Leur mot de passe de test est enregistré à côté des fichiers chiffrés afin de
permettre le lancement automatique. Cette facilité n'est pas destinée à des fonds réels.
Les portefeuilles indépendants créés avec la commande ci-dessous utilisent un
mot de passe choisi par leur propriétaire et ne sont pas chargés par le serveur.

## Installer sur un autre ordinateur

Python 3.11 ou plus récent est nécessaire. Depuis le dossier du projet :

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m novacoin.demo
```

Le lanceur macOS privilégie automatiquement `.venv/bin/python` lorsqu'il existe.
Sur Linux, utiliser la commande Python. Pour choisir d'autres ports :

```sh
python -m novacoin.demo --port 19441
```

## Utiliser un portefeuille indépendant

Les commandes suivantes supposent l'environnement Python activé et un nœud lancé.
Remplacer les textes entre chevrons par les valeurs réelles, sans conserver les chevrons.

```sh
python -m novacoin wallet-create --wallet .local/mon-portefeuille.pem
python -m novacoin wallet-address --wallet .local/mon-portefeuille.pem
python -m novacoin balance --address <mon-adresse>
python -m novacoin mine --address <mon-adresse> --count 3 \
  --token-file .local/demo/node-1/admin.token
python -m novacoin send --wallet .local/mon-portefeuille.pem \
  --to <adresse-destinataire> --amount 10 --fee 0.001
python -m novacoin status
```

La commande `send` signe sur l'ordinateur du propriétaire ; seul le paiement signé
est transmis au nœud. Le mot de passe est demandé sans s'afficher.
Pour l'automatisation, `NOVA_WALLET_PASSWORD` est également accepté.
Sauvegarder le fichier `.pem` et son mot de passe séparément :
il n'existe pas de fonction « mot de passe oublié » ni de phrase de récupération en V4.

## Lancer les nœuds séparément

Voir l'exemple de la section V4 ci-dessus. Chaque nœud a sa propre base SQLite, sa propre
identité (`node.key`) et son propre jeton administrateur. Utiliser un dossier de données
différent pour chaque nœud. Un pair supplémentaire s'ajoute avec
`peer-add --peer https://adresse:port[#identifiant] --token-file CHEMIN`.
Chaque commande cliente accepte `--node http://adresse:port` (le port local).

Le port local écoute sur `127.0.0.1` par défaut ; ne pas l'ouvrir à un réseau : le
tableau de bord et les commandes n'y sont pas chiffrés. Seul le port des pairs est fait
pour être ouvert. Ses clients doivent gérer TLS 1.3 avec des certificats Ed25519
(OpenSSL 1.1.1 ou plus récent ; le `curl` fourni avec macOS ne convient pas).

## Règles de cette chaîne

| Élément | Règle V6 |
|---|---|
| Identifiant du réseau | `nova-testnet-3` |
| Unité | 1 NOVA = 100 000 000 unités entières |
| Création initiale | 50 NOVA par bloc miné, aucune pièce au genesis |
| Réduction de la récompense | Division entière par deux tous les 210 000 blocs |
| Plafond de l'émission théorique | Au plus 21 millions de NOVA ; arrondi inférieur |
| Disponibilité des récompenses | Dépensables dans un bloc situé au moins deux hauteurs après leur création |
| Signatures | Ed25519, avec séparation explicite du réseau |
| Empreintes et preuve de travail | SHA-256 |
| Difficulté initiale | 22 bits (cible 2²³⁴) ; bornes de 16 à 96 bits |
| Ajustement | Tous les 20 blocs ; temps mesuré entre blocs médians ; objectif 60 secondes par bloc (V13) |
| Amplitude d'ajustement | Temps mesuré borné entre ¼ et 4× l'objectif (cible ÷4 ou ×4 au maximum) |
| Choix de chaîne | Chaîne valide ayant le plus de travail cumulé (⌊2²⁵⁶ ÷ (cible+1)⌋ par bloc) ; pas uniquement la plus longue |
| Paiements | Modèle UTXO, toutes les entrées d'un paiement appartiennent à une seule clé |
| Frais | Différence entre entrées et sorties ; 0,001 NOVA par défaut dans la démonstration |
| Horodatage | Supérieur au bloc précédent et à la médiane des 11 derniers, au plus 60 secondes dans le futur |
| Conservation | SQLite, transactions disque, revalidation au démarrage |

Le minage est déclenché à la demande. L'objectif de dix secondes règle la difficulté ;
il ne s'agit pas d'un minuteur qui produit automatiquement un bloc.
Une chaîne concurrente peut faire disparaître provisoirement une confirmation.
Les paiements encore valides issus des blocs remplacés retournent dans la file d'attente.

## Ce qui est inclus

- Moteur de consensus, genesis fixe et format canonique des données.
- Portefeuilles chiffrés, adresses avec contrôle d'intégrité, signatures des paiements.
- Vérification des montants, de la propriété, de la maturité et des doubles dépenses.
- Preuve de travail, adaptation de difficulté, calcul du travail cumulé.
- Validation des blocs et remplacement de l'historique par une chaîne valide plus forte.
- File de paiements persistante, gestion des conflits et des paiements redevenus non confirmés.
- Synchronisation HTTP entre nœuds et reprise après indisponibilité.
- Tableau de bord en français, commandes locales protégées par un jeton.
- Client en ligne de commande, lanceur à deux processus et tests automatisés.

## Limites précises de la V6

Cette version privilégie une chaîne lisible et testable. Elle ne reprend pas toutes
les fonctions, protections, performances ou garanties de Bitcoin Core.

- Les échanges entre nœuds sont chiffrés et authentifiés (V4), mais **un pair malveillant
  authentifié peut toujours mentir ou ralentir un nœud** (les blocs reçus sont validés
  intégralement). Rien n'empêche quelqu'un de créer de nombreuses identités : l'authentification
  prouve qui parle, pas que l'interlocuteur soit honnête. Chaîne limitée à 500 000 blocs
  (sur disque ; l'ensemble des pièces reste en mémoire).
- Les clés d'identité de nœud ne sont pas chiffrées sur disque (droits 0600) ; pas de rotation
  de clé ni de liste de révocation. Les bannissements ne survivent pas à un redémarrage.
- Le port local (tableau de bord, administration) reste en HTTP : il est réservé à la machine.
- Blocs de 256 000 octets et 200 transactions au maximum, récompense comprise.
- Transactions de 16 000 octets, 64 entrées et 64 sorties au maximum.
- File d'attente limitée à 1 000 transactions et 2 Mo ; 16 pairs configurés au maximum.
- Difficulté faible pour les essais : aucune résistance économique crédible à un
  attaquant disposant de davantage de puissance de calcul.
- Découverte de pairs limitée au réseau local/privé : pas de découverte mondiale ni de
  mécanisme anti-Sybil. Les horodatages restent la seule horloge du consensus
  (voir V6) : un mineur majoritaire pourrait encore les manipuler de façon répétée sur de
  nombreux blocs pour fausser l'ajustement, dans les bornes ×4 / ÷4.
- Pas de multisignature, contrats intelligents, serveur de pool, application mobile,
  portefeuille matériel, marché d'échange ou récupération de clé.
- Protection réseau de base (tailles, délais, connexions bornées), sans audit indépendant
  ni protection complète contre les dénis de service.
- La démonstration utilise trois processus sur un seul ordinateur :
  elle prouve la synchronisation logicielle, pas une décentralisation réelle.

Avant de viser un réseau public, il faudra notamment un audit indépendant,
des essais prolongés avec des opérateurs distincts, une synchronisation incrémentale
et un modèle de sécurité adapté à la puissance de minage disponible.

## Vérifier et modifier

```sh
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

Les tests réseau ouvrent temporairement des ports sur la boucle locale.
Si un environnement isolé bloque l'ouverture de ports, les tests réseau doivent
être exécutés dans un environnement autorisant ces serveurs locaux.

| Fichier | Rôle |
|---|---|
| `novacoin/core.py` | Règles de consensus et minage |
| `novacoin/wallet.py` | Clés simples et construction des paiements |
| `novacoin/hdwallet.py` | Phrase de 12 mots, adresses neuves, contacts, restauration |
| `novacoin/node.py` | Stockage, serveurs (local et pairs), synchronisation, file d'attente |
| `novacoin/selftest.py`, `novacoin/release_sign.py`, `tools/verify_install.py`, `tools/make_checkpoints.py` | Auto-test, signature et vérification de livraison, points de contrôle |
| `novacoin/doctor.py`, `tools/soak.py` | Contrôle de machine, essai de longue durée |
| `novacoin/explorer.html` | Explorateur de blocs (page locale) |
| `PROTOCOLE.md`, `tools/independent_check.py` | Spécification et vérificateur indépendant |
| `novacoin/attack_bench.py` | Banc d'attaques et rapport |
| `novacoin/p2p.py` | Identité, TLS, requêtes signées, limites de débit, bannissements |
| `novacoin/cli.py` | Commandes utilisateur |
| `novacoin/demo.py` | Lancement de deux processus indépendants |
| `novacoin/verify.py` | Tests + rapport de validation reproductible |
| `novacoin/dashboard.html` | Interface sans dépendance externe |
| `tests/` | Tests de consensus, stockage, sécurité des paiements et réseau |

Modifier une règle de consensus nécessite de coordonner tous les nœuds.
Pour une nouvelle expérience incompatible, choisir un nouvel identifiant réseau
et des dossiers de données neufs, en conservant les anciens comme sauvegarde.

Repères de conception : [blockchain](https://developer.bitcoin.org/devguide/block_chain.html),
[transactions](https://developer.bitcoin.org/devguide/transactions.html),
[réseau](https://developer.bitcoin.org/devguide/p2p_network.html).
L'implémentation de Nova est autonome et volontairement différente du protocole Bitcoin.
