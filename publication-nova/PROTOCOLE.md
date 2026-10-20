# Protocole Nova — spécification (réseau `nova-testnet-3`, logiciel 1.3)

Ce document décrit **tout ce qu'un autre logiciel doit faire** pour suivre la même chaîne.
`tools/independent_check.py` en est une implémentation de vérification écrite **uniquement à partir
de ce texte**, sans réutiliser le code du nœud ; elle est testée contre la vraie chaîne.
En cas de désaccord entre ce document et le code, c'est un défaut à signaler.

Réseau d'essai : aucune valeur monétaire, aucune garantie. Les mots DOIT / DOIVENT désignent
une règle de consensus (un bloc qui la viole est refusé par tous les nœuds).

## 1. Constantes

| Nom | Valeur (réseau réel) | Réseau de test automatisé (`…-easy`) |
|---|---|---|
| Identifiant réseau | `nova-testnet-3` | `nova-testnet-3-easy` |
| Unité | 1 NOVA = 100 000 000 unités | idem |
| Récompense initiale | 50 NOVA, divisée par deux (décalage binaire) tous les 210 000 blocs | idem |
| Plafond d'un montant | 21 000 000 NOVA | idem |
| Maturité d'une récompense | 2 blocs | idem |
| Difficulté initiale | 22 bits : cible 2²³⁴ | 6 bits : cible 2²⁵⁰ |
| Bornes de la cible | de 2²⁴⁰ (16 bits, la plus facile) à 2¹⁶⁰ (96 bits) | de 2²⁵² à 2¹⁶⁰ |
| Fenêtre d'ajustement | 20 blocs ; facteur maximal ×4 / ÷4 | idem |
| Objectif | 60 secondes par bloc | idem |
| Avance maximale d'un horodatage | 60 s sur l'heure du nœud | idem |
| Taille maximale | bloc 256 000 octets, transaction 16 000 octets | idem |
| Limites | 200 transactions par bloc (récompense comprise), 64 entrées, 64 sorties par transaction | idem |
| Version de bloc | 2 ; version de transaction : 1 ou 2 (verrouillage par date et multisignature) | idem |

## 2. Encodage et empreintes

- **JSON canonique** : clés triées par ordre alphabétique, séparateurs `,` et `:` sans espace,
  caractères non ASCII échappés (`\\uXXXX`), nombres entiers uniquement (aucune virgule flottante,
  aucun `NaN`). Les grands entiers (cibles) sont de simples nombres JSON.
- `empreinte(x)` = SHA-256 de l'encodage canonique de `x`, en hexadécimal minuscule (64 caractères).
- **Identifiant de bloc** = `empreinte(en-tête)`, l'en-tête étant l'objet
  `{version, network, height, previous, timestamp, target, nonce, merkle_root}`.
- **Identifiant de transaction** = `empreinte` de la transaction **sans ses signatures** : sans le champ `signature`
  (paiement à un signataire) et sans `multisig.signatures` (multisignature). Re-signer un paiement ne change donc pas
  son identifiant (pas de malléabilité). La récompense n'a pas de signature : c'est l'empreinte de l'objet complet.
  Les signatures restent vérifiées et font partie des octets du bloc, mais **ne sont pas engagées par la racine de Merkle**.

## 3. Blocs

Un bloc est un objet aux champs exacts (aucun autre) :
`version, network, height, previous, timestamp, target, nonce, merkle_root, transactions`.

Le **genesis** est fixe : `version` 2, `network`, `height` 0, `previous` 64 zéros,
`timestamp` 1 700 000 000, `target` initiale, `nonce` 0, `merkle_root` = SHA-256 (hexadécimal)
des octets vides, `transactions` vide. Il est identique pour tous les nœuds.

Un bloc `B` de hauteur `h` ajouté à la chaîne `C` (genesis = indice 0) DOIT respecter :

1. `version` = 2, `network` = identifiant du réseau, `height` = `h` = longueur de `C`.
2. `previous` = identifiant du dernier bloc de `C`.
3. **Horodatage** (entier) : strictement supérieur à celui du bloc précédent, strictement supérieur
   à la **médiane** des horodatages des 11 derniers blocs de `C` (genesis compris ; élément de rang
   `⌊n/2⌋` après tri croissant), et au plus l'heure locale du nœud + 60 s.
4. `target` = **cible attendue** (§4) ; l'identifiant du bloc, lu comme un entier en hexadécimal,
   DOIT être **strictement inférieur** à `target` (preuve de travail). `nonce` entier de 0 à 2⁶⁴−1.
5. 1 à 200 transactions ; la première est la **récompense**, les autres sont des paiements ;
   aucune transaction en double ; `merkle_root` correspond (§6) ; taille du bloc ≤ 256 000 octets.
6. Les paiements, appliqués dans l'ordre sur l'ensemble des pièces non dépensées (UTXO), sont valides (§5).
7. **Récompense** : objet `{type:"coinbase", network, height, outputs}` avec `height` = `h` et au plus
   une sortie ; son montant DOIT être égal à `subsidy(h)` + somme des frais des paiements du bloc,
   où `subsidy(h) = 5 000 000 000 >> ((h−1) div 210 000)`.

**Travail d'un bloc** = ⌊2²⁵⁶ ÷ (`target`+1)⌋. La chaîne choisie est la chaîne **valide ayant le plus
grand travail cumulé** ; à égalité, un nœud garde celle qu'il connaît déjà.

## 4. Cible attendue (difficulté)

Soit `C` la chaîne existante, `n` sa longueur et `t` la cible de son dernier bloc.

- Si `n > 20` et `(n − 1)` est multiple de 20, soit `milieu(i) = bas + ⌊(i − bas + 1) ÷ 2⌋`
  avec `bas = max(1, i − 10)`. Alors `debut = milieu(n − 20)`, `fin = milieu(n − 1)`,
  `attendu = 60 × (fin − debut)`, `ecoule = timestamp[fin] − timestamp[debut]` borné entre
  `⌊attendu ÷ 4⌋` et `attendu × 4`, et la nouvelle cible = `⌊t × ecoule ÷ attendu⌋`.
- Sinon la cible est `t`.
- Le résultat est ramené dans les bornes du §1.

(Les horodatages étant strictement croissants, le bloc « médian » est celui du milieu par position.)

## 5. Transactions

Paiement de version 1 : `{version:1, network, inputs, outputs, public_key, signature}` (la version 2 est décrite au §5 bis).

- `inputs` : 1 à 64 objets `{txid, index}` (64 hexadécimaux, 0 ≤ index ≤ 63), sans doublon.
  `outputs` : 1 à 64 objets `{address, amount}` (adresse valide — préfixe `nv1` ou `nm1` —, entier 1 ≤ montant ≤ plafond).
- `public_key` : clé publique Ed25519 brute, 64 hexadécimaux ; `signature` : 128 hexadécimaux.
- **Signature** : Ed25519 sur les octets `NOVA-TX-V1` + octet nul + encodage canonique de la
  transaction **sans** son champ `signature`.
- Toutes les entrées appartiennent à la **même clé** : l'adresse de chaque pièce dépensée DOIT être
  l'adresse de `public_key`. Un paiement de plusieurs adresses est donc plusieurs transactions.
- Chaque pièce `(txid, index)` DOIT exister et être non dépensée ; une récompense n'est dépensable
  que dans un bloc de hauteur ≥ hauteur de création + 2.
- Somme des entrées ≥ somme des sorties ; la différence est le **frais**.
- Les sorties créent les pièces `(identifiant de la transaction, rang)`. Pour une récompense, les
  pièces sont créées de la même façon et marquées « récompense ».

**Adresse** d'une clé publique `K` (octets) : `corps = SHA-256(K)` en hexadécimal, 40 premiers
caractères ; `somme = SHA-256(identifiant réseau + corps)` en hexadécimal, 8 premiers caractères ;
adresse = `nv1` + `corps` + `somme` (51 caractères).

### 5 bis. Paiements de version 2 (verrouillage et multisignature)

Un paiement de version 2 a les champs `version` (2), `network`, `inputs`, `outputs`, **`locktime`** et soit
`public_key` + `signature` (un seul signataire), soit **`multisig`** (jamais les deux).

- **Verrouillage** : `locktime` est un entier de 0 à 2³¹−1. Le paiement ne peut figurer que dans un bloc de
  hauteur **supérieure ou égale** à `locktime` (0 = aucun verrouillage). La file d'attente d'un nœud
  n'accepte un paiement verrouillé qu'une fois cette hauteur atteignable par le prochain bloc.
- **Signature** : les octets signés sont `NOVA-TX-V2` + octet nul + JSON canonique du paiement **sans** son champ
  `signature` ; pour une multisignature, sans le champ `multisig.signatures` (la politique est signée,
  les signatures ne le sont pas).
- **Adresse multisignature** : `nm1` + 40 premiers hexadécimaux de `SHA-256(JSON canonique {"m": seuil, "keys":
  clés})` + 8 premiers hexadécimaux de `SHA-256(identifiant réseau + corps)`. Les clés (64 hexadécimaux) sont
  **triées et distinctes**, 1 ≤ `m` ≤ nombre de clés ≤ 5.
- **`multisig`** : `{threshold, keys, signatures}` où `signatures` est une liste de `{key, signature}`. Il faut
  au moins `threshold` signatures **valides** de clés **distinctes** appartenant à `keys`, et pas plus que
  de clés. L'adresse calculée de la politique DOIT être celle de chaque pièce dépensée.
- Les règles du §5 sur les pièces, la maturité, les montants et les frais s'appliquent inchangées.
  L'identifiant de transaction ne dépend pas des signatures (§2) : ajouter ou changer une signature valide ne le
  modifie pas. Deux variantes du même paiement ne peuvent donc pas figurer dans le même bloc (identifiant dupliqué).

## 6. Racine de Merkle

Liste des identifiants de transactions. Si elle est vide : SHA-256 des octets vides (hexadécimal).
Tant qu'elle compte plus d'un élément : si le nombre est impair, dupliquer le dernier ; remplacer
chaque paire `(a, b)` par `SHA-256(octets(a) ‖ octets(b))` (hexadécimal). Le dernier élément est la racine.

## 7. Politiques locales (hors consensus)

(V11) Points de contrôle automatiques (un bloc sur cent, une fois enterré à 50 blocs ou plus) ; un nœud qui
doit effacer plus de 6 blocs exige que la branche concurrente porte au moins 10 % de travail de plus que la
branche effacée (25 % au-delà de 20 blocs) ; budget de débit par pair pour les blocs servis ; limites de taille par
route ; échéance globale de 15 s par requête ; au plus 2 pairs par réseau /16 et la moitié de la table
réservée aux pairs choisis par l'opérateur.

Ces règles varient d'un nœud à l'autre et ne rendent pas un bloc invalide : frais minimal pour la
file (10 unités par octet), seuil de poussière (1 000 unités), réorganisation maximale acceptée
(50 blocs par défaut), points de contrôle, taille de la file (1 000 paiements, 2 Mo).

## 8. Transport entre nœuds (V4 et suivantes)

- **TLS 1.3 uniquement.** Le certificat est auto-signé avec une clé **Ed25519**, et cette clé
  publique (64 hexadécimaux) est l'**identifiant du nœud**. Le client DOIT vérifier que la clé du
  certificat est celle attendue (épinglage) ou la mémoriser au premier contact.
- Adresse de pair : `https://hôte:port` ou `https://hôte:port#identifiant`.
- **Requêtes signées.** En-têtes : `X-Nova-Id` (identifiant de l'expéditeur), `X-Nova-Time` (secondes),
  `X-Nova-Nonce` (24 hexadécimaux, unique), `X-Nova-Work` (entier : preuve de coût d'identité, voir ci-dessous), `X-Nova-Listen` (optionnel : port d'écoute annoncé),
  `X-Nova-Sig` (Ed25519, 128 hexadécimaux) sur les octets `NOVA-P2P-V4` + octet nul + JSON canonique de
  `{network, method, target, body (SHA-256 hexadécimal du contenu), time, nonce, from, to, listen}` où
  `target` est le chemin avec sa requête et `to` l'identifiant du destinataire. Le destinataire refuse
  si l'écart d'horloge dépasse 60 s, si le nonce a déjà été vu, ou si la signature est fausse.
- **Coût d'identité (V11)** : l'identifiant d'un nœud n'est accepté que si `SHA-256("NOVA-ID" ‖ 0x00 ‖ identifiant
  réseau ‖ 0x00 ‖ octets de l'identifiant ‖ nonce sur 8 octets, gros-boutiste)`, lu comme un entier de 256 bits, a au moins
  22 bits de poids fort à zéro (6 sur le réseau `…-easy`). Le nonce est l'en-tête `X-Nova-Work`.
- **Routes** (aucune commande d'administration) : `GET /p2p/status`, `/p2p/hashes?from=&limit=`,
  `/p2p/blocks?from=&limit=` (limite ≤ 100), `/p2p/mempool`, `/p2p/peers` ; `POST /p2p/transactions`,
  `/p2p/blocks`. Les réponses sont du JSON canonique ; contenu ≤ 300 000 octets en envoi.
- **Synchronisation** : comparer le travail cumulé annoncé ; chercher le dernier bloc commun par
  dichotomie avec `/p2p/hashes` ; télécharger la suite par lots de 100 ; valider chaque bloc
  avant d'adopter la chaîne si son travail cumulé est strictement supérieur.
- **Abus** : limites de débit, au plus 8 connexions par adresse, poignée de main TLS limitée à
  5 s, points de mauvaise conduite et bannissement temporaire.

## 9. Vérifier une chaîne avec un autre logiciel

```sh
NOVA_EASY=1 python tools/independent_check.py chemin/vers/chain.sqlite3   # réseau de test
python tools/independent_check.py chemin/vers/chain.sqlite3              # réseau réel
```

Pour un nœud en marche, faire d'abord une copie cohérente (`sqlite3 chain.sqlite3 ".backup copie.sqlite3"`) :
les données récentes peuvent se trouver dans le journal WAL et pas encore dans le fichier principal.
Le script lit en lecture seule la table `blocks` d'une base de nœud et applique les règles ci-dessus ;
il affiche la hauteur, le dernier identifiant et le travail cumulé, ou la première règle violée.
