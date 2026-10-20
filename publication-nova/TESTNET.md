# Réseau de test fermé — guide des participants

Un réseau de test fermé réunit quelques personnes de confiance qui font tourner un nœud chacune.
**Les pièces n'ont aucune valeur, rien n'est promis, et le réseau peut être réinitialisé à tout
moment.** Ne rien y mettre qui compte. Ce guide ne publie rien : l'organisateur décide à qui il
transmet l'adresse de ses nœuds.

## 1. Pour chaque participant

```sh
python -m pip install -r requirements.txt
python -m novacoin doctor --data .local/mon-noeud --port 18441 --p2p-port 28441
```

`doctor` vérifie Python, TLS 1.3, la bibliothèque de chiffrement, les ports, l'espace disque et
les droits des fichiers. Corriger tout ce qui est marqué `FAIL`.

## 2. Échanger les identités

Chaque nœud a une identité propre. Au premier lancement, il affiche son adresse de pair complète :

```
Pairs (TLS) : https://203.0.113.7:28441#<identifiant de 64 caractères>
```

Chaque participant transmet cette ligne à l'organisateur **par un canal qu'il estime sûr** (en main
propre, messagerie chiffrée) : l'identifiant épingle le nœud et empêche qu'on se fasse passer pour lui.
L'organisateur assemble un fichier `pairs.txt` (une adresse par ligne, `#` pour commenter) et le
renvoie aux participants.

## 3. Lancer un nœud fermé

```sh
python -m novacoin node --data .local/mon-noeud --port 18441 --p2p-port 28441 \
  --p2p-host 0.0.0.0 --peers-file pairs.txt --closed
```

- `--p2p-host 0.0.0.0` ouvre **uniquement** le port des pairs (chiffré). Le port local (tableau de
  bord, administration) reste sur 127.0.0.1 : n'utilisez jamais `--allow-remote-local-port`.
- `--closed` : seuls les identités listées dans `pairs.txt` sont acceptées, sans découverte.
- Ouvrir le port 28441 (TCP) sur le routeur ou le pare-feu, vers cette machine.
- L'heure du système doit être synchronisée (les échanges refusent plus de 60 s d'écart).

## 3 bis. Protéger la clé du nœud (recommandé)

```sh
NOVA_NEW_NODE_PASSWORD="un mot de passe de 12 caractères ou plus" python -m novacoin key-protect --data .local/mon-noeud
NOVA_NODE_PASSWORD_FILE=/chemin/secret.txt python -m novacoin node --data .local/mon-noeud ...
```
Les alertes du tableau de bord signalent une clé non chiffrée, un seul pair joignable, une horloge décalée ou
une chaîne plus lourde refusée. Pour remplacer le jeton administrateur : arrêter le nœud, puis `token-rotate`.

## 4. Utiliser

- Tableau de bord : `http://127.0.0.1:18441` ; explorateur : `http://127.0.0.1:18441/explorer`.
- Minage : `python -m novacoin automine --address ADRESSE --token-file .local/mon-noeud/admin.token`
  (un processeur occupé en continu ; l'arrêter avec `--off`).
- Portefeuille récupérable : `python -m novacoin hd-create --wallet mon.json` (noter la phrase).

## 5. Règles du jeu

1. Un participant qui perd sa clé de nœud (`node.key`) obtient une nouvelle identité : l'organisateur
   doit mettre à jour `pairs.txt`. Ne jamais partager `node.key`, `admin.token` ni les portefeuilles.
2. Mettre à jour le logiciel tous ensemble : un nœud d'une autre version peut diverger.
3. Si votre nœud affiche « historiques différents » durablement, ne pas forcer : décrire le problème
   (onglet « Journal des nœuds » du tableau de bord) à l'organisateur.
4. Signaler tout comportement étrange ; c'est le but de l'exercice.

## 6. Ce que l'organisateur doit décider avant d'inviter

- Qui participe, et un canal sûr pour les identités.
- Une durée de vie annoncée et la possibilité de réinitialiser.
- Que rien ne soit promis, vendu ni échangé contre quoi que ce soit.
