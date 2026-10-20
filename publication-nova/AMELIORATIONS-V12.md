# Améliorations V12 (1.2.0rc1)

Mêmes règles de chaîne que la V11 (réseau `nova-testnet-2`) : une V12 et une V11 se parlent. La V11 reste gelée telle
quelle dans son dossier ; la V12 en est une évolution.

## 1. La chaîne vit dans la base, plus en mémoire
- Les blocs restent dans SQLite ; seuls les **128 derniers** sont gardés en mémoire (`novacoin/chainstore.py`). Le reste
  est lu à la demande. Le nœud se comporte comme avant (mêmes réponses qu'une liste, vérifié par des tests).
- La validation de toute la chaîne se fait **en flux** avec une fenêtre de 64 blocs (`Tail`), donc en mémoire constante.
- La limite passe de 100 000 à **500 000 blocs**.
- **Défaut de performance trouvé en mesurant** : la validation recopiait tout l'ensemble des pièces à chaque bloc
  (coût quadratique). Le démarrage d'un nœud sur 2 000 blocs est passé de **9,9 s à 0,2 s**. La recopie reste
  la règle quand on valide un bloc isolé ; elle est supprimée seulement pour le rejeu de la chaîne.
- **Ce qui reste en mémoire** : l'ensemble des pièces non dépensées, la liste des empreintes de blocs (64 caractères
  par bloc), les paiements en attente, et l'index de l'explorateur quand on l'utilise. **Chaque bloc reçu recopie
  encore l'ensemble des pièces** pour être validé : sur une chaîne avec des centaines de milliers de pièces, ce coût
  deviendrait gênant (non traité ici).

## 2. Clé de publication : commandes prêtes
```sh
python -m novacoin release-keygen --out ~/cle-publication.key        # affiche la clé PUBLIQUE à diffuser
python tools/build_release.py --out dist --sign-with ~/cle-publication.key
python -m novacoin verify-release --file nova-X.zip --sig nova-X.zip.sig --pubkey <clé publique>
```
Le mot de passe se donne par `NOVA_RELEASE_KEY_PASSWORD` ou au clavier. La commande refuse d'écraser une clé existante.
**Je n'ai pas créé de clé** : c'est la racine de la confiance, elle doit naître sur votre machine et rester hors ligne.

## 3. Simulations d'attaques
`python tools/simulate.py` → [RAPPORT-SIMULATIONS.md](RAPPORT-SIMULATIONS.md) : minage égoïste (comparé à la formule de
Eyal et Sirer), effacement d'un paiement (comparé au modèle exact), blocs concurrents selon la latence. Constats :
- le minage égoïste commence à payer vers **un tiers** de la puissance (un quart avec γ = 0,5) : aucune règle de Nova
  ne l'empêche, c'est une propriété de la preuve de travail ;
- la table de probabilité du livre blanc de Bitcoin **sous-estime** un peu le risque (30 % de puissance, 6 confirmations :
  13 % annoncés contre **16 %** réels) : les documents de Nova utilisent maintenant le modèle exact ;
- avec **10 s par bloc**, une latence de 1 à 2 s donne **10 à 18 %** de blocs concurrents ; Bitcoin vise 600 s pour rester
  sous 1 %. **Un temps de bloc plus long serait plus sûr sur un vrai réseau** (changement de règles, donc nouveau réseau).

## 4. Mesure de mémoire
`python tools/measure_memory.py --blocks 20000 --versions ../novacoin-v11 ../novacoin-v12` : ouvre la même base avec deux
versions et relève la mémoire maximale et le temps de démarrage. Résultats dans `VALIDATION.md`.
