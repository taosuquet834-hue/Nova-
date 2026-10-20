# Nova — blockchain expérimentale indépendante

Nova est une blockchain expérimentale que j'ai créée. J'aimerais qu'elle devienne réelle. Le code est ouvert (AGPL-3.0) : je laisse le
projet à ceux qui veulent le reprendre, l'améliorer et le faire grandir. Écrivez-moi en privé : A_COMPLETER (adresse e-mail à renseigner).

**État actuel : réseau d'essai.** Les pièces n'ont aucune valeur, rien n'est à vendre, aucune promesse n'est faite, et le projet n'a pas été audité.

> **Réseau d'essai. Les pièces NOVA n'ont aucune valeur, rien n'est promis, rien n'est à vendre.**
> Ne pas l'utiliser pour de l'argent réel. Voir [LIMITES-ET-AVERTISSEMENTS.md](LIMITES-ET-AVERTISSEMENTS.md).

Nova est une petite blockchain écrite pour **comprendre** comment fonctionne une monnaie numérique :
blocs liés par des empreintes, preuve de travail, paiements signés, plusieurs nœuds qui se mettent
d'accord. Ce n'est pas Bitcoin et ce n'est affilié à aucun projet existant. Version **1.3.0rc1**
(candidate), réseau **`nova-testnet-3`**.

## Essayer en 5 minutes

```sh
python3 -m venv .venv && source .venv/bin/activate
python -m pip install -r requirements.txt
python -m novacoin doctor            # vérifie la machine
python -m novacoin.demo              # lance 3 nœuds locaux et ouvre le tableau de bord
```

Tableau de bord `http://127.0.0.1:18441`, explorateur `http://127.0.0.1:18441/explorer`.

## Ce que contient le projet

| Besoin | Où |
|---|---|
| Comprendre et utiliser | [LISEZ-MOI.md](LISEZ-MOI.md) |
| Écrire un autre logiciel compatible | [PROTOCOLE.md](PROTOCOLE.md), `tools/independent_check.py` |
| Faire tourner un réseau de test fermé | [TESTNET.md](TESTNET.md), [seeds.txt](seeds.txt) |
| Ce qui a été durci en V11 et V12 | [DURCISSEMENT-V11.md](DURCISSEMENT-V11.md), [AMELIORATIONS-V12.md](AMELIORATIONS-V12.md), [AMELIORATIONS-V13.md](AMELIORATIONS-V13.md), [RAPPORT-SIMULATIONS.md](RAPPORT-SIMULATIONS.md) |
| Ce qui a été vérifié | [VALIDATION.md](VALIDATION.md), [RAPPORT-ATTAQUES.md](RAPPORT-ATTAQUES.md), [AUDIT-INTERNE.md](AUDIT-INTERNE.md) |
| Confier un audit à des tiers | [CAHIER-AUDIT-EXTERNE.md](CAHIER-AUDIT-EXTERNE.md) |
| Signaler une faille | [SECURITY.md](SECURITY.md) |
| Historique des versions | [CHANGELOG.md](CHANGELOG.md) |
| Avant de publier | [JURIDIQUE-A-VALIDER.md](JURIDIQUE-A-VALIDER.md), [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md) |

## Licence

Nova est publié sous licence **GNU AGPL v3** (`LICENSE`). En bref : vous pouvez l'utiliser, l'étudier, le modifier et le redistribuer ;
si vous distribuez une version modifiée, **ou si vous la faites tourner comme un service accessible à d'autres par le réseau**,
vous devez en publier le code source modifié sous la même licence. Contributions : voir [CONTRIBUTING.md](CONTRIBUTING.md).
Le logiciel est fourni « en l'état », sans garantie.

## Ce que Nova n'est pas

- Pas un placement, pas une promesse de gain, pas une « crypto » à acheter : **aucune vente, aucun
  préminage, aucune pièce au départ** ; les pièces ne naissent que par le minage.
- Pas aussi sûr que Bitcoin : la sécurité d'une chaîne à preuve de travail vient de la puissance de
  calcul qui la protège. Un petit réseau peut être réécrit par un seul acteur bien équipé
  (voir le tableau de probabilités de [RAPPORT-ATTAQUES.md](RAPPORT-ATTAQUES.md)).
- Pas audité par un tiers indépendant.

## Vérifier soi-même

```sh
python -m pip install -r requirements-dev.txt
python -m novacoin.verify            # toute la suite de tests, avec rapport
python -m novacoin.attack_bench      # banc d'attaques
python tools/build_release.py        # archive reproductible + SHA256SUMS
```
