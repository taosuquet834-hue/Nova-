# Liste de contrôle avant publication

Générée par `tools/release_check.py` le 20/10/2026 17:40 UTC pour la version **1.3.0rc1**, réseau **nova-testnet-3**. Rien n'a été publié, envoyé ni téléversé.

## Contrôles automatiques

| Contrôle | Résultat | Détail |
|---|---|---|
| Suite de tests complète | OK | 209 passed in 217.08s (0:03:37) (218 s) |
| Banc d'attaques | OK | 9 tiennent, 0 cassent, 1 inhérent (puissance majoritaire) |
| Essai de longue durée | OK | 1.0 min, 4 nœuds : hauteurs finales [114, 114, 114, 114], convergence : True, paiements 63 (refusés 16), coupures 5, événements journalisés 120 |
| Archive reproductible | OK | deux constructions : 1da8dfa623d119ca… identiques |
| Aucun secret ni cache dans l'archive | OK | 76 fichiers |
| Documents requis présents | OK | tous présents |
| Version cohérente | OK | 1.3.0rc1 |
| Identifiant de réseau cohérent | OK | nova-testnet-3 |
| Champs à compléter signalés | OK | 1 fichier(s) : SECURITY.md |
| Licence | OK | AGPL-3.0 présente |

## Décisions et actions qui reviennent à une personne

- [ ] **Renseigner le contact de sécurité** dans `SECURITY.md` (champ `A_COMPLETER`).
- [ ] **Faire valider les points juridiques** de `JURIDIQUE-A-VALIDER.md` par un juriste, et vérifier que le nom « Nova » est utilisable.
- [ ] **Décider où et comment publier** (dépôt de code, page, annonce) et relire les textes publics : aucune promesse de valeur.
- [ ] **Faire relire par des humains compétents** `PROTOCOLE.md` et le code (`CAHIER-AUDIT-EXTERNE.md`) ; idéalement un audit avant d'ouvrir le réseau à des inconnus.
- [ ] **Renseigner `seeds.txt`** avec les nœuds que vous exploiterez vraiment, après vérification de leurs identifiants.
- [ ] **Exploiter au moins 3 nœuds sur des machines et des réseaux différents** pendant plusieurs jours avant l'ouverture (les essais faits ici durent quelques minutes sur une seule machine).
- [ ] **Vérifier l'archive finale** (`dist/SHA256SUMS`) sur une machine propre : `python -m novacoin doctor`, `python -m novacoin.demo`.
- [ ] **Annoncer une durée de vie** du réseau d'essai et le droit de le réinitialiser.
