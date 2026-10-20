# Points juridiques à faire valider avant publication

**Ceci n'est pas un avis juridique.** Ce sont des questions à poser à un juriste (droit du numérique /
crypto-actifs) avant de rendre le projet public. L'auteur du code n'est pas juriste.

## 1. Qualification des NOVA
- Des jetons sans valeur, distribués uniquement par minage sur un réseau d'essai, restent-ils hors du
  champ des règles sur les crypto-actifs (en Europe, le règlement MiCA ; en France, le régime AMF/ACPR) ?
  La réponse peut dépendre de la manière dont le projet est présenté (« essai gratuit » ou « monnaie »).
- À éviter tant que la question n'est pas tranchée : toute vente, tout échange contre de l'argent,
  toute promesse de valeur, toute cotation, toute communication de type investissement.

## 2. Nom et marque
- « Nova » est un nom très courant : vérifier les marques existantes (INPI, EUIPO, USPTO) et les projets
  de crypto du même nom avant d'utiliser le nom publiquement. Prévoir un nom de rechange.

## 3. Licence et contributions
- Le propriétaire a choisi la **GNU AGPL v3** (`LICENSE`). À faire confirmer : compatibilité avec vos objectifs (elle impose de publier
  les versions modifiées, même exploitées comme service en ligne), et la mention du titulaire des droits (vous ? une structure ?).
- Décider de la politique de contributions (propriété, accord de contribution).

## 4. Données personnelles
- Un nœud mémorise les adresses réseau de ses pairs et des événements (200 derniers). Si des tiers
  participent, vérifier si cela relève du RGPD (information, durée de conservation).

## 5. Cryptographie
- Le projet utilise de la cryptographie standard (TLS 1.3, Ed25519, SHA-256, AES-GCM, scrypt) via la
  bibliothèque `cryptography`. Vérifier les éventuelles formalités d'import/export applicables.

## 6. Responsabilité et avertissements
- Faire relire les avertissements (README, LIMITES-ET-AVERTISSEMENTS) et la clause d'exclusion de garantie
  de la licence choisie.
- Prévoir qui répond en cas de faille ou de mauvaise utilisation (voir SECURITY.md).

## 7. Réseau ouvert
- Ouvrir le port des pairs à Internet expose des machines de tiers : prévoir un cadre (conditions de
  participation, durée de vie annoncée, droit de réinitialiser, absence de contrepartie).
