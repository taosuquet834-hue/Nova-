# Limites et avertissements

À lire avant d'utiliser, de partager ou de publier Nova. Ce texte est volontairement sans fard.

## Ce que c'est

Un **laboratoire** : une blockchain complète mais petite, écrite pour apprendre et expérimenter.
Les pièces n'ont **aucune valeur** et le réseau peut être réinitialisé à tout moment.

## Ce qui est vrai de la sécurité

1. **La puissance de calcul fait la sécurité, pas le code.** Sur un petit réseau, une seule personne
   bien équipée peut réécrire l'histoire récente. À partir de 50 % de la puissance, l'attaque réussit
   toujours ; avec 30 %, un paiement confirmé 6 fois est annulé dans environ 16 % des cas.
   Voir la table de [RAPPORT-ATTAQUES.md](RAPPORT-ATTAQUES.md).
2. **Aucun audit indépendant.** Le code, les tests, le banc d'attaques et l'audit interne ont été
   produits par le même auteur (un assistant d'IA). Ils ne remplacent pas des yeux extérieurs.
3. **Défenses réelles mais limitées** : transport chiffré et authentifié, requêtes signées, limites de
   débit, bannissements, validation stricte (fuzzing sans erreur interne). Elles n'ont été éprouvées que
   sur quelques machines simulées, quelques minutes à la fois.
4. **Ce qui n'existe pas** : anti-éclipse, anti-Sybil, chiffrement de la clé d'identité des nœuds,
   rotation de clés, portefeuille matériel, signatures multiples, contrats, récupération par un tiers.
5. **Pas de récupération** : phrase de 12 mots et fichier de portefeuille perdus = pièces perdues.
   La liste de mots est celle de Nova, **pas** celle de BIP39.
6. **Limites techniques** : 500 000 blocs au plus (les blocs sont sur disque, l'ensemble des pièces reste en mémoire), 200 transactions par
   bloc, port local en HTTP (doit rester sur 127.0.0.1), l'horloge fait partie du consensus (60 s).

## Ce que le projet ne fait pas et ne doit pas faire

- Aucune vente, aucune levée de fonds, aucune promesse de prix, de rendement ou de liquidité.
- Aucune pièce n'est créée au départ : pas de préminage, pas d'allocation.
- Aucune affiliation à Bitcoin ou à une autre monnaie.

## Avant de publier

Voir [JURIDIQUE-A-VALIDER.md](JURIDIQUE-A-VALIDER.md) et [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md) :
des décisions restent à prendre par une personne (licence, nom, contact de sécurité, avis juridique).
