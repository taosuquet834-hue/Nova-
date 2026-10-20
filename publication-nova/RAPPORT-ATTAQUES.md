# Rapport du banc d'attaques Nova (V7)

Exécuté le 20/10/2026 12:18 UTC sur le réseau de laboratoire (difficulté minimale). Les défenses sont celles du code de ce dossier.

| Attaque | Défense attendue | Résultat | Observé |
|---|---|---|---|
| Double dépense dans la file | Le second paiement des mêmes pièces est refusé | **TIENT** | Refusé : Pièce absente ou déjà dépensée |
| Double dépense dans un bloc | Un bloc qui dépense deux fois est refusé | **TIENT** | Refusé : Pièce absente ou déjà dépensée |
| Retournement de paiement par un attaquant plus puissant | AUCUNE défense de protocole : c'est la définition de la sécurité par preuve de travail | **INHÉRENT** | Paiement annulé après 6 confirmations par une chaîne secrète plus lourde |
| Chaîne secrète à travail égal | Le nœud garde la première chaîne vue | **TIENT** | Paiement conservé |
| Réécriture de plus de 50 blocs | Un nœud refuse de lui-même de remplacer plus de 50 blocs (politique locale) | **TIENT** | Refusé : Réorganisation de 60 blocs refusée (limite 50) |
| Manipulation des horodatages (time warp) | Le temps mesuré d'une fenêtre ne peut pas être gonflé de plus de 60 s | **TIENT** | Meilleur gonflement obtenu : +60 s sur une fenêtre réelle de 14 s (un réglage reste borné à ×4 / ÷4) |
| Blocs et paiements mutés au hasard | Toute mutation est refusée proprement (jamais d'erreur interne) et l'état reste sain | **TIENT** | 4925 objets essayés, 2 acceptés (mutations sans effet), aucune erreur interne |
| Inondation de paiements invalides | Tous refusés, file inchangée, coût borné | **TIENT** | 2000/2000 refusés en 0.0 s, file : 0 |
| File pleine de paiements à frais minimaux | Un paiement bien rémunéré reste accepté (éviction des moins payants) | **TIENT** | File de 1000 paiements ; le paiement à frais élevés a été accepté |
| Pair menteur annonçant 90 000 blocs | Coût borné (quelques dizaines de requêtes) et pair sanctionné | **TIENT** | 2 requêtes pour une tentative (chaîne locale de 250 blocs) ; pair banni après 3 tentatives : True |

## Remarques
- *Retournement de paiement par un attaquant plus puissant* : La sécurité dépend de la puissance honnête, pas du code (voir table ci-dessous).
- *Réécriture de plus de 50 blocs* : Limite : un attaquant très majoritaire peut cibler des nœuds fraîchement installés.
- *Manipulation des horodatages (time warp)* : Sur un réseau lent (fenêtre de plusieurs minutes), 60 s pèsent peu ; sur un réseau très rapide ils pèsent beaucoup. Un attaquant majoritaire peut répéter l'opération à chaque fenêtre.

## Chance qu'un attaquant efface un paiement (modèle exact)

Part de puissance de l'attaquant (lignes) et confirmations attendues (colonnes). C'est la limite théorique de toute chaîne à preuve de travail, quel que soit le code. (Le tableau d'origine du livre blanc de Bitcoin, calculé par approximation, sous-estime un peu ces chances ; ces valeurs sont exactes et confirmées par simulation, voir `RAPPORT-SIMULATIONS.md`.)

| Part \ confirmations | 1 | 2 | 6 | 12 | 30 |
|---|---|---|---|---|---|
| 10 % | 20.00 % | 5.60 % | 0.06 % | 0.00 % | 0.00 % |
| 25 % | 50.00 % | 31.25 % | 6.87 % | 0.93 % | 0.00 % |
| 30 % | 60.00 % | 43.20 % | 15.64 % | 4.29 % | 0.13 % |
| 40 % | 80.00 % | 70.40 % | 49.30 % | 32.73 % | 11.91 % |
| 45 % | 90.00 % | 85.05 % | 73.38 % | 62.69 % | 43.93 % |
| 51 % | 100.00 % | 100.00 % | 100.00 % | 100.00 % | 100.00 % |

Au-delà de 50 % de la puissance, l'attaque réussit toujours. Sur un réseau jeune et petit, une seule personne bien équipée peut dépasser 50 %.

Rejoué sur la V13 (1.3.0rc1, réseau nova-testnet-3) le 20/10/2026 : mêmes résultats (9 tiennent, 1 inhérent). Depuis la V10, des tests de non-régression couvrent aussi le fuzzing du réseau (260 entrées malformées ou signées hostiles par exécution), les paiements multisignature mutés (1 500 mutations sans erreur interne) et 8 coupures brutales (`kill -9`) d'un nœud en plein minage.

## Défauts trouvés par le banc, et corrigés dans cette version

1. **Coût quadratique de la file de paiements.** Chaque paiement reçu faisait revalider toute la
   file, signatures comprises : le scénario « file pleine » ne se terminait pas en dix minutes.
   Désormais une vue « chaîne + file » est gardée en mémoire et un paiement reçu ne coûte que sa
   propre validation (testé : une seule validation par paiement reçu).
2. **File pleine = file bloquée.** Une file remplie de paiements aux frais minimaux refusait tout
   le monde, y compris un paiement bien rémunéré. Le paiement le moins rémunéré par octet dont
   personne ne dépend est maintenant remplacé par un paiement qui paie strictement plus.
3. **Recherche d'ancêtre commun linéaire.** Face à un pair qui annonce 90 000 blocs, le nombre de
   requêtes dépendait de la longueur de la chaîne locale. Elle est maintenant dichotomique
   (environ log2 de la hauteur) et un pair dont le bloc de départ diffère est sanctionné.
4. Le fuzzing (près de 5 000 blocs et paiements mutés au hasard) n'a trouvé **aucune erreur
   interne** : tout est refusé proprement.

## Ce que le banc ne couvre pas

Minage égoïste, éclipse d'un nœud (isolé avec uniquement des pairs hostiles), inondation répartie sur
de nombreuses identités, attaques sur le système (disque, mémoire), compromission d'une clé,
canaux auxiliaires. Les résultats « TIENT » valent pour les scénarios décrits, pas pour toute
attaque imaginable.
