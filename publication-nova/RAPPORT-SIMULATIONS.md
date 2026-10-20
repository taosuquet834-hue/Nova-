# Simulations d'attaques sur la preuve de travail

Générées par `python tools/simulate.py` (graine 1  400 000 blocs par cas). Ce sont des **modèles des règles du protocole** (la chaîne au plus grand travail l'emporte)  pas des essais du code ; ils sont comparés aux formules publiées.

## 1. Minage égoïste (Eyal et Sirer)

Un groupe de mineurs retient ses blocs pour gagner plus que sa part. `γ` est la part des autres mineurs qui suivent le groupe en cas d'égalité. Un résultat **au-dessus de la puissance du groupe** signifie que tricher paie.

| Puissance α | γ | Part des blocs (simulée) | Formule publiée | Tricher paie ? |
|---|---|---|---|---|
| 10% | 0.5 | 0.072 | 0.072 | non |
| 25% | 0.0 | 0.195 | 0.195 | non |
| 25% | 0.5 | 0.251 | 0.250 | non |
| 30% | 0.5 | 0.329 | 0.327 | **oui** |
| 33% | 0.0 | 0.326 | 0.327 | non |
| 35% | 0.0 | 0.366 | 0.367 | **oui** |
| 40% | 0.0 | 0.488 | 0.484 | **oui** |
| 45% | 0.5 | 0.680 | 0.681 | **oui** |

Seuil : avec γ = 0 le minage égoïste commence à payer vers **un tiers** de la puissance ; avec γ = 0,5 vers **un quart** ; avec γ = 1, dès qu'on a de la puissance. **Aucune règle de Nova ne l'empêche** : c'est une propriété de la preuve de travail.

## 2. Effacer un paiement confirmé

| Puissance de l'attaquant | Confirmations | Simulé | Modèle exact |
|---|---|---|---|
| 10% | 6 | 0.001 | 0.001 |
| 25% | 3 | 0.210 | 0.207 |
| 25% | 6 | 0.069 | 0.069 |
| 30% | 6 | 0.156 | 0.156 |
| 40% | 6 | 0.492 | 0.493 |
| 40% | 12 | 0.326 | 0.327 |

## 3. Blocs concurrents selon la latence du réseau

Part des blocs qui ont un concurrent trouvé avant d'avoir pu être connu : du travail perdu, et un réseau plus facile à diviser.

| Temps de bloc | Latence de propagation | Simulé | Formule 1 − e^(−Δ/T) |
|---|---|---|---|
| 10 s | 1 s | 0.096 | 0.095 |
| 10 s | 2 s | 0.181 | 0.181 |
| 60 s | 1 s | 0.017 | 0.017 |
| 60 s | 2 s | 0.033 | 0.033 |
| 60 s | 5 s | 0.080 | 0.080 |
| 600 s | 2 s | 0.003 | 0.003 |

## 4. Si la puissance de calcul change brutalement

Temps moyen entre deux blocs, fenêtre après fenêtre (20 blocs), avec la **vraie règle d'ajustement** du protocole. Cible : 60 s. Moyenne sur 200 essais.

| Puissance | Fenêtre 1 | Fenêtre 2 | Fenêtre 3 | Fenêtre 4 | Fenêtre 5 | Fenêtre 6 | Temps total perdu au-dessus de la cible |
|---|---|---|---|---|---|---|---|
| ÷10 (90 % des mineurs partent) | 555.2 s | 145.6 s | 41.0 s | 42.0 s | 63.4 s | 64.0 s | 284 min |
| ÷2 | 114.2 s | 63.2 s | 49.2 s | 59.2 s | 59.1 s | 59.0 s | 115 min |
| ×4 | 14.4 s | 51.7 s | 73.4 s | 63.6 s | 58.5 s | 57.5 s | 86 min |
| ×10 | 5.9 s | 22.0 s | 71.3 s | 71.5 s | 61.5 s | 57.8 s | 78 min |

Si 90 % des mineurs partent, les blocs deviennent 10 fois plus lents et il faut plusieurs fenêtres (chacune limitée à ×4) pour revenir à 60 s : le réseau reste **très lent pendant plusieurs dizaines de minutes**, puis redevient normal sans intervention. À l'inverse, une arrivée massive accélère les blocs (donc plus de blocs concurrents) jusqu'à l'ajustement suivant.


**Lecture** : avec 10 secondes par bloc (versions 3 à 12), une latence réaliste sur Internet (1 à 2 s) produisait 10 à 18 % de blocs concurrents. **Depuis la V13, le temps de bloc est de 60 s** : 2 s de latence donnent environ 3 % de blocs concurrents. Bitcoin, à 600 s, reste sous 1 %.
