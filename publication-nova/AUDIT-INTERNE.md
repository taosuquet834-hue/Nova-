# Audit interne de sécurité — Nova V9

**Ce n'est pas un audit indépendant.** Il a été fait par le même auteur que le code (un assistant
d'IA), avec les mêmes angles morts. Il sert à corriger ce qui se voit déjà et à préparer un audit
externe (voir `CAHIER-AUDIT-EXTERNE.md`). Date : 20 octobre 2026.

## Méthode

1. Relecture complète des fichiers qui touchent à l'extérieur : `p2p.py`, `node.py` (serveurs,
   synchronisation, file de paiements), `core.py` (consensus), `wallet.py`, `hdwallet.py`, `cli.py`.
2. Modèle de menace par surface (tableau ci-dessous).
3. Contrôles automatisés conservés comme tests (`tests/test_ops.py`, `tests/test_security.py`,
   `tests/test_attacks.py`) : motifs dangereux absents du code, droits des fichiers secrets, secrets
   absents des journaux, rejeu, signatures, bannissement, fuzzing.
4. Essai de longue durée (`tools/soak.py`) : mineurs, paiements, coupures et reprises aléatoires.
   Exécutions réalisées : 3 de 4 à 5 minutes (4 nœuds en processus, 30 à 40 coupures chacune) ;
   la dernière, sans limite de réorganisation : 143 blocs, 256 paiements, offre monétaire exacte à chaque
   étape, convergence finale des 4 nœuds. Cela ne remplace pas des heures ou des jours d'essai réel.

## Surfaces et résultats

| Surface | Menace | Défense | État |
|---|---|---|---|
| Port des pairs | Écoute, usurpation, rejeu, relais | TLS 1.3, identité épinglée, requêtes signées liées au destinataire, nonce | testé |
| Port des pairs | Déni de service | Débit par adresse et par identité, 8 connexions par adresse, poignée de main limitée, taille bornée, bannissement | testé, limites non éprouvées à grande échelle |
| Port local | Prise de contrôle depuis le réseau | Écoute sur 127.0.0.1 ; refus d'une autre adresse sans option explicite | **corrigé en V9** |
| Port local | Attaque depuis une page web (CSRF, DNS rebinding) | Jeton administrateur en en-tête, contrôle de l'origine, **contrôle du nom d'hôte** | **corrigé en V9** |
| Consensus | Blocs ou paiements malformés | Validation stricte, fuzzing de près de 5 000 objets sans erreur interne | testé |
| Consensus | Réécriture de l'histoire | Preuve de travail ; politiques locales (réorganisation maximale, points de contrôle) | limite inhérente : puissance honnête |
| Files d'attente | Saturation, coût de validation | Frais minimaux, poussière, éviction, validation incrémentale | corrigé en V7 |
| Clés | Vol du fichier de portefeuille | Chiffrement scrypt + AES-GCM, droits 0600 | testé |
| Clés | Vol de `node.key` (identité) | Droits 0600 ; **non chiffrée** | **limite connue** |
| Données | Corruption de la base | Revalidation complète au démarrage ; refus de démarrer | testé |
| Journaux | Fuite de secrets | Jeton et clés absents du statut et des événements | testé |
| Chaîne logicielle | Dépendances | Versions fixées (`requirements.txt`) ; une seule dépendance d'exécution | vérifié |

## Défauts trouvés pendant cet audit

1. **Réexposition possible du port local** (`--host 0.0.0.0` ouvrait le tableau de bord et
   l'administration en clair). Corrigé : refus sans `--allow-remote-local-port`.
2. **Pas de contrôle du nom d'hôte** sur le port local : une page hostile dont le nom pointe vers
   127.0.0.1 (DNS rebinding) pouvait lire les routes sans jeton (explorateur, état). Corrigé : seuls
   `127.0.0.1`, `localhost`, `::1` et l'adresse liée sont servis.
3. **Mineur bloqué par les horodatages** (essai de longue durée) : avec des horodatages strictement
   croissants et 60 s d'avance maximale, un mineur qui enchaînait plus de 60 blocs dans la même seconde
   produisait des blocs refusés (« trop futur ») puis s'arrêtait en erreur. Sans effet sur le réseau réel
   (un bloc toutes les 10 s) mais gênant sur un réseau très facile. Corrigé : le mineur attend.
4. Le message d'erreur d'une adresse de pair en `http://` était masqué par un message générique. Corrigé.
5. **Nœud durablement bloqué par la limite de réorganisation** (essai de longue durée, 4 nœuds,
   coupures aléatoires) : un nœud isolé qui avait miné 59 blocs de son côté refusait, par politique
   (limite 50), la chaîne plus lourde du reste du réseau, **sans avertissement clair** et en
   inscrivant le même refus toutes les 2 secondes dans son journal. La politique est voulue, mais
   l'opérateur doit le savoir : le refus n'est maintenant journalisé qu'une fois, le tableau de bord
   affiche un avertissement, et la commande `reorg-limit --value N` (jeton administrateur) permet de
   lever la limite en connaissance de cause. Le même essai, sans limite, converge.

## Mise à jour V11 (même jour)

Les limites suivantes de la V9 sont traitées en V11 : clé d'identité chiffrable, bannissements conservés,
détection d'éclipse et limites de pairs par réseau, journal altérable détecté. Défaut trouvé pendant ce travail :
la marge de preuve exigée pour effacer beaucoup de blocs était d'abord calculée sur le travail total de la
chaîne, donc impossible à atteindre sur une longue chaîne ; elle porte désormais sur les branches en
concurrence (test de non-régression). Voir [DURCISSEMENT-V11.md](DURCISSEMENT-V11.md). Toujours vrai :
aucun audit indépendant.

## Limites connues, non corrigées

- `node.key` n'est pas chiffrée au repos ; pas de rotation ni de révocation d'identité.
- Les bannissements et les compteurs ne survivent pas à un redémarrage.
- Un attaquant qui crée beaucoup d'identités contourne les sanctions par identité (la limite par
  adresse aide, mais n'arrête pas un réseau de machines).
- La découverte automatique reste limitée aux adresses privées ; aucun mécanisme anti-éclipse
  (un nœud dont tous les pairs sont hostiles voit une fausse chaîne).
- (V12) Les blocs sont sur disque ; restent en mémoire l'ensemble des pièces non dépensées, la liste des empreintes et l'index de l'explorateur ; 500 000 blocs au plus ; la validation d'un bloc recopie encore l'ensemble des pièces.
- L'horloge système fait partie du consensus (60 s de tolérance) ; une horloge fausse isole un nœud.
- Le port local reste en HTTP : il est réservé à la machine.
- Le mot de passe des portefeuilles de démonstration est stocké à côté d'eux (démonstration seulement).

## Ce qui n'a pas été examiné

Compromission du système d'exploitation, attaques physiques, canaux auxiliaires, comportement de
Python et d'OpenSSL eux-mêmes, conformité réglementaire. Un audit par des humains compétents en
cryptographie appliquée et en protocoles pair à pair est nécessaire avant toute ouverture.
