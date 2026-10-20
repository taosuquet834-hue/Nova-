# Contribuer à Nova

Merci de l'intérêt. Nova est un projet **éducatif et expérimental** ; les retours les plus utiles sont des failles, des
incohérences entre `PROTOCOLE.md` et le code, et des essais sur de vraies machines.

- **Avant tout** : lire `LIMITES-ET-AVERTISSEMENTS.md`. Aucune valeur monétaire n'est attachée aux pièces.
- **Failles de sécurité** : ne pas ouvrir de demande publique, suivre `SECURITY.md`.
- **Modifier le code** : lancer `python -m pip install -r requirements-dev.txt` puis `python -m pytest -q` ; toute modification du consensus
  doit mettre à jour `PROTOCOLE.md`, `tools/independent_check.py` et les tests. Un changement de règles exige un nouvel identifiant de réseau.
- **Licence des contributions** : en envoyant une contribution, vous acceptez qu'elle soit publiée sous la licence du projet (GNU AGPL v3).
- **Ne jamais envoyer** de clés, jetons, mots de passe ou portefeuilles, même de test réels.
