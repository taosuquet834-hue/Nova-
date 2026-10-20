# Signaler une faille de sécurité

Nova est un projet expérimental sans valeur monétaire ; les failles restent précieuses car elles
montrent ce qui doit être corrigé avant toute ouverture plus large.

**Contact de sécurité : A_COMPLETER** (adresse e-mail ou formulaire privé du propriétaire du projet —
à renseigner avant publication ; voir RELEASE-CHECKLIST.md).

Merci de ne pas publier une faille avant d'en avoir informé le propriétaire et de lui avoir laissé un
délai raisonnable. Indiquer : version (`python -m novacoin version`), ce qui a été observé, les étapes
minimales de reproduction, l'impact estimé. Les failles qui touchent le consensus ou la création de
pièces sont prioritaires ; voir `CAHIER-AUDIT-EXTERNE.md` pour les questions déjà identifiées.
Aucune prime n'est prévue.

**Vérifier ce que vous installez** : comparer la signature de l'archive (`python -m novacoin verify-release --file F --sig S --pubkey CLÉ`) avec la clé de publication annoncée par le propriétaire, puis `python tools/verify_install.py`.
