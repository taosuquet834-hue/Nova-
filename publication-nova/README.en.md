# Nova — an independent experimental blockchain

> **Test network. NOVA coins have no value, nothing is promised, nothing is for sale.**
> Do not use it for real money. See [LIMITES-ET-AVERTISSEMENTS.md](LIMITES-ET-AVERTISSEMENTS.md) (French).

Nova is a small blockchain written to **understand** how a digital currency works: blocks linked by
hashes, proof of work, signed payments, several nodes reaching agreement. It is not Bitcoin and is not
affiliated with any existing project. Version **1.3.0rc1** (release candidate), network **`nova-testnet-3`**.

- **Chain**: SHA-256 proof of work with a continuous 256-bit target, retargeting every 20 blocks measured
  between median blocks, 60 s block target, UTXO model, Ed25519 signatures, halving every 210,000 blocks,
  21 million cap, no premine. Full specification: `PROTOCOLE.md` (French) and an independent verifier,
  `tools/independent_check.py`, written from the specification alone.
- **Network**: TLS 1.3 with pinned Ed25519 node identities, signed requests bound to the recipient, rate
  limits and temporary bans, incremental synchronisation, closed mode with an identity allow-list.
- **Wallet**: encrypted file, 12-word recovery phrase (Nova's own 2048-word list, *not* BIP39), fresh
  address per receipt, contacts.
- **Tooling**: local dashboard and block explorer, attack bench, soak test, pre-flight `doctor`.
- **V11 hardening** (see `DURCISSEMENT-V11.md`, French): encrypted node key, persistent bans, anti-eclipse peer limits, automatic checkpoints, reorganisation evidence margin, operator alerts, hash-chained signed journal, network fuzzing, crash tests, 2-of-n multisignature and timelocked payments (new network `nova-testnet-3`), verified wallet backups, signed releases with file manifest.
- **V12**: chain stored in SQLite with a 128-block memory window (500,000-block limit), linear start-up, release-key commands, attack simulations validated against published formulas (selfish mining threshold, exact double-spend odds, fork rate vs latency) — `AMELIORATIONS-V12.md`, `RAPPORT-SIMULATIONS.md`.
- **V13** (new network `nova-testnet-3`): 60 s block time (10 s forked too often: 10–18 % competing blocks at 1–2 s latency vs ~3 %), transaction ids no longer depend on signatures (no malleability) — `AMELIORATIONS-V13.md`.
- **Verification**: 140+ automated tests (`python -m novacoin.verify`). An internal audit was done; **no
  independent audit exists**.

License: **GNU AGPL v3** (`LICENSE`) — modified versions, including ones run as a network service, must be published under the same license. No warranty.

Quick start: `python -m pip install -r requirements.txt && python -m novacoin.demo` (three local nodes).

Honest limits: a small proof-of-work network can be rewritten by one well-equipped party (see the
probability table in `RAPPORT-ATTAQUES.md`); no independent audit; blocks are on disk (500,000 max) but the
unspent-coin set stays in memory; local port is plain HTTP and must stay on localhost; recovery phrase format is Nova-specific.
