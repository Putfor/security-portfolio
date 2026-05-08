# Putfor — Smart Contract Security Portfolio

Smart contract security researcher focused on EVM protocols, exploit reproduction, and protocol state integrity.

## About Me

I started learning smart contract security in 2025 and have been focused on hands-on security research ever since — from educational protocols and contest reviews to deeper dives into ECDSA, protocol accounting, and state consistency issues.

Most of my work is centered around manual review and exploit validation with Foundry. I enjoy understanding why vulnerabilities happen, not just identifying their symptoms.

## Research Focus

- Access control & trust boundary analysis
- ECDSA verification pitfalls and replay vectors
- Protocol accounting and state consistency
- Reward distribution edge cases
- Exploit reproduction with Foundry
- Security assumptions in upgrade and migration flows

## Tooling

- Solidity
- Foundry
- Slither
- Aderyn
- Fuzz and invariant testing

## Selected Findings

Some vulnerability classes and scenarios I've explored in my reviews:

- Reward claiming bypass caused by balance-dependent eligibility checks
- Permanent accounting desynchronization after escrow migration
- Off-by-one supply enforcement leading to irreversible mint denial
- Unsafe ETH transfers using `transfer()` causing failed withdrawals
- Signature replay risks caused by unhashed metadata
- Missing access control in privileged protocol flows

## Contest & Independent Reviews

| Protocol | Type | Scope (nSLOC) | Notes | Report |
|----------|------|---------------|--------|--------|
| Monetrix | Code4rena Contest | 1,726 | Independent review and submitted findings | [📄 Report](./2026-05-03-monetrix-audit-report.md) |
| The Standard | Independent Review of Completed Contest | 609 | Replay-style review against finalized findings | [📄 Report](./2026-04-01-theStandard-audit-report.md) |

## Educational Reviews

These reviews were completed as part of structured practice and training.  
The focus was on developing audit workflow, exploit validation, and vulnerability reasoning.

| Protocol | Focus Areas | Report |
|----------|-------------|--------|
| DatingDapp | State validation, access control, reward logic | [📄 Report](./2026-03-01-datingDapp-audit-report.md) |
| AirDropper | Merkle proofs, accounting edge cases | [📄 Report](./2026-02-22-airDropper-audit-report.md) |
| BeatLand Festival | NFT logic, protocol state handling | [📄 Report](./2026-01-22-beatLand-festival-audit-report.md) |
| Santa's List | Supply accounting and mint restrictions | [📄 Report](./2026-01-08-santasList-audit-report.md) |
| TSwap | AMM accounting and unsafe state transitions | [📄 Report](./2025-11-06-tswap-audit.pdf) |
| Puppy Raffle | Access control and protocol invariants | [📄 Report](./2025-10-30-puppyRaffle-audit.pdf) |
| Password Store | Authorization and storage exposure | [📄 Report](./2025-10-19-passworStore-audit.pdf) |

**Total reviewed:** 3,383 nSLOC across multiple protocol types

## Collaboration

Currently interested in:
- Smart contract security collaborations
- Private review assistance
- Contest participation
- Shadow or trial audit opportunities

## Connect

- **Twitter/X:** [@putfor_sol](https://x.com/putfor_sol)
- **Telegram:** [@putfor](https://t.me/putfor)
- **CodeHawks:** [putfor](https://profiles.cyfrin.io/u/putfor)
- **Code4rena:** [putfor](https://code4rena.com/@l_Snowman_l)
- **Sherlock:** [putfor](https://audits.sherlock.xyz/watson/putfor)
