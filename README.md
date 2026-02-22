# Putfor - Smart Contract Security Portfolio 🛡️

> Independent security researcher specializing in EVM-based smart contract audits

## About Me

Hey! I'm **putfor**, a smart contract security researcher focused on finding vulnerabilities in Solidity protocols. I believe in thorough, detail-oriented security reviews backed by comprehensive testing and clear communication.

My approach combines manual code review with systematic testing using Foundry, complemented by static analysis tools to ensure no stone is left unturned.

## 🔗 Connect

- **Twitter/X:** [@putfor_sol](https://x.com/putfor_sol)
- **CodeHawks:** [putfor](https://profiles.cyfrin.io/u/putfor)
- **Code4rena:** [putfor](https://code4rena.com/@l_Snowman_l)
- **Sherlock:** [putfor](https://audits.sherlock.xyz/watson/putfor)

## 🛠️ Technical Stack

**Languages & Frameworks:**
- Solidity (Primary focus)
- Foundry (Testing & PoC development)

**Analysis Tools:**
- Slither (Static analysis)
- Aderyn (Automated detection)
- Custom Foundry test suites

**Specialization:**
- EVM-based protocols
- DeFi security
- Access control & state management
- Economic attack vectors

## 📊 Audit Reports

Below are detailed security assessments I've conducted on educational protocols. Each report includes:
- Comprehensive risk classification
- Proof of concept with Foundry tests
- Detailed mitigation recommendations
- Gas optimization notes where applicable

### Featured Audits

| Protocol | Date | Scope (nSLOC) | Findings | Report |
|----------|------|---------------|----------|--------|
| AirDropper | Feb 2026 | 62 | 2H, 2L | [📄 View Report](./2026-02-22-airDropper-audit-report.pdf) |
| BeatLand Festival | Jan 2026 | 234 | 2M, 2L | [📄 View Report](./2026-01-22-beatLand-festival-audit-report.pdf) |
| Santa's List | Jan 2026 | 116 | 3H, 2L | [📄 View Report](./2026-01-08-santasList-audit-report.pdf) |
| TSwap | Nov 2025 | 276 | 4H, 1M, 2L, 9I | [📄 View Report](./2025-11-06-tswap-audit.pdf) |
| Puppy Raffle | Oct 2025 | 143 | 4H, 2M, 8I | [📄 View Report](./2025-10-30-puppyRaffle-audit.pdf) |
| Password Store | Oct 2025 | 20 | 2H, 1I | [📄 View Report](./2025-10-19-passworStore-audit.pdf) |

**Total audited:** 851 nSLOC across multiple protocol types

## 🎯 Audit Highlights

Some interesting vulnerabilities I've identified:

- **Missing state management** leading to permanent protocol misconfiguration
- **Off-by-one errors** in supply enforcement causing loss of NFT minting rights
- **Unsafe ETH transfers** using deprecated `transfer()` causing withdrawal failures
- **Unhandled panic reverts** from unsafe token ID encoding

Each finding is documented with:
- Clear impact and likelihood assessment
- Working Foundry PoC demonstrating exploitability
- Concrete mitigation with code diffs

## 🤝 Open for Collaboration

I'm actively looking to:
- 🔍 Participate in **audit contests** (Code4rena, Sherlock, CodeHawks)
- 🤝 Collaborate on **private security reviews**
- 💡 Join forces for **contest team-ups**

If you're working on a protocol that needs security eyes or want to collaborate on contests, feel free to reach out!

## 📫 Contact

- **Twitter DMs:** [@putfor_sol](https://x.com/putfor_sol)
- **Telegram:** [@putfor](https://t.me/putfor)

---

*Building a safer Web3, one vulnerability at a time* 🚀
