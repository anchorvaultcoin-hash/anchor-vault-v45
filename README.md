# AnchorVaultCoin

Non-custodial multi-asset vault for ERC-20 tokens on Ethereum.

Vault operations are authorized by **two dedicated keys**, neither of which is the
owner's wallet. A compromised seed phrase does not give an attacker control of the
vault: without the auth keys they cannot withdraw to an address of their choosing,
transfer the vault, or rotate its keys.

The one action available without a signature is `panicWithdraw` — and it pays out
**only to the owner's own pre-set emergency address**, never to the caller, at a
20% penalty. An attacker holding just the wallet key can therefore force an exit,
but cannot steal: the funds land in the owner's backup address and 80% of the
principal is preserved.

**License:** BUSL-1.1 · **Status:** Audit completed by Hexens (0 Critical, 0 High) · Live on Ethereum Mainnet

---

## ✨ Features

- **Multi-token support** — ERC-20 tokens with `decimals()` between 6 and 18 (USDC, WBTC, WETH, DAI, ANCR, …)
- **Adaptive minimum deposit** — `0.01 token`, derived from the token's own `decimals()`
- **EIP-712 off-chain auth** — 2FA design (wallet + signing key), per-vault nonce, deadline
- **Two security keys** — Main (daily ops) + Recovery (emergency ops)
- **Vault levels** — SAFE / VAULT / FORTRESS with escalating fees & timelocks
- **Two transfer paths** — quick transfer (requires recipient's consent signature) and secure transfer (2-step escrow, 48 h)
- **User-owned emergency address** — set once, change requires 7-day timelock
- **Global pause** — 2-day delayed pause or immediate emergency pause; withdrawals stay available
- **Voluntary lock** — up to 5 years, blocks main-key ops, can only be extended
- **Creator/Guardian roles** — fully separated, 2-step transfers with cooldowns

---

## 📊 Contract Metrics

| Metric | Value |
|--------|-------|
| **Deployed bytecode** | *(run `forge build --sizes` on the current `AnchorVaultCoin.sol` and update)* |
| **EIP-170 limit** | 24,576 bytes |
| **Solidity version** | 0.8.26 |
| **Optimizer** | `runs = 1`, `via_ir = true`, `evm_version = cancun` |
| **OpenZeppelin** | 5.6.1 |
| **Unit & integration tests** | *(run `forge test` and update — count changed after audit fixes)* |
| **Invariant tests** | 5/5 passed (128,000 calls each) |
| **Slither** | 0 High, 0 Critical |

---

## 🔍 Audit Status

An external security audit was completed by
[Hexens](https://hexens.io/) under their Builder Support Ecosystem Program.

| Stage | Status |
|-------|--------|
| Audit start | ✅ 20 Jul 2026 |
| Initial report | ✅ 31 Jul 2026 |
| Revision received | ✅ 3 Aug 2026 |
| **Final report** | ✅ **10 Aug 2026** |

**Result: 0 Critical, 0 High severity findings.** 4 issues were identified (2 Medium,
1 Low, 1 Informational) — all fixed by the development team and verified by Hexens.

From the report's executive summary: *"We can confidently say that the overall
security and code quality have increased after completion of our audit."*

Full report available on request / see `hexens-anchorvault-jul-26(Final).pdf` in this repo.

### Internal verification

| Check | Status |
|-------|--------|
| Foundry tests | ✅ passing |
| Invariants | ✅ solvency and `lockedPrincipal` consistency hold across all tokens |
| Gas report | ✅ within expected ranges |
| Slither (static analysis) | ✅ 0 High, 0 Critical |

---

## 🛡️ Security

**What the design protects against.** The threat model is compromise of the owner's
wallet key — the most common way individual holders lose funds. Vault operations
require EIP-712 signatures from keys that are never the wallet itself, so a stolen
seed phrase is not enough to redirect funds.

**What it does not claim.** The vault is not immovable. `panicWithdraw` is a
deliberate escape hatch that works without any signature, so a user who has lost
their auth keys is never permanently locked out. Its destination is fixed to the
owner's emergency address and it costs 20% — the price of keeping that exit open.
Voluntary locks and timelocks likewise do not block the emergency paths.

Implementation details:

- Per-vault nonce + deadline + domain separator (chainId, contract address) — replay protection
- Quick transfer requires a consent signature from the receiving address
- Timelocked vaults cannot be moved through either transfer path
- `wasSupported` — prevents rescue of tokens that were ever whitelisted
- `ReentrancyGuard` on all external user operations
- Role separation: `creator` ≠ `guardian`, 2-step role transfers with cooldowns
- Withdrawals remain available while the contract is paused
- `rewardPool` holds user funds and has no creator withdrawal path by design

*(Verify `SECURITY.md` and `SECURITY_MODEL.md` are present and current before linking them here.)*

---

## 🧪 Testing

```bash
forge install
forge build
forge test
```

**Run gas report:**
```bash
forge test --gas-report
```

**Check contract size:**
```bash
forge build --sizes | grep AnchorVaultCoin
```

**Run invariant tests:**
```bash
forge test --match-test invariant
```

**Run audit-finding regression tests:**
```bash
forge test --match-path test/ANCV1_Findings.t.sol
```

---

## 🧠 Architecture

### Vault Levels

| Level | Fee (open & deposit) | Max Timelock |
|-------|----------------------|--------------|
| SAFE | 0.50% | none |
| VAULT | 1.50% | 72 h |
| FORTRESS | 2.00% | 168 h |

Opening a vault and topping it up are charged at the same rate, so closing and
reopening a vault never costs less than a direct deposit.

### Fee & Penalty Structure

| Operation | Fee | Authorization | Destination |
|-----------|-----|---------------|-------------|
| Open vault / deposit | per level | — | — |
| Withdraw | 0.50% | main key | any address |
| Quick transfer | 0.50% | main key + recipient consent | recipient |
| Secure transfer | 0.50% | main key + recipient confirmation | recipient |
| Early close | 5% | recovery key | owner |
| Recover to emergency address | 10% | recovery key | owner's emergency address |
| Emergency withdraw to any | 15% | recovery key | any address |
| Panic withdraw | 20% | **none** | owner's emergency address only |

Cost rises with the freedom the path grants. The no-signature path is the most
expensive and the most constrained in destination.

### Penalty Distribution

**For ANCR:**
- 20% burned
- 25% creator fees
- 20% strategic reserve
- 35% reward pool

**For other tokens:**
- 50% creator fees
- 50% strategic reserve

**While paused:** ANCR penalties go 100% to the reward pool; other tokens split
50/50 creator/reserve. Since the normal 0.5% withdrawal stays available while
paused, users are never pushed toward the 20% exit.

---

## 🔐 Roles

| Role | Capabilities |
|------|--------------|
| **Creator** | Withdraw fees/reserve (7-day timelock), add/remove tokens, set welcome bonus, unpause, transfer roles (2-step + cooldown). Cannot touch user principal or the reward pool. |
| **Guardian** | Request delayed pause (2 days), execute emergency pause (immediate). Cannot unpause or move funds. |
| **User (vault owner)** | Full control of own vaults via two auth keys. |

---

## 📦 Deployment

| Network | Status |
|---------|--------|
| **Ethereum Mainnet** | ✅ **Live** |
| Sepolia (testnet) | Earlier revision — not the version currently deployed |

**Contracts:**

- **AnchorVaultCoin (vault):** [`0xAc362D7bFCe7a4475873C37A0A96F2CE5C00E929`](https://etherscan.io/address/0xAc362D7bFCe7a4475873C37A0A96F2CE5C00E929)
- **ANCR token:** [`0x52FBd42e9c9CBD3E1CED969EE4245C0e6ED9219B`](https://etherscan.io/address/0x52FBd42e9c9CBD3E1CED969EE4245C0e6ED9219B)

**Initial distribution** (one-time, `initializeDistribution()`):
- Reward pool: 500,000 ANCR
- Strategic reserve: 300,000 ANCR
- Payout wallet: 200,000 ANCR

The distribution requires the contract to hold the full amount **in addition to**
all balances already committed to users, so it can never be funded from user deposits.

---

## 📄 License

BUSL-1.1 — Licensor: Vitaliy — Copyright © 2026 AnchorVaultCoin.
Change Date: 2030-01-01 → GPL-2.0-or-later.
Imported OpenZeppelin files are MIT. Commercial use before the Change Date requires written permission.
