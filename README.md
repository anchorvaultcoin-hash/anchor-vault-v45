
## ✨ Features

- **Multi-token support** — any standard ERC-20 (USDC, USDT, DAI, WETH, ANCR, etc.)
- **Adaptive minimum deposit** — `0.01 token` automatically calculated from `decimals()`
- **EIP-712 off-chain auth** — 2FA design (wallet + signing key), per-vault nonce, deadline
- **Two security keys** — Main (daily ops) + Recovery (emergency ops)
- **Vault levels** — SAFE / VAULT / FORTRESS with escalating fees & timelocks
- **Flexible transfers** — Quick transfer (1-step) & Secure transfer (2-step escrow, 48h)
- **User-owned emergency address** — set once, change requires 7-day timelock
- **Global pause** — 2-day delayed pause or immediate emergency pause; withdrawals stay available
- **Voluntary lock** — up to 5 years, blocks main-key ops, can only be extended
- **Creator/Guardian roles** — fully separated, 2-step transfers with cooldowns

---

## 📊 Contract Metrics

| Metric | Value |
|--------|-------|
| **Deployed bytecode** | **24,516 bytes** (spare: 60) |
| **EIP-170 limit** | 24,576 bytes |
| **Solidity version** | 0.8.26 |
| **Optimizer** | `runs = 1`, `via_ir = true` |
| **Tests** | **351/351 passed** |
| **Slither** | **0 High**, 0 Critical |
| **Coverage** | >95% |

---

## ✅ Audit Status

| Check | Status |
|-------|--------|
| Foundry tests | ✅ 351/351 |
| Invariants | ✅ `lockedPrincipal` matches vault sum, `solvency` holds |
| Gas report | ✅ within expected ranges |
| Slither (static analysis) | ✅ 0 High, 0 Critical |

**Ready for audit and mainnet deployment.**

---

## 🛡️ Security

- `wasSupported` — prevents rescue of tokens that were ever whitelisted (audit fix)
- `ReentrancyGuard` on all external user operations
- EIP-712 signatures with per-vault nonce (replay protection)
- Role separation: `creator` ≠ `guardian`, 2-step role transfers with cooldowns
- Non-custodial guarantee: withdrawals remain available even when paused

See [`SECURITY.md`](./SECURITY.md) for threat model, invariants, and accepted design decisions.

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
forge build --sizes | grep AnchorVaultV45
```

**Run invariant tests:**
```bash
forge test -vvv --match-contract AnchorVaultInvariantTest
```

---

## 📦 Deployment (Sepolia)

| Contract | Address |
|----------|---------|
| AnchorVaultV45 | `0x8E1F46fC913c4928303BbCEB92ccb7c54cD95BA4` |
| ANCR token | `0x6a837125eeB63cc4D3d38E93e2adCd30a2603cF7` |
| Creator / payout | `0x725F1408c2CDa5757d8B44a92a84EACc529F5150` |
| Guardian | `0x0838238A55d846A2a92fC6889Cc96558533B68ab` |

**Initial distribution:**
- Reward pool: 500,000 ANCR
- Strategic reserve: 300,000 ANCR
- Payout wallet: 200,000 ANCR

---

## 🧠 Architecture

### Vault Levels

| Level | Deposit Fee | Max Timelock |
|-------|-------------|--------------|
| SAFE | 0.50% | 0 h |
| VAULT | 1.50% | 72 h |
| FORTRESS | 2.00% | 168 h |

### Fee & Penalty Structure

| Operation | Fee |
|-----------|-----|
| Open vault | 0.20% |
| Withdraw / Transfer / Secure transfer | 0.50% |
| Early close | 5% |
| Recover to safe | 10% |
| Emergency withdraw to any | 15% |
| Panic withdraw | 20% |

### Penalty Distribution

**For ANCR tokens:**
- 20% burned
- 25% creator fees
- 20% strategic reserve
- 35% reward pool

**For other tokens:**
- 50% creator fees
- 50% strategic reserve

**While paused:** ANCR penalties go 100% to reward pool; other tokens split 50/50 creator/reserve.

---

## 🔐 Roles

| Role | Capabilities |
|------|--------------|
| **Creator** | Withdraw fees/reserve (7-day timelock), add/remove tokens, set welcome bonus, unpause, transfer roles (2-step + cooldown). Cannot touch user principal. |
| **Guardian** | Request delayed pause (2 days), execute emergency pause (immediate). Cannot unpause or move funds. |
| **User (vault owner)** | Full control of own vaults via two auth keys. |

---

## 📄 License

BUSL-1.1 — Licensor: Vitaliy — Copyright © 2026 AnchorVaultCoin.  
Change Date: 2030-01-01 → GPL-2.0-or-later.  
Imported OpenZeppelin files are MIT. Commercial use before Change Date requires written permission.' > README.md && git add README.md && git commit -m "docs: update README for v45 final (24516 bytes, 351 tests)" && git push
