# AnchorVaultV45 — Testing Summary

**Date:** 2026-06-22
**Version:** 45
**Contract:** AnchorVaultV45.sol
**Chain:** Sepolia (testnet) — mainnet pending external audit

> This is an internal testing summary collected during development. It is **not** an audit and makes no security guarantee. Mainnet deployment is gated on an external professional audit.

---

## 1. Summary

| Metric | Result |
|--------|--------|
| **Deployed bytecode** | 24,516 bytes (spare: 60) |
| **EIP-170 limit** | 24,576 bytes |
| **Solidity** | 0.8.26 |
| **Optimizer** | `runs = 1`, `via_ir = true` |
| **Tests** | 351/351 passed |
| **Coverage** | 95.06% lines, 91.00% statements |
| **Slither (our code)** | 0 High, 0 Critical |
| **Invariants** | 2/2 passed (128k fuzz calls each) |
| **Gas** | Within expected ranges |

---

## 2. Contract Overview

**AnchorVaultV45** is a non-custodial, multi-asset ERC-20 vault system with:

- EIP-712 off-chain authorization (main + recovery keys)
- Three vault levels: SAFE, VAULT, FORTRESS
- Adaptive minimum deposit per token (0.01 token)
- Quick transfer + secure two-step transfer with 48h escrow
- User-set global emergency address (change requires 7-day timelock)
- Pause mechanism (2-day delayed or immediate by guardian)
- Voluntary lock (up to 5 years), timelock per vault
- Creator / guardian role separation with 2-step transfers

---

## 3. Test Results

### 3.1 Test Suite

| Suite | Passed | Total |
|-------|--------|-------|
| `AnchorVaultV45.t.sol` | 239 | 239 |
| `AnchorVaultV45Extended.t.sol` | 102 | 102 |
| `LiveAttackVectorTests.t.sol` | 8 | 8 |
| `AnchorVaultInvariant_t.sol` | 2 | 2 |
| **Total** | **351** | **351** |

**Invariants exercised:**
- `lockedPrincipal` matches sum of all active vault amounts
- Contract solvency (balance ≥ lockedPrincipal + fees + reserve)

### 3.2 Coverage

| File | Lines | Statements | Branches | Functions |
|------|-------|------------|----------|-----------|
| `AnchorVaultV45.sol` | 96.93% | 92.16% | 73.15% | 97.30% |
| **Total** | **95.06%** | **91.00%** | **72.84%** | **91.84%** |

### 3.3 Slither (Static Analysis)

| Severity | Count | Status |
|----------|-------|--------|
| High (our code) | 0 | — |
| High (OZ Math) | 1 | known false positive |
| Medium | 12 | reviewed / accepted |
| Low | 15 | reviewed / accepted |

### 3.4 Gas Report (Key Functions)

| Function | Avg Gas | Max Gas |
|----------|---------|---------|
| `openVault` | 289,839 | 428,555 |
| `depositToVault` | 99,143 | 99,217 |
| `withdrawFromVault` | 98,209 | 119,312 |
| `earlyClose` | 97,901 | 115,228 |
| `panicWithdraw` | 99,212 | 115,160 |
| `transferVault` | 259,893 | 268,274 |
| `confirmSecureTransfer` | 264,504 | 274,574 |
| `initSecureTransfer` | 189,991 | 195,635 |
| `setTimelock` | 48,419 | 49,613 |
| `setVoluntaryLock` | 48,904 | 49,127 |
| `rotateAuthKeys` | 51,606 | 52,065 |
| `withdrawCreatorFees` | 55,252 | 55,507 |
| `donateToRewardPool` | 48,640 | 85,135 |

---

## 4. Security Properties (as implemented)

| Property | Implementation |
|----------|----------------|
| **Non-custodial** | Withdrawals remain available even when paused. |
| **Replay protection** | EIP-712 signatures + per-vault nonce + deadline. |
| **Role separation** | `creator` ≠ `guardian`, 2-step transfers with cooldowns. |
| **Emergency address** | First set immediate; change requires 7-day timelock. |
| **Token rescue** | `wasSupported` prevents rescue of ever-whitelisted tokens. |
| **Reentrancy** | `ReentrancyGuard` on all external user operations. |
| **Voluntary lock** | Up to 5 years, blocks main-key ops, can only be extended. |
| **Minimum deposit** | Precomputed on token addition using `(10^decimals + 99)/100`. |

---

## 5. Notable Implementation Decisions

- `wasSupported` — prevents rescue of ever-whitelisted tokens
- `minDeposit` private mapping — saves 84+ bytes
- Ceiling division formula — handles edge cases
- `address(0)` check removed from `addSupportedToken` — `.decimals()` already reverts
- Secure transfer conflict handling — status `4` (CONFLICT)
- Recipient can reject incoming transfer immediately
- Role merge prevention on accept — creator ≠ guardian

---

## 6. Deployment (Sepolia)

| Component | Address |
|-----------|---------|
| AnchorVaultV45 | `0x8E1F46fC913c4928303BbCEB92ccb7c54cD95BA4` |
| ANCR token | `0x6a837125eeB63cc4D3d38E93e2adCd30a2603cF7` |
| Creator / payout | `0x725F1408c2CDa5757d8B44a92a84EACc529F5150` |
| Guardian | `0x0838238A55d846A2a92fC6889Cc96558533B68ab` |

**Initial distribution:**
- Reward pool: 500,000 ANCR
- Strategic reserve: 300,000 ANCR
- Payout wallet: 200,000 ANCR

> Note: the currently deployed Sepolia instance is the earlier 18-decimal-only build. The multi-token build in this repo has not been redeployed yet.

---

## 7. Known Risks (Accepted by Design)

| Risk | Mitigation |
|------|------------|
| Creator can whitelist non-standard tokens | Creator is trusted; mainnet should use multisig. |
| Guardian can pause contract | Pause does not affect withdrawals. |
| Block timestamp manipulation | Used only for cooldowns/locks, not critical fund movement. |

---

## 8. Notes for Mainnet (self-imposed, pre-conditions)

- Separate `creator` and `payoutWallet` addresses.
- Use a multisig wallet for the `creator` role.
- Verify `minDeposit` values for all expected tokens before deployment.
- Ensure `payoutWallet` is an EOA (constructor already enforces `code.length == 0`).
- **Mainnet only after an external professional audit and with a TVL cap.**

---

**Status:** internal testing complete; external audit pending.
