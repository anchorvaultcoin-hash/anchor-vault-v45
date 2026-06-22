# Upgrade: AnchorVaultV45 — Multi-Token Support

## Context

The original contract only supported tokens with **18 decimals**, limiting the use of major stablecoins (USDC, USDT) and requiring wrappers.

We have performed a **contract upgrade** to expand capabilities and fix several audit findings.

---

## What Changed

### 1. Support for Any ERC-20 Token
- Added `tokenDecimals[token]` mapping to store decimals per token.
- `addSupportedToken` no longer requires 18 decimals — now accepts **any token** implementing `decimals()`.
- Minimum deposit is now dynamic via `getMinimumDeposit(token)` = `0.01 token` (adapts to decimals).

### 2. Fixed Vulnerabilities (L-1, L-2, L-3)
- **L-1 (timelock bypass via `rescueERC20`):** `rescueERC20` is now blocked for all supported tokens (`supportedTokens`).
- **L-2 (role merging):** `acceptCreatorship` and `acceptGuardianship` now prevent accepting a role if it matches the current holder of the other role.
- **L-3 (inconsistent pause behavior):** `withdrawFromVault` now uses `_settlePenalty`, ensuring consistent penalty distribution during pause.

### 3. UX and Security Improvements
- **`rejectIncomingTransfer`** — recipient can immediately reject an incoming transfer (no 48-hour wait).
- **`CONFLICT` status (4)** for secure transfers — if the recipient already has a vault, the transfer moves to conflict status, allowing the sender to cancel manually.
- **Key rotation** and emergency functions (`recoverToSafe`, `emergencyWithdrawToAny`) now ignore voluntary locks (as originally intended).

### 4. Size Reduction
- Removed `wasSupported` mapping (logic replaced with `supportedTokens`).
- Removed `emergencyAddress` field from `Vault` struct and `getVaultCore` (~80 bytes saved).
- Removed unused constants.

---

## Test Results

- **351 tests** passed (0 failures).
- Invariants (`invariant_solvency`, `invariant_lockedMatchesVault`) — all green.
- Contract size: **24,569 bytes** (7 bytes below the 24,576 EIP-170 limit).

---

## What Stayed the Same

- EIP-712 signatures, nonce, deadline — unchanged.
- Creator/guardian roles, pause, emergency functions — logic preserved.
- Fee and penalty distribution — unchanged (ANCR: 20/25/20/35; other tokens: 50/50).

---

## For Auditors

The core change is **multi-token support**. The contract now accepts any ERC-20 token without decimals restrictions. All vulnerability fixes have been tested and verified.

Current code: `src/AnchorVaultV45.sol`  
Tests: `test/AnchorVaultV45.t.sol` (351 tests).

---

**Upgrade Date:** 2026-06-22  
**Contract Version:** V45 (multi-token)
