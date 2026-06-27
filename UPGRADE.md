# Upgrade: AnchorVaultCoin V45 — Multi-Token Support

## Context

The original contract only supported tokens with 18 decimals, limiting the use of major stablecoins (USDC, USDT) and requiring wrappers. This upgrade expands token support while preserving all existing security guarantees.

> **Deployment status:** The contract deployed at `0x8E1F46fC913c4928303BbCEB92ccb7c54cD95BA4` (Sepolia) is the **previous 18-decimal-only version**. The multi-token source in this repo is compiled, tested, and ready, but **not yet redeployed**.

---

## What Changed

### 1. Support for Any ERC-20 Token

- `addSupportedToken` no longer requires 18 decimals — it now accepts any token implementing `decimals()`.
- The per-token minimum deposit is **precomputed once** at whitelisting time and stored in a private `minDeposit[token]` mapping: `(10 ** decimals + 99) / 100` = 0.01 token in native units.
- This design keeps the minimum-deposit check O(1) at deposit time (a single storage read), with no exponentiation in the hot path.
- Frontends compute the displayed minimum directly from the token's `decimals()`.

### 2. Verified Vulnerability Fixes (L-2, L-3)

- **L-2 (role merging):** `acceptCreatorship` and `acceptGuardianship` now revert if the pending role equals the current holder of the other role (`if (pendingCreator == guardian) revert InvalidAddress();` and the symmetric check).
- **L-3 (inconsistent pause behavior):** `withdrawFromVault` now routes its fee through `_settlePenalty`, ensuring consistent penalty distribution whether or not the contract is paused.

### 3. Security & UX (already present, preserved)

- `rescueERC20` is blocked for **any token that was ever supported** — gated by the `wasSupported` mapping (stronger than `supportedTokens`: it also blocks de-listed tokens, protecting user principal).
- `rejectIncomingTransfer` — recipient can immediately reject an incoming transfer without the 48-hour wait.
- `CONFLICT` status (4) for secure transfers — if the recipient already holds a vault for that token, the transfer moves to conflict status and the sender can cancel/reclaim manually.
- Emergency functions (`recoverToSafe`, `emergencyWithdrawToAny`, `rotateAuthKeys`) bypass voluntary locks by design; `earlyClose` respects the voluntary lock.

---

## Size Optimization

The 18-decimals removal and multi-token logic would have pushed the contract over the EIP-170 limit. To stay within budget, the minimum-deposit value is **precomputed and stored** (rather than recomputed via `10 ** decimals` on every deposit), and the `minDeposit` mapping is kept **private** (no auto-generated public getter, ~67 bytes saved).

Nothing was removed from the `Vault` struct, and the `wasSupported` mapping was **kept** (it is load-bearing for `rescueERC20` principal protection).

---

## Test Results

- **351 tests passed, 0 failed.**
- Invariant suite (solvency + locked-principal integrity) — all green over fuzzed runs.
- **Contract size: 24,516 / 24,576 bytes (60 bytes spare)** under production flags (`solc 0.8.26`, `via_ir = true`, `optimizer_runs = 1`, `evm_version = cancun`, `bytecode_hash = none`).

---

## What Stayed the Same

- EIP-712 signatures, per-vault nonce, deadline — unchanged.
- Creator/guardian roles, pause flow, emergency functions — logic preserved.
- Fee and penalty distribution — unchanged (ANCR: 20% burn / 25% creator / 20% reserve / 35% reward pool; other tokens: 50/50 creator/reserve).

---

## For Auditors

The core change is multi-token support: the contract now accepts any ERC-20 token without a decimals restriction, with a precomputed per-token minimum deposit. The `wasSupported` principal-protection gate on `rescueERC20` is unchanged. All transfers use OpenZeppelin `SafeERC20` (handles non-standard tokens like USDT that do not return a bool).

- Current code: `src/AnchorVaultV45.sol`
- Tests: `test/AnchorVaultV45.t.sol` (+ Extended, Invariant, LiveAttackVector suites) — 351 tests total.

**Upgrade date:** 2026-06-22 · **Contract version:** V45 (multi-token)
