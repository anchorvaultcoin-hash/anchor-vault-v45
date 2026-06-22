# AnchorVaultCoin V45

Non-custodial, multi-asset ERC-20 vault with EIP-712 off-chain authorization.

---

## Overview

AnchorVaultCoin V45 lets a user lock ERC-20 tokens into a personal vault controlled by two user-held authorization keys:

- **Main key** — authorizes everyday operations (withdraw, transfer, set locks).
- **Recovery key** — authorizes emergency operations (recover, emergency withdraw, rotate keys, early close). This is the most powerful credential.

Every state-changing user operation is authorized by an EIP-712 signature from the appropriate key, and `msg.sender` must also be the vault owner — a 2-factor design (wallet account + signing key). Replay is prevented by a per-vault nonce, a deadline, and the EIP-712 domain (chainId + contract address).

---

## Supported Tokens

AnchorVaultCoin V45 accepts **any standard ERC-20 token** with a `decimals()` function — including USDC (6 decimals), USDT (6 decimals), DAI (18 decimals), WETH (18 decimals), and ANCR (18 decimals).

The minimum deposit adapts automatically to each token: **0.01 token** in its native units.  
Query via: `getMinimumDeposit(tokenAddress)`.

Tokens must be whitelisted by the creator via `addSupportedToken(address)`. Any token lacking a `decimals()` function is rejected at whitelisting.

> **Operational note (M-1):** The creator should only whitelist standard, non-rebasing, non-fee-on-transfer, non-reentrant ERC-20 tokens. `_safeReceive` handles deposit-side fee-on-transfer (credits actual received), but withdraw-side fee and rebase are not reconciled — adding such a token would desync `lockedPrincipal` from the real balance and could block withdrawals. Gated by creator trust; ANCR is a standard token.

---

## Invariants (Critical Guarantees)

The contract enforces the following invariants. Auditors should verify these hold under all conditions.

1. **Principal integrity:** `lockedPrincipal[token]` always equals the sum of `v.amount` of all active vaults for that token.
2. **User solvency:** A user can always withdraw their full vault balance — withdrawals remain available even when the contract is paused (non-custodial guarantee).
3. **Nonce monotonicity:** Each vault's nonce increases strictly by 1 only after a successful signed operation. Failed signatures do not change the nonce.
4. **Role separation:** `creator` and `guardian` cannot be the same address. `creator` cannot withdraw user principal; `guardian` cannot unpause.
5. **Emergency address immutability (first set):** Once a user sets `globalEmergency`, changing it requires a 7-day timelock.

**Automated verification:** `test/AnchorVaultInvariant_t.sol` fuzzes random sequences of open/deposit/withdraw/early-close and asserts after every step:
- `balance ≥ lockedPrincipal + creatorFees + strategicReserve + rewardPool`
- `lockedPrincipal` always matches the live sum of vault amounts.

---

## EIP-712 Signature Example (Withdraw)

**Domain separator:**
```json
{
  "name": "AnchorVault",
  "version": "45",
  "chainId": 11155111,
  "verifyingContract": "0x8E1F46fC913c4928303BbCEB92ccb7c54cD95BA4"
}
```

**Message (Withdraw):**
```json
{
  "owner": "0x725F1408c2CDa5757d8B44a92a84EACc529F5150",
  "vaultId": "1",
  "amount": "10000000000000000000",
  "to": "0x725F1408c2CDa5757d8B44a92a84EACc529F5150",
  "nonce": "0",
  "deadline": "1749600000"
}
```

Similar structures exist for: `TransferVault`, `InitSecureTransfer`, `SetTimelock`, `SetVoluntaryLock`, `RotateAuthKeys`, `EarlyClose`, `RecoverToSafe`, `EmergencyWithdraw`.

---

## Vault Levels

| Level | Deposit fee | Max timelock |
|---|---|---|
| SAFE | 0.50% | 0 h |
| VAULT | 1.50% | 72 h |
| FORTRESS | 2.00% | 168 h |

---

## Fees & Penalties

| Operation | Fee |
|---|---|
| Open vault | 0.20% |
| Withdraw / Transfer / Secure transfer | 0.50% |
| Early close | 5% |
| Recover to safe | 10% |
| Emergency withdraw to any | 15% |
| Panic withdraw | 20% |

**Penalty distribution:**
- ANCR: 20% burned, 25% creator fees, 20% strategic reserve, 35% reward pool.
- Other tokens: 50% creator fees, 50% strategic reserve.
- While paused: ANCR → 100% reward pool; other tokens → 50/50 creator/reserve.

---

## Roles & Trust

- **creator:** Withdraws accrued fees and strategic reserve (7-day timelock each), sets welcome bonus, adds/removes supported tokens, unpauses, transfers roles (2-step + cooldown). Cannot touch user principal.
- **guardian:** Pauses the contract (2-day delayed pause or immediate `emergencyPause`). Cannot unpause and cannot move funds.

Role transfers are two-step with cooldowns; `creator` and `guardian` must differ.

---

## Key Mechanisms

- **Global emergency address** (per user, EOA only): first set is immediate; changing requires 7-day timelock (propose → confirm → can cancel).
- **Quick transfer** (`transferVault`): one-step vault move to another user.
- **Secure transfer** (`initSecureTransfer → confirmSecureTransfer`): two-step escrow with 48h window; sender can cancel/reclaim, recipient can reject.
- **Voluntary lock:** Hard, time-bounded lock (≤ 5 years) blocking main-key operations. Can only be extended.
- **Timelock** (`timelockHours`): Soft, owner-set withdrawal cooldown from vault creation.
- **Pause:** Stops new deposits/transfers; withdrawals of user funds stay available (non-custodial guarantee).

---

## Build

- Solidity 0.8.26
- OpenZeppelin Contracts 5.6.1
- Settings: `via_ir = true`, `optimizer = true`, `optimizer_runs = 1`, `evm_version = cancun`, `bytecode_hash = none`

```bash
forge install OpenZeppelin/openzeppelin-contracts@v5.6.1
forge install foundry-rs/forge-std
forge build
forge test
```

**Deploy:**
```bash
ANCR_TOKEN=0x... GUARDIAN=0x... PAYOUT_WALLET=0x... \
forge script script/Deploy.s.sol --rpc-url $SEPOLIA_RPC --broadcast --verify
```

**Size monitoring** (EIP-170 limit: 24,576 bytes):
```bash
forge build --sizes | grep AnchorVaultV45
```

---

## Audit Scope

- **In scope:** `src/AnchorVaultV45.sol`
- **Out of scope:** OpenZeppelin libraries (IERC20, SafeERC20, IERC20Metadata, ReentrancyGuard, EIP712, ECDSA).

See `SECURITY.md` for the threat model, centralization summary, accounting invariant, and accepted design decisions.

---

## Deployment (Sepolia testnet, chainId 11155111)

| | Address |
|---|---|
| AnchorVaultV45 | `0x8E1F46fC913c4928303BbCEB92ccb7c54cD95BA4` |
| ANCR token (AnchorCoin) | `0x6a837125eeB63cc4D3d38E93e2adCd30a2603cF7` |
| creator / payout wallet | `0x725F1408c2CDa5757d8B44a92a84EACc529F5150` |
| guardian | `0x0838238A55d846A2a92fC6889Cc96558533B68ab` |

**Build settings (required for bytecode verification):** `solc 0.8.26`, `optimizer_runs = 1`, `via_ir = true`, `evm_version = cancun`, `bytecode_hash = none`.

Token distribution initialized: 500,000 ANCR rewardPool + 300,000 ANCR strategicReserve held in the vault, 200,000 ANCR sent to the payout wallet.

> **Centralization note:** In this testnet deployment, `payoutWallet` equals the creator address. For mainnet, separate these and make `creator` a multisig.

---

## License

BUSL-1.1 — Licensor: Vitaliy — Copyright © 2026 AnchorVaultCoin.  
Change Date: 2030-01-01 → GPL-2.0-or-later.  
Imported OpenZeppelin files are MIT. Commercial use before the Change Date requires written permission from the Licensor.
