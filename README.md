# AnchorVaultV45

Non-custodial, multi-asset ERC-20 vault with EIP-712 off-chain authorization.

## Overview

AnchorVaultV45 lets a user lock 18-decimal ERC-20 tokens into a personal **vault**
controlled by **two user-held authorization keys**:

- **Main key** — authorizes everyday operations (withdraw, transfer, set locks).
- **Recovery key** — authorizes emergency operations (recover, emergency withdraw,
  rotate keys, early close). This is the most powerful credential.

Every state-changing user operation is authorized by an **EIP-712 signature** from the
appropriate key, and `msg.sender` must also be the vault owner — a 2-factor design
(wallet account + signing key). Replay is prevented by a per-vault `nonce`, a `deadline`,
and the EIP-712 domain (chainId + contract address).

## Vault levels

| Level    | Deposit fee | Max timelock |
|----------|-------------|--------------|
| SAFE     | 0.50 %      | 0 h          |
| VAULT    | 1.50 %      | 72 h         |
| FORTRESS | 2.00 %      | 168 h        |

## Fees & penalties

| Operation                   | Fee   |
|-----------------------------|-------|
| Open vault                  | 0.20 %|
| Withdraw / Transfer / Secure transfer | 0.50 %|
| Early close                 | 5 %   |
| Recover to safe             | 10 %  |
| Emergency withdraw to any   | 15 %  |
| Panic withdraw              | 20 %  |

**Penalty distribution**

- **ANCR:** 20 % burned, 25 % creator fees, 20 % strategic reserve, 35 % reward pool.
- **Other tokens:** 50 % creator fees, 50 % strategic reserve (no burn, no reward pool).
- **While paused:** ANCR → 100 % reward pool; other tokens → 50 / 50 creator / reserve.

## Roles & trust

- **creator** (deployer): withdraws accrued creator fees and strategic reserve
  (each behind a 7-day timelock), sets the welcome bonus, adds/removes supported tokens,
  unpauses, transfers roles (2-step, cooldown). **Cannot touch user principal.**
- **guardian:** pauses the contract (2-day delayed pause, or immediate `emergencyPause`).
  **Cannot unpause and cannot move funds.**

Role transfers are two-step with cooldowns; `creator` and `guardian` must differ.

## Key mechanisms

- **Global emergency address** (per user, EOA only): first set is immediate; changing it
  needs a 7-day timelock (propose → confirm → can cancel). Recovery operations route here.
- **Quick transfer** (`transferVault`): one-step move of a vault to another user.
- **Secure transfer** (`initSecureTransfer` → `confirmSecureTransfer`): two-step escrow
  with a 48 h window; sender can cancel/reclaim, recipient can reject.
- **Voluntary lock:** a hard, time-bounded lock (≤ 5 years) blocking main-key
  operations. Can only be extended.
- **Timelock (`timelockHours`):** a soft, owner-set withdrawal cooldown, measured from
  vault creation.
- **Pause:** stops new deposits/transfers; **withdrawals of user funds stay available**
  (non-custodial guarantee).

## Build

- Solidity **0.8.26**
- OpenZeppelin Contracts **5.6.1**
- Settings: `via_ir = true`, `optimizer = true`, `optimizer_runs = 1`, `evm_version = cancun`
- Runtime size: **24,499 / 24,576 bytes** (EIP-170)

```bash
forge install OpenZeppelin/openzeppelin-contracts@v5.6.1
forge install foundry-rs/forge-std
forge build
forge test
```

Deploy (constructor args via env, no secrets in repo):

```bash
ANCR_TOKEN=0x... GUARDIAN=0x... PAYOUT_WALLET=0x... \
forge script script/Deploy.s.sol --rpc-url $SEPOLIA_RPC --broadcast --verify
```

## Audit scope

- **In scope:** `src/AnchorVaultV45.sol`
- **Out of scope:** OpenZeppelin libraries (`IERC20`, `SafeERC20`, `IERC20Metadata`,
  `ReentrancyGuard`, `EIP712`, `ECDSA`).

See **`SECURITY.md`** for the threat model, centralization summary, accounting
invariant, and accepted design decisions.

## Deployment (Sepolia testnet, chainId 11155111)

- AnchorVaultV45: `0x8E1F46fC913c4928303BbCEB92ccb7c54cD95BA4`
- ANCR token (AnchorCoin): `0x6a837125eeB63cc4D3d38E93e2adCd30a2603cF7`
- creator:        `0x725F1408c2CDa5757d8B44a92a84EACc529F5150`
- guardian:       `0x0838238A55d846A2a92fC6889Cc96558533B68ab`
- payout wallet:  `0x725F1408c2CDa5757d8B44a92a84EACc529F5150`

Build settings (must match for bytecode verification): solc 0.8.26, `optimizer_runs = 1`,
`via_ir = true`, `evm_version = "cancun"`, `bytecode_hash = "none"`. Token distribution
initialized: 500,000 ANCR rewardPool + 300,000 ANCR strategicReserve held in the vault,
200,000 ANCR sent to the payout wallet.

## License

BUSL-1.1 — Licensor: Vitaliy — Copyright (c) 2026 AnchorVaultCoin.
Change Date 2030-01-01 → GPL-2.0-or-later. Imported OpenZeppelin files are MIT.
Commercial use before the Change Date requires written permission from the Licensor.
