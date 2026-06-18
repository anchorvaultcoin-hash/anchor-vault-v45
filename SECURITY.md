# Security Policy — AnchorVaultV45

## Disclosure

Found a vulnerability? Please report it privately to **anchorvaultcoin@gmail.com**.

Do **not** open a public issue until a fix is released. We aim to acknowledge reports within 72 hours.

## Scope

- **In scope:** `src/AnchorVaultV45.sol` (the vault contract).
- **Out of scope:** OpenZeppelin libraries (`IERC20`, `SafeERC20`, `IERC20Metadata`, `ReentrancyGuard`, `EIP712`, `ECDSA`) — audited upstream and pinned by commit (see *Dependencies*).

## Trust Model & Roles

The contract is **non-custodial**: a user's principal can only leave the contract through that user's own signed operation. No privileged role can move user principal.

| Role | Can do | Cannot do |
|---|---|---|
| **creator** (deployer) | withdraw accrued `creatorFees` / `strategicReserve` (each behind a 7-day timelock), set welcome bonus, add/remove supported tokens, unpause, transfer roles (2-step + cooldown) | **touch user principal**; rescue any token that was ever supported |
| **guardian** | pause (2-day delayed, or immediate `emergencyPause`) | unpause; move any funds |
| **owner** (user) | open/deposit/withdraw/transfer/close their own vault | act on another user's vault |
| **mainAuthKey** (per vault) | sign withdraw, transfer, secure-transfer, set timelock/voluntary-lock | sign recovery operations |
| **recoveryAuthKey** (per vault) | sign rotate-keys, early-close, recover, emergency-withdraw | — |
| **globalEmergency[user]** | receive funds from `recoverToSafe` / `panicWithdraw` | set instantly after first change (7-day timelock) |

**Two-factor design:** every state-changing user operation requires both `msg.sender == owner` **and** a valid EIP-712 signature from the relevant key. Compromising the wallet account alone does not allow fund movement.

### Centralization summary

- `creator` and `guardian` must be different addresses (enforced in the constructor and on every role transfer).
- `creator` **cannot** reach user principal: `rescueERC20` rejects any token in `wasSupported`, and `removeSupportedToken` never touches balances.
- **Known centralization point:** in the current testnet deployment `payoutWallet` **equals** `creator` (`0x725F…5150`), so the 200k ANCR payout share and all creator/reserve withdrawals route to a single EOA. **For mainnet, separate these and make `creator` a multisig.**

## Accounting Invariant (Critical Guarantee)

For every supported token, the contract must always satisfy:

```
balanceOf(contract) >= lockedPrincipal[token]
                       + creatorFees[token]
                       + strategicReserve[token]
                       + rewardPool[token]
```

and `lockedPrincipal[token]` always equals the sum of `v.amount` over all active vaults for that token.

**Automated check:** `test/AnchorVaultInvariant_t.sol` is a Foundry invariant suite that fuzzes random sequences of open/deposit/withdraw/early-close and asserts both properties after every step. Full suite: **314 passing, 0 failing**.

## Threat Model

| Vector | Mitigation (verified in code) |
|---|---|
| Reentrancy | `nonReentrant` on all external entry points + Checks-Effects-Interactions; external transfers/burns happen last |
| Signature replay | per-vault `nonce` + `deadline` + EIP-712 domain (chainId + contract address) |
| Signature malleability | OpenZeppelin ECDSA v5 rejects high-`s` signatures |
| Cross-vault / cross-user replay | typehash binds `owner` and `vaultId` |
| Admin principal drain | `rescueERC20` gated by `wasSupported`; `removeSupportedToken` cannot move balances |
| Role merger | `creator != guardian` enforced everywhere |
| Fee-on-transfer tokens | `_safeReceive` credits the actually-received amount (balance diff) |
| Sham-transfer griefing | recipient can `rejectIncomingTransfer`; conflicting transfers move to CONFLICT status |
| Welcome-bonus drain | per-address claim flag + max-claims cap + per-claim cap + pool check |
| Gas / DoS | no unbounded loops; all per-user/token lookups are O(1) |

## Accepted Design Decisions

These are intentional trade-offs, not vulnerabilities.

- **Nonce width (`uint64`):** the contract **does** check for overflow — `if (v.nonce == type(uint64).max) revert NonceOverflow();` runs before the increment, and only the `+= 1` is `unchecked`. Reaching the `uint64` max is infeasible; the check is a defensive backstop.
- **Voluntary lock vs. emergency ops:** `recoverToSafe`, `emergencyWithdrawToAny`, `rotateAuthKeys` ignore `voluntaryLockUntil` (they call `_checkSig(..., enforceLock = false)`); `earlyClose` respects it (`enforceLock = true`); `panicWithdraw` carries no signature and bypasses the lock by design. Emergency exits must remain possible under a voluntary lock.
- **`panicWithdraw` without signature:** a deliberate dead-man's-switch. If both keys are lost, the owner (`msg.sender`) can evacuate to the pre-set `globalEmergency` for a 20% penalty. Residual risk: an attacker controlling the owner EOA for >7 days could change `globalEmergency` and then panic — `globalEmergency` must be treated as a critical address.
- **Penalty distribution on pause:** ANCR penalties go 100% to `rewardPool` (no burn / creator / reserve); non-ANCR penalties stay 50/50 creator/reserve. This prevents the creator from profiting from a forced pause.
- **`block.timestamp` for timelocks:** all intervals are hours/days, so seconds-level validator drift is irrelevant.
- **EIP-712 domain separation:** prevents cross-chain replay via chainId + contract address in the domain.
- **Supported tokens must be standard (operational rule, M-1):** the creator must only whitelist standard 18-decimal, non-rebasing, non-fee-on-transfer, non-reentrant ERC-20 tokens via `addSupportedToken`. `_safeReceive` handles deposit-side fee-on-transfer (credits actual received), but **withdraw-side fee and rebase are not reconciled** — adding such a token would desync `lockedPrincipal` from the real balance and could block withdrawals (token-level insolvency). Gated by creator trust; ANCR is a standard token.
- **Authorization keys must be EOAs:** `ECDSA.recover` does not support ERC-1271, so smart-contract wallets (Safe, Argent) **cannot** be used as `mainAuthKey` / `recoveryAuthKey`. Using one would make the vault unmanageable (only `panicWithdraw` would work). The frontend must enforce and communicate this.
- **Deposit into a de-listed token (L-1):** `depositToVault` checks vault status but not `supportedTokens`, so an existing vault owner can keep depositing after `removeSupportedToken`. Harmless (1:1 accounting, user adds own funds; not a share-vault). By design.
- **`transferVault` (quick) needs no recipient consent:** sender unilaterally creates a vault for `to`. Not economically abusable (sender loses funds, recipient can always extract via panic); the consented path is secure-transfer. `code.length == 0` is an EOA heuristic, not a hard guarantee (counterfactual CREATE2) — no exploit, the user sets their own address.

## Continuous Monitoring

- **CI (GitHub Actions):** every push to `main` runs `forge build --sizes` + `forge test` (314 tests). See `.github/workflows/ci.yml`.
- **Dependencies pinned:** OpenZeppelin Contracts (5.6.1) and forge-std are git submodules locked to fixed commits — no silent dependency drift.
- **Bytecode size:** current source (with L-2/L-3 fixes) compiles to **24,498 / 24,576 bytes (spare 78)** under prod flags on OZ 5.6.1 — verified by direct compilation (0 errors, 0 warnings). Margin is thin; any future change must be re-measured.
- **Key hygiene:** the per-vault `recoveryAuthKey` is the most powerful credential and should be cold-stored, separate from `mainAuthKey`. Users may rotate keys via `rotateAuthKeys`.
- **Planned:** Slither static analysis as a CI step, and an external human audit before mainnet. *(Not yet active — do not claim these as live until configured.)*

## Audit History

| Date | Type | Findings | Status |
|---|---|---|---|
| 2026-05-29 | AI-assisted review (Claude, DeepSeek) | All criticals resolved | ✅ Done |
| 2026-06-12 | Invariant test suite added (Foundry) | Solvency + principal-integrity hold over fuzzed runs; 314 tests green | ✅ Done |
| 2026-06-18 | Deep manual + tooling audit (Claude) | 0 critical/high; L-2/L-3 fixes verified by direct compile (0 errors/warnings, 24,498 bytes); M-1 (non-standard tokens) documented as operational rule | ✅ Done |
| (Planned) | External human audit (e.g. Code4rena / Cantina) + TVL cap | TBD | ⬜ Pending |

> Note: AI-assisted review is **not** a substitute for an independent human audit. A full external audit and an initial TVL cap are required before any mainnet deployment.

## Contacts

- **Security reports:** anchorvaultcoin@gmail.com
- **Contract (Sepolia):** `0x8E1F46fC913c4928303BbCEB92ccb7c54cD95BA4` *(verified on Etherscan; this is the pre-L-2/L-3 revision. The source in this repo includes the L-2/L-3 fixes and is not yet redeployed — redeploy planned before mainnet.)*
- **creator / admin:** `0x725F1408c2CDa5757d8B44a92a84EACc529F5150`
- **guardian:** `0x0838238A55d846A2a92fC6889Cc96558533B68ab`
