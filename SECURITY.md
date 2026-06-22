# Security Policy — AnchorVaultCoin V45

## Disclosure

Found a vulnerability? Report it privately to **anchorvaultcoin@gmail.com**.

Do not open a public issue until a fix is released. We aim to acknowledge reports within 72 hours.

---

## Scope

- **In scope:** `src/AnchorVaultV45.sol` (the vault contract).
- **Out of scope:** OpenZeppelin libraries (IERC20, SafeERC20, IERC20Metadata, ReentrancyGuard, EIP712, ECDSA) — audited upstream and pinned by commit.

---

## Supported Tokens

AnchorVaultCoin V45 accepts **any ERC-20 token** with a `decimals()` function — including USDC (6 decimals), USDT (6 decimals), DAI (18 decimals), WETH (18 decimals), and ANCR (18 decimals).

The minimum deposit adapts automatically to each token: **0.01 token** in its native units.  
Query via: `getMinimumDeposit(tokenAddress)`.

Tokens must be whitelisted by the creator via `addSupportedToken(address)`. Any token lacking a `decimals()` function is rejected at whitelisting.

> **Operational rule (M-1):** The creator should only whitelist standard, non-rebasing, non-fee-on-transfer, non-reentrant ERC-20 tokens. `_safeReceive` handles deposit-side fee-on-transfer (credits actual received), but withdraw-side fee and rebase are not reconciled — adding such a token would desync `lockedPrincipal` and could block withdrawals. Gated by creator trust.

---

## Trust Model & Roles

The contract is **non-custodial**: a user's principal can only leave through that user's own signed operation. No privileged role can move user principal.

| Role | Can do | Cannot do |
|---|---|---|
| **creator** | Withdraw accrued creatorFees / strategicReserve (7-day timelock), set welcome bonus, add/remove supported tokens, unpause, transfer roles | Touch user principal; rescue any token ever supported |
| **guardian** | Pause (2-day delayed or immediate emergencyPause) | Unpause; move any funds |
| **owner (user)** | Open/deposit/withdraw/transfer/close their own vault | Act on another user's vault |
| **mainAuthKey** | Sign withdraw, transfer, secure-transfer, set timelock/voluntary-lock | Sign recovery operations |
| **recoveryAuthKey** | Sign rotate-keys, early-close, recover, emergency-withdraw | — |
| **globalEmergency[user]** | Receive funds from recoverToSafe / panicWithdraw | Change without 7-day timelock (after first set) |

Two-factor design: every state-changing user operation requires both `msg.sender == owner` and a valid EIP-712 signature from the relevant key.

---

## Centralization Summary

- `creator` and `guardian` must be different addresses (enforced in constructor and on every role transfer).
- `creator` cannot reach user principal: `rescueERC20` rejects any token in `wasSupported`.
- **Known centralization point:** In the current testnet deployment, `payoutWallet` equals `creator`. For mainnet, separate these and make `creator` a multisig.

---

## Accounting Invariant (Critical Guarantee)

For every supported token:

```
balanceOf(contract) >= lockedPrincipal[token]
                       + creatorFees[token]
                       + strategicReserve[token]
                       + rewardPool[token]
```

`lockedPrincipal[token]` always equals the sum of `v.amount` over all active vaults for that token.

**Automated check:** Foundry invariant suite fuzzes random sequences of open/deposit/withdraw/early-close and asserts both properties after every step.

---

## Threat Model

| Vector | Mitigation |
|---|---|
| Reentrancy | `nonReentrant` on all external entry points + CEI; external transfers/burns happen last |
| Signature replay | Per-vault nonce + deadline + EIP-712 domain (chainId + contract address) |
| Signature malleability | OpenZeppelin ECDSA v5 rejects high-s signatures |
| Cross-vault replay | typehash binds owner and vaultId |
| Admin principal drain | `rescueERC20` gated by `wasSupported`; `removeSupportedToken` cannot move balances |
| Role merger | creator != guardian enforced everywhere |
| Fee-on-transfer tokens | `_safeReceive` credits actually-received amount (balance diff) |
| Sham-transfer griefing | Recipient can `rejectIncomingTransfer`; conflicting transfers → CONFLICT status |
| Welcome-bonus drain | Per-address claim flag + max-claims cap + per-claim cap + pool check |
| Gas / DoS | No unbounded loops; all lookups O(1) |

---

## Accepted Design Decisions

- **Nonce width (uint64):** Overflow check runs before increment; reaching uint64 max is infeasible — defensive backstop.
- **Voluntary lock vs. emergency ops:** `recoverToSafe`, `emergencyWithdrawToAny`, `rotateAuthKeys`, and `earlyClose` all bypass `voluntaryLockUntil` (`enforceLock = false`) — emergency exits must remain possible under a voluntary lock. `panicWithdraw` carries no signature and bypasses the lock by design.
- **panicWithdraw without signature:** Dead-man's switch. Owner evacuates to pre-set `globalEmergency` for a 20% penalty. Residual risk: an attacker controlling the owner EOA for >7 days could change `globalEmergency` — treat it as a critical address.
- **Penalty on pause:** ANCR penalties → 100% rewardPool; non-ANCR → 50/50 creator/reserve. Creator cannot profit from a forced pause.
- **block.timestamp for timelocks:** All intervals are hours/days; validator drift is irrelevant.
- **Authorization keys must be EOAs:** ECDSA.recover does not support ERC-1271 — smart-contract wallets cannot be used as auth keys. Frontend must enforce this.
- **Deposit into a de-listed token:** `depositToVault` checks vault status but not `supportedTokens`, so an existing vault owner can keep depositing after `removeSupportedToken`. Harmless by design (1:1 accounting, user adds own funds).

---

## Continuous Monitoring

- **CI (GitHub Actions):** Every push to `main` runs `forge build --sizes` + `forge test`. See `.github/workflows/ci.yml`.
- **Dependencies pinned:** OpenZeppelin Contracts and forge-std are git submodules locked to fixed commits.
- **Bytecode size:** Monitored on every build. Must stay ≤ 24,576 bytes (EIP-170).
- **Planned:** Slither static analysis as a CI step + external human audit before mainnet.

---

## Audit History

| Date | Type | Findings | Status |
|---|---|---|---|
| 2026-05-29 | AI-assisted review (Claude, DeepSeek) | All criticals resolved | ✅ Done |
| 2026-06-12 | Invariant test suite (Foundry) | Solvency + principal-integrity hold | ✅ Done |
| 2026-06-18 | Deep manual + tooling audit (Claude) | 0 critical/high; L-2/L-3 fixes verified | ✅ Done |
| 2026-06-22 | Multi-token support added | Any ERC-20 with `decimals()` accepted; min deposit dynamic | ✅ Done |
| (Planned) | External human audit (Code4rena / Cantina) + TVL cap | TBD | ⬜ Pending |

> AI-assisted review is **not** a substitute for an independent human audit. A full external audit and TVL cap are required before any mainnet deployment.

---

## Contacts

- **Security reports:** anchorvaultcoin@gmail.com
- Deployment addresses — *to be filled after next deploy*
