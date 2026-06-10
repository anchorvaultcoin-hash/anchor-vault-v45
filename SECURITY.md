# Security Notes — AnchorVaultV45

## Threat model

Each vault is protected by two user-held keys plus the owner's wallet account:

- The **owner account** (`msg.sender`) must equal the vault owner on every call.
- The **main key** signs everyday operations.
- The **recovery key** signs emergency operations.

**The recovery key is effectively the master key.** It can move funds to any address
(`emergencyWithdrawToAny`), rotate both keys (`rotateAuthKeys`), and it bypasses the
voluntary lock. Users must keep the recovery key in the coldest possible storage.

## Replay & signature safety

- The EIP-712 domain binds chainId + contract address.
- Each signed struct includes a per-vault `nonce` (incremented on use) and a `deadline`.
- Signatures are verified with OpenZeppelin `ECDSA.recover`, which rejects malleable
  (high-`s`) signatures.

## Accounting invariant

For every token, the contract balance always covers all obligations:

```
balance(token) >= lockedPrincipal(token)
                + creatorFees(token)
                + strategicReserve(token)
                + rewardPool(token)
```

`creator` withdrawals are bounded by `creatorFees` / `strategicReserve` and can never
reach `lockedPrincipal` (user funds).

## Reentrancy

All external state-changing functions use `nonReentrant` and follow
checks-effects-interactions: state is updated before any external call, and token burns
and payouts happen last.

## Accepted design decisions (not bugs)

1. **Withdrawals are allowed while paused.** Pause halts new deposits and transfers but
   never traps user funds — a deliberate non-custodial guarantee. Adding `whenNotPaused`
   to `withdrawFromVault` would let an operator freeze user funds and is intentionally
   avoided.
2. **`panicWithdraw` bypasses the voluntary lock.** It is an emergency exit to the user's
   pre-committed emergency address with a 20 % penalty.
3. **`timelockHours` is a soft cooldown, not a hard lock.** It is set by the main key and
   can be lowered to 0 by the same key, so it is not a theft-prevention control. The hard
   lock is `voluntaryLock`, which **is** enforced in withdraw, quick transfer, and secure
   transfer.
4. **`depositedAt` is not reset on deposit.** The timelock is measured from vault
   creation; topping up does not re-lock the vault.
5. **The emergency address is restricted to EOAs** (`code.length == 0`). Rationale: an EOA
   can always custody the token and adds no callback/reentrancy surface as a payout
   destination. This excludes smart-contract wallets / multisigs as emergency destinations.
6. **Recovery operations ignore the voluntary lock** (`recoverToSafe`,
   `emergencyWithdrawToAny`, `rotateAuthKeys`) so a user can always escape a compromised
   main key.

## Centralization summary

| Power                       | Holder   | Constraint                              |
|-----------------------------|----------|-----------------------------------------|
| Withdraw creator fees       | creator  | 7-day timelock                          |
| Withdraw strategic reserve  | creator  | 7-day timelock                          |
| Set welcome bonus           | creator  | ≤ MAX_WELCOME_BONUS                      |
| Add / remove supported token| creator  | —                                       |
| Unpause                     | creator  | —                                       |
| Pause                       | guardian | 2-day delay, or immediate emergencyPause|
| Transfer roles              | creator  | 2-step, 7-day / 2-day cooldown          |

No role can access user principal.

## Hardening applied before this audit

- **M-1:** the voluntary lock can now be extended, and `setTimelock` works while
  voluntarily locked (previously the lock blocked its own management).
- **L-1:** a recipient can immediately reject an unwanted incoming secure transfer
  (`rejectIncomingTransfer`) instead of waiting 48 h.
- Renamed a misleading error to `EmergencyAlreadySet`.
- `totalBurnedANCR` now increments only after tokens actually leave the contract.
- `donateToRewardPool` is restricted to ANCR (the reward pool is consumed only for ANCR
  welcome bonuses), preventing stuck non-ANCR donations.
- Removed an unused storage field and dead errors; consolidated the four signature checks
  into one and the creator/reserve withdrawal logic into shared helpers.

## Reporting

Please report security findings privately to the Licensor before public disclosure.
