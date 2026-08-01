# AnchorVaultCoin — Security Model & Design Rationale

> Companion document for the external audit (Hexens). It states the intended
> security model, the economic rationale behind the fee structure, and the
> explicit by-design decisions / accepted trade-offs, so review effort can be
> spent on calibration and edge cases rather than on rediscovering intent.
>
> Status: external audit in progress (Hexens, Builder Support Ecosystem Program).
> Initial report received 31 Jul 2026; remediation complete; retest pending.
> Not deployed to mainnet. Mainnet is gated on the final audit report and a TVL cap.

---

## 1. Purpose & scope

AnchorVaultCoin is a **non-custodial, multi-asset ERC-20 "safe" service**. A user
who wants protected storage *opts in* by creating a vault and accepting the
service rules; a user who does not want it simply transacts normally and never
touches the vault. The contract is a storage/safety layer, **not an exchange or
AMM** — it does not swap, price, or route assets.

Supported assets: any ERC-20 with `decimals()` between 6 and 18 (gated by
`addSupportedToken`, creator-only). The minimum deposit is derived per token as
`0.01` in that token's own decimals. The project token ANCR is supported at
construction.

---

## 1a. Service positioning & user consent

AnchorVaultCoin should be evaluated as a **safety / custody-assist service**, not
as a token-routing primitive. The mental model is closer to a **safe-deposit box
at a bank** than to a swap venue:

- The user comes **for protection**, not for a free transfer.
- The service has **published terms** (fees, locks, emergency mechanics).
- The user **accepts those terms at entry** — explicit checkboxes in the
  frontend gate vault creation (see §6). A user who declines simply does not
  create a vault and continues to hold / transfer tokens normally.
- In return, the user receives **isolation and recovery guarantees** (§3) that a
  bare wallet does not provide.

**Transparency stance.** All fees are flat, single-figure, and disclosed *before*
the action. There are no compounding charges, no mandatory add-ons, and no hidden
effective rate. The normal-exit fee (0.5%) is competitive with — and often below —
typical custodial / transfer fees; the high emergency fees (up to 20%) apply
**only** to the deliberately-chosen emergency paths, and their cost is shown up
front. This places the economics on the disclosed-and-accepted side rather than
the concealed side.

```
  USER ENTERS THE SERVICE
  ────────────────────────────────────────────────────────────────
     wants protection? ──no──►  use wallet normally (no vault)
           │ yes
           ▼
     reads + accepts terms   (frontend)
           │
           ▼
     opens vault  ──►  isolation + recovery guarantees apply
```

---

## 2. Core security model — two-factor (EOA + auth key)

Every vault has two dedicated keys set at creation, neither of which may equal
the owner's wallet address, the other auth key, or the contract itself
(`_validateAuthKeys`):

- **`mainAuthKey`** — daily operations: withdraw, transfer, deposit-adjacent
  settings (timelock, voluntary lock, key rotation, early close).
- **`recoveryAuthKey`** — emergency operations: recover-to-safe,
  emergency-withdraw-to-any.

All key-gated operations are EIP-712 signed, with a per-vault `nonce`, a caller-set
`deadline`, and a domain separator binding `chainId` and the contract address.
Signature verification is `ECDSA.recover` against the expected key — there is no
implicit trust in `msg.sender` beyond selecting which vault is being acted on.

**What this buys.** Possession of the owner's wallet (private key or seed phrase)
is not, by itself, sufficient to move funds through any signature-gated path. An
attacker without the auth keys cannot withdraw to an address of their choosing,
transfer the vault, or rotate its keys.

---

## 3. Primary guarantee — wallet-compromise isolation, precisely stated

The design target is the most common real-world loss vector for individual
holders: **theft or leakage of the wallet's seed phrase**, independent of any
auth-key compromise. A representative case in this class is the Ill Bloom
incident (weak client-side seed generation, $5M+ lost) — a pure wallet-key
compromise, not a protocol or multisig failure.

**The guarantee is isolation, not immobility.** One path moves funds without any
signature: `panicWithdraw`. It is intentionally left open so that a user who has
lost their auth keys — through the same kind of compromise the design protects
against, or through simple loss — is never permanently locked out. Its behavior
is fully constrained:

- **Destination is fixed** to `globalEmergency[msg.sender]` — the owner's own
  pre-registered backup address. The caller does not choose it and cannot
  redirect it.
- **Cost is 20%**, burned/redistributed as a deterrent — routine use is
  discouraged, but the exit is never blocked.
- **Only the vault's own owner can trigger it** for their own vault
  (`vaultExists(msg.sender, vid)`); a third party cannot panic someone else's vault.

An attacker who has obtained *only* the wallet key can therefore force an exit,
but cannot steal: at most 20% is lost as the price of the isolation guarantee,
and the remaining 80% lands in the owner's own emergency address, not the
attacker's.

**Correct framing for external claims:** *"Normal vault operations require
authorization from dedicated security keys separate from the owner's wallet. A
compromised seed phrase alone does not provide access to normal vault
operations — the one signature-free path pays out only to the owner's own
pre-set backup address, at a fixed penalty."* Do not claim funds "can only be
moved with signatures" — `panicWithdraw` is a deliberate, documented exception,
not an oversight.

---

## 4. Fee model & economic rationale

| Path | Fee | Key required | Notes |
|------|-----|--------------|-------|
| `openVault` | 0.5% / 1.5% / 2.0% | — (creation) | same rate as deposit, by level |
| `depositToVault` | 0.5% / 1.5% / 2.0% | — | by level SAFE/VAULT/FORTRESS |
| `withdrawFromVault` | 0.5% | main | timelock-gated |
| `transferVault` (quick) | 0.5% | main + recipient consent signature | |
| secure transfer (confirm) | 0.5% | main (init) + recipient's own tx (confirm) | |
| `earlyClose` | 5% | recovery | |
| `recoverToSafe` | 10% | recovery | to owner's emergency |
| `emergencyWithdrawToAny` | 15% | recovery | to any address |
| `panicWithdraw` | 20% | — | to owner's emergency only |

**Open/deposit parity.** Opening a vault and topping it up are charged at
identical rates per level. Earlier revisions charged a flat 0.20% on open
regardless of level, which made "close, then reopen with a larger amount"
cheaper than a direct top-up on VAULT/FORTRESS tiers — this was reported by
Hexens (ANCV1-4) and fixed by removing the separate open-discount entirely
rather than capping it, since a cap re-introduces the same arbitrage at smaller
scale and depends on a per-token unit judgment call the contract has no way to
make safely (see §10).

**Rationale.** Normal, key-authorized exits are cheap (~0.5%). The emergency
exits are deliberately expensive and scale with how much freedom they grant. The
high `panicWithdraw` cost (20%) is an **intentional friction / deterrent**: the
no-signature escape hatch should be used only when access is genuinely lost or an
attack is in progress, not as a routine withdrawal. The price is disclosed and
accepted at the UI layer before vault creation (see §6).

```
  EXIT PATHS  (cost rises with freedom / urgency; destination tightens)
  ────────────────────────────────────────────────────────────────────
   NORMAL  (key required, cheap)
     withdrawFromVault ........ 0.5%  | main key                  | to: any  | timelock
     transferVault ............ 0.5%  | main key + recipient sig  | to: recipient
     earlyClose ............... 5%    | recovery key              | to: owner

   EMERGENCY  (expensive, escape hatches)
     recoverToSafe ............ 10%   | recovery key | to: owner's emergency
     emergencyWithdrawToAny ... 15%   | recovery key | to: any address
     panicWithdraw ............ 20%   | NO signature | to: owner's emergency
                                                       ▲
                                  no-key escape, but destination is fixed
                                  to the owner's own backup (see §3)
```

**Penalty distribution.**
- ANCR: burn 20% / creator 25% / strategic reserve 20% / reward pool 35%.
- Other tokens: creator 50% / strategic reserve 50%.

**Creator-incentive analysis.** The creator earns a share of penalties as
legitimate service revenue, withdrawable only via a 7-day timelock
(`requestCreatorWithdraw` → `withdrawCreatorFees`). Critically, the creator has
**no mechanism to force user panics**:

- `panicWithdraw` operates only on the *caller's own* vault — the creator cannot
  panic a user's vault.
- Pausing does not coerce panics: in the paused state normal `withdrawFromVault`
  (0.5%) still works, so users are never pushed toward the 20% exit.
- When paused, ANCR penalties route entirely to the reward pool (`_settlePenalty`),
  *removing* the creator's share — i.e., pausing is economically **disincentivized**
  for the creator.

No griefing-for-profit vector was identified.

**Reward pool.** `rewardPool` holds user-side funds. By hard project rule there
is **no creator withdrawal path** for the reward pool — it is spent only on
welcome bonuses. The `initializeDistribution` balance check requires the
distribution amount **in addition to** every balance already committed to users
(locked principal, creator fees, strategic reserve, reward pool) — it cannot be
satisfied out of user deposits (see §10, H-1).

---

## 5. Solvency invariant

Per token:

```
balance(token) >= lockedPrincipal[token] + creatorFees[token]
                  + strategicReserve[token] + rewardPool[token]
```

The accounting in every exit path (`withdrawFromVault`, `_closeAndPayout` for
panic/recover/emergency/early-close, `transferVault`, `confirmSecureTransfer`)
reduces the left and right sides by equal amounts (principal out + penalty
redistributed + burn removed). Confirmed by Foundry invariant fuzzing
(`invariant_solvency`, `invariant_solvency_allTokens`): 0 failures across
multi-actor, multi-token runs of 128,000 calls each.

**Rebasing tokens** are intentionally excluded from the strict solvency assertion:
a balance reduction caused by an external rebase is inherent to that token type,
not a contract fault.

---

## 5a. Test coverage of the security model

The guarantees in this document are backed by an executable test suite (Foundry),
not just prose:

- **Wallet-compromise isolation (§3)** — a test drives the scenario where an
  attacker controls the owner's EOA but holds no auth keys, and asserts that
  `panicWithdraw` sends funds to the owner's `globalEmergency` (not the attacker)
  and that an arbitrary-destination withdraw reverts (`BadSignature`).
- **Two-factor enforcement (§2)** — withdraw with the wrong key reverts; withdraw
  with the correct main key succeeds.
- **Per-owner vault isolation** — calling `panicWithdraw` against another user's
  vault id reverts (`BadVaultId`).
- **Recipient consent (§10, ANCV1-2)** — `transferVault` reverts with
  `BadSignature` if the recipient's consent signature is missing, forged, or
  does not match the actual transfer parameters; succeeds only with a genuine
  consent signature from the recipient.
- **Transfer-lock integrity (§10, ANCV1-1)** — a stale CONFLICT-status transfer
  record cannot release a vault that is locked by a newer transfer; the newer
  transfer's recipient still receives a fully-funded vault with the correct token.
- **Distribution isolation (§10, H-1)** — `initializeDistribution` reverts if the
  contract balance covers the distribution amount only by counting funds already
  committed to users; succeeds once genuinely uncommitted balance covers it.
- **Timelock vs. transfer (§10, M-3)** — both `transferVault` and
  `initSecureTransfer` revert with `VaultTimelocked` while a timelock is active,
  and succeed once it expires.
- **Voluntary-lock semantics (T-2)** — a locked vault blocks normal withdraw but
  `panicWithdraw` bypasses the lock (documenting the intended escape-hatch
  behavior).
- **Fee rates** — `panicWithdraw` pays out exactly 80%; normal withdraw pays out
  exactly 99.5%.
- **Roles & admin** — two-step transfer, cooldowns, wrong-acceptor rejection, and
  old-holder access loss are covered by the existing role test suite.
- **Solvency invariant** — exercised by Foundry invariant fuzzing across
  multi-actor / multi-token runs (0 failures, 128,000 calls each).

(Test files: `test/AnchorVaultBusinessLogic.t.sol`, `test/AnchorVaultV45.t.sol`,
`test/ANCV1_Findings.t.sol`, and the invariant harnesses
`test/AnchorVaultInvariant_t.sol` / `test/AnchorVaultInvariantExt_t.sol`.)

---

## 6. Consent & the frontend boundary (accepted boundary B-1)

User consent to the *service terms* (fees, locks, emergency mechanics) is
captured at the **UI layer**: the frontend requires explicit acknowledgement
before a vault can be created. The **contract does not enforce this consent
gating** — that is a UX concern, not a fund-safety one.

This is distinct from **recipient consent on transfer** (§10, ANCV1-2), which
*is* enforced on-chain: `transferVault` requires a signature from the recipient
themselves, verified by the contract, not merely displayed by a frontend.

A caller interacting with the contract **directly** (via a block explorer or a
custom script, bypassing the official frontend) does not see the terms
checkboxes. This is **by design**: the realistic user population uses the
frontend and clicks a button; direct contract interaction requires deliberate
technical effort, and such an actor is by definition aware of what the call
does. Documented here as a known boundary rather than a defect.

---

## 7. Accepted design decisions & trade-offs

- **T-1 — Wallet-only compromise can still trigger a 20% panic.** An attacker
  holding only the owner's EOA (no auth keys) can call `panicWithdraw`. This
  **moves funds to the owner's own emergency address (no theft)** and burns 20%
  as the deterrent cost. Accepted: 80% of principal is preserved to the owner's
  backup; the 20% is the price of the isolation guarantee. See §3 for the full
  framing — this is the central trade-off of the entire design.

- **T-2 — Voluntary lock is not absolute.** `setVoluntaryLock` blocks normal
  `withdrawFromVault` and `earlyClose` (both `enforceLock = true`), but
  `recoverToSafe`, `emergencyWithdrawToAny`, and `panicWithdraw` **bypass** it
  (and `_closeAndPayout` clears `voluntaryLockUntil`). Intent: a user must never
  be permanently trapped — an emergency exit always exists. **Consumers must not
  treat a voluntary lock as an unbreakable guarantee that funds are immovable.**

- **T-3 — Fee-on-transfer tokens.** Inbound amounts are measured by balance delta
  (`_safeReceive`), so internal accounting is exact. On withdrawal the recipient
  receives less than `net` by the token's own transfer fee. By-design; contract
  solvency is unaffected.

- **T-4 — Pending-transfer slot griefing.** A third party can transiently occupy
  a recipient's `pendingIncomingTransfer[recipient][token]` slot via a sham
  secure transfer, but the recipient can clear it **immediately** with
  `rejectIncomingTransfer`, so it is not a durable DoS. The initiator also locks
  up their own vault while the sham transfer is pending. Residual low-severity
  griefing accepted.

- **T-5 — `deadline` as signer-controlled maximum.** A signer may set a
  far-future deadline; this is the signer's prerogative. By-design.

- **T-6 — Burn fallback dust (informational).** If `ANCR.burn()` reverts *and*
  the fallback transfer to `address(0)` also reverts, the burn amount stays in
  the contract, unaccounted by any pool. This is **not** insolvency (balance ≥
  liabilities still holds — balance is merely larger) and **not** a theft vector;
  it only results in stranded dust. Non-ANCR tokens never reach the burn path
  (`burnAmt == 0` for them).

- **T-7 — Timelock anchoring.** `timelockHours` is anchored to the first deposit
  and is not extended by subsequent deposits. By-design (per-vault, set once).

- **T-8 — Quick transfer requires an EOA recipient.** The recipient's consent
  signature (§10, ANCV1-2) is verified with `ECDSA.recover`, so smart-contract
  wallets (Safe and similar, ERC-1271) cannot accept a quick transfer. The
  secure-transfer path remains fully available to contract wallets, since there
  the recipient confirms with their own transaction rather than a signature.
  ERC-1271 support was omitted to stay within the EIP-170 bytecode limit.

- **T-9 — No open-vault discount tier.** Removed rather than capped (§4, §10).
  A per-unit cap would need re-tuning for every newly whitelisted token and
  re-introduces the same close-and-reopen arbitrage below the cap. Uniform
  per-level pricing has no arbitrage window and needs no token-specific
  parameter.

---

## 8. Roles & administration

- **creator** — token management (`addSupportedToken` / `removeSupportedToken`),
  fee/reserve withdrawals (7-day timelock), `setWelcomeBonus`,
  `initializeDistribution`, `rescueERC20` (only tokens **never** supported,
  `wasSupported == false` — cannot touch principal), `unpause`.
- **guardian** — pause flow only (`requestPause` with 2-day delay,
  `executePause`, `emergencyPause`, `cancelPauseRequest`).
- Role transfers are **two-step with cooldowns** (creator 7 days, guardian
  2 days) and **merge prevention on accept** (`pendingCreator != guardian`,
  `pendingGuardian != creator`).

---

## 9. Out of scope

Frontend (`docs/pulse.html`) security; oracle/price feeds (none used);
cross-protocol composability beyond standard ERC-20 transfer semantics; mainnet
deployment (blocked pending the final audit report + TVL cap).

---

## 10. Fixes applied following the Hexens initial report (31 Jul 2026)

Findings reported by Hexens:

- **ANCV1-1 (Medium)** — a stale CONFLICT-status secure-transfer record could
  release a vault now held by a newer transfer, letting an attacker quick-transfer
  the vault away and leaving the intended recipient with a zero-value,
  zero-token vault on confirmation. Fixed by binding each lock to the specific
  transfer id (`Vault.lockedByTransfer`); `_closeTransfer` and
  `confirmSecureTransfer` now only release a vault or clear an incoming slot if
  they still belong to the transfer being closed.
- **ANCV1-2 (Medium)** — `transferVault` created a vault for an arbitrary
  address with sender-chosen keys, with no signature from the recipient,
  allowing an attacker to front-run a user's first `openVault` call and lock
  them out of funds they had not yet deposited. Fixed by requiring a second
  EIP-712 signature (`AcceptVaultTransfer`) from the recipient before the
  transfer executes.
- **ANCV1-3 (Informational)** — the minimum-deposit check was performed twice,
  once on the raw input and once on the net amount after fees. The raw-input
  check was redundant since `net <= amount` always. Removed; only the net
  amount is checked.
- **ANCV1-4 (Low)** — opening a vault was charged a flat 0.20% regardless of
  level, while topping up an existing vault was charged the level's full rate
  (up to 2%). This made "withdraw, then reopen with a larger deposit" cheaper
  than a direct top-up on VAULT/FORTRESS tiers. Fixed by charging the same
  per-level rate on open and deposit; see §4 and T-9 for why a cap was not used
  instead.

Additional issues identified during internal review after the initial report,
fixed in the same remediation pass:

- **H-1** — `initializeDistribution` checked only the raw contract balance
  against the 1,000,000 ANCR distribution amount. If called after user deposits
  had already accrued, the check could pass using user funds, and the payout
  share would be transferred out of principal that was not the creator's. Fixed
  by requiring the balance to cover the distribution amount **in addition to**
  `lockedPrincipal + creatorFees + strategicReserve + rewardPool` already
  committed to users. Operationally, the function is still called immediately
  after deployment before any deposits are accepted; this fix makes that
  invariant hold regardless of call order.
- **M-3** — `transferVault` did not check `timelockHours`, and the vault
  created for the recipient did not inherit the timelock. A user under an
  active timelock could bypass it by transferring the vault to a second address
  of their own at 0.5%, far below the intended penalty ladder
  (5% / 10% / 15% / 20%) for early exit. `initSecureTransfer` had the same gap.
  Fixed by checking the timelock in both functions before allowing the transfer
  to proceed.

An additional item previously tracked internally as "M-2" (non-functional
timelock on withdrawal) did not reproduce against the current codebase —
`withdrawFromVault` correctly enforces `depositedAt + timelockHours`. No change
was needed.

Renaming: the contract was renamed from `AnchorVaultV45` to `AnchorVaultCoin`
(source file, contract identifier, and EIP-712 domain name) because `AnchorVault`
is already in mainnet use by an unrelated Anchor Protocol contract
(`0xA2F987A546D4CD1c607Ee8141276876C26b72Bdf`). This is a naming change only —
no functional behavior is affected. The EIP-712 domain version string ("45") was
left unchanged.
