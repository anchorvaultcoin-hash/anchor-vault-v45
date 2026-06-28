# AnchorVaultV45 — Security Model & Design Rationale (Pre-Audit)

> Companion document for the external audit (Hexens). It states the intended
> security model, the economic rationale behind the fee structure, and the
> explicit by-design decisions / accepted trade-offs, so review effort can be
> spent on calibration and edge cases rather than on rediscovering intent.
>
> Status: Sepolia testnet only. Not deployed to mainnet. Mainnet is gated on
> this audit and a TVL cap.

---

## 1. Purpose & scope

AnchorVaultV45 is a **non-custodial, multi-asset ERC-20 "safe" service**. A user
who wants protected storage *opts in* by creating a vault and accepting the
service rules; a user who does not want it simply transacts normally and never
touches the vault. The contract is a storage/safety layer, **not an exchange or
AMM** — it does not swap, price, or route assets.

Supported assets: any ERC-20 with `decimals() == 18` (gated by `addSupportedToken`,
creator-only). The project token ANCR is supported at construction.

---

## 1a. Service positioning & user consent

AnchorVaultV45 should be evaluated as a **safety / custody-assist service**, not
as a token-routing primitive. The mental model is closer to a **safe-deposit box
at a bank** than to a swap venue:

- The user comes **for protection**, not for a free transfer.
- The service has **published terms** (fees, locks, emergency mechanics).
- The user **accepts those terms at entry** — four explicit checkboxes in the
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
     reads + accepts terms   (4 checkboxes, frontend)
           │
           ▼
     opens vault  ──►  isolation + recovery guarantees apply
```

---

## 2. Core security model — two-factor (EOA + auth key)

A vault is keyed by the owner's externally-owned account: `vaults[owner][id]`.
**Every value-moving operation additionally requires an EIP-712 signature from a
per-vault key**, and the owner address (`msg.sender`) is bound into the signed
struct and checked against `vaults[msg.sender]`. Consequently an attacker must
simultaneously control **both**:

1. the owner's EOA (to be `msg.sender`), and
2. the relevant per-vault auth key (to produce a valid signature).

Each vault has **two independent keys** (`_validateAuthKeys` enforces
`main != recovery`, both `!= owner`, both `!= contract`):

| Key | Authorizes |
|-----|-----------|
| `mainAuthKey` | normal ops: `withdrawFromVault`, `transferVault`, `initSecureTransfer`, `setTimelock`, `setVoluntaryLock` |
| `recoveryAuthKey` | emergency ops: `earlyClose`, `recoverToSafe`, `emergencyWithdrawToAny`, `rotateAuthKeys` |

Replay protection: per-vault `nonce` (incremented in `_checkSig`), `deadline`,
the EIP-712 domain separator (chainId + contract address), distinct typehash per
operation, and `vaultId` in the struct.

```
  TWO-FACTOR ACCESS  (both factors required for any value move)
  ────────────────────────────────────────────────────────────────
                       ┌─────────────────────┐
       factor 1 ──────►│  owner EOA           │  must be msg.sender
       (wallet)        │  (bound into sig)    │  → selects vaults[owner][id]
                       └──────────┬───────────┘
                                  │  AND
                       ┌──────────┴───────────┐
       factor 2 ──────►│  per-vault auth key  │  ECDSA signer must equal
       (signing key)   │  main  OR  recovery  │  stored key, else BadSignature
                       └──────────┬───────────┘
                                  ▼
                   ┌──────────────────────────────┐
                   │  main key  → normal ops       │  withdraw / transfer /
                   │              (0.5%)           │  secure-transfer / locks
                   ├──────────────────────────────┤
                   │  recovery  → emergency ops    │  earlyClose / recover /
                   │              (5–15%)          │  emergencyToAny / rotate
                   └──────────────────────────────┘

   Compromising ONE factor is insufficient:
     • wallet only            → cannot sign  → no withdraw/transfer/emergency
     • signing key only       → not msg.sender → cannot select the vault
```

**Key-sensitivity note (for user documentation).** `mainAuthKey` authorizes
`withdrawFromVault` to an arbitrary destination. It is therefore a *hot spending
key* and must be protected as strongly as the recovery key. The "normal vs
emergency" naming should not lead users to treat the main key as low-value.

---

## 3. Primary guarantee — wallet-compromise isolation

The central design goal: **compromise of the owner's wallet (EOA) alone must not
allow theft of vault funds.** Verified against the code:

- `withdrawFromVault`, `transferVault`, `initSecureTransfer`, `earlyClose`,
  `recoverToSafe`, `emergencyWithdrawToAny`, `rotateAuthKeys` all call `_checkSig`
  and revert (`BadSignature`) unless the recovered signer equals the stored key.
  Without an auth key, none of these succeed.
- `panicWithdraw` requires **no signature**, but it has **no destination
  parameter** — funds are sent to `globalEmergency[msg.sender]`, the owner's own
  pre-registered backup EOA. An attacker controlling only the wallet **cannot
  redirect funds to themselves**.
- `globalEmergency` may be *set* once instantly, but *changed* only through a
  **7-day timelock** (`proposeGlobalEmergencyChange` → `confirmGlobalEmergencyChange`),
  cancellable by the owner. The "funds can only reach the owner's backup"
  guarantee therefore holds for at least 7 days — enough time for the owner to
  react to a known compromise.
- A vault cannot even exist without `globalEmergency` set (`openVault` reverts
  `NoEmergencySet`), so the backup destination always exists.

Net result: a wallet-only compromise yields **no theft path**. (Residual effect:
trade-off T-1 below.)

```
  WALLET COMPROMISE — WHAT AN ATTACKER WITH ONLY THE EOA CAN DO
  ────────────────────────────────────────────────────────────────
   Attacker holds owner's wallet, but NOT main key and NOT recovery key.

     funds sitting loose in the wallet ............ LOST (outside the vault)
     funds inside the vault ....................... PROTECTED

   Attempted action on the vault:
     withdraw / transfer / emergency-to-any ....... REVERT (BadSignature)
     panicWithdraw ................................ ALLOWED, but:
                                                      → sends to
                                                        globalEmergency[owner]
                                                        (owner's own backup)
                                                      → attacker gains NOTHING
                                                      → 20% burned as the cost
     change globalEmergency to attacker ........... blocked 7 days (timelock),
                                                      owner can cancel

   Takeaway: the vault converts "wallet theft = total loss" into
   "wallet theft = at worst a forced 20% to the OWNER's own backup".
```

**Isolation is not confidentiality.** The protection above is **access-barrier
isolation**, not privacy. AnchorVaultV45 runs on a public chain: vault existence,
balances, and history are visible on-chain to anyone who inspects the contract
(e.g. via a block explorer or analytics). The guarantee is **not** "an attacker
cannot see the funds" — a determined attacker can. The guarantee is "even seeing
the funds, an attacker cannot move them without the auth keys." Any user-facing
copy must avoid implying privacy/anonymity; the correct claim is *isolation and
recovery*, not *confidentiality*.

---

## 4. Fee model & economic rationale

Two tiers of exit:

| Path | Fee | Key required | Notes |
|------|-----|--------------|-------|
| `openVault` | 0.20% | — (creation) | |
| `depositToVault` | 0.5% / 1.5% / 2.0% | — | by level SAFE/VAULT/FORTRESS |
| `withdrawFromVault` | 0.5% | main | timelock-gated |
| `transferVault` / secure transfer | 0.5% | main | |
| `earlyClose` | 5% | recovery | |
| `recoverToSafe` | 10% | recovery | to owner's emergency |
| `emergencyWithdrawToAny` | 15% | recovery | to any address |
| `panicWithdraw` | 20% | — | to owner's emergency |

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
     withdrawFromVault ........ 0.5%  | main key     | to: any  | timelock
     transferVault ............ 0.5%  | main key     | to: user vault
     earlyClose ............... 5%    | recovery key | to: owner

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
welcome bonuses. The `initializeDistribution` balance check is
invariant-protective and is not weakened.

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
redistributed + burn removed). Confirmed by Medusa fuzzing: `failures: 0` across
multi-actor, multi-token runs.

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
- **Voluntary-lock semantics (T-2)** — a locked vault blocks normal withdraw but
  `panicWithdraw` bypasses the lock (documenting the intended escape-hatch
  behavior).
- **Fee rates** — `panicWithdraw` pays out exactly 80%; normal withdraw pays out
  exactly 99.5%.
- **Roles & admin** — two-step transfer, cooldowns, wrong-acceptor rejection, and
  old-holder access loss are covered by the existing role test suite.
- **Solvency invariant** — exercised by Medusa across multi-actor / multi-token
  runs (`failures: 0`).

(Test files: `test/AnchorVaultBusinessLogic.t.sol`, `test/AnchorVaultV45.t.sol`,
and the Medusa harness `test/AnchorVaultInvariantExt_t.sol`.)

---

## 6. Consent & the frontend boundary (accepted boundary B-1)

User consent is captured at the **UI layer**: `pulse.html` requires four explicit
checkboxes (acknowledging the rules, including emergency fees) before a vault can
be created. The **contract does not enforce consent gating**.

A caller interacting with the contract **directly** (via a block explorer or a
custom script, bypassing the official frontend) does not see the checkboxes. This
is **by design**: the realistic user population uses the frontend and clicks a
button; direct contract interaction requires deliberate technical effort, and
such an actor is by definition aware of what the call does. Documented here as a
known boundary rather than a defect.

---

## 7. Accepted design decisions & trade-offs

- **T-1 — Wallet-only compromise can still trigger a 20% panic.** An attacker
  holding only the owner's EOA (no auth keys) can call `panicWithdraw`. This
  **moves funds to the owner's own emergency address (no theft)** and burns 20%
  as the deterrent cost. Accepted: 80% of principal is preserved to the owner's
  backup; the 20% is the price of the isolation guarantee.

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
  `rejectIncomingTransfer` (L-1 fix), so it is not a durable DoS. The initiator
  also locks up their own vault while the sham transfer is pending. Residual
  low-severity griefing accepted.

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

---

## 8. Roles & administration

- **creator** — token management (`addSupportedToken` / `removeSupportedToken`),
  fee/reserve withdrawals (7-day timelock), `setWelcomeBonus`,
  `initializeDistribution`, `rescueERC20` (only tokens **never** supported,
  `wasSupported == false` — cannot touch principal), `unpause`.
- **guardian** — pause flow only (`requestPause` with 2-day delay,
  `executePause`, `emergencyPause`, `cancelPauseRequest`).
- Role transfers are **two-step with cooldowns** (creator 7 days, guardian
  2 days) and **merge prevention on accept** (L-2 fix: `pendingCreator != guardian`,
  `pendingGuardian != creator`).

---

## 9. Out of scope

Frontend (`pulse.html`) security; oracle/price feeds (none used); cross-protocol
composability beyond standard ERC-20 transfer semantics; mainnet deployment
(blocked pending this audit + TVL cap).

---

## 10. Fixes already applied (for audit history)

- **L-1** — recipient can immediately reject an incoming secure transfer
  (`rejectIncomingTransfer`), removing the 48h block from sham transfers.
- **L-2** — role-merge prevented on `acceptCreatorship` / `acceptGuardianship`.
- **L-3** — uniform penalty handling on pause (`_settlePenalty`) across normal
  and emergency exits.
- Secure-transfer CONFLICT path sets status 4 and **clears**
  `pendingIncomingTransfer` (line ~677); `cancel` / `reclaim` accept status 4.
