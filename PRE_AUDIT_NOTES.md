# AnchorVaultV45 — Pre-Audit Development Notes

**Purpose.** These are notes I kept during development while stress-testing the contract against the vulnerability classes I considered most relevant to a multi-asset vault: multi-token edge cases, the solvency invariant, the EIP-712 layer, the vault state machine, reentrancy, access control, and boundary conditions. I'm documenting the items I considered and my reasoning on each, so the review team doesn't spend time re-deriving conclusions I've already worked through.

**This is not a substitute for your audit.** I treat all conclusions below as provisional and welcome correction. Line references are to `src/AnchorVaultV45.sol` at the current commit.

**Build settings.** solc 0.8.26, `via_ir = true`, `optimizer_runs = 1`, `evm_version = cancun`, `bytecode_hash = none`. Runtime size 24,516 bytes (EIP-170 headroom: 60 bytes). This tight headroom is the main constraint on adding further defensive checks.

---

## Architecture facts relevant to the items below

- **Vault storage namespace.** Vaults live in `mapping(address => mapping(uint256 => Vault)) private vaults`, keyed by **owner first**: `vaults[owner][vaultId]`. Every vault entry point uses `vaults[msg.sender][vid]` plus the `vaultExists(msg.sender, vid)` modifier. A caller can only ever reach their own vaults; there is no global `vaultId` namespace.
- **EIP-712 binding.** Every signed operation embeds `msg.sender` as the first struct field, a per-vault `nonce` (incremented in `_checkSig`, with an explicit `uint64.max` overflow guard), and a `deadline`. The domain separator (`EIP712("AnchorVault","45")`) binds `chainId` and the contract address. ECDSA via OpenZeppelin.
- **Solvency invariant.** For each token: `balanceOf(this) >= lockedPrincipal[token] + creatorFees[token] + strategicReserve[token] + rewardPool[token]`. `lockedPrincipal` is user principal (1:1); the other three are protocol-side balances. This is the property I focused on most; the invariant fuzz test in the suite exercises it and I found no violating path.
- **Checked arithmetic.** Solidity 0.8 default; the only `unchecked` block is the `nonce += 1` increment, guarded by the preceding overflow check.

---

## Items I considered worth noting

### N-1 — Fee-on-transfer tokens (withdrawal side) — *Informational*

A fee-on-transfer (FoT) token charges a fee on `transfer`. On **deposit**, this is already handled: `_safeReceive` measures the actual received amount via a balance-difference, so accounting reflects what truly arrived. On **withdrawal**, `withdrawFromVault` decrements `lockedPrincipal[token] -= amount`, routes the 0.5% protocol fee through `_settlePenalty`, and transfers `net = amount - fee` out.

I checked the solvency impact. The contract balance falls by exactly `net` (the amount the `safeTransfer` moves out); accounting falls by `amount` on `lockedPrincipal` minus `fee` re-credited to the protocol balances, i.e. by `net` as well. **The invariant is preserved.** The only effect of a FoT token is that the withdrawing user receives `net` minus the token's own transfer fee — a cost borne by that user on their own vault, with their own choice of token. No other user's principal and no protocol balance is affected.

Token listing is creator-gated via `addSupportedToken`, so a problematic FoT token is excluded by not listing it. I document this as an operational rule rather than enforcing it on-chain (size headroom is 60 bytes). Happy to add an explicit FoT-rejection check in `addSupportedToken` if you consider it worth the bytecode.

### N-2 — Signed `deadline` may be set arbitrarily large — *Informational*

`_checkSig` enforces `block.timestamp > deadline → revert`. A user could sign an operation with `deadline = type(uint256).max`, making that one signature non-expiring. The `deadline` is chosen by the signer and the signature requires the user's own `mainAuthKey`/`recoveryAuthKey`; it only ever authorizes operations on that user's own vault. I treat this as a front-end best-practice concern (the client should set bounded deadlines) rather than a contract-level issue — there is no path by which a third party benefits.

### N-3 — Pending-incoming-transfer slot can be griefed — *Low / accepted*

Secure transfers reserve one incoming slot per `(recipient, token)` via `pendingIncomingTransfer[to][token]`, which blocks a second concurrent inbound transfer of the same token to the same recipient (`TransferAlreadyExists`). An attacker can initiate a sham transfer to occupy that slot. This is mitigated in-contract by `rejectIncomingTransfer`, which lets the recipient clear the slot immediately without waiting for expiry; `_closeTransfer` restores the sender's vault status and zeroes the pending slot, leaving no residual state. A determined griefer can re-initiate, but each attempt costs them gas, the recipient's rejection is cheap, no funds are at risk, and every pending transfer self-expires after 48h (`SECURE_TRANSFER_TIMEOUT`). I accept this as an inherent trade-off of the one-slot design.

---

## Things I checked and concluded are non-issues

Listed for completeness; I don't believe these need attention, but I'm flagging my reasoning in case you disagree.

- **Underflow in `depositToVault`.** `net = received - fee` where `fee = received * depositFeeBps / 10000` and `depositFeeBps ≤ 200`. `fee ≤ received` always, and 0.8 checked arithmetic would revert rather than wrap regardless. No underflow.
- **Overflow in `_writeSecureTransfer` / `nextSecureTransferId`.** No `unchecked` block is present; `block.timestamp + 48h` is a checked uint256 addition with a safe `uint48` cast, and `nextSecureTransferId` (uint256, +1 per transfer) cannot realistically overflow.
- **Reentrancy / solvency desync in `_closeAndPayout`.** All state writes (`v.amount = 0`, `v.status = 2`, `lockedPrincipal -= amount`, penalty settlement) precede the external `safeTransfer` (CEI), the vault is marked closed before the transfer, and all four callers (`earlyClose`, `recoverToSafe`, `emergencyWithdrawToAny`, `panicWithdraw`) are `nonReentrant`. No desync window.
- **Distribution exactness in `_accrueFees`.** `burn + creator + reserve` sums to ≤ `penalty` (0.65·penalty for ANCR), with the remainder explicitly routed to `rewardPool`; no wei is lost and inputs derive from `uint120` vault amounts.
- **`panicWithdraw` without a signature.** By design. It reads `vaults[msg.sender][vid]` and pays out to the caller's own `globalEmergency[msg.sender]` address (whose change is timelocked 7 days). It cannot touch another user's vault and is the intended last-resort path when auth keys are lost.

---

I'm happy to provide a diff against the previously deployed (18-decimal-only) version, the test suite (351 passing, including the solvency invariant fuzz), or any additional context that would help scoping.
