# Security Policy — AnchorVaultCoin

## 📋 Scope

| Component | In Scope |
|-----------|----------|
| `src/AnchorVaultCoin.sol` | ✅ Full audit scope |
| `src/AnchorCoin.sol` (ANCR token) | ✅ Fixed supply, no mint after deployment |
| OpenZeppelin libraries | ⚠️ Out of scope (assumed trusted) |
| Tests & deployment scripts | ⚠️ Out of scope |
| Frontend (maintained in a separate repository) | ⚠️ Out of scope |

---

## 🔍 Audit Status

External audit **completed** by [Hexens](https://hexens.io/) under their Builder
Support Ecosystem Program. Audit started 20 Jul 2026; initial report 31 Jul 2026;
**final report 10 Aug 2026**.

**Result: 0 Critical, 0 High.** Four findings (2 Medium, 1 Low, 1 Informational) —
all fixed by the development team and verified by Hexens on commit `6fead3f`.

Full report (PDF, 3.2 MB):
https://anchorvaultcoin-hash.github.io/anchor-vault-frontend/hexens-audit-anchorvaultcoin-2026-08-10.pdf

---

## 🔒 Threat Model

### Trust Assumptions

| Entity | Trust Level | Rationale |
|--------|-------------|-----------|
| **Creator** | High | Can add/remove tokens, withdraw fees/reserve (7-day timelock), unpause, transfer roles. Cannot touch user principal or the reward pool. |
| **Guardian** | Medium | Can pause the contract (2-day delay or immediate emergency). Cannot unpause or move funds. |
| **Users (vault owners)** | Full | Full control of own vaults via two auth keys. Non-custodial guarantee. |
| **Auditors** | Full | Full access to source code and tests. |

### Primary Attack Scenario Addressed

The contract is designed around **compromise of the owner's wallet key**. A stolen
seed phrase alone does not grant access to vault funds: every value-moving operation
requires an EIP-712 signature from a separate key that is never the wallet itself.

A representative real-world case in this class is the Ill Bloom incident (weak seed
generation, $5M+ lost), where wallet-level compromise was sufficient to drain funds.
Protocol-level or multisig incidents are a different threat class and are not what
this design targets.

### Key Security Properties

| Property | Implementation |
|----------|----------------|
| **Non-custodial** | Withdrawals remain available even when paused. |
| **Two-key authorization** | Main key for daily ops, Recovery key for emergency ops; neither may equal the owner's address or the contract. |
| **Replay protection** | EIP-712 signatures with per-vault nonce, deadline, and domain separator (chainId + contract address). |
| **Recipient consent** | Quick transfer requires a signature from the receiving address, so a vault cannot be forced onto a user. |
| **Timelock integrity** | A timelocked vault cannot be moved through either transfer path. |
| **Role separation** | `creator` ≠ `guardian`, enforced at construction; 2-step role transfers with cooldowns. |
| **Emergency address** | First set is immediate; change requires 7-day timelock and can be cancelled. |
| **Token rescue** | `wasSupported` prevents rescue of ever-whitelisted tokens. |
| **Reentrancy** | `ReentrancyGuard` on all external user operations. |
| **Voluntary lock** | Up to 5 years, blocks main-key ops, can only be extended. |
| **Reward pool** | Holds user funds; no creator withdrawal path exists by design. |

---

## 🛡️ Verification

### Invariants (Automated Fuzzing)

| Invariant | Status | Verification |
|-----------|--------|--------------|
| `lockedPrincipal` matches sum of vault amounts | ✅ | Foundry invariant fuzzing (128k calls) |
| Solvency: balance ≥ lockedPrincipal + fees + reserve + reward pool | ✅ | Foundry invariant fuzzing (128k calls) |
| Solvency across all supported tokens | ✅ | Foundry invariant fuzzing (128k calls) |
| Burn counter monotonicity | ✅ | Foundry invariant fuzzing (128k calls) |
| Roles never merge | ✅ | Foundry invariant fuzzing (128k calls) |

The solvency invariant holds under adversarial handlers including rebasing and
fee-on-transfer token mocks.

### Test Suite

| Suite | Count |
|-------|-------|
| Unit, integration & attack-vector tests | 365 |
| Invariant tests | 5 |
| Audit-finding regression tests | 12 (`test/ANCV1_Findings.t.sol`) |

### Static Analysis

| Tool | Result |
|------|--------|
| Slither 0.11.5 | 0 High, 0 Critical |
| solc 0.8.26 | 0 warnings |
| forge lint | 23 informational (`block-timestamp`, `unsafe-typecast`) — reviewed, all guarded or intentional |

Static analyzers do not detect multi-step stateful attack chains; manual review
remains necessary and is the reason for the external audit.

---

## ⚠️ Known Design Trade-offs

Labelled `DD-n` (design decision) to avoid confusion with audit finding identifiers.

### DD-1: Creator trust for token whitelisting
**Risk:** The creator can whitelist non-standard tokens (rebasing, fee-on-transfer, reentrant).
**Mitigation:** `_safeReceive` reconciles deposit-side fee-on-transfer by measuring the
actual balance delta. Withdraw-side fees and rebases are **not** reconciled — whitelisting
such a token could desync `lockedPrincipal`. Accepted under the creator trust model;
only vetted tokens are to be added.

### DD-2: Emergency pause centralization
**Risk:** The guardian can pause the contract, immediately in the emergency case.
**Mitigation:** Pause never blocks withdrawals — the non-custodial guarantee holds
while paused. The guardian cannot unpause or move funds. A multisig is recommended
for this role.

### DD-3: Role transfer delays
**Risk:** Role handover is not instantaneous (7-day creator, 2-day guardian).
**Mitigation:** Intentional. The 2-step process with cooldown allows the current
holder to cancel a pending transfer, which protects against a single compromised
transaction handing over control.

### DD-4: Quick transfer requires an EOA recipient
**Risk:** The recipient's consent signature is verified with `ECDSA.recover`, so smart
contract wallets (ERC-1271) cannot accept a quick transfer.
**Mitigation:** The secure transfer path remains fully available to contract wallets —
there the recipient confirms with their own transaction rather than a signature.
ERC-1271 support was omitted to stay within the EIP-170 bytecode limit.

---

## ✅ Deployment Recommendations

| Recommendation | Status |
|----------------|--------|
| Multisig for creator and guardian roles | Recommended |
| `payoutWallet` separate from creator | ✅ Enforced as an immutable constructor parameter |
| Run `initializeDistribution()` before accepting user deposits | ✅ Enforced by balance check |
| Monitor `wasSupported` before any rescue call | ✅ Implemented |
| TVL cap during the initial period | Recommended |
| Full test run after every change | ✅ CI |

---

## 📦 Deployment Status

| Network | Status |
|---------|--------|
| Sepolia (testnet) | Earlier revision; **not** the audited version |
| Ethereum Mainnet | ✅ **Live** — source verified on Etherscan (exact match) |

**Contracts:**

- Vault — `0xAc362D7bFCe7a4475873C37A0A96F2CE5C00E929`
- ANCR token — `0x52FBd42e9c9CBD3E1CED969EE4245C0e6ED9219B`

Both are verified on Etherscan with the exact compiler settings used to build them,
so the bytecode running on mainnet provably corresponds to the source in this
repository — the same code Hexens reviewed at commit `6fead3f`.

---

## 🔑 Operational Incident — Creator key (18–27 Aug 2026)

Disclosed here because the role change is permanently visible on-chain.

On 18 Aug 2026 the private key of the **Creator role** was exposed through operator
error: it was pasted into a request to a third-party API in place of an API key.
This was a key-handling mistake by the operator, **not a contract vulnerability** —
no flaw in the code was involved.

**Response.** The role was handed over to a new address using the contract's own
two-step transfer: requested 18 Aug, accepted 27 Aug 2026 after the 7-day cooldown.
The previous address now holds no privileges of any kind.

**Impact on users: none.** The Creator role cannot touch user principal or the
reward pool (see the trust model above), so user funds were never reachable
through this key at any point.

One thing worth stating plainly: the two-step role transfer with cooldown described
in DD-3 was exercised on mainnet under real conditions, and it did what it was
designed to do.

---

## 📢 Reporting a Vulnerability

Please report security issues **privately**, using GitHub's private advisory
channel: the **Security** tab of this repository → **Report a vulnerability**.

Do not open a public issue, and please do not disclose details publicly until a fix
is available. Disclosure will be coordinated with you.

An external audit shows the code was sound at the time it was reviewed. It is not a
promise that nothing will ever be found, which is why this channel exists.

---

## 📄 License

BUSL-1.1 — See [LICENSE](./LICENSE) for details.
