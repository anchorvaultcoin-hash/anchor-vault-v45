## 📋 Scope

| Component | In Scope |
|-----------|----------|
| `src/AnchorVaultV45.sol` | ✅ Full audit scope |
| OpenZeppelin libraries | ⚠️ Out of scope (assumed trusted) |
| Tests & deployment scripts | ⚠️ Out of scope (audit focus) |

---

## 🔒 Threat Model

### Trust Assumptions

| Entity | Trust Level | Rationale |
|--------|-------------|-----------|
| **Creator** | High | Can add/remove tokens, withdraw fees/reserve (7-day timelock), unpause, transfer roles. Cannot touch user principal. |
| **Guardian** | Medium | Can pause contract (2-day delay or immediate emergency). Cannot unpause or move funds. |
| **Users (vault owners)** | Full | Full control of own vaults via two auth keys. Non-custodial guarantee. |
| **Auditors** | Full | Full access to source code and tests. |

### Key Security Properties

| Property | Implementation |
|----------|----------------|
| **Non-custodial** | Withdrawals remain available even when paused. |
| **Replay protection** | EIP-712 signatures with per-vault nonce and deadline. |
| **Role separation** | `creator` ≠ `guardian`, 2-step role transfers with cooldowns. |
| **Emergency address** | First set is immediate; change requires 7-day timelock. |
| **Token rescue** | `wasSupported` prevents rescue of ever-whitelisted tokens. |
| **Reentrancy** | `ReentrancyGuard` on all external user operations. |
| **Voluntary lock** | Up to 5 years, blocks main-key ops, can only be extended. |

---

## 🛡️ Audited Guarantees

### Invariants (Automated Verification)

| Invariant | Status | Verification |
|-----------|--------|--------------|
| `lockedPrincipal` matches sum of vault amounts | ✅ | Foundry invariant fuzzing (128k calls) |
| User solvency (balance ≥ lockedPrincipal + fees + reserve) | ✅ | Foundry invariant fuzzing (128k calls) |
| Nonce monotonicity | ✅ | EIP-712 design + tests |
| Role separation | ✅ | Constructor + 2-step transfers |

### Static Analysis (Slither)

| Severity | Count | Status |
|----------|-------|--------|
| High | 0 | ✅ |
| Medium | 12 | ⚠️ All accepted (see below) |
| Low | 15 | ⚠️ All accepted (see below) |

**Accepted Medium/Low findings:**

| Finding | Location | Acceptance Rationale |
|---------|----------|----------------------|
| `timestamp` usage | Various | Required for timelocks, cooldowns, and pause delays. |
| `reentrancy-benign` | `_burnIfNeeded` | Fallback only; external functions protected by `ReentrancyGuard`. |
| `incorrect-equality` | `_accrueFees`, `_burnIfNeeded` | Safe comparison with zero. |
| `locked-ether` | `receive()`/`fallback()` | Functions revert; no ether locked. |
| `low-level-calls` | `_burnIfNeeded` | Fallback transfer to 0x0; safe. |

---

## ⚠️ Known Design Trade-offs

### 1. Creator Trust for Token Whitelisting (M-1)
**Risk:** Creator can whitelist non-standard tokens (rebasing, fee-on-transfer, reentrant).  
**Mitigation:** Creator trust model; ANCR is a standard token. `_safeReceive` handles deposit-side fee-on-transfer, but withdraw-side fees and rebase are not reconciled. Adding such a token could desync `lockedPrincipal`.

### 2. Emergency Pause Centralization (M-2)
**Risk:** Guardian can pause contract (2-day delay or immediate).  
**Mitigation:** Guardian role is controlled by a trusted entity (multisig recommended). Pause does not affect withdrawals.

### 3. Creator/Guardian Role Transfers (M-3)
**Risk:** Delayed role transfers (7-day creator, 2-day guardian) with cooldowns.  
**Mitigation:** 2-step process; pending role can be cancelled by current role holder.

---

## ✅ Audit Recommendations

| Recommendation | Status |
|----------------|--------|
| Deploy with multisig for creator/guardian | ✅ Recommended |
| Use `payoutWallet` separate from creator | ✅ Testnet uses same; mainnet separate |
| Monitor `wasSupported` for rescue safety | ✅ Implemented |
| Regular test runs after changes | ✅ CI/CD recommended |

---

## 📦 Deployment Summary

| Network | Address | Status |
|---------|---------|--------|
| Sepolia (testnet) | `0x8E1F46fC913c4928303BbCEB92ccb7c54cD95BA4` | ✅ Deployed |
| Mainnet | TBD | ⏳ After audit |

---

## 📄 License

BUSL-1.1 — See [LICENSE](./LICENSE) for details.
EOF
git add SECURITY.md
git commit -m "docs: update SECURITY.md for v45 final"
git push

