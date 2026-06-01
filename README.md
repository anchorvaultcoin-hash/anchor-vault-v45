# AnchorVault V45

> A multi-asset on-chain vault with EIP-712 dual-key authorization,
> designed to be phishing-resistant: vault operations are authorized by
> per-vault signing keys, not by the owner's EOA private key.

> ⚠️ **Not audited externally yet.** Sepolia testnet validation is
> complete; the contract is ready for an external audit pass. Do **not**
> deploy to mainnet before the audit completes and findings are
> remediated. Mainnet rollout will be capped (per-vault and TVL).

---

## Why AnchorVault

Standard ERC-20 vaults inherit a single point of failure from the
underlying account: if the user signs a malicious transaction (phishing,
wallet compromise, blind-signing a swap), the vault is drained.
AnchorVault decouples vault authorization from the EOA:

1. **Vault-local keys.** Each vault has two dedicated authorization keys
   — `mainAuthKey` (regular operations) and `recoveryAuthKey` (emergency
   operations). These are independent from the owner's wallet key; the
   owner's wallet can never directly authorize a vault operation.
2. **Owner = identity, not signer.** The owner controls the vault as an
   account, but every state-changing call requires a valid EIP-712
   signature from the appropriate vault key.
3. **Defense-in-depth.** Time-locks, voluntary locks, role separation,
   pause flow, and a fixed `globalEmergency` cold-wallet destination
   bound the damage from any single compromise.

---

## Quick links

- **Contract:** [`src/AnchorVaultV45.sol`](./src/AnchorVaultV45.sol)
- **Distributor (separate):** [`src/AnchorDistributor.sol`](./src/AnchorDistributor.sol)
- **Tests:** [`test/AnchorVaultV45.t.sol`](./test/AnchorVaultV45.t.sol)
- **Deploy script:** [`script/Deploy.s.sol`](./script/Deploy.s.sol)
- **Project status:** [`PROJECT_STATUS.md`](./PROJECT_STATUS.md)
- **Known issues / auditor checklist:** [`KNOWN_ISSUES.md`](./KNOWN_ISSUES.md)
- **Testnet checklist:** [`TESTNET_CHECKLIST.md`](./TESTNET_CHECKLIST.md)
- **AI handoff context:** [`HANDOFF_CONTEXT.md`](./HANDOFF_CONTEXT.md)

---

## Sepolia testnet (live)

```
AnchorVaultV45  0xFd74CB71E0feff1EE961cEB1F6e19350371e0dF9
MockANCR        0x490Dd216A9aaD4fA389deca73a7cA4Ca01B24BDD
Creator         0x6226828cc3d1B9c5fc1c4d9BE3dF7b03A4A70479
Guardian        0xe0DACa428Abc3F1D5BD333C2D1Ca12dd1a36964D
Chain ID        11155111
```

Block explorer:
[sepolia.etherscan.io/address/0xFd74CB71E0feff1EE961cEB1F6e19350371e0dF9](https://sepolia.etherscan.io/address/0xFd74CB71E0feff1EE961cEB1F6e19350371e0dF9)

The `TESTNET_CHECKLIST.md` (sections A–G) has been completed at 100% on
this deployment. See `broadcast/Deploy.s.sol/11155111/` for transaction
hashes.

---

## Architecture (one screen)

### Roles
- **Owner** (per vault, the EOA address): identity of the vault holder.
  Cannot sign vault operations directly.
- **mainAuthKey** (per vault): authorizes deposit, withdraw, deposit,
  setTimelock, setVoluntaryLock, transferVault, initSecureTransfer.
- **recoveryAuthKey** (per vault): authorizes earlyClose,
  recoverToSafe, emergencyWithdrawToAny.
- **Creator** (global): adds supported tokens, sets welcome bonus,
  withdraws creator-fee pool (7-day timelock), unpauses.
- **Guardian** (global): pauses (2-day delay normally, instant in
  emergency). Cannot unpause, cannot withdraw funds, cannot change roles.
- **globalEmergency[owner]**: cold-wallet destination for
  `panicWithdraw`; set once, changes require 7-day timelock.

### Vault levels
- `SAFE` — 0.5% deposit fee, no timelock cap.
- `VAULT` — 1.5% deposit fee, timelock up to 72h.
- `FORTRESS` — 2.0% deposit fee, timelock up to 168h.

### Operation flow (EIP-712)
1. UI requests vault keys (held offline) to sign a typed-data message
   matching the EIP-712 type for the operation
   (`WITHDRAW_TYPEHASH`, `EARLY_CLOSE_TYPEHASH`, …).
2. Signature includes per-vault `nonce` + `deadline` + the operation
   parameters; domain separator binds chainId + address.
3. On-chain `_verify…Auth` validates against the vault's stored
   `mainAuthKey` / `recoveryAuthKey` and increments `nonce`.

### Emergency hierarchy (most-to-least restrictive)
1. **withdraw** — 0.5% fee, requires main key, works on pause.
2. **earlyClose** — 5% penalty, requires recovery key, funds to owner.
3. **recoverToSafe** — 10% penalty, requires recovery key, funds to
   snapshotted `emergencyAddress`.
4. **emergencyWithdrawToAny** — 15% penalty, requires recovery key,
   funds to any address.
5. **panicWithdraw** — 20% penalty, **no signature required**, funds
   to current `globalEmergency`. Last-resort lever.

### Secure transfer
48-hour escrow: sender initiates with a confirm code (hashed), recipient
confirms with the code. State machine: PENDING → CONFIRMED / CANCELLED /
EXPIRED. Recipient slot per (recipient, token) prevents simultaneous
double-incoming; expired transfers can be reclaimed by anyone (returns
control to sender).

---

## Build & test

```bash
# 1. Install Foundry
curl -L https://foundry.paradigm.xyz | bash && foundryup

# 2. Dependencies
forge install foundry-rs/forge-std --no-commit
forge install OpenZeppelin/openzeppelin-contracts@v5.1.0 --no-commit

# 3. Build
forge build

# 4. Tests
forge test -vv                          # 12 unit + EIP-712 tests
forge test --match-test invariant       # solvency invariant
forge coverage                          # coverage
```

### Build configuration (reproducible bytecode)

```toml
# foundry.toml
solc_version = "0.8.26"
via_ir = true
optimizer = true
optimizer_runs = 200
evm_version = "cancun"
```

Any Etherscan verification or auditor reproduction must use these exact
flags.

---

## Deploy (Sepolia)

```bash
cp .env.example .env
# Fill .env:
#   PRIVATE_KEY        — test wallet private key (0x… 66 chars total)
#   GUARDIAN_ADDRESS   — separate test address (must differ from deployer)
#   SEPOLIA_RPC_URL    — any RPC endpoint (public RPCs work; we used Tenderly)

set -a; source .env; set +a
forge script script/Deploy.s.sol:Deploy \
  --rpc-url $SEPOLIA_RPC_URL \
  --broadcast --legacy --gas-price 5000000000 \
  -vvv
```

Notes on deploy (lessons from this project):

- Use `--legacy --gas-price <wei>` to bypass RPC-inflated EIP-1559
  estimates; Sepolia base-fee is typically 1–3 gwei.
- Foundry's preflight balance check uses RPC-reported gas price, not
  the `--gas-price` flag — keep a buffer in the deployer wallet
  (≥ 0.16 ETH on Sepolia is comfortable).
- After deploy, the dashboard hard-codes the vault address in
  `dashboard/anchorvault-v45-dashboard.html`. Update accordingly.

---

## Source layout

```
src/
  AnchorVaultV45.sol        — main vault contract
  AnchorDistributor.sol     — one-off token distributor (separate
                              concern, separate audit boundary)
test/
  AnchorVaultV45.t.sol      — full test suite
  mocks/MockANCR.sol        — ERC-20 mock used in tests and Sepolia
script/
  Deploy.s.sol              — Sepolia deployment script
dashboard/
  index.html                — landing page
  anchorvault-v45-dashboard.html
                            — operational dashboard (vault address
                              hard-coded after deploy)
```

---

## Known issues (auditor priorities)

See [`KNOWN_ISSUES.md`](./KNOWN_ISSUES.md) for full detail. Summary:

| ID  | Title                                       | Severity      | Status            |
| --- | ------------------------------------------- | ------------- | ----------------- |
| I-1 | `emergencyAddress` snapshot vs. live        | Informational | Intentional       |
| I-2 | Single `nonce` for main + recovery          | Low           | Accepted          |
| I-3 | Griefing of incoming `secureTransfer` slot  | Low           | Mitigation planned for V45.1 |
| I-4 | `forge-lint unsafe-typecast` warnings       | Informational | False positives   |
| I-5 | Build-flag comment inconsistency            | Informational | Resolved          |
| I-6 | Orphan MockANCR on Sepolia                  | Informational | Testnet-only artifact |

We invite auditors to challenge all severity classifications.

---

## Token compatibility

- **Supported:** ERC-20 with `decimals() == 18`, non-rebase.
- **Supported with caveats:** fee-on-transfer (handled via balance-delta
  in `_safeReceive`).
- **Not supported:** rebase tokens, tokens with `decimals() ≠ 18`, tokens
  that revert on transfer-to-self or transfer-to-zero in non-standard ways.

The creator gates token additions via `addSupportedToken`. ANCR is set
immutably in the constructor; cannot be removed.

---

## License

MIT. See SPDX headers in source files.

## Operational Security

- **Auth keys** (`mainAuthKey`, `recoveryAuthKey`) must be generated and stored on **air‑gapped machines**.
- Transactions are signed offline and submitted by a separate hot wallet.
- For recovery operations, use a **hardware wallet** with a separate seed, not linked to the owner's EOA.
- Regularly monitor the `AuthKeysRotated` event for unauthorized key changes.
- Run `./security-check.sh` before each commit.

## Institutional Readiness
AnchorVault V45 is designed to meet the security and operational requirements of regulated financial institutions:
- **Separation of duties:** `creator` (admin) vs `guardian` (pause-only)
- **Timelocked withdrawals:** 7-day delay for admin fee withdrawals
- **Immutable core:** No upgradeable proxies, eliminating storage collision risks
- **Cold wallet emergency:** `globalEmergency` with 7-day change timelock and cancel option
- **Key security:** Offline EIP-712 signing keys, never exposed on-chain
- **Continuous monitoring:** GitHub Actions CI/CD + Slither static analysis
- **Audit-ready:** Full test suite (18/18), fuzzed invariants, detailed documentation

👉 See `INSTITUTIONAL_SECURITY.md` for a complete due diligence questionnaire.
