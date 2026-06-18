// SPDX-License-Identifier: BUSL-1.1
// Licensed Work:  AnchorVaultV45
// Licensor:       Vitaliy
// Copyright (c) 2026 AnchorVaultCoin
//
// Лицензия Business Source License 1.1 (BUSL-1.1).
// Дополнительные права на использование: НЕТ.
// Дата перехода в open-source: 2030-01-01.
// После Change Date лицензия меняется на: GPL-2.0-or-later.
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

interface IBurnable {
    function burn(uint256 amount) external;
}

contract AnchorVaultV45 is ReentrancyGuard, EIP712 {
    using SafeERC20 for IERC20;

    // ─── ERRORS ─────────────────────────────────────────────
    error BadVaultId();
    error NotActive();
    error ZeroAddress();
    error InvalidAddress();
    error Locked();
    error NotCreator();
    error NotGuardian();
    error ContractPaused();
    error TokenNotSupported();
    error DepositBelowMinimum();
    error InvalidAmount();
    error InvalidLevel();
    error VaultLimitReached();
    error TimelockTooLong();
    error LockTooLong();
    error CooldownNotExpired();
    error NotPendingRole();
    error PauseTimeoutNotReached();
    error NoPauseRequest();
    error AdminRequestPending();
    error TimelockNotExpired();
    error NoAdminRequest();
    error BonusExceedsLimit();
    error AmountExceedsUint120();
    error DirectTransferForbidden();
    error NoEmergencySet();
    error TransferNotPending();
    error TransferExpired();
    error TransferAlreadyExists();
    error NotTransferRecipient();
    error NotTransferSender();
    error TransferStillValid();
    error TransferNotFound();
    error SignatureExpired();
    error BadSignature();
    error BadAuthKey();
    error AlreadyInitialized();
    error InsufficientBalanceForDistribution();
    error EmergencyAlreadySet();
    error NoGlobalEmergencyChange();
    error EmergencyTimelockNotExpired();
    error VaultTimelocked();
    error NameTooLong();
    error NonceOverflow();

    // ─── EVENTS ─────────────────────────────────────────────
    event VaultCreated(address indexed user, uint256 vaultId, address indexed token, uint256 amount, string name, address emergencyAddress, uint8 level);
    event VaultDeposited(address indexed user, uint256 vaultId, address indexed token, uint256 net, uint256 newTotal);
    event VaultWithdrawn(address indexed user, uint256 vaultId, address indexed token, uint256 amount);
    event VaultEarlyClosed(address indexed user, uint256 vaultId, uint256 payout, uint256 penalty);
    event VaultRecovered(address indexed user, uint256 vaultId, address indexed to, uint256 payout, uint256 penalty);
    event EmergencyWithdrawToAny(address indexed user, uint256 vaultId, address indexed to, uint256 amount, uint256 fee);
    event PanicWithdraw(address indexed user, uint256 indexed vid, address indexed to, uint256 payout, uint256 penalty);
    event VaultTransferred(address indexed from, address indexed to, uint256 fromId, uint256 toId);
    event AuthKeysRotated(address indexed user, uint256 vaultId);
    event TimelockSet(address indexed user, uint256 vaultId, uint256 hoursVal);
    event VoluntaryLockSet(address indexed user, uint256 vaultId, uint256 lockedUntil);
    event PenaltyDistributed(address indexed token, uint256 burnAmt, uint256 creatorAmt, uint256 reserveAmt, uint256 rewardsAmt);
    event PenaltyToRewardPool(address indexed token, uint256 amount);
    event FeeCollected(address indexed user, address indexed token, uint256 fee);
    event WelcomeBonusPaid(address indexed user, uint256 amount);
    event WelcomeBonusSkipped(address indexed user, uint8 reason); // 1=не задан 2=уже получал 3=лимит 4=мало в пуле
    event WelcomeBonusChanged(uint256 newAmount, uint256 maxClaims);
    event RewardPoolDonated(address indexed from, address indexed token, uint256 amount);
    event ERC20Rescued(address indexed token, address indexed to, uint256 amount);
    event TokenSupported(address indexed token);
    event TokenUnsupported(address indexed token);
    event PauseRequested(address indexed guardian, uint256 effectiveAt);
    event PauseRequestCancelled(address indexed guardian);
    event PauseStateChanged(bool paused, bool emergency);
    event CreatorshipTransferRequested(address indexed current, address indexed pending);
    event GuardianshipTransferRequested(address indexed current, address indexed pending);
    event CreatorshipAccepted(address indexed newCreator);
    event GuardianshipAccepted(address indexed newGuardian);
    event CreatorshipTransferCancelled(address indexed current);
    event GuardianshipTransferCancelled(address indexed current);
    event CreatorWithdrawRequested(address indexed token, uint256 amount, uint256 unlocksAt);
    event ReserveWithdrawRequested(address indexed token, uint256 amount, uint256 unlocksAt);
    event CreatorWithdrawn(address indexed token, address indexed to, uint256 amount);
    event ReserveWithdrawn(address indexed token, address indexed to, uint256 amount);
    event CreatorWithdrawCancelled(address indexed token);
    event ReserveWithdrawCancelled(address indexed token);
    event GlobalEmergencySet(address indexed user, address indexed emergency);
    event GlobalEmergencyChangeProposed(address indexed user, address indexed pending, uint256 unlocksAt);
    event GlobalEmergencyChangeCancelled(address indexed user);
    event SecureTransferInitiated(uint256 indexed transferId, address indexed from, address indexed to, uint256 vaultId, uint48 expiresAt);
    event SecureTransferConfirmed(uint256 indexed transferId, address indexed from, address indexed to);
    event SecureTransferCancelled(uint256 indexed transferId);
    event SecureTransferAutoCancelled(uint256 indexed transferId);
    event SecureTransferExpired(uint256 indexed transferId);
    event BurnFailed(address indexed token, uint256 amount, bool transferredToZero);

    enum VaultLevel { SAFE, VAULT, FORTRESS }

    struct VaultParams {
        string  name;
        address mainAuthKey;
        address recoveryAuthKey;
        uint256 amount;
    }

    struct Vault {
        address token;
        uint120 amount;
        uint64  id;
        uint64  nonce;
        uint48  depositedAt;
        uint48  voluntaryLockUntil;
        uint16  timelockHours;
        uint8   level;
        uint8   status;
        address mainAuthKey;
        address recoveryAuthKey;
        string  name;
    }

    struct SecureTransfer {
        address from;
        address to;
        uint256 vaultId;
        address newMainKey;
        address newRecoveryKey;
        uint48  expiresAt;
        uint8   status; // 0=PENDING, 1=CONFIRMED, 2=CANCELLED, 3=EXPIRED, 4=CONFLICT
    }

    struct EmergencyChange {
        address pending;
        uint48  unlocksAt;
    }

    // ─── CONSTANTS ──────────────────────────────────────────
    uint256 public constant VERSION = 45;
    uint256 public constant MIN_DEPOSIT = 10**16;
    uint256 public constant CREATOR_COOLDOWN = 7 days;
    uint256 public constant GUARDIAN_COOLDOWN = 2 days;

    uint256 public constant SAFE_DEPOSIT_FEE_BPS = 50;
    uint256 public constant VAULT_DEPOSIT_FEE_BPS = 150;
    uint256 public constant FORTRESS_DEPOSIT_FEE_BPS = 200;

    uint256 public constant SAFE_MAX_TIMELOCK_HOURS = 0;
    uint256 public constant VAULT_MAX_TIMELOCK_HOURS = 72;
    uint256 public constant FORTRESS_MAX_TIMELOCK_HOURS = 168;

    uint256 public constant OPEN_VAULT_FEE_BPS = 20;
    uint256 public constant WITHDRAW_FEE_BPS = 50;
    uint256 public constant TRANSFER_FEE_BPS = 50;
    uint256 public constant SECURE_TRANSFER_FEE_BPS = 50;
    uint256 public constant EARLY_CLOSE_FEE_BPS = 500;
    uint256 public constant RECOVER_TO_SAFE_FEE_BPS = 1000;
    uint256 public constant EMERGENCY_ANY_FEE_BPS = 1500;
    uint256 public constant PANIC_FEE_BPS = 2000;

    uint256 public constant PEN_BURN_BPS_ANCR = 2000;
    uint256 public constant PEN_CREATOR_BPS_ANCR = 2500;
    uint256 public constant PEN_RESERVE_BPS_ANCR = 2000;

    uint256 public constant PAUSE_DELAY = 2 days;
    uint256 public constant ADMIN_WITHDRAW_TIMELOCK = 7 days;
    uint256 public constant EMERGENCY_CHANGE_TIMELOCK = 7 days;
    uint256 public constant MAX_VOLUNTARY_LOCK = 5 * 365 days;
    uint256 public constant MAX_WELCOME_BONUS = MIN_DEPOSIT / 2;
    uint256 public constant SECURE_TRANSFER_TIMEOUT = 48 hours;

    // EIP-712 typehashes
    bytes32 private constant WITHDRAW_TYPEHASH = keccak256("Withdraw(address owner,uint256 vaultId,uint256 amount,address to,uint64 nonce,uint256 deadline)");
    bytes32 private constant TRANSFER_TYPEHASH = keccak256("TransferVault(address owner,uint256 vaultId,address to,address newMainKey,address newRecoveryKey,uint64 nonce,uint256 deadline)");
    bytes32 private constant INIT_SECURE_TYPEHASH = keccak256("InitSecureTransfer(address owner,uint256 vaultId,address to,address newMainKey,address newRecoveryKey,uint64 nonce,uint256 deadline)");
    bytes32 private constant SET_TIMELOCK_TYPEHASH = keccak256("SetTimelock(address owner,uint256 vaultId,uint256 hoursVal,uint64 nonce,uint256 deadline)");
    bytes32 private constant SET_VLOCK_TYPEHASH = keccak256("SetVoluntaryLock(address owner,uint256 vaultId,uint256 lockUntil,uint64 nonce,uint256 deadline)");
    bytes32 private constant ROTATE_KEYS_TYPEHASH = keccak256("RotateAuthKeys(address owner,uint256 vaultId,address newMainKey,address newRecoveryKey,uint64 nonce,uint256 deadline)");
    bytes32 private constant EARLY_CLOSE_TYPEHASH = keccak256("EarlyClose(address owner,uint256 vaultId,uint64 nonce,uint256 deadline)");
    bytes32 private constant RECOVER_TYPEHASH = keccak256("RecoverToSafe(address owner,uint256 vaultId,uint64 nonce,uint256 deadline)");
    bytes32 private constant EMERGENCY_ANY_TYPEHASH = keccak256("EmergencyWithdraw(address owner,uint256 vaultId,address to,uint64 nonce,uint256 deadline)");

    // ─── IMMUTABLES ─────────────────────────────────────────
    address public immutable ANCR_TOKEN;
    address public immutable payoutWallet;

    // ─── STORAGE ────────────────────────────────────────────
    mapping(address => bool) public supportedTokens;
    mapping(address => bool) public wasSupported;
    mapping(address => mapping(uint256 => Vault)) private vaults;
    mapping(address => uint256) public userVaultCount;
    mapping(address => mapping(address => uint256)) public activeVaultIdByToken;
    mapping(address => address) public globalEmergency;
    mapping(address => EmergencyChange) public globalEmergencyChange;
    mapping(uint256 => SecureTransfer) private secureTransfers;
    uint256 public nextSecureTransferId;
    mapping(address => mapping(address => uint256)) public pendingIncomingTransfer;
    uint256 public welcomeBonus;
    uint256 public maxWelcomeBonusClaims;
    uint256 public welcomeBonusClaims;
    mapping(address => bool) public welcomeBonusClaimed;
    mapping(address => uint256) public lockedPrincipal;
    mapping(address => uint256) public creatorFees;
    mapping(address => uint256) public strategicReserve;
    mapping(address => uint256) public rewardPool;
    uint256 public totalBurnedANCR;
    bool public distributionInitialized;
    address public creator;
    address public guardian;
    address public pendingCreator;
    address public pendingGuardian;
    uint256 public creatorshipRequestedAt;
    uint256 public guardianshipRequestedAt;
    bool public paused;
    uint256 public pauseTimestamp;
    mapping(address => address) public creatorWithdrawalTo;
    mapping(address => uint256) public creatorWithdrawalAmount;
    mapping(address => uint256) public creatorWithdrawalUnlock;
    mapping(address => address) public reserveWithdrawalTo;
    mapping(address => uint256) public reserveWithdrawalAmount;
    mapping(address => uint256) public reserveWithdrawalUnlock;

    // ─── CONSTRUCTOR ────────────────────────────────────────
    constructor(address _ancrToken, address _guardian, address _payoutWallet) EIP712("AnchorVault", "45") {
        if (_ancrToken == address(0) || _guardian == address(0) || _payoutWallet == address(0)) revert ZeroAddress();
        if (_guardian == msg.sender) revert InvalidAddress();
        if (_ancrToken == msg.sender || _ancrToken == _guardian) revert InvalidAddress();
        if (_payoutWallet == address(this)) revert InvalidAddress();
        if (_payoutWallet.code.length != 0) revert InvalidAddress();
        ANCR_TOKEN = _ancrToken;
        creator = msg.sender;
        guardian = _guardian;
        payoutWallet = _payoutWallet;
        supportedTokens[_ancrToken] = true;
        wasSupported[_ancrToken] = true;
        nextSecureTransferId = 1;
        emit TokenSupported(_ancrToken);
    }

    modifier whenNotPaused() { if (paused) revert ContractPaused(); _; }
    modifier vaultExists(address user, uint256 vid) {
        if (vid == 0 || vaults[user][vid].id != vid) revert BadVaultId();
        _;
    }
    modifier onlyCreator() { if (msg.sender != creator) revert NotCreator(); _; }
    modifier onlyGuardian() { if (msg.sender != guardian) revert NotGuardian(); _; }

    // ═══════════════════════════════════════════════════════
    //                 EIP-712 AUTHORIZATION
    // ═══════════════════════════════════════════════════════
    // Единая проверка EIP-712 подписи.
    //  expectedKey  — чей ключ должен подписать (mainAuthKey или recoveryAuthKey).
    //  enforceLock  — true: операция запрещена во время добровольной блокировки
    //                 (вывод/перевод); false: разрешена даже под блокировкой
    //                 (усиление ограничений и recovery-операции).
    function _checkSig(
        Vault storage v, bytes32 structHash, uint256 deadline,
        bytes calldata sig, address expectedKey, bool enforceLock
    ) internal {
        if (block.timestamp > deadline) revert SignatureExpired();
        if (enforceLock && block.timestamp < v.voluntaryLockUntil) revert Locked();
        if (ECDSA.recover(_hashTypedDataV4(structHash), sig) != expectedKey) revert BadSignature();
        if (v.nonce == type(uint64).max) revert NonceOverflow();
        unchecked { v.nonce += 1; }
    }

    function domainSeparator() external view returns (bytes32) { return _domainSeparatorV4(); }

    // ═══════════════════════════════════════════════════════
    //                 TOKEN MANAGEMENT
    // ═══════════════════════════════════════════════════════
    function addSupportedToken(address token) external onlyCreator nonReentrant {
        if (token == address(0)) revert ZeroAddress();
        if (IERC20Metadata(token).decimals() != 18) revert TokenNotSupported();
        supportedTokens[token] = true;
        wasSupported[token] = true;
        emit TokenSupported(token);
    }

    function removeSupportedToken(address token) external onlyCreator nonReentrant {
        if (token == ANCR_TOKEN) revert InvalidAddress();
        supportedTokens[token] = false;
        emit TokenUnsupported(token);
    }

    // ═══════════════════════════════════════════════════════
    //          GLOBAL EMERGENCY (только EOA)
    // ═══════════════════════════════════════════════════════
    function setGlobalEmergency(address emergency) external nonReentrant {
        if (globalEmergency[msg.sender] != address(0)) revert EmergencyAlreadySet();
        _validateEmergency(emergency);
        if (emergency.code.length != 0) revert InvalidAddress();
        globalEmergency[msg.sender] = emergency;
        emit GlobalEmergencySet(msg.sender, emergency);
    }

    function proposeGlobalEmergencyChange(address emergency) external nonReentrant {
        if (globalEmergency[msg.sender] == address(0)) revert NoEmergencySet();
        _validateEmergency(emergency);
        if (emergency.code.length != 0) revert InvalidAddress();
        uint48 unlocksAt = uint48(block.timestamp + EMERGENCY_CHANGE_TIMELOCK);
        globalEmergencyChange[msg.sender] = EmergencyChange(emergency, unlocksAt);
        emit GlobalEmergencyChangeProposed(msg.sender, emergency, unlocksAt);
    }

    function confirmGlobalEmergencyChange() external nonReentrant {
        EmergencyChange memory ec = globalEmergencyChange[msg.sender];
        if (ec.pending == address(0)) revert NoGlobalEmergencyChange();
        if (block.timestamp < ec.unlocksAt) revert EmergencyTimelockNotExpired();
        globalEmergency[msg.sender] = ec.pending;
        delete globalEmergencyChange[msg.sender];
        emit GlobalEmergencySet(msg.sender, ec.pending);
    }

    function cancelGlobalEmergencyChange() external nonReentrant {
        if (globalEmergencyChange[msg.sender].pending == address(0)) revert NoGlobalEmergencyChange();
        delete globalEmergencyChange[msg.sender];
        emit GlobalEmergencyChangeCancelled(msg.sender);
    }

    function _validateEmergency(address emergency) internal view {
        if (emergency == address(0)) revert ZeroAddress();
        if (emergency == msg.sender) revert InvalidAddress();
        if (emergency == address(this)) revert InvalidAddress();
        if (emergency == globalEmergency[msg.sender]) revert InvalidAddress();
    }

    // ═══════════════════════════════════════════════════════
    //                 HELPERS
    // ═══════════════════════════════════════════════════════
    function _checkUint120(uint256 amount) internal pure {
        if (amount > type(uint120).max) revert AmountExceedsUint120();
    }
    function _applyPenalty(uint256 amount, uint256 bps) internal pure returns (uint256 penalty) {
        penalty = (amount * bps) / 10000;
    }
    function _getDepositFee(uint256 level) internal pure returns (uint256) {
        if (level == uint256(VaultLevel.SAFE)) return SAFE_DEPOSIT_FEE_BPS;
        if (level == uint256(VaultLevel.VAULT)) return VAULT_DEPOSIT_FEE_BPS;
        if (level == uint256(VaultLevel.FORTRESS)) return FORTRESS_DEPOSIT_FEE_BPS;
        revert InvalidLevel();
    }
    function _getMaxTimelock(uint256 level) internal pure returns (uint256) {
        if (level == uint256(VaultLevel.SAFE)) return SAFE_MAX_TIMELOCK_HOURS;
        if (level == uint256(VaultLevel.VAULT)) return VAULT_MAX_TIMELOCK_HOURS;
        if (level == uint256(VaultLevel.FORTRESS)) return FORTRESS_MAX_TIMELOCK_HOURS;
        revert InvalidLevel();
    }
    function _validateAuthKeys(address mainKey, address recoveryKey, address owner) internal view {
        if (mainKey == address(0) || recoveryKey == address(0)) revert BadAuthKey();
        if (mainKey == recoveryKey) revert BadAuthKey();
        if (mainKey == owner || recoveryKey == owner) revert BadAuthKey();
        if (mainKey == address(this) || recoveryKey == address(this)) revert BadAuthKey();
    }
    function _safeReceive(address token, address from, uint256 amount) internal returns (uint256 received) {
        uint256 balBefore = IERC20(token).balanceOf(address(this));
        IERC20(token).safeTransferFrom(from, address(this), amount);
        received = IERC20(token).balanceOf(address(this)) - balBefore;
    }

    // ═══════════════════════════════════════════════════════
    //          PENALTY / FEE DISTRIBUTION
    // ═══════════════════════════════════════════════════════
    function _accrueFees(address token, uint256 penalty) internal returns (uint256 burnAmt) {
        if (penalty == 0) return 0;
        uint256 creatorAmt;
        uint256 reserveAmt;
        if (token == ANCR_TOKEN) {
            burnAmt    = (penalty * PEN_BURN_BPS_ANCR) / 10000;
            creatorAmt = (penalty * PEN_CREATOR_BPS_ANCR) / 10000;
            reserveAmt = (penalty * PEN_RESERVE_BPS_ANCR) / 10000;
        } else {
            creatorAmt = penalty / 2;
            reserveAmt = penalty - creatorAmt;
        }
        uint256 sum = burnAmt + creatorAmt + reserveAmt;
        uint256 rewardsAmt = penalty > sum ? penalty - sum : 0;
        creatorFees[token] += creatorAmt;
        strategicReserve[token] += reserveAmt;
        rewardPool[token] += rewardsAmt;
        emit PenaltyDistributed(token, burnAmt, creatorAmt, reserveAmt, rewardsAmt);
    }

    function _settlePenalty(address token, uint256 penalty) internal returns (uint256 burnAmt) {
        if (penalty == 0) return 0;
        if (paused) {
            if (token == ANCR_TOKEN) {
                rewardPool[token] += penalty;
                emit PenaltyToRewardPool(token, penalty);
                return 0;
            } else {
                uint256 creatorAmt = penalty / 2;
                uint256 reserveAmt = penalty - creatorAmt;
                creatorFees[token] += creatorAmt;
                strategicReserve[token] += reserveAmt;
                emit PenaltyDistributed(token, 0, creatorAmt, reserveAmt, 0);
                return 0;
            }
        }
        return _accrueFees(token, penalty);
    }

    function _burnIfNeeded(address token, uint256 burnAmt) internal {
        if (burnAmt == 0) return;
        try IBurnable(token).burn(burnAmt) {
            totalBurnedANCR += burnAmt;
        } catch {
            // запасной путь: перевод на 0x0; счётчик растёт только если токены реально ушли
            (bool success, ) = token.call(abi.encodeWithSelector(IERC20.transfer.selector, address(0), burnAmt));
            if (success) totalBurnedANCR += burnAmt;
            emit BurnFailed(token, burnAmt, success);
        }
    }

    // ═══════════════════════════════════════════════════════
    //          OPEN VAULT
    // ═══════════════════════════════════════════════════════
    function openVault(address token, VaultParams calldata p, uint8 level_)
        external nonReentrant whenNotPaused returns (uint256 vaultId)
    {
        if (!supportedTokens[token]) revert TokenNotSupported();
        _checkUint120(p.amount);
        if (level_ > uint8(VaultLevel.FORTRESS)) revert InvalidLevel();
        if (p.amount < MIN_DEPOSIT) revert DepositBelowMinimum();
        address emergency = globalEmergency[msg.sender];
        if (emergency == address(0)) revert NoEmergencySet();
        if (activeVaultIdByToken[msg.sender][token] != 0) revert VaultLimitReached();
        _validateAuthKeys(p.mainAuthKey, p.recoveryAuthKey, msg.sender);

        if (bytes(p.name).length > 64) revert NameTooLong();

        vaultId = ++userVaultCount[msg.sender];
        activeVaultIdByToken[msg.sender][token] = vaultId;

        uint256 received = _safeReceive(token, msg.sender, p.amount);
        uint256 openFee = (received * OPEN_VAULT_FEE_BPS) / 10000;
        uint256 net = received - openFee;
        if (net < MIN_DEPOSIT) revert DepositBelowMinimum();
        _checkUint120(net);

        Vault storage v = vaults[msg.sender][vaultId];
        v.token = token;
        v.id = uint64(vaultId);
        v.amount = uint120(net);
        v.depositedAt = uint48(block.timestamp);
        v.level = level_;
        v.mainAuthKey = p.mainAuthKey;
        v.recoveryAuthKey = p.recoveryAuthKey;
        v.name = p.name;
        v.status = 0;

        lockedPrincipal[token] += net;
        uint256 burnAmt = _accrueFees(token, openFee);

        emit FeeCollected(msg.sender, token, openFee);
        emit VaultCreated(msg.sender, vaultId, token, net, p.name, emergency, level_);

        _maybePayWelcomeBonus();
        _burnIfNeeded(token, burnAmt);
    }

    function _maybePayWelcomeBonus() internal {
        uint256 bonus = welcomeBonus;
        if (bonus == 0) {
            emit WelcomeBonusSkipped(msg.sender, 1);
            return;
        }
        if (welcomeBonusClaimed[msg.sender]) {
            emit WelcomeBonusSkipped(msg.sender, 2);
            return;
        }
        if (welcomeBonusClaims >= maxWelcomeBonusClaims) {
            emit WelcomeBonusSkipped(msg.sender, 3);
            return;
        }
        if (rewardPool[ANCR_TOKEN] < bonus) {
            emit WelcomeBonusSkipped(msg.sender, 4);
            return;
        }
        welcomeBonusClaimed[msg.sender] = true;
        welcomeBonusClaims += 1;
        rewardPool[ANCR_TOKEN] -= bonus;
        IERC20(ANCR_TOKEN).safeTransfer(msg.sender, bonus);
        emit WelcomeBonusPaid(msg.sender, bonus);
    }

    // ═══════════════════════════════════════════════════════
    //          DEPOSIT
    // ═══════════════════════════════════════════════════════
    function depositToVault(uint256 vid, uint256 amount)
        external nonReentrant whenNotPaused vaultExists(msg.sender, vid)
    {
        _checkUint120(amount);
        if (amount < MIN_DEPOSIT) revert DepositBelowMinimum();
        Vault storage v = vaults[msg.sender][vid];
        if (v.status != 0) revert NotActive();
        address token = v.token;
        uint256 received = _safeReceive(token, msg.sender, amount);
        uint256 fee = (received * _getDepositFee(v.level)) / 10000;
        uint256 net = received - fee;
        if (net < MIN_DEPOSIT) revert DepositBelowMinimum();
        _checkUint120(uint256(v.amount) + net);
        v.amount += uint120(net);
        lockedPrincipal[token] += net;
        uint256 burnAmt = _accrueFees(token, fee);
        emit FeeCollected(msg.sender, token, fee);
        emit VaultDeposited(msg.sender, vid, token, net, v.amount);
        _burnIfNeeded(token, burnAmt);
    }

    // ═══════════════════════════════════════════════════════
    //          WITHDRAW
    // ═══════════════════════════════════════════════════════
    function withdrawFromVault(uint256 vid, uint256 amount, address to, uint256 deadline, bytes calldata sig)
        external nonReentrant vaultExists(msg.sender, vid)
    {
        Vault storage v = vaults[msg.sender][vid];
        if (v.status != 0) revert NotActive();
        if (amount == 0 || amount > v.amount) revert InvalidAmount();
        if (to == address(0) || to == address(this)) revert InvalidAddress();
        if (block.timestamp < uint256(v.depositedAt) + uint256(v.timelockHours) * 1 hours) revert VaultTimelocked();

        bytes32 sh = keccak256(abi.encode(WITHDRAW_TYPEHASH, msg.sender, vid, amount, to, v.nonce, deadline));
        _checkSig(v, sh, deadline, sig, v.mainAuthKey, true);

        uint256 fee = (amount * WITHDRAW_FEE_BPS) / 10000;
        uint256 net = amount - fee;
        address token = v.token;
        v.amount -= uint120(amount);
        lockedPrincipal[token] -= amount;
        uint256 burnAmt = _settlePenalty(token, fee); // L-3 fix: единое поведение на паузе

        if (v.amount == 0) {
            v.status = 2;
            activeVaultIdByToken[msg.sender][token] = 0;
        }
        emit VaultWithdrawn(msg.sender, vid, token, net);
        IERC20(token).safeTransfer(to, net);
        _burnIfNeeded(token, burnAmt);
    }

    // ═══════════════════════════════════════════════════════
    //          QUICK TRANSFER
    // ═══════════════════════════════════════════════════════
    function transferVault(
        uint256 vid, address to, address newMainKey, address newRecoveryKey,
        uint256 deadline, bytes calldata sig
    ) external nonReentrant whenNotPaused vaultExists(msg.sender, vid) {
        Vault storage v = vaults[msg.sender][vid];
        if (v.status != 0) revert NotActive();
        if (to == address(0) || to == msg.sender || to == address(this)) revert InvalidAddress();
        address token = v.token;
        if (activeVaultIdByToken[to][token] != 0) revert VaultLimitReached();
        if (pendingIncomingTransfer[to][token] != 0) revert TransferAlreadyExists();
        if (globalEmergency[to] == address(0)) revert NoEmergencySet();
        _validateAuthKeys(newMainKey, newRecoveryKey, to);

        bytes32 sh = keccak256(abi.encode(TRANSFER_TYPEHASH, msg.sender, vid, to, newMainKey, newRecoveryKey, v.nonce, deadline));
        _checkSig(v, sh, deadline, sig, v.mainAuthKey, true);

        uint256 fee = _applyPenalty(v.amount, TRANSFER_FEE_BPS);
        uint256 net = uint256(v.amount) - fee;
        _checkUint120(net);
        uint256 burnAmt = _accrueFees(token, fee);

        lockedPrincipal[token] -= v.amount;

        uint256 newId = _createReceivedVault(to, token, net, v.level, newMainKey, newRecoveryKey, v.name);

        delete vaults[msg.sender][vid];
        activeVaultIdByToken[msg.sender][token] = 0;

        emit VaultTransferred(msg.sender, to, vid, newId);
        _burnIfNeeded(token, burnAmt);
    }

    // ═══════════════════════════════════════════════════════
    //          SECURE TRANSFER
    // ═══════════════════════════════════════════════════════
    function initSecureTransfer(
        uint256 vid, address to, address newMainKey, address newRecoveryKey,
        uint256 deadline, bytes calldata sig
    ) external nonReentrant whenNotPaused vaultExists(msg.sender, vid) returns (uint256 transferId) {
        Vault storage v = vaults[msg.sender][vid];
        if (v.status != 0) revert NotActive();
        if (to == address(0) || to == msg.sender || to == address(this)) revert InvalidAddress();
        address token = v.token;
        if (activeVaultIdByToken[to][token] != 0) revert VaultLimitReached();
        if (pendingIncomingTransfer[to][token] != 0) revert TransferAlreadyExists();
        if (globalEmergency[to] == address(0)) revert NoEmergencySet();
        _validateAuthKeys(newMainKey, newRecoveryKey, to);

        bytes32 sh = keccak256(abi.encode(INIT_SECURE_TYPEHASH, msg.sender, vid, to, newMainKey, newRecoveryKey, v.nonce, deadline));
        _checkSig(v, sh, deadline, sig, v.mainAuthKey, true);

        v.status = 1;
        transferId = _writeSecureTransfer(msg.sender, to, vid, newMainKey, newRecoveryKey);
        pendingIncomingTransfer[to][token] = transferId;
    }

    function _writeSecureTransfer(
        address from, address to, uint256 vid, address newMainKey, address newRecoveryKey
    ) internal returns (uint256 transferId) {
        transferId = nextSecureTransferId++;
        SecureTransfer storage st = secureTransfers[transferId];
        st.from = from;
        st.to = to;
        st.vaultId = vid;
        st.newMainKey = newMainKey;
        st.newRecoveryKey = newRecoveryKey;
        uint48 exp = uint48(block.timestamp + SECURE_TRANSFER_TIMEOUT);
        st.expiresAt = exp;
        st.status = 0;
        emit SecureTransferInitiated(transferId, from, to, vid, exp);
    }

    function _createReceivedVault(
        address to, address token, uint256 net, uint8 level,
        address newMainKey, address newRecoveryKey, string memory vName
    ) internal returns (uint256 newId) {
        if (bytes(vName).length > 64) revert NameTooLong();

        newId = ++userVaultCount[to];
        Vault storage nv = vaults[to][newId];
        nv.token = token;
        nv.id = uint64(newId);
        nv.amount = uint120(net);
        nv.depositedAt = uint48(block.timestamp);
        nv.level = level;
        nv.mainAuthKey = newMainKey;
        nv.recoveryAuthKey = newRecoveryKey;
        nv.name = vName;
        nv.status = 0;
        activeVaultIdByToken[to][token] = newId;
        lockedPrincipal[token] += net;
    }

    function confirmSecureTransfer(uint256 transferId) external nonReentrant whenNotPaused {
        SecureTransfer storage st = secureTransfers[transferId];
        if (transferId == 0 || transferId >= nextSecureTransferId || st.from == address(0)) revert TransferNotFound();
        if (st.status != 0) revert TransferNotPending();
        if (msg.sender != st.to) revert NotTransferRecipient();
        if (block.timestamp >= st.expiresAt) revert TransferExpired();

        address from = st.from;
        address to = st.to;
        uint256 fromVid = st.vaultId;
        Vault storage v = vaults[from][fromVid];
        address token = v.token;

        if (globalEmergency[to] == address(0)) revert NoEmergencySet();

        // ИСПРАВЛЕНИЕ: конфликт переводит в статус 4 (CONFLICT)
        if (activeVaultIdByToken[to][token] != 0) {
            st.status = 4;               // CONFLICT
            v.status = 0;
            pendingIncomingTransfer[to][token] = 0;
            emit SecureTransferAutoCancelled(transferId);
            return;
        }

        uint256 fee = _applyPenalty(v.amount, SECURE_TRANSFER_FEE_BPS);
        uint256 net = uint256(v.amount) - fee;
        _checkUint120(net);
        uint256 burnAmt = _accrueFees(token, fee);

        lockedPrincipal[token] -= v.amount;

        _createReceivedVault(to, token, net, v.level, st.newMainKey, st.newRecoveryKey, v.name);

        delete vaults[from][fromVid];
        activeVaultIdByToken[from][token] = 0;
        pendingIncomingTransfer[to][token] = 0;
        st.status = 1;

        emit SecureTransferConfirmed(transferId, from, to);
        _burnIfNeeded(token, burnAmt);
    }

    function cancelSecureTransfer(uint256 transferId) external nonReentrant {
        SecureTransfer storage st = secureTransfers[transferId];
        if (transferId == 0 || transferId >= nextSecureTransferId || st.from == address(0)) revert TransferNotFound();
        // ИСПРАВЛЕНИЕ: разрешаем отмену также для статуса CONFLICT (4)
        if (st.status != 0 && st.status != 4) revert TransferNotPending();
        if (msg.sender != st.from) revert NotTransferSender();
        _closeTransfer(transferId, st, 2);
        emit SecureTransferCancelled(transferId);
    }

    function reclaimExpiredTransfer(uint256 transferId) external nonReentrant {
        SecureTransfer storage st = secureTransfers[transferId];
        if (transferId == 0 || transferId >= nextSecureTransferId || st.from == address(0)) revert TransferNotFound();
        // ИСПРАВЛЕНИЕ: разрешаем возврат также для статуса CONFLICT (4)
        if (st.status != 0 && st.status != 4) revert TransferNotPending();
        if (block.timestamp < st.expiresAt) revert TransferStillValid();
        _closeTransfer(transferId, st, 3);
        emit SecureTransferExpired(transferId);
    }

    // L-1 FIX: получатель может СРАЗУ отклонить входящий перевод, не дожидаясь
    // истечения 48ч. Защита от мелкого вредительства: чужой sham-перевод больше
    // не блокирует входящие переводы жертвы по этому токену.
    function rejectIncomingTransfer(uint256 transferId) external nonReentrant {
        SecureTransfer storage st = secureTransfers[transferId];
        if (transferId == 0 || transferId >= nextSecureTransferId || st.from == address(0)) revert TransferNotFound();
        if (st.status != 0) revert TransferNotPending();
        if (msg.sender != st.to) revert NotTransferRecipient();
        _closeTransfer(transferId, st, 2); // 2 = CANCELLED; сейф отправителя возвращается в активный статус
        emit SecureTransferCancelled(transferId);
    }

    function _closeTransfer(uint256 /*transferId*/, SecureTransfer storage st, uint8 newStatus) internal {
        address token = vaults[st.from][st.vaultId].token;
        vaults[st.from][st.vaultId].status = 0;
        pendingIncomingTransfer[st.to][token] = 0;
        st.status = newStatus;
    }

    // ═══════════════════════════════════════════════════════
    //          EARLY CLOSE
    // ═══════════════════════════════════════════════════════
    function earlyClose(uint256 vid, uint256 deadline, bytes calldata sig)
        external nonReentrant vaultExists(msg.sender, vid)
    {
        Vault storage v = vaults[msg.sender][vid];
        if (v.status != 0) revert NotActive();
        bytes32 sh = keccak256(abi.encode(EARLY_CLOSE_TYPEHASH, msg.sender, vid, v.nonce, deadline));
        _checkSig(v, sh, deadline, sig, v.recoveryAuthKey, true);
        _closeAndPayout(v, vid, msg.sender, EARLY_CLOSE_FEE_BPS, 0);
    }

    // ═══════════════════════════════════════════════════════
    //          RECOVER TO SAFE
    // ═══════════════════════════════════════════════════════
    function recoverToSafe(uint256 vid, uint256 deadline, bytes calldata sig)
        external nonReentrant vaultExists(msg.sender, vid)
    {
        Vault storage v = vaults[msg.sender][vid];
        if (v.status != 0) revert NotActive();
        address to = globalEmergency[msg.sender];
        if (to == address(0)) revert NoEmergencySet();
        bytes32 sh = keccak256(abi.encode(RECOVER_TYPEHASH, msg.sender, vid, v.nonce, deadline));
        _checkSig(v, sh, deadline, sig, v.recoveryAuthKey, false);
        _closeAndPayout(v, vid, to, RECOVER_TO_SAFE_FEE_BPS, 1);
    }

    // ═══════════════════════════════════════════════════════
    //          EMERGENCY WITHDRAW TO ANY
    // ═══════════════════════════════════════════════════════
    function emergencyWithdrawToAny(uint256 vid, address to, uint256 deadline, bytes calldata sig)
        external nonReentrant vaultExists(msg.sender, vid)
    {
        Vault storage v = vaults[msg.sender][vid];
        if (v.status != 0) revert NotActive();
        if (to == address(0) || to == address(this)) revert InvalidAddress();
        bytes32 sh = keccak256(abi.encode(EMERGENCY_ANY_TYPEHASH, msg.sender, vid, to, v.nonce, deadline));
        _checkSig(v, sh, deadline, sig, v.recoveryAuthKey, false);
        _closeAndPayout(v, vid, to, EMERGENCY_ANY_FEE_BPS, 2);
    }

    // ═══════════════════════════════════════════════════════
    //          PANIC WITHDRAW
    // ═══════════════════════════════════════════════════════
    function panicWithdraw(uint256 vid) external nonReentrant vaultExists(msg.sender, vid) {
        Vault storage v = vaults[msg.sender][vid];
        if (v.status != 0) revert NotActive();
        address to = globalEmergency[msg.sender];
        if (to == address(0)) revert NoEmergencySet();
        _closeAndPayout(v, vid, to, PANIC_FEE_BPS, 3);
    }

    function _closeAndPayout(Vault storage v, uint256 vid, address to, uint256 feeBps, uint8 kind) internal {
        address token = v.token;
        uint256 amount = v.amount;
        uint256 penalty = _applyPenalty(amount, feeBps);
        uint256 payout = amount - penalty;

        v.amount = 0;
        v.status = 2;
        v.voluntaryLockUntil = 0;
        lockedPrincipal[token] -= amount;
        if (activeVaultIdByToken[msg.sender][token] == vid) activeVaultIdByToken[msg.sender][token] = 0;

        uint256 burnAmt = _settlePenalty(token, penalty);

        if (kind == 0) emit VaultEarlyClosed(msg.sender, vid, payout, penalty);
        else if (kind == 1) emit VaultRecovered(msg.sender, vid, to, payout, penalty);
        else if (kind == 2) emit EmergencyWithdrawToAny(msg.sender, vid, to, payout, penalty);
        else emit PanicWithdraw(msg.sender, vid, to, payout, penalty);

        IERC20(token).safeTransfer(to, payout);
        _burnIfNeeded(token, burnAmt);
    }

    // ═══════════════════════════════════════════════════════
    //          ROTATE AUTH KEYS
    // ═══════════════════════════════════════════════════════
    function rotateAuthKeys(
        uint256 vid, address newMainKey, address newRecoveryKey,
        uint256 deadline, bytes calldata sig
    ) external nonReentrant vaultExists(msg.sender, vid) {
        Vault storage v = vaults[msg.sender][vid];
        if (v.status != 0) revert NotActive();
        _validateAuthKeys(newMainKey, newRecoveryKey, msg.sender);
        bytes32 sh = keccak256(abi.encode(ROTATE_KEYS_TYPEHASH, msg.sender, vid, newMainKey, newRecoveryKey, v.nonce, deadline));
        _checkSig(v, sh, deadline, sig, v.recoveryAuthKey, false);
        v.mainAuthKey = newMainKey;
        v.recoveryAuthKey = newRecoveryKey;
        emit AuthKeysRotated(msg.sender, vid);
    }

    // ═══════════════════════════════════════════════════════
    //          SET TIMELOCK / VOLUNTARY LOCK
    // ═══════════════════════════════════════════════════════
    function setTimelock(uint256 vid, uint256 hoursVal, uint256 deadline, bytes calldata sig)
        external nonReentrant whenNotPaused vaultExists(msg.sender, vid)
    {
        Vault storage v = vaults[msg.sender][vid];
        if (v.status != 0) revert NotActive();
        if (hoursVal > _getMaxTimelock(v.level)) revert TimelockTooLong();
        bytes32 sh = keccak256(abi.encode(SET_TIMELOCK_TYPEHASH, msg.sender, vid, hoursVal, v.nonce, deadline));
        _checkSig(v, sh, deadline, sig, v.mainAuthKey, false);
        v.timelockHours = uint16(hoursVal);
        emit TimelockSet(msg.sender, vid, hoursVal);
    }

    function setVoluntaryLock(uint256 vid, uint256 lockUntilTimestamp, uint256 deadline, bytes calldata sig)
        external nonReentrant whenNotPaused vaultExists(msg.sender, vid)
    {
        Vault storage v = vaults[msg.sender][vid];
        if (v.status != 0) revert NotActive();
        if (lockUntilTimestamp <= block.timestamp) revert InvalidAmount();
        if (lockUntilTimestamp > block.timestamp + MAX_VOLUNTARY_LOCK) revert LockTooLong();
        if (lockUntilTimestamp > type(uint48).max) revert LockTooLong();
        bytes32 sh = keccak256(abi.encode(SET_VLOCK_TYPEHASH, msg.sender, vid, lockUntilTimestamp, v.nonce, deadline));
        _checkSig(v, sh, deadline, sig, v.mainAuthKey, false);
        if (uint48(lockUntilTimestamp) > v.voluntaryLockUntil) {
            v.voluntaryLockUntil = uint48(lockUntilTimestamp);
        }
        emit VoluntaryLockSet(msg.sender, vid, v.voluntaryLockUntil);
    }

    // ═══════════════════════════════════════════════════════
    //          WELCOME BONUS / DONATIONS
    // ═══════════════════════════════════════════════════════
    function setWelcomeBonus(uint256 amount, uint256 maxClaims) external onlyCreator nonReentrant {
        if (amount > MAX_WELCOME_BONUS) revert BonusExceedsLimit();
        welcomeBonus = amount;
        maxWelcomeBonusClaims = maxClaims;
        emit WelcomeBonusChanged(amount, maxClaims);
    }

    function initializeDistribution() external onlyCreator nonReentrant {
        if (distributionInitialized) revert AlreadyInitialized();
        uint256 total        = 1_000_000 ether;
        uint256 payoutShare  = 200_000 ether;
        uint256 reserveShare = 300_000 ether;
        uint256 rewardShare  = total - payoutShare - reserveShare;
        if (IERC20(ANCR_TOKEN).balanceOf(address(this)) < total) revert InsufficientBalanceForDistribution();
        distributionInitialized = true;
        rewardPool[ANCR_TOKEN] += rewardShare;
        strategicReserve[ANCR_TOKEN] += reserveShare;
        emit RewardPoolDonated(address(this), ANCR_TOKEN, rewardShare);
        IERC20(ANCR_TOKEN).safeTransfer(payoutWallet, payoutShare);
    }

    function donateToRewardPool(address token, uint256 amount) external nonReentrant {
        if (token != ANCR_TOKEN) revert TokenNotSupported(); // reward-пул используется только для ANCR
        if (amount == 0) revert InvalidAmount();
        uint256 received = _safeReceive(token, msg.sender, amount);
        rewardPool[token] += received;
        emit RewardPoolDonated(msg.sender, token, received);
    }

    // ═══════════════════════════════════════════════════════
    //          RESCUE (только для токенов, НИКОГДА не бывших в поддержке)
    // ═══════════════════════════════════════════════════════
    function rescueERC20(address token, address to, uint256 amount) external onlyCreator nonReentrant {
        // ИСПРАВЛЕНИЕ: запрещаем спасать ЛЮБЫЕ токены, которые когда-либо были добавлены
        if (wasSupported[token]) revert TokenNotSupported();
        if (to == address(0) || to == address(this)) revert InvalidAddress();
        if (amount == 0) revert InvalidAmount();
        IERC20(token).safeTransfer(to, amount);
        emit ERC20Rescued(token, to, amount);
    }

    // ═══════════════════════════════════════════════════════
    //          ROLE TRANSFERS
    // ═══════════════════════════════════════════════════════
    function transferCreatorship(address newCreator) external onlyCreator nonReentrant {
        if (newCreator == address(0)) revert ZeroAddress();
        if (newCreator == creator) revert InvalidAddress();
        if (newCreator == guardian) revert InvalidAddress();
        pendingCreator = newCreator;
        creatorshipRequestedAt = block.timestamp;
        emit CreatorshipTransferRequested(creator, newCreator);
    }
    function acceptCreatorship() external nonReentrant {
        if (msg.sender != pendingCreator) revert NotPendingRole();
        if (pendingCreator == guardian) revert InvalidAddress(); // L-2 fix: запрет слияния ролей на accept
        if (block.timestamp < creatorshipRequestedAt + CREATOR_COOLDOWN) revert CooldownNotExpired();
        creator = pendingCreator;
        pendingCreator = address(0);
        creatorshipRequestedAt = 0;
        emit CreatorshipAccepted(creator);
    }
    function cancelCreatorshipTransfer() external onlyCreator nonReentrant {
        if (pendingCreator == address(0)) revert NotPendingRole();
        pendingCreator = address(0);
        creatorshipRequestedAt = 0;
        emit CreatorshipTransferCancelled(creator);
    }
    function transferGuardianship(address newGuardian) external onlyCreator nonReentrant {
        if (newGuardian == address(0)) revert ZeroAddress();
        if (newGuardian == guardian) revert InvalidAddress();
        if (newGuardian == creator) revert InvalidAddress();
        pendingGuardian = newGuardian;
        guardianshipRequestedAt = block.timestamp;
        emit GuardianshipTransferRequested(guardian, newGuardian);
    }
    function acceptGuardianship() external nonReentrant {
        if (msg.sender != pendingGuardian) revert NotPendingRole();
        if (pendingGuardian == creator) revert InvalidAddress(); // L-2 fix: запрет слияния ролей на accept
        if (block.timestamp < guardianshipRequestedAt + GUARDIAN_COOLDOWN) revert CooldownNotExpired();
        guardian = pendingGuardian;
        pendingGuardian = address(0);
        guardianshipRequestedAt = 0;
        emit GuardianshipAccepted(guardian);
    }
    function cancelGuardianshipTransfer() external onlyCreator nonReentrant {
        if (pendingGuardian == address(0)) revert NotPendingRole();
        pendingGuardian = address(0);
        guardianshipRequestedAt = 0;
        emit GuardianshipTransferCancelled(guardian);
    }

    // ═══════════════════════════════════════════════════════
    //          PAUSE FLOW
    // ═══════════════════════════════════════════════════════
    function requestPause() external onlyGuardian nonReentrant {
        if (pauseTimestamp != 0) revert AdminRequestPending();
        pauseTimestamp = block.timestamp + PAUSE_DELAY;
        emit PauseRequested(msg.sender, pauseTimestamp);
    }
    function cancelPauseRequest() external onlyGuardian nonReentrant {
        if (pauseTimestamp == 0) revert NoPauseRequest();
        pauseTimestamp = 0;
        emit PauseRequestCancelled(msg.sender);
    }
    function executePause() external onlyGuardian nonReentrant {
        if (pauseTimestamp == 0) revert NoPauseRequest();
        if (block.timestamp < pauseTimestamp) revert PauseTimeoutNotReached();
        paused = true;
        pauseTimestamp = 0;
        emit PauseStateChanged(true, false);
    }
    function emergencyPause() external onlyGuardian nonReentrant {
        // ИСПРАВЛЕНИЕ: отменяем ожидающий запрос паузы
        if (pauseTimestamp != 0) {
            emit PauseRequestCancelled(msg.sender);
            pauseTimestamp = 0;
        }
        paused = true;
        emit PauseStateChanged(true, true);
    }
    function unpause() external onlyCreator nonReentrant {
        paused = false;
        pauseTimestamp = 0;
        emit PauseStateChanged(false, false);
    }

    // ═══════════════════════════════════════════════════════
    //          CREATOR / RESERVE WITHDRAW (7-day timelock)
    // ═══════════════════════════════════════════════════════
    function requestCreatorWithdraw(address token, address to, uint256 amount) external onlyCreator nonReentrant {
        _requestWithdraw(creatorFees, creatorWithdrawalTo, creatorWithdrawalAmount, creatorWithdrawalUnlock, token, to, amount);
        emit CreatorWithdrawRequested(token, amount, creatorWithdrawalUnlock[token]);
    }
    function cancelCreatorWithdraw(address token) external onlyCreator nonReentrant {
        _cancelWithdraw(creatorWithdrawalTo, creatorWithdrawalAmount, creatorWithdrawalUnlock, token);
        emit CreatorWithdrawCancelled(token);
    }
    function withdrawCreatorFees(address token) external onlyCreator nonReentrant {
        (address to, uint256 amount) = _execWithdraw(creatorFees, creatorWithdrawalTo, creatorWithdrawalAmount, creatorWithdrawalUnlock, token);
        emit CreatorWithdrawn(token, to, amount);
    }
    function requestReserveWithdraw(address token, address to, uint256 amount) external onlyCreator nonReentrant {
        _requestWithdraw(strategicReserve, reserveWithdrawalTo, reserveWithdrawalAmount, reserveWithdrawalUnlock, token, to, amount);
        emit ReserveWithdrawRequested(token, amount, reserveWithdrawalUnlock[token]);
    }
    function cancelReserveWithdraw(address token) external onlyCreator nonReentrant {
        _cancelWithdraw(reserveWithdrawalTo, reserveWithdrawalAmount, reserveWithdrawalUnlock, token);
        emit ReserveWithdrawCancelled(token);
    }
    function withdrawStrategicReserve(address token) external onlyCreator nonReentrant {
        (address to, uint256 amount) = _execWithdraw(strategicReserve, reserveWithdrawalTo, reserveWithdrawalAmount, reserveWithdrawalUnlock, token);
        emit ReserveWithdrawn(token, to, amount);
    }

    // Общая логика заявки/отмены/исполнения вывода (creator и reserve используют одно и то же).
    function _requestWithdraw(
        mapping(address => uint256) storage avail,
        mapping(address => address) storage toM,
        mapping(address => uint256) storage amtM,
        mapping(address => uint256) storage unlockM,
        address token, address to, uint256 amount
    ) internal {
        if (to == address(0)) revert ZeroAddress();
        if (to == address(this)) revert InvalidAddress();
        if (amount == 0 || amount > avail[token]) revert InvalidAmount();
        if (unlockM[token] != 0) revert AdminRequestPending();
        toM[token] = to;
        amtM[token] = amount;
        unlockM[token] = block.timestamp + ADMIN_WITHDRAW_TIMELOCK;
    }
    function _cancelWithdraw(
        mapping(address => address) storage toM,
        mapping(address => uint256) storage amtM,
        mapping(address => uint256) storage unlockM,
        address token
    ) internal {
        if (unlockM[token] == 0) revert NoAdminRequest();
        toM[token] = address(0);
        amtM[token] = 0;
        unlockM[token] = 0;
    }
    function _execWithdraw(
        mapping(address => uint256) storage avail,
        mapping(address => address) storage toM,
        mapping(address => uint256) storage amtM,
        mapping(address => uint256) storage unlockM,
        address token
    ) internal returns (address to, uint256 amount) {
        uint256 unlockAt = unlockM[token];
        if (unlockAt == 0) revert NoAdminRequest();
        if (block.timestamp < unlockAt) revert TimelockNotExpired();
        amount = amtM[token];
        to = toM[token];
        if (amount > avail[token]) revert InvalidAmount();
        avail[token] -= amount;
        toM[token] = address(0);
        amtM[token] = 0;
        unlockM[token] = 0;
        IERC20(token).safeTransfer(to, amount);
    }

    // ═══════════════════════════════════════════════════════
    //          VIEW GETTERS
    // ═══════════════════════════════════════════════════════
    function getVaultCore(address user, uint256 vid) external view vaultExists(user, vid)
        returns (uint64 id, address token, uint120 amount, string memory name, uint8 status, uint8 level)
    {
        Vault storage v = vaults[user][vid];
        return (v.id, v.token, v.amount, v.name, v.status, v.level);
    }
    function getVaultTimings(address user, uint256 vid) external view vaultExists(user, vid)
        returns (uint48 depositedAt, uint48 voluntaryLockUntil, uint16 timelockHours)
    {
        Vault storage v = vaults[user][vid];
        return (v.depositedAt, v.voluntaryLockUntil, v.timelockHours);
    }
    function getVaultAuth(address user, uint256 vid) external view vaultExists(user, vid)
        returns (uint64 nonce, address mainAuthKey, address recoveryAuthKey)
    {
        Vault storage v = vaults[user][vid];
        return (v.nonce, v.mainAuthKey, v.recoveryAuthKey);
    }
    function getSecureTransfer(uint256 transferId) external view
        returns (address from, address to, uint256 vaultId, uint48 expiresAt, uint8 status)
    {
        SecureTransfer storage st = secureTransfers[transferId];
        return (st.from, st.to, st.vaultId, st.expiresAt, st.status);
    }

    receive() external payable { revert DirectTransferForbidden(); }
    fallback() external payable { revert DirectTransferForbidden(); }
}
