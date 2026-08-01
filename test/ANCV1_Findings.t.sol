// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {AnchorVaultCoin} from "../src/AnchorVaultCoin.sol";

contract MockANCRForPoC is ERC20 {
    constructor() ERC20("Mock ANCR", "mANCR") {}
    function mint(address to, uint256 amount) external { _mint(to, amount); }
}

/// @notice PoC-тесты по initial report Hexens (ANCV1, 31.07.2026).
///         Каждый тест воспроизводит сценарий из отчёта и проверяет,
///         что после исправления атака больше не проходит.
contract ANCV1FindingsTest is Test {
    AnchorVaultCoin internal vault;
    MockANCRForPoC internal ancr;

    address internal guardian;
    address internal payout;

    // участники
    address internal attacker;
    uint256 internal attackerPk;
    address internal helper;
    address internal victim;
    address internal accomplice;

    // ключи сейфов
    address internal aMain;
    uint256 internal aMainPk;
    address internal aRec;
    address internal hMain;
    uint256 internal hMainPk;
    address internal hRec;
    address internal vMain;
    uint256 internal vMainPk;
    address internal vRec;
    address internal cMain;
    address internal cRec;

    uint256 internal victimPk;
    uint256 internal accomplicePk;

    uint256 internal constant AMOUNT = 1_000 ether;

    bytes32 internal constant INIT_SECURE_TYPEHASH =
        keccak256("InitSecureTransfer(address owner,uint256 vaultId,address to,address newMainKey,address newRecoveryKey,uint64 nonce,uint256 deadline)");
    bytes32 internal constant TRANSFER_TYPEHASH =
        keccak256("TransferVault(address owner,uint256 vaultId,address to,address newMainKey,address newRecoveryKey,uint64 nonce,uint256 deadline)");
    bytes32 internal constant WITHDRAW_TYPEHASH =
        keccak256("Withdraw(address owner,uint256 vaultId,uint256 amount,address to,uint64 nonce,uint256 deadline)");
    bytes32 internal constant SET_TIMELOCK_TYPEHASH =
        keccak256("SetTimelock(address owner,uint256 vaultId,uint256 hoursVal,uint64 nonce,uint256 deadline)");
    bytes32 internal constant ACCEPT_TRANSFER_TYPEHASH =
        keccak256("AcceptVaultTransfer(address from,uint256 vaultId,address to,address newMainKey,address newRecoveryKey,uint256 deadline)");

    function setUp() public {
        // Foundry стартует с block.timestamp = 1 — уводим вперёд,
        // чтобы окна и таймлоки считались от вменяемого времени.
        vm.warp(1_000_000);

        ancr = new MockANCRForPoC();
        guardian = makeAddr("guardian");
        payout = makeAddr("payout");

        vault = new AnchorVaultCoin(address(ancr), guardian, payout);

        (attacker, attackerPk) = makeAddrAndKey("attacker");
        helper = makeAddr("helper");
        (victim, victimPk) = makeAddrAndKey("victim");
        (accomplice, accomplicePk) = makeAddrAndKey("accomplice");

        (aMain, aMainPk) = makeAddrAndKey("aMain");
        aRec = makeAddr("aRec");
        (hMain, hMainPk) = makeAddrAndKey("hMain");
        hRec = makeAddr("hRec");
        (vMain, vMainPk) = makeAddrAndKey("vMain");
        vRec = makeAddr("vRec");
        cMain = makeAddr("cMain");
        cRec = makeAddr("cRec");

        _fund(attacker);
        _fund(helper);
        _fund(victim);
        _fund(accomplice);

        _setEmergency(attacker, "emgA");
        _setEmergency(helper, "emgH");
        _setEmergency(victim, "emgV");
        _setEmergency(accomplice, "emgC");
    }

    // ──────────────────────────────────────────────────────────
    //  ANCV1-1 (Medium)
    //  Устаревшая CONFLICT-запись не должна освобождать сейф,
    //  который уже удерживается более новым переводом.
    // ──────────────────────────────────────────────────────────
    function test_ANCV1_1_conflictRecordCannotUnlockNewerTransfer() public {
        // Атакующий открывает сейф.
        uint256 vid = _openVault(attacker, aMain, aRec);

        // Шаг 1: перевод на подставного получателя.
        uint256 tid1 = _initSecureTransfer(attacker, vid, helper, hMain, hRec, aMainPk);

        // Подставной открывает свой сейф по тому же токену → при подтверждении
        // сработает конфликтная ветка, сейф-источник разблокируется,
        // а запись останется в статусе CONFLICT (4).
        _openVault(helper, hMain, hRec);
        vm.prank(helper);
        vault.confirmSecureTransfer(tid1);

        (, , , uint8 st1) = _transferStatus(tid1);
        assertEq(st1, 4, "tid1 must be CONFLICT");

        // Шаг 2: новый перевод того же сейфа — уже на жертву.
        uint256 tid2 = _initSecureTransfer(attacker, vid, victim, vMain, vRec, aMainPk);

        // Шаг 3: атакующий гасит старую конфликтную запись.
        // До исправления это снимало блокировку с сейфа, который
        // теперь обеспечивает перевод жертве.
        vm.prank(attacker);
        vault.cancelSecureTransfer(tid1);

        // Сейф обязан остаться заблокированным под tid2.
        (, , , uint8 vaultStatus, ) = vault.getVaultCore(attacker, vid);
        assertEq(vaultStatus, 1, "source vault must stay locked by tid2");

        // Шаг 4: увести сейф быстрым переводом больше нельзя.
        (uint64 nonce, , ) = vault.getVaultAuth(attacker, vid);
        uint256 deadline = block.timestamp + 1 hours;
        // Подписи строим ДО expectRevert: vm.sign внутри аргумента
        // после expectRevert съедает ожидание реверта.
        bytes memory sig = _sign(
            aMainPk,
            keccak256(abi.encode(TRANSFER_TYPEHASH, attacker, vid, accomplice, cMain, cRec, nonce, deadline))
        );
        bytes memory acceptSig = _sign(
            accomplicePk,
            keccak256(abi.encode(ACCEPT_TRANSFER_TYPEHASH, attacker, vid, accomplice, cMain, cRec, deadline))
        );
        vm.prank(attacker);
        vm.expectRevert(AnchorVaultCoin.NotActive.selector);
        vault.transferVault(vid, accomplice, cMain, cRec, deadline, sig, acceptSig);

        // Шаг 5: жертва подтверждает и получает полноценный сейф,
        // а не пустышку с token == address(0).
        vm.prank(victim);
        vault.confirmSecureTransfer(tid2);

        uint256 victimVid = vault.activeVaultIdByToken(victim, address(ancr));
        assertGt(victimVid, 0, "victim must own a vault");

        (, address vToken, uint120 vAmount, , ) = vault.getVaultCore(victim, victimVid);
        assertEq(vToken, address(ancr), "victim vault must hold the real token");
        assertGt(vAmount, 0, "victim vault must be funded");

        // Входящий слот жертвы освобождён — блокировки на будущее нет.
        assertEq(vault.pendingIncomingTransfer(victim, address(ancr)), 0, "incoming slot must be free");
    }

    /// Обратная сторона: свой собственный перевод отменяться обязан.
    function test_ANCV1_1_ownTransferStillCancellable() public {
        uint256 vid = _openVault(attacker, aMain, aRec);
        uint256 tid = _initSecureTransfer(attacker, vid, victim, vMain, vRec, aMainPk);

        vm.prank(attacker);
        vault.cancelSecureTransfer(tid);

        (, , , uint8 vaultStatus, ) = vault.getVaultCore(attacker, vid);
        assertEq(vaultStatus, 0, "vault must be released by its own transfer");
        assertEq(vault.pendingIncomingTransfer(victim, address(ancr)), 0, "incoming slot must be cleared");
    }

    // ──────────────────────────────────────────────────────────
    //  ANCV1-2 (Medium)
    //  Быстрый перевод требует согласия получателя.
    // ──────────────────────────────────────────────────────────
    function test_ANCV1_2_transferVaultRejectsMissingRecipientConsent() public {
        uint256 vid = _openVault(attacker, aMain, aRec);

        (uint64 nonce, , ) = vault.getVaultAuth(attacker, vid);
        uint256 deadline = block.timestamp + 1 hours;

        bytes memory sig = _sign(
            aMainPk,
            keccak256(abi.encode(TRANSFER_TYPEHASH, attacker, vid, victim, cMain, cRec, nonce, deadline))
        );
        // Атакующий подписывает «согласие» жертвы сам за себя.
        bytes memory forgedAccept = _sign(
            attackerPk,
            keccak256(abi.encode(ACCEPT_TRANSFER_TYPEHASH, attacker, vid, victim, cMain, cRec, deadline))
        );

        vm.prank(attacker);
        vm.expectRevert(AnchorVaultCoin.BadSignature.selector);
        vault.transferVault(vid, victim, cMain, cRec, deadline, sig, forgedAccept);

        // Сейф жертве не навязан.
        assertEq(vault.activeVaultIdByToken(victim, address(ancr)), 0, "victim must not receive a vault");
    }

    function test_ANCV1_2_transferVaultSucceedsWithRecipientConsent() public {
        uint256 vid = _openVault(attacker, aMain, aRec);

        (uint64 nonce, , ) = vault.getVaultAuth(attacker, vid);
        uint256 deadline = block.timestamp + 1 hours;

        bytes memory sig = _sign(
            aMainPk,
            keccak256(abi.encode(TRANSFER_TYPEHASH, attacker, vid, victim, cMain, cRec, nonce, deadline))
        );
        bytes memory acceptSig = _sign(
            victimPk,
            keccak256(abi.encode(ACCEPT_TRANSFER_TYPEHASH, attacker, vid, victim, cMain, cRec, deadline))
        );

        vm.prank(attacker);
        vault.transferVault(vid, victim, cMain, cRec, deadline, sig, acceptSig);

        uint256 newVid = vault.activeVaultIdByToken(victim, address(ancr));
        assertGt(newVid, 0, "recipient must own the vault after consent");
        assertEq(vault.activeVaultIdByToken(attacker, address(ancr)), 0, "sender slot must be freed");
    }

    // ──────────────────────────────────────────────────────────
    //  ANCV1-3 (Informational)
    //  Минимум проверяется по фактически зачисленной сумме.
    // ──────────────────────────────────────────────────────────
    function test_ANCV1_3_minimumEnforcedOnNetAmount() public {
        // Ровно минимум на входе: после комиссии открытия net < minDeposit.
        uint256 minDep = vault.MIN_DEPOSIT();

        vm.prank(attacker);
        vm.expectRevert(AnchorVaultCoin.DepositBelowMinimum.selector);
        vault.openVault(
            address(ancr),
            AnchorVaultCoin.VaultParams({mainAuthKey: aMain, recoveryAuthKey: aRec, amount: minDep}),
            0
        );
    }

    // ──────────────────────────────────────────────────────────
    //  ANCV1-4 (Low)
    //  Открытие тарифицируется по ставке уровня, поэтому
    //  «закрыть и переоткрыть» больше не даёт экономии.
    // ──────────────────────────────────────────────────────────
    function test_ANCV1_4_reopenIsNoLongerCheaperThanTopUp() public {
        uint256 base = 100_000 ether;
        uint256 topUp = 100_000 ether;

        // Путь 1 — честное пополнение FORTRESS.
        ancr.mint(attacker, 500_000 ether);
        uint256 vidA = _openVaultAtLevel(attacker, aMain, aRec, 2, base);
        vm.prank(attacker);
        vault.depositToVault(vidA, topUp);
        (, , uint120 honestNet, , ) = vault.getVaultCore(attacker, vidA);

        // Путь 2 — вывести всё и открыть заново большей суммой.
        ancr.mint(victim, 500_000 ether);
        uint256 vidB = _openVaultAtLevel(victim, vMain, vRec, 2, base);
        (, , uint120 openedNet, , ) = vault.getVaultCore(victim, vidB);

        uint256 balBefore = ancr.balanceOf(victim);
        _withdrawAll(victim, vidB, openedNet, vMainPk);
        uint256 returned = ancr.balanceOf(victim) - balBefore;

        uint256 vidB2 = _openVaultAtLevel(victim, vMain, vRec, 2, returned + topUp);
        (, , uint120 dodgeNet, , ) = vault.getVaultCore(victim, vidB2);

        // Обходной маршрут обязан оставлять пользователя в минусе:
        // он дополнительно платит комиссию за вывод.
        assertLt(dodgeNet, honestNet, "reopen route must not be cheaper");
    }

    /// Открытие и пополнение стоят одинаково на каждом уровне.
    function test_ANCV1_4_openMatchesDepositFeePerTier() public {
        uint256 amount = 10_000 ether;

        // SAFE: 50 bps
        ancr.mint(attacker, 100_000 ether);
        uint256 safeVid = _openVaultAtLevel(attacker, aMain, aRec, 0, amount);
        (, , uint120 safeNet, , ) = vault.getVaultCore(attacker, safeVid);
        assertEq(uint256(safeNet), amount - (amount * 50) / 10000, "SAFE open fee must equal deposit fee");

        // FORTRESS: 200 bps
        ancr.mint(victim, 100_000 ether);
        uint256 fortVid = _openVaultAtLevel(victim, vMain, vRec, 2, amount);
        (, , uint120 fortNet, , ) = vault.getVaultCore(victim, fortVid);
        assertEq(uint256(fortNet), amount - (amount * 200) / 10000, "FORTRESS open fee must equal deposit fee");
    }

    // ──────────────────────────────────────────────────────────
    //  H-1 (найдено внутренним ревью)
    //  Раздача не должна проходить за счёт пользовательских средств.
    // ──────────────────────────────────────────────────────────
    function test_H1_distributionCannotConsumeUserFunds() public {
        // Пользователь заводит в контракт больше миллиона — теперь голой
        // проверки balanceOf() хватило бы, чтобы раздать чужое.
        ancr.mint(attacker, 1_100_000 ether);
        vm.prank(attacker);
        vault.openVault(
            address(ancr),
            AnchorVaultCoin.VaultParams({mainAuthKey: aMain, recoveryAuthKey: aRec, amount: 1_050_000 ether}),
            0
        );
        assertGe(ancr.balanceOf(address(vault)), 1_000_000 ether, "balance must look sufficient");

        // Создатель своих средств не вносил — раздача обязана сорваться.
        vm.expectRevert(AnchorVaultCoin.InsufficientBalanceForDistribution.selector);
        vault.initializeDistribution();

        assertEq(ancr.balanceOf(payout), 0, "payout wallet must stay empty");
    }

    function test_H1_distributionSucceedsOnOwnFunds() public {
        // Пользовательские средства в контракте есть...
        uint256 userVid = _openVault(attacker, aMain, aRec);
        assertGt(userVid, 0);

        // Комиссия за открытие уже частично осела в резерве — сравниваем дельту.
        uint256 reserveBefore = vault.strategicReserve(address(ancr));
        uint256 rewardBefore = vault.rewardPool(address(ancr));

        // ...и создатель заводит СВОЙ миллион сверх них.
        ancr.mint(address(vault), 1_000_000 ether);

        vault.initializeDistribution();

        assertEq(ancr.balanceOf(payout), 200_000 ether, "payout share must be delivered");
        assertEq(vault.strategicReserve(address(ancr)) - reserveBefore, 300_000 ether, "reserve share");
        assertEq(vault.rewardPool(address(ancr)) - rewardBefore, 500_000 ether, "reward share");
    }

    // ──────────────────────────────────────────────────────────
    //  M-3 (найдено внутренним ревью)
    //  Таймлок не обходится переводом сейфа за 0.5%.
    // ──────────────────────────────────────────────────────────
    function test_M3_timelockBlocksQuickTransfer() public {
        uint256 vid = _openVaultAtLevel(attacker, aMain, aRec, 2);
        _setTimelock(attacker, vid, 72, aMainPk);

        (uint64 nonce, , ) = vault.getVaultAuth(attacker, vid);
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(
            aMainPk,
            keccak256(abi.encode(TRANSFER_TYPEHASH, attacker, vid, victim, cMain, cRec, nonce, deadline))
        );
        bytes memory acceptSig = _sign(
            victimPk,
            keccak256(abi.encode(ACCEPT_TRANSFER_TYPEHASH, attacker, vid, victim, cMain, cRec, deadline))
        );

        vm.prank(attacker);
        vm.expectRevert(AnchorVaultCoin.VaultTimelocked.selector);
        vault.transferVault(vid, victim, cMain, cRec, deadline, sig, acceptSig);
    }

    function test_M3_timelockBlocksSecureTransfer() public {
        uint256 vid = _openVaultAtLevel(attacker, aMain, aRec, 2);
        _setTimelock(attacker, vid, 72, aMainPk);

        (uint64 nonce, , ) = vault.getVaultAuth(attacker, vid);
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(
            aMainPk,
            keccak256(abi.encode(INIT_SECURE_TYPEHASH, attacker, vid, victim, vMain, vRec, nonce, deadline))
        );

        vm.prank(attacker);
        vm.expectRevert(AnchorVaultCoin.VaultTimelocked.selector);
        vault.initSecureTransfer(vid, victim, vMain, vRec, deadline, sig);
    }

    /// После истечения таймлока перевод снова разрешён.
    function test_M3_transferAllowedAfterTimelockExpires() public {
        uint256 vid = _openVaultAtLevel(attacker, aMain, aRec, 2);
        _setTimelock(attacker, vid, 72, aMainPk);

        vm.warp(block.timestamp + 73 hours);

        (uint64 nonce, , ) = vault.getVaultAuth(attacker, vid);
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(
            aMainPk,
            keccak256(abi.encode(TRANSFER_TYPEHASH, attacker, vid, victim, cMain, cRec, nonce, deadline))
        );
        bytes memory acceptSig = _sign(
            victimPk,
            keccak256(abi.encode(ACCEPT_TRANSFER_TYPEHASH, attacker, vid, victim, cMain, cRec, deadline))
        );

        vm.prank(attacker);
        vault.transferVault(vid, victim, cMain, cRec, deadline, sig, acceptSig);
        assertGt(vault.activeVaultIdByToken(victim, address(ancr)), 0, "transfer must pass after expiry");
    }

    // ──────────────────────────────────────────────────────────
    //  ХЕЛПЕРЫ
    // ──────────────────────────────────────────────────────────
    function _setTimelock(address owner, uint256 vid, uint256 hoursVal, uint256 signerPk) internal {
        (uint64 nonce, , ) = vault.getVaultAuth(owner, vid);
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(
            signerPk,
            keccak256(abi.encode(SET_TIMELOCK_TYPEHASH, owner, vid, hoursVal, nonce, deadline))
        );
        vm.prank(owner);
        vault.setTimelock(vid, hoursVal, deadline, sig);
    }

    function _fund(address who) internal {
        ancr.mint(who, 10_000 ether);
        vm.prank(who);
        ancr.approve(address(vault), type(uint256).max);
    }

    function _setEmergency(address who, string memory label) internal {
        vm.prank(who);
        vault.setGlobalEmergency(makeAddr(label));
    }

    function _openVault(address owner, address mainKey, address recKey) internal returns (uint256 vid) {
        return _openVaultAtLevel(owner, mainKey, recKey, 0);
    }

    /// Таймлок доступен только на VAULT (до 72ч) и FORTRESS (до 168ч);
    /// на SAFE максимум равен нулю.
    function _openVaultAtLevel(address owner, address mainKey, address recKey, uint8 level)
        internal
        returns (uint256 vid)
    {
        return _openVaultAtLevel(owner, mainKey, recKey, level, AMOUNT);
    }

    function _openVaultAtLevel(address owner, address mainKey, address recKey, uint8 level, uint256 amount)
        internal
        returns (uint256 vid)
    {
        vm.prank(owner);
        vid = vault.openVault(
            address(ancr),
            AnchorVaultCoin.VaultParams({mainAuthKey: mainKey, recoveryAuthKey: recKey, amount: amount}),
            level
        );
    }

    function _withdrawAll(address owner, uint256 vid, uint256 amount, uint256 signerPk) internal {
        (uint64 nonce, , ) = vault.getVaultAuth(owner, vid);
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(
            signerPk,
            keccak256(abi.encode(WITHDRAW_TYPEHASH, owner, vid, amount, owner, nonce, deadline))
        );
        vm.prank(owner);
        vault.withdrawFromVault(vid, amount, owner, deadline, sig);
    }

    function _initSecureTransfer(
        address owner,
        uint256 vid,
        address to,
        address newMain,
        address newRec,
        uint256 signerPk
    ) internal returns (uint256 tid) {
        (uint64 nonce, , ) = vault.getVaultAuth(owner, vid);
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(
            signerPk,
            keccak256(abi.encode(INIT_SECURE_TYPEHASH, owner, vid, to, newMain, newRec, nonce, deadline))
        );
        vm.prank(owner);
        tid = vault.initSecureTransfer(vid, to, newMain, newRec, deadline, sig);
    }

    function _transferStatus(uint256 tid)
        internal
        view
        returns (address from, address to, uint256 vaultId, uint8 status)
    {
        (from, to, vaultId, , status) = vault.getSecureTransfer(tid);
    }

    function _sign(uint256 pk, bytes32 structHash) internal view returns (bytes memory) {
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", vault.domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }
}
