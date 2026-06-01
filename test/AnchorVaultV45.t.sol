// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, console2} from "forge-std/Test.sol";
import {AnchorVaultV45} from "../src/AnchorVaultV45.sol";
import {MockANCR} from "./mocks/MockANCR.sol";

/**
 * @notice Unit + EIP-712 + инвариант платёжеспособности для AnchorVaultV45.
 *         Перенос ключевых проверок из ganache-набора (test.js/audit.js) на Foundry.
 *         Запуск:  forge test -vv
 */
contract AnchorVaultV45Test is Test {
    AnchorVaultV45 vault;
    MockANCR ancr;

    address creator = address(0xC0);
    address guardian = address(0x6A);
    address payoutWallet = address(0xBEEF01);
    address alice;
    address aliceEmergency = address(0xE1);

    // авторизационные ключи (отдельные от EOA владельца)
    uint256 aMainPk = 0xA11CE0001;
    uint256 aRecPk  = 0xA11CE0002;
    address aMain;
    address aRec;

    bytes32 constant WITHDRAW_TYPEHASH =
        keccak256("Withdraw(address owner,uint256 vaultId,uint256 amount,address to,uint64 nonce,uint256 deadline)");
    bytes32 constant EARLY_CLOSE_TYPEHASH =
        keccak256("EarlyClose(address owner,uint256 vaultId,uint64 nonce,uint256 deadline)");

    function setUp() public {
        alice = address(0xA11CE);
        aMain = vm.addr(aMainPk);
        aRec  = vm.addr(aRecPk);

        vm.prank(creator);
        ancr = new MockANCR(10_000_000 ether);

        vm.prank(creator);
        vault = new AnchorVaultV45(address(ancr), guardian, payoutWallet);

        // раздать Алисе токены
        vm.prank(creator);
        ancr.transfer(alice, 10_000 ether);

        // emergency + апрув
        vm.prank(alice);
        vault.setGlobalEmergency(aliceEmergency);
        vm.prank(alice);
        ancr.approve(address(vault), type(uint256).max);
    }

    function _domainSeparator() internal view returns (bytes32) {
        return vault.domainSeparator();
    }

    function _sign(uint256 pk, bytes32 structHash) internal view returns (bytes memory) {
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _openAlice(uint256 amount, uint8 level) internal returns (uint256 vid) {
        AnchorVaultV45.VaultParams memory p = AnchorVaultV45.VaultParams({
            name: "AliceVault", mainAuthKey: aMain, recoveryAuthKey: aRec, amount: amount
        });
        vm.prank(alice);
        vault.openVault(address(ancr), p, level);
        vid = vault.activeVaultIdByToken(alice, address(ancr));
    }

    // ───────────────────────────────────────────────
    function test_OpenVault_NetAfterFee() public {
        uint256 vid = _openAlice(100 ether, 1);
        (, , uint120 amount, , , , ) = vault.getVaultCore(alice, vid);
        assertEq(uint256(amount), 99.8 ether); // 100 - 0.2%
    }

    function test_OpenVault_RevertIfAuthKeyEqualsOwner() public {
        AnchorVaultV45.VaultParams memory p = AnchorVaultV45.VaultParams({
            name: "X", mainAuthKey: alice, recoveryAuthKey: aRec, amount: 100 ether
        });
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.BadAuthKey.selector);
        vault.openVault(address(ancr), p, 1);
    }

    function test_Withdraw_ValidSignature() public {
        uint256 vid = _openAlice(100 ether, 1);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes32 sh = keccak256(abi.encode(WITHDRAW_TYPEHASH, alice, vid, uint256(20 ether), alice, nonce, dl));
        bytes memory sig = _sign(aMainPk, sh);

        uint256 balBefore = ancr.balanceOf(alice);
        vm.prank(alice);
        vault.withdrawFromVault(vid, 20 ether, alice, dl, sig);
        assertEq(ancr.balanceOf(alice) - balBefore, 19.9 ether); // 20 - 0.5%
    }

    function test_Withdraw_RejectsWrongKey() public {
        uint256 vid = _openAlice(100 ether, 1);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes32 sh = keccak256(abi.encode(WITHDRAW_TYPEHASH, alice, vid, uint256(20 ether), alice, nonce, dl));
        bytes memory sig = _sign(aRecPk, sh); // recovery-ключ вместо main

        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.BadSignature.selector);
        vault.withdrawFromVault(vid, 20 ether, alice, dl, sig);
    }

    function test_Withdraw_ReplayBlocked() public {
        uint256 vid = _openAlice(100 ether, 1);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes32 sh = keccak256(abi.encode(WITHDRAW_TYPEHASH, alice, vid, uint256(20 ether), alice, nonce, dl));
        bytes memory sig = _sign(aMainPk, sh);

        vm.prank(alice);
        vault.withdrawFromVault(vid, 20 ether, alice, dl, sig);
        // повтор — nonce уже сдвинут
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.BadSignature.selector);
        vault.withdrawFromVault(vid, 20 ether, alice, dl, sig);
    }

    function test_Withdraw_AmountTamper() public {
        uint256 vid = _openAlice(100 ether, 1);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes32 sh = keccak256(abi.encode(WITHDRAW_TYPEHASH, alice, vid, uint256(10 ether), alice, nonce, dl));
        bytes memory sig = _sign(aMainPk, sh);
        // подпись на 10, вызов на 50
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.BadSignature.selector);
        vault.withdrawFromVault(vid, 50 ether, alice, dl, sig);
    }

    function test_Timelock_BlocksWithdraw() public {
        // Foundry по умолчанию block.timestamp=1; ставим реалистичное время,
        // чтобы depositedAt и арифметика таймлока были осмысленными.
        vm.warp(1_700_000_000);

        uint256 vid = _openAlice(100 ether, 2); // FORTRESS (max timelock 168ч)
        // sanity: сейф существует и активен
        (uint64 id,,,, uint8 status,,) = vault.getVaultCore(alice, vid);
        assertEq(uint256(id), vid);
        assertEq(uint256(status), 0);

        uint256 dl = block.timestamp + 1 hours;

        // ставим таймлок 48ч подписью main
        bytes32 TL = keccak256("SetTimelock(address owner,uint256 vaultId,uint256 hoursVal,uint64 nonce,uint256 deadline)");
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        bytes32 sh = keccak256(abi.encode(TL, alice, vid, uint256(48), nonce, dl));
        bytes memory tlSig = _sign(aMainPk, sh);
        vm.prank(alice);
        vault.setTimelock(vid, 48, dl, tlSig);

        // таймлок записан
        (, , uint16 tlHours) = vault.getVaultTimings(alice, vid);
        assertEq(uint256(tlHours), 48);

        // попытка вывода до истечения 48ч — должна отлететь VaultTimelocked
        (uint64 n2,,) = vault.getVaultAuth(alice, vid);
        bytes32 wsh = keccak256(abi.encode(WITHDRAW_TYPEHASH, alice, vid, uint256(10 ether), alice, n2, dl));
        bytes memory wsig = _sign(aMainPk, wsh); // строим ДО expectRevert
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.VaultTimelocked.selector);
        vault.withdrawFromVault(vid, 10 ether, alice, dl, wsig);
    }

    function test_Panic_NoSignature_ToEmergency() public {
        uint256 vid = _openAlice(100 ether, 1);
        uint256 emBefore = ancr.balanceOf(aliceEmergency);
        vm.prank(alice);
        vault.panicWithdraw(vid);
        // 99.8 net, panic 20% -> 79.84
        assertEq(ancr.balanceOf(aliceEmergency) - emBefore, 79.84 ether);
    }

    function test_EarlyClose_RejectsMainKey() public {
        uint256 vid = _openAlice(100 ether, 1);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes32 sh = keccak256(abi.encode(EARLY_CLOSE_TYPEHASH, alice, vid, nonce, dl));
        // ВАЖНО: подпись строим ДО expectRevert — _sign использует vm.sign (cheatcode),
        // иначе он "съедает" expectRevert и тест ложно падает.
        bytes memory badSig = _sign(aMainPk, sh); // main-ключ на recovery-операцию
        // earlyClose требует recovery — main должен отлететь
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.BadSignature.selector);
        vault.earlyClose(vid, dl, badSig);
    }

    function test_GlobalEmergency_ChangeNeedsTimelock() public {
        vm.prank(alice);
        vault.proposeGlobalEmergencyChange(address(0xBEEF));
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.EmergencyTimelockNotExpired.selector);
        vault.confirmGlobalEmergencyChange();
        // старый ещё активен
        assertEq(vault.globalEmergency(alice), aliceEmergency);
        // через 7 дней — ок
        vm.warp(block.timestamp + 7 days + 1);
        vm.prank(alice);
        vault.confirmGlobalEmergencyChange();
        assertEq(vault.globalEmergency(alice), address(0xBEEF));
    }

    function test_Roles_UserCannotAdmin() public {
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.NotCreator.selector);
        vault.addSupportedToken(address(ancr));

        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.NotGuardian.selector);
        vault.emergencyPause();
    }

    function test_Distribution_RevertIfNoBalance() public {
        // на контракте нет 1 млн → отбой (защита инварианта)
        vm.prank(creator);
        vm.expectRevert(AnchorVaultV45.InsufficientBalanceForDistribution.selector);
        vault.initializeDistribution();
    }

    function test_Rescue_OnlyNonSupportedByCreator() public {
        MockANCR stray = new MockANCR(1_000_000 ether);
        stray.transfer(address(vault), 500 ether);
        // поддерживаемый ANCR спасать нельзя
        vm.prank(creator);
        vm.expectRevert(AnchorVaultV45.TokenNotSupported.selector);
        vault.rescueERC20(address(ancr), creator, 1 ether);
        // не-creator нельзя
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.NotCreator.selector);
        vault.rescueERC20(address(stray), alice, 1 ether);
        // чужой токен — creator спасает
        uint256 before = stray.balanceOf(creator);
        vm.prank(creator);
        vault.rescueERC20(address(stray), creator, 500 ether);
        assertEq(stray.balanceOf(creator) - before, 500 ether);
    }

    function test_Distribution_RevertIfNotCreator() public {
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.NotCreator.selector);
        vault.initializeDistribution();
    }

    function test_Distribution_HappyPathAndInvariant() public {
        // переводим 1 млн на контракт
        vm.prank(creator);
        ancr.transfer(address(vault), 1_000_000 ether);

        uint256 payoutBefore = ancr.balanceOf(payoutWallet);
        vm.prank(creator);
        vault.initializeDistribution();

        assertEq(ancr.balanceOf(payoutWallet) - payoutBefore, 200_000 ether);
        assertEq(vault.rewardPool(address(ancr)), 500_000 ether);
        assertEq(vault.strategicReserve(address(ancr)), 300_000 ether);
        assertEq(ancr.balanceOf(address(vault)), 800_000 ether);
        assertTrue(vault.distributionInitialized());

        // повторно — отбой
        vm.prank(creator);
        vm.expectRevert(AnchorVaultV45.AlreadyInitialized.selector);
        vault.initializeDistribution();

        // инвариант
        uint256 bal = ancr.balanceOf(address(vault));
        uint256 liab = vault.lockedPrincipal(address(ancr)) + vault.creatorFees(address(ancr))
            + vault.strategicReserve(address(ancr)) + vault.rewardPool(address(ancr));
        assertGe(bal, liab);
    }

    // ─── ИНВАРИАНТ ПЛАТЁЖЕСПОСОБНОСТИ ───────────────
    // Баланс контракта по ANCR всегда >= суммы всех учётных обязательств.
    function invariant_Solvency() public view {
        uint256 bal = ancr.balanceOf(address(vault));
        uint256 liabilities = vault.lockedPrincipal(address(ancr))
            + vault.creatorFees(address(ancr))
            + vault.strategicReserve(address(ancr))
            + vault.rewardPool(address(ancr));
        assertGe(bal, liabilities);
    }
}
