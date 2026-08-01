// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {AnchorVaultCoin} from "../src/AnchorVaultCoin.sol";
import {MockANCR} from "./mocks/MockANCR.sol";

/// @title Тесты бизнес-логики AnchorVaultCoin
/// @notice Проверяют замысел, а не только код: изоляция средств от
///         скомпрометированного кошелька, 2FA (EOA + ключ), невозможность
///         тронуть чужой сейф, обход voluntary lock аварийными выходами,
///         фактические ставки комиссий.
contract AnchorVaultBusinessLogicTest is Test {
    AnchorVaultCoin internal vault;
    MockANCR internal ancr;

    // роли деплоя (адреса задаются в setUp)
    address internal guardian;
    address internal payout;

    // ── EIP-712 typehashes (копия из контракта) ──
    bytes32 constant WITHDRAW_TH =
        keccak256("Withdraw(address owner,uint256 vaultId,uint256 amount,address to,uint64 nonce,uint256 deadline)");
    bytes32 constant SET_VLOCK_TH =
        keccak256("SetVoluntaryLock(address owner,uint256 vaultId,uint256 lockUntil,uint64 nonce,uint256 deadline)");

    function setUp() public {
        guardian = vm.addr(0xA1);
        payout   = vm.addr(0xA2);
        ancr = new MockANCR(100_000_000 ether);
        vault = new AnchorVaultCoin(address(ancr), guardian, payout);
    }

    // ───────────────────────── helpers ─────────────────────────

    function _digest(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", vault.domainSeparator(), structHash));
    }

    function _sign(uint256 pk, bytes32 structHash) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, _digest(structHash));
        return abi.encodePacked(r, s, v);
    }

    function _nonce(address owner, uint256 vid) internal view returns (uint64 n) {
        (n,,) = vault.getVaultAuth(owner, vid);
    }

    function _amount(address owner, uint256 vid) internal view returns (uint120 a) {
        (,, a,,) = vault.getVaultCore(owner, vid);
    }

    /// Открывает сейф уровня SAFE (timelock=0) на токене ANCR.
    function _openVault(
        uint256 ownerPk, address mainKey, address recKey, address emergency, uint256 amount
    ) internal returns (address owner, uint256 vid) {
        owner = vm.addr(ownerPk);
        ancr.transfer(owner, amount);                          // фондируем владельца

        vm.startPrank(owner);
        ancr.approve(address(vault), amount);
        vault.setGlobalEmergency(emergency);
        AnchorVaultCoin.VaultParams memory p = AnchorVaultCoin.VaultParams({
            mainAuthKey: mainKey,
            recoveryAuthKey: recKey,
            amount: amount
        });
        vid = vault.openVault(address(ancr), p, 0);            // level SAFE
        vm.stopPrank();
    }

    function _withdrawStruct(
        address owner, uint256 vid, uint256 amt, address to, uint64 nonce, uint256 deadline
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(WITHDRAW_TH, owner, vid, amt, to, nonce, deadline));
    }

    // ═══════════════════════════════════════════════════════════
    // 1. КОРОННЫЙ ТЕСТ: компрометация кошелька не даёт кражи.
    //    Вор управляет EOA владельца (prank), но ключей сейфа нет.
    //    Паника уводит средства на globalEmergency ВЛАДЕЛЬЦА, не вору.
    // ═══════════════════════════════════════════════════════════
    function test_Panic_SendsToOwnerEmergency_AttackerGetsNothing() public {
        address emergency = vm.addr(0xE1);
        address attacker  = vm.addr(0xBAD);
        (address owner, uint256 vid) =
            _openVault(0x01, vm.addr(0x11), vm.addr(0x12), emergency, 1000 ether);

        uint120 net = _amount(owner, vid);                    // принципал после open-fee
        uint256 expectedPayout = uint256(net) * 8000 / 10000; // 80% (паника 20%)

        uint256 emgBefore = ancr.balanceOf(emergency);
        uint256 atkBefore = ancr.balanceOf(attacker);

        // Вор завладел кошельком владельца -> действует как owner.
        // panicWithdraw НЕ имеет параметра `to` -> вор не может выбрать получателя.
        vm.prank(owner);
        vault.panicWithdraw(vid);

        // Деньги ушли на аварийный адрес ВЛАДЕЛЬЦА.
        assertEq(ancr.balanceOf(emergency) - emgBefore, expectedPayout, "payout must go to owner emergency");
        // Вору не досталось НИЧЕГО.
        assertEq(ancr.balanceOf(attacker), atkBefore, "attacker must receive nothing");
        // Сейф закрыт.
        (,, uint120 amtAfter, uint8 status,) = vault.getVaultCore(owner, vid);
        assertEq(amtAfter, 0, "vault emptied");
        assertEq(status, 2, "vault closed");
    }

    // ═══════════════════════════════════════════════════════════
    // 2. Нельзя паниковать ЧУЖОЙ сейф (модель vaults[msg.sender]).
    // ═══════════════════════════════════════════════════════════
    function test_CannotPanic_OthersVault() public {
        (, uint256 vid) =
            _openVault(0x02, vm.addr(0x21), vm.addr(0x22), vm.addr(0xE2), 1000 ether);

        address attacker = vm.addr(0xBAD2);
        // attacker зовёт panic с чужим vid -> vaults[attacker][vid].id == 0 -> BadVaultId
        vm.prank(attacker);
        vm.expectRevert(AnchorVaultCoin.BadVaultId.selector);
        vault.panicWithdraw(vid);
    }

    // ═══════════════════════════════════════════════════════════
    // 3. 2FA: вывод требует ПОДПИСЬ main-ключа. Чужой ключ -> revert.
    // ═══════════════════════════════════════════════════════════
    function test_Withdraw_RequiresMainKey_WrongSignerReverts() public {
        uint256 mainPk = 0x31;
        uint256 recPk  = 0x32;
        (address owner, uint256 vid) =
            _openVault(0x03, vm.addr(mainPk), vm.addr(recPk), vm.addr(0xE3), 1000 ether);

        uint120 amt = _amount(owner, vid);
        address to = vm.addr(0xDDD);
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 sh = _withdrawStruct(owner, vid, amt, to, _nonce(owner, vid), deadline);

        // Подпись RECOVERY-ключом (неверный для withdraw) -> BadSignature.
        bytes memory wrongSig = _sign(recPk, sh);
        vm.prank(owner);
        vm.expectRevert(AnchorVaultCoin.BadSignature.selector);
        vault.withdrawFromVault(vid, amt, to, deadline, wrongSig);

        // Подпись MAIN-ключом -> успех.
        bytes memory goodSig = _sign(mainPk, sh);
        vm.prank(owner);
        vault.withdrawFromVault(vid, amt, to, deadline, goodSig);
        assertGt(ancr.balanceOf(to), 0, "withdraw with main key must succeed");
    }

    // ═══════════════════════════════════════════════════════════
    // 4. Кошелёк БЕЗ ключа не может вывести на произвольный адрес.
    //    Вор управляет EOA (prank owner), но подписывает СВОИМ ключом.
    // ═══════════════════════════════════════════════════════════
    function test_WalletCompromise_CannotWithdrawToArbitrary() public {
        (address owner, uint256 vid) =
            _openVault(0x04, vm.addr(0x41), vm.addr(0x42), vm.addr(0xE4), 1000 ether);

        uint256 attackerPk = 0xBAD4;
        address attacker = vm.addr(attackerPk);
        uint120 amt = _amount(owner, vid);
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 sh = _withdrawStruct(owner, vid, amt, attacker, _nonce(owner, vid), deadline);

        // Вор подписывает своим ключом -> не совпадает с mainAuthKey -> BadSignature.
        bytes memory atkSig = _sign(attackerPk, sh);
        vm.prank(owner);
        vm.expectRevert(AnchorVaultCoin.BadSignature.selector);
        vault.withdrawFromVault(vid, amt, attacker, deadline, atkSig);
    }

    // ═══════════════════════════════════════════════════════════
    // 5. Voluntary lock блокирует обычный вывод, но паника его ОБХОДИТ (T-2).
    // ═══════════════════════════════════════════════════════════
    function test_VoluntaryLock_BlocksWithdraw_ButPanicBypasses() public {
        uint256 mainPk = 0x51;
        address emergency = vm.addr(0xE5);
        (address owner, uint256 vid) =
            _openVault(0x05, vm.addr(mainPk), vm.addr(0x52), emergency, 1000 ether);

        // Ставим добровольную блокировку на будущее.
        uint256 lockUntil = block.timestamp + 30 days;
        uint256 dl1 = block.timestamp + 1 hours;
        bytes32 lockSh =
            keccak256(abi.encode(SET_VLOCK_TH, owner, vid, lockUntil, _nonce(owner, vid), dl1));
        bytes memory lockSig = _sign(mainPk, lockSh);
        vm.prank(owner);
        vault.setVoluntaryLock(vid, lockUntil, dl1, lockSig);

        // Обычный вывод (с валидной main-подписью) -> заблокирован Locked.
        uint120 amt = _amount(owner, vid);
        address to = vm.addr(0xDDD5);
        uint256 dl2 = block.timestamp + 1 hours;
        bytes32 wSh = _withdrawStruct(owner, vid, amt, to, _nonce(owner, vid), dl2);
        bytes memory wSig = _sign(mainPk, wSh);
        vm.prank(owner);
        vm.expectRevert(AnchorVaultCoin.Locked.selector);
        vault.withdrawFromVault(vid, amt, to, dl2, wSig);

        // Паника (без подписи) -> проходит несмотря на блокировку.
        uint256 emgBefore = ancr.balanceOf(emergency);
        vm.prank(owner);
        vault.panicWithdraw(vid);
        assertGt(ancr.balanceOf(emergency) - emgBefore, 0, "panic must bypass voluntary lock");
    }

    // ═══════════════════════════════════════════════════════════
    // 6. Фактические ставки: паника = 20%, обычный вывод = 0.5%.
    // ═══════════════════════════════════════════════════════════
    function test_FeeRates_Panic20_Withdraw0p5() public {
        // -- паника 20% --
        {
            address emergency = vm.addr(0xE6);
            (address owner, uint256 vid) =
                _openVault(0x06, vm.addr(0x61), vm.addr(0x62), emergency, 1000 ether);
            uint120 net = _amount(owner, vid);
            uint256 before = ancr.balanceOf(emergency);
            vm.prank(owner);
            vault.panicWithdraw(vid);
            uint256 got = ancr.balanceOf(emergency) - before;
            assertEq(got, uint256(net) * 8000 / 10000, "panic must pay out exactly 80%");
        }
        // -- обычный вывод 0.5% --
        {
            uint256 mainPk = 0x71;
            (address owner, uint256 vid) =
                _openVault(0x07, vm.addr(mainPk), vm.addr(0x72), vm.addr(0xE7), 1000 ether);
            uint120 amt = _amount(owner, vid);
            address to = vm.addr(0xDDD7);
            uint256 dl = block.timestamp + 1 hours;
            bytes32 sh = _withdrawStruct(owner, vid, amt, to, _nonce(owner, vid), dl);
            bytes memory sig = _sign(mainPk, sh);
            vm.prank(owner);
            vault.withdrawFromVault(vid, amt, to, dl, sig);
            assertEq(ancr.balanceOf(to), uint256(amt) * 9950 / 10000, "withdraw must pay out exactly 99.5%");
        }
    }
}
