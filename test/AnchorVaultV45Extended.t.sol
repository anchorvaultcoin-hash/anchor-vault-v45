// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, console2} from "forge-std/Test.sol";
import {AnchorVaultCoin} from "../src/AnchorVaultCoin.sol";
import {MockANCR} from "./mocks/MockANCR.sol";
import {MaliciousCallbackToken} from "./mocks/MaliciousCallbackToken.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title AnchorVaultCoin Extended Tests
 * @notice Добавленные категории: Fuzz, DoS/Gas, EIP-712 malleability,
 *         SecureTransfer edge, Multi-vault, Invariant, Stress.
 */
contract AnchorVaultCoinExtendedTest is Test {
    AnchorVaultCoin vault;
    MockANCR ancr;

    address creator = address(0xC0);
    address guardian = address(0x6A);
    address payoutWallet = address(0xBEEF01);
    address alice;
    address aliceEmergency = address(0xE1);
    uint256 alicePk = 0xA11CE0000;
    uint256 bobPk   = 0xB0B0000;
    address bob;
    address bobEmergency = address(0xB0BE);

    uint256 aMainPk = 0xA11CE0001;
    uint256 aRecPk  = 0xA11CE0002;
    address aMain;
    address aRec;

    uint256 bMainPk = 0xB0B0001;
    uint256 bRecPk  = 0xB0B0002;
    address bMain;
    address bRec;

    bytes32 constant ACCEPT_TRANSFER_TYPEHASH =
        keccak256("AcceptVaultTransfer(address from,uint256 vaultId,address to,address newMainKey,address newRecoveryKey,uint256 deadline)");
    bytes32 constant WITHDRAW_TYPEHASH =
        keccak256("Withdraw(address owner,uint256 vaultId,uint256 amount,address to,uint64 nonce,uint256 deadline)");
    bytes32 constant EARLY_CLOSE_TYPEHASH =
        keccak256("EarlyClose(address owner,uint256 vaultId,uint64 nonce,uint256 deadline)");
    bytes32 constant RECOVER_TYPEHASH =
        keccak256("RecoverToSafe(address owner,uint256 vaultId,uint64 nonce,uint256 deadline)");
    bytes32 constant EMERGENCY_ANY_TYPEHASH =
        keccak256("EmergencyWithdraw(address owner,uint256 vaultId,address to,uint64 nonce,uint256 deadline)");
    bytes32 constant TRANSFER_TYPEHASH =
        keccak256("TransferVault(address owner,uint256 vaultId,address to,address newMainKey,address newRecoveryKey,uint64 nonce,uint256 deadline)");
    bytes32 constant INIT_SECURE_TYPEHASH =
        keccak256("InitSecureTransfer(address owner,uint256 vaultId,address to,address newMainKey,address newRecoveryKey,uint64 nonce,uint256 deadline)");
    bytes32 constant SET_TIMELOCK_TYPEHASH =
        keccak256("SetTimelock(address owner,uint256 vaultId,uint256 hoursVal,uint64 nonce,uint256 deadline)");
    bytes32 constant SET_VOLUNTARY_LOCK_TYPEHASH =
        keccak256("SetVoluntaryLock(address owner,uint256 vaultId,uint256 lockUntil,uint64 nonce,uint256 deadline)");
    bytes32 constant ROTATE_KEYS_TYPEHASH =
        keccak256("RotateAuthKeys(address owner,uint256 vaultId,address newMainKey,address newRecoveryKey,uint64 nonce,uint256 deadline)");

    function setUp() public {
        alice = vm.addr(alicePk);
        bob = vm.addr(bobPk);
        aMain = vm.addr(aMainPk);
        aRec  = vm.addr(aRecPk);
        bMain = vm.addr(bMainPk);
        bRec  = vm.addr(bRecPk);

        vm.prank(creator);
        ancr = new MockANCR(10_000_000 ether);

        vm.prank(creator);
        vault = new AnchorVaultCoin(address(ancr), guardian, payoutWallet);

        vm.prank(creator);
        ancr.transfer(alice, 100_000 ether);
        vm.prank(creator);
        ancr.transfer(bob, 100_000 ether);

        vm.prank(alice);
        ancr.approve(address(vault), type(uint256).max);
        vm.prank(bob);
        ancr.approve(address(vault), type(uint256).max);

        vm.prank(alice);
        vault.setGlobalEmergency(aliceEmergency);
        vm.prank(bob);
        vault.setGlobalEmergency(bobEmergency);
    }

    // ─── HELPERS ───────────────────────────────────────────────

    function _domainSeparator() internal view returns (bytes32) {
        return vault.domainSeparator();
    }

    function _sign(uint256 pk, bytes32 structHash) internal view returns (bytes memory) {
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @dev Создаёт malleable подпись (invert s, flip v)
    function _makeMalleable(bytes memory sig) internal pure returns (bytes memory) {
        require(sig.length == 65, "bad sig len");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }
        // secp256k1 half-curve order
        bytes32 n = bytes32(0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0);
        bytes32 sNew;
        unchecked {
            sNew = bytes32(uint256(n) - uint256(s));
        }
        uint8 vNew = v ^ 1;
        return abi.encodePacked(r, sNew, vNew);
    }

    function _signWithdraw(address owner, uint256 vid, uint256 amount, address to, uint64 nonce, uint256 deadline, uint256 pk)
        internal view returns (bytes memory)
    {
        bytes32 sh = keccak256(abi.encode(WITHDRAW_TYPEHASH, owner, vid, amount, to, nonce, deadline));
        return _sign(pk, sh);
    }

    function _signTransfer(address owner, uint256 vid, address to, address newMain, address newRec, uint64 nonce, uint256 deadline, uint256 pk)
        internal view returns (bytes memory)
    {
        bytes32 sh = keccak256(abi.encode(TRANSFER_TYPEHASH, owner, vid, to, newMain, newRec, nonce, deadline));
        return _sign(pk, sh);
    }

    function _signEarlyClose(address owner, uint256 vid, uint64 nonce, uint256 deadline, uint256 pk)
        internal view returns (bytes memory)
    {
        bytes32 sh = keccak256(abi.encode(EARLY_CLOSE_TYPEHASH, owner, vid, nonce, deadline));
        return _sign(pk, sh);
    }

    function _signSetTimelock(address owner, uint256 vid, uint256 hoursVal, uint64 nonce, uint256 deadline, uint256 pk)
        internal view returns (bytes memory)
    {
        bytes32 sh = keccak256(abi.encode(SET_TIMELOCK_TYPEHASH, owner, vid, hoursVal, nonce, deadline));
        return _sign(pk, sh);
    }

    function _signSetVoluntaryLock(address owner, uint256 vid, uint256 lockUntil, uint64 nonce, uint256 deadline, uint256 pk)
        internal view returns (bytes memory)
    {
        bytes32 sh = keccak256(abi.encode(SET_VOLUNTARY_LOCK_TYPEHASH, owner, vid, lockUntil, nonce, deadline));
        return _sign(pk, sh);
    }

    function _signRotateKeys(address owner, uint256 vid, address newMain, address newRec, uint64 nonce, uint256 deadline, uint256 pk)
        internal view returns (bytes memory)
    {
        bytes32 sh = keccak256(abi.encode(ROTATE_KEYS_TYPEHASH, owner, vid, newMain, newRec, nonce, deadline));
        return _sign(pk, sh);
    }

    function _signRecover(address owner, uint256 vid, uint64 nonce, uint256 deadline, uint256 pk)
        internal view returns (bytes memory)
    {
        bytes32 sh = keccak256(abi.encode(RECOVER_TYPEHASH, owner, vid, nonce, deadline));
        return _sign(pk, sh);
    }

    function _signEmergencyAny(address owner, uint256 vid, address to, uint64 nonce, uint256 deadline, uint256 pk)
        internal view returns (bytes memory)
    {
        bytes32 sh = keccak256(abi.encode(EMERGENCY_ANY_TYPEHASH, owner, vid, to, nonce, deadline));
        return _sign(pk, sh);
    }

    function _signInitSecure(address owner, uint256 vid, address to, address newMain, address newRec, uint64 nonce, uint256 deadline, uint256 pk)
        internal view returns (bytes memory)
    {
        bytes32 sh = keccak256(abi.encode(INIT_SECURE_TYPEHASH, owner, vid, to, newMain, newRec, nonce, deadline));
        return _sign(pk, sh);
    }

    function _openAliceVault(uint256 amount, uint8 level) internal returns (uint256 vid) {
        AnchorVaultCoin.VaultParams memory p = AnchorVaultCoin.VaultParams({
            mainAuthKey: aMain, recoveryAuthKey: aRec, amount: amount
        });
        vm.prank(alice);
        vault.openVault(address(ancr), p, level);
        vid = vault.activeVaultIdByToken(alice, address(ancr));
    }

    function _openBobVault(uint256 amount, uint8 level) internal returns (uint256 vid) {
        AnchorVaultCoin.VaultParams memory p = AnchorVaultCoin.VaultParams({
            mainAuthKey: bMain, recoveryAuthKey: bRec, amount: amount
        });
        vm.prank(bob);
        vault.openVault(address(ancr), p, level);
        vid = vault.activeVaultIdByToken(bob, address(ancr));
    }

    function _openVault(address user, uint256 pkMain, uint256 pkRec, uint256 amount, uint8 level, address emergency) internal returns (uint256 vid) {
        address mainKey = vm.addr(pkMain);
        address recKey = vm.addr(pkRec);
        vm.prank(user);
        vault.setGlobalEmergency(emergency);
        AnchorVaultCoin.VaultParams memory p = AnchorVaultCoin.VaultParams({
            mainAuthKey: mainKey, recoveryAuthKey: recKey, amount: amount
        });
        vm.prank(user);
        vault.openVault(address(ancr), p, level);
        vid = vault.activeVaultIdByToken(user, address(ancr));
    }

    function _tol(uint256 val) internal pure returns (uint256) { return val / 100; }

    function _approxEq(uint256 a, uint256 b, uint256 tol) internal pure {
        if (a > b) assertLe(a - b, tol);
        else assertLe(b - a, tol);
    }

    // ═══════════════════════════════════════════════════════════
    // РАЗДЕЛ 1: FUZZ ТЕСТЫ (20 шт)
    // ═══════════════════════════════════════════════════════════

    /// @notice Открытие сейфа с разными суммами
    function testFuzz_OpenVault_DifferentAmounts(uint96 amount) public {
        amount = uint96(bound(uint256(amount), 0.1 ether, 50_000 ether));
        AnchorVaultCoin.VaultParams memory p = AnchorVaultCoin.VaultParams({
            mainAuthKey: aMain, recoveryAuthKey: aRec, amount: amount
        });
        vm.prank(alice);
        vault.openVault(address(ancr), p, 0);
        uint256 vid = vault.activeVaultIdByToken(alice, address(ancr));
        assertTrue(vid > 0);
    }

    /// @notice Депозит разных сумм
    function testFuzz_Deposit_DifferentAmounts(uint96 amount) public {
        amount = uint96(bound(uint256(amount), 0.1 ether, 50_000 ether));
        uint256 vid = _openAliceVault(1000 ether, 0);
        vm.prank(alice);
        vault.depositToVault(vid, amount);
        (,, uint120 vaultAmount,, ) = vault.getVaultCore(alice, vid);
        assertTrue(uint256(vaultAmount) > 0);
    }

    /// @notice Вывод разных процентов
    function testFuzz_Withdraw_Percentages(uint64 pct) public {
        vm.assume(pct > 0 && pct <= 100);
        uint256 vid = _openAliceVault(1000 ether, 0);
        (,, uint120 vAmount,, ) = vault.getVaultCore(alice, vid);
        uint256 wd = (uint256(vAmount) * pct) / 100;
        vm.assume(wd > 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signWithdraw(alice, vid, wd, alice, nonce, dl, aMainPk);
        vm.prank(alice);
        vault.withdrawFromVault(vid, wd, alice, dl, sig);
    }

    /// @notice Voluntary lock с разной длительностью
    function testFuzz_VoluntaryLock_ValidDuration(uint32 daysVal) public {
        vm.assume(daysVal > 0 && daysVal <= 365 * 5);
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 lockUntil = block.timestamp + uint256(daysVal) * 1 days;
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signSetVoluntaryLock(alice, vid, lockUntil, nonce, dl, aMainPk);
        vm.prank(alice);
        vault.setVoluntaryLock(vid, lockUntil, dl, sig);
        (, uint48 vLock,) = vault.getVaultTimings(alice, vid);
        assertEq(vLock, lockUntil);
    }

    /// @notice Ротация ключей с разными адресами
    function testFuzz_RotateKeys_DifferentAddresses(address newMain, address newRec) public {
        vm.assume(newMain != address(0) && newRec != address(0));
        vm.assume(newMain != newRec);
        vm.assume(newMain != alice && newRec != alice);
        vm.assume(newMain != address(vault) && newRec != address(vault));
        vm.assume(newMain.code.length == 0 && newRec.code.length == 0);

        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signRotateKeys(alice, vid, newMain, newRec, nonce, dl, aRecPk);

        vm.prank(alice);
        vault.rotateAuthKeys(vid, newMain, newRec, dl, sig);

        (, address mainAfter, address recAfter) = vault.getVaultAuth(alice, vid);
        assertEq(mainAfter, newMain);
        assertEq(recAfter, newRec);
    }

    /// @notice Timelock с разными значениями (в пределах уровня)
    function testFuzz_Timelock_VAULT_Level(uint16 hoursVal) public {
        vm.assume(hoursVal <= 72);
        uint256 vid = _openAliceVault(100 ether, 1);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signSetTimelock(alice, vid, hoursVal, nonce, dl, aMainPk);

        vm.prank(alice);
        vault.setTimelock(vid, hoursVal, dl, sig);

        (, , uint16 tl) = vault.getVaultTimings(alice, vid);
        assertEq(tl, hoursVal);
    }

    /// @notice Multiple deposits разные суммы
    function testFuzz_MultipleDeposits(uint64 d1, uint64 d2, uint64 d3) public {
        d1 = uint64(bound(uint256(d1), 0.1 ether, 5 ether));
        d2 = uint64(bound(uint256(d2), 0.1 ether, 5 ether));
        d3 = uint64(bound(uint256(d3), 0.1 ether, 5 ether));
        uint256 vid = _openAliceVault(1000 ether, 0);
        vm.prank(alice); vault.depositToVault(vid, d1);
        vm.prank(alice); vault.depositToVault(vid, d2);
        vm.prank(alice); vault.depositToVault(vid, d3);
        uint256 lp = vault.lockedPrincipal(address(ancr));
        // ANCV1-4: открытие SAFE теперь 50 bps → 995 ether от базового депозита.
        assertTrue(lp > 995 ether);
    }

    /// @notice GlobalEmergency с разными адресами
    function testFuzz_GlobalEmergency_SetFirstTime(address em) public {
        vm.assume(em != address(0) && em != address(vault));
        vm.assume(em != address(ancr));
        vm.assume(em.code.length == 0); // emergency должен быть EOA (контракт режет адреса с кодом)
        address charlie = address(0xCAFE1111);
        vm.prank(charlie);
        vault.setGlobalEmergency(em);
        assertEq(vault.globalEmergency(charlie), em);
    }

    /// @notice Creator fees withdraw проверка
    function testFuzz_CreatorWithdraw_Amounts(uint256 amount) public {
        uint256 vid = _openAliceVault(1000 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signEarlyClose(alice, vid, nonce, dl, aRecPk);
        vm.prank(alice);
        vault.earlyClose(vid, dl, sig);

        uint256 cf = vault.creatorFees(address(ancr));
        vm.assume(amount > 0 && amount <= cf);

        vm.prank(creator);
        vault.requestCreatorWithdraw(address(ancr), creator, amount);
        vm.warp(block.timestamp + 8 days);
        vm.prank(creator);
        vault.withdrawCreatorFees(address(ancr));

        _approxEq(vault.creatorFees(address(ancr)), cf - amount, _tol(cf));
    }

    /// @notice Secure transfer с разными суммами
    function testFuzz_SecureTransfer_DifferentAmounts(uint96 amount) public {
        amount = uint96(bound(uint256(amount), 0.1 ether, 50_000 ether));
        uint256 vid = _openAliceVault(uint256(amount), 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signInitSecure(alice, vid, bob, aMain, aRec, nonce, dl, aMainPk);
        vm.prank(alice);
        uint256 tid = vault.initSecureTransfer(vid, bob, aMain, aRec, dl, sig);
        vm.prank(bob);
        vault.confirmSecureTransfer(tid);
        assertTrue(vault.activeVaultIdByToken(bob, address(ancr)) > 0);
    }

    /// @notice Transfer vault с разными ключами
    function testFuzz_TransferVault_DifferentKeys(address mk, address rk) public {
        vm.assume(mk != address(0) && rk != address(0));
        vm.assume(mk != rk && mk != bob && rk != bob);
        vm.assume(mk != address(vault) && rk != address(vault));
        vm.assume(mk.code.length == 0 && rk.code.length == 0);

        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signTransfer(alice, vid, bob, mk, rk, nonce, dl, aMainPk);
        bytes memory accSig = _signAccept(alice, vid, bob, mk, rk, dl, bobPk);
        vm.prank(alice);
        vault.transferVault(vid, bob, mk, rk, dl, sig, accSig);

        (, address m, address r) = vault.getVaultAuth(bob, vault.activeVaultIdByToken(bob, address(ancr)));
        assertEq(m, mk);
        assertEq(r, rk);
    }

    // ═══════════════════════════════════════════════════════════
    // РАЗДЕЛ 2: EIP-712 MALLEABILITY (6 тестов)
    // ═══════════════════════════════════════════════════════════

    function test_EIP712_MalleableWithdraw_Reverts() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signWithdraw(alice, vid, 10 ether, alice, nonce, dl, aMainPk);
        bytes memory mal = _makeMalleable(sig);
        vm.prank(alice);
        vm.expectRevert(bytes4(keccak256("ECDSAInvalidSignature()")));
        vault.withdrawFromVault(vid, 10 ether, alice, dl, mal);
    }

    function test_EIP712_MalleableSetTimelock_Reverts() public {
        uint256 vid = _openAliceVault(100 ether, 1);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signSetTimelock(alice, vid, 24, nonce, dl, aMainPk);
        bytes memory mal = _makeMalleable(sig);
        vm.prank(alice);
        vm.expectRevert(bytes4(keccak256("ECDSAInvalidSignature()")));
        vault.setTimelock(vid, 24, dl, mal);
    }

    function test_EIP712_MalleableEarlyClose_Reverts() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signEarlyClose(alice, vid, nonce, dl, aRecPk);
        bytes memory mal = _makeMalleable(sig);
        vm.prank(alice);
        vm.expectRevert(bytes4(keccak256("ECDSAInvalidSignature()")));
        vault.earlyClose(vid, dl, mal);
    }

    function test_EIP712_MalleableTransfer_Reverts() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signTransfer(alice, vid, bob, aMain, aRec, nonce, dl, aMainPk);
        bytes memory mal = _makeMalleable(sig);
        bytes memory accSig = _signAccept(alice, vid, bob, aMain, aRec, dl, bobPk);
        vm.prank(alice);
        vm.expectRevert(bytes4(keccak256("ECDSAInvalidSignature()")));
        vault.transferVault(vid, bob, aMain, aRec, dl, mal, accSig);
    }

    function test_EIP712_MalleableRotateKeys_Reverts() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signRotateKeys(alice, vid, address(0xAA), address(0xBB), nonce, dl, aRecPk);
        bytes memory mal = _makeMalleable(sig);
        vm.prank(alice);
        vm.expectRevert(bytes4(keccak256("ECDSAInvalidSignature()")));
        vault.rotateAuthKeys(vid, address(0xAA), address(0xBB), dl, mal);
    }

    function test_EIP712_MalleableVoluntaryLock_Reverts() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signSetVoluntaryLock(alice, vid, block.timestamp + 7 days, nonce, dl, aMainPk);
        bytes memory mal = _makeMalleable(sig);
        vm.prank(alice);
        vm.expectRevert(bytes4(keccak256("ECDSAInvalidSignature()")));
        vault.setVoluntaryLock(vid, block.timestamp + 7 days, dl, mal);
    }

    // ═══════════════════════════════════════════════════════════
    // РАЗДЕЛ 3: DOS/GAS СТРЕСС (10 тестов)
    // ═══════════════════════════════════════════════════════════

    /// @notice 10 микро-депозитов подряд
    function test_DoS_MicroDeposits() public {
        uint256 vid = _openAliceVault(1000 ether, 0);
        for (uint256 i = 0; i < 10; i++) {
            vm.prank(alice);
            vault.depositToVault(vid, 0.02 ether);
        }
        (,, uint120 amount,, ) = vault.getVaultCore(alice, vid);
        // ANCV1-4: открытие SAFE теперь 50 bps → 995 ether, плюс микродепозиты.
        assertTrue(uint256(amount) > 995 ether);
    }

    /// @notice 5 пользователей открывают сейфы
    function test_DoS_MultipleUsers() public {
        for (uint256 i = 0; i < 5; i++) {
            address user = address(uint160(0x1000 + i));
            address em = address(uint160(0x2000 + i));
            uint256 pk = 0xDEAD + i;
            vm.prank(creator);
            ancr.transfer(user, 1000 ether);
            vm.prank(user);
            ancr.approve(address(vault), type(uint256).max);
            vm.prank(user);
            vault.setGlobalEmergency(em);
            AnchorVaultCoin.VaultParams memory p = AnchorVaultCoin.VaultParams({
                mainAuthKey: vm.addr(pk),
                recoveryAuthKey: vm.addr(pk + 1_000_000),
                amount: 100 ether
            });
            vm.prank(user);
            vault.openVault(address(ancr), p, 0);
            assertTrue(vault.activeVaultIdByToken(user, address(ancr)) > 0);
        }
    }

    /// @notice deprecated: withdraw with zero amount (уже есть в основном файле)
    /// @notice Donate в rewardPool разными пользователями
    function test_DoS_MultipleDonations() public {
        for (uint256 i = 0; i < 5; i++) {
            address user = address(uint160(0x3000 + i));
            vm.prank(creator);
            ancr.transfer(user, 1000 ether);
            vm.prank(user);
            ancr.approve(address(vault), type(uint256).max);
            vm.prank(user);
            vault.donateToRewardPool(address(ancr), 100 ether);
        }
        assertEq(vault.rewardPool(address(ancr)), 500 ether);
    }

    /// @notice Большое кол-во операций с одним сейфом
    function test_DoS_ManyOperations() public {
        uint256 vid = _openAliceVault(1000 ether, 0);
        for (uint256 i = 0; i < 5; i++) {
            vm.prank(alice);
            vault.depositToVault(vid, 50 ether);
            (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
            uint256 dl = block.timestamp + 1 hours;
            bytes memory sig = _signWithdraw(alice, vid, 30 ether, alice, nonce, dl, aMainPk);
            vm.prank(alice);
            vault.withdrawFromVault(vid, 30 ether, alice, dl, sig);
        }
        (,, uint120 amount,, ) = vault.getVaultCore(alice, vid);
        assertTrue(uint256(amount) > 1000 ether);
    }

    /// @notice Emergency change + confirm
    function test_DoS_EmergencyChange() public {
        address em1 = address(0xCAFE01);
        vm.prank(alice);
        vault.proposeGlobalEmergencyChange(em1);
        vm.warp(block.timestamp + 8 days);
        vm.prank(alice);
        vault.confirmGlobalEmergencyChange();
        assertEq(vault.globalEmergency(alice), em1);
    }

    /// @notice Creator withdraw full flow — reserve
    function test_DoS_ReserveFlow() public {
        ancr.mint(address(vault), 1_000_000 ether);
        vm.prank(creator);
        vault.initializeDistribution();
        uint256 rs = vault.strategicReserve(address(ancr));
        vm.prank(creator);
        vault.requestReserveWithdraw(address(ancr), creator, rs);
        vm.warp(block.timestamp + 8 days);
        vm.prank(creator);
        vault.withdrawStrategicReserve(address(ancr));
        assertEq(vault.strategicReserve(address(ancr)), 0);
    }

    /// @notice Creator withdraw + cancel
    function test_DoS_CreatorCancel() public {
        uint256 vid = _openAliceVault(1000 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signEarlyClose(alice, vid, nonce, dl, aRecPk);
        vm.prank(alice);
        vault.earlyClose(vid, dl, sig);

        uint256 cf = vault.creatorFees(address(ancr));
        vm.prank(creator);
        vault.requestCreatorWithdraw(address(ancr), creator, cf / 2);
        assertTrue(vault.creatorWithdrawalUnlock(address(ancr)) > 0);

        vm.prank(creator);
        vault.cancelCreatorWithdraw(address(ancr));
        assertEq(vault.creatorWithdrawalUnlock(address(ancr)), 0);
    }

    /// @notice Добавление и удаление токена
    function test_DoS_AddRemoveToken() public {
        MaliciousCallbackToken tk = new MaliciousCallbackToken(address(vault));
        vm.prank(creator);
        vault.addSupportedToken(address(tk));
        assertTrue(vault.supportedTokens(address(tk)));
        vm.prank(creator);
        vault.removeSupportedToken(address(tk));
        assertFalse(vault.supportedTokens(address(tk)));
    }

    /// @notice Accrue fees через multiple operations
    function test_DoS_FeeAccrual() public {
        _openAliceVault(1000 ether, 0);
        uint256 cf = vault.creatorFees(address(ancr));
        assertTrue(cf > 0);
    }

    // ═══════════════════════════════════════════════════════════
    // РАЗДЕЛ 4: SECURE TRANSFER EDGE (8 тестов)
    // ═══════════════════════════════════════════════════════════

    function test_SecureTransfer_RevertIfInitToZero() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signInitSecure(alice, vid, address(0), address(0xBAD1), address(0xBAD2), nonce, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultCoin.InvalidAddress.selector);
        vault.initSecureTransfer(vid, address(0), address(0xBAD1), address(0xBAD2), dl, sig);
    }

    function test_SecureTransfer_RevertIfInitToSelf() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signInitSecure(alice, vid, alice, address(0xBAD1), address(0xBAD2), nonce, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultCoin.InvalidAddress.selector);
        vault.initSecureTransfer(vid, alice, address(0xBAD1), address(0xBAD2), dl, sig);
    }

    function test_SecureTransfer_RevertIfToNoEmergency() public {
        address charlie = address(0xCAFE);
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signInitSecure(alice, vid, charlie, address(0xBAD1), address(0xBAD2), nonce, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultCoin.NoEmergencySet.selector);
        vault.initSecureTransfer(vid, charlie, address(0xBAD1), address(0xBAD2), dl, sig);
    }

    function test_SecureTransfer_RevertIfVaultNotActive() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        (,, uint120 vAmount,, ) = vault.getVaultCore(alice, vid);
        bytes memory sigW = _signWithdraw(alice, vid, uint256(vAmount), alice, nonce, dl, aMainPk);
        vm.prank(alice);
        vault.withdrawFromVault(vid, uint256(vAmount), alice, dl, sigW);

        (uint64 nonce2,,) = vault.getVaultAuth(alice, vid);
        bytes memory sig = _signInitSecure(alice, vid, bob, aMain, aRec, nonce2, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultCoin.NotActive.selector);
        vault.initSecureTransfer(vid, bob, aMain, aRec, dl, sig);
    }

    function test_SecureTransfer_RevertIfTransferExists() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signInitSecure(alice, vid, bob, aMain, aRec, nonce, dl, aMainPk);
        vm.prank(alice);
        vault.initSecureTransfer(vid, bob, aMain, aRec, dl, sig);
        // Попытка инициировать второй Secure Transfer на тот же токен
        (uint64 nonce2,,) = vault.getVaultAuth(alice, vid);
        bytes memory sig2 = _signInitSecure(alice, vid, bob, aMain, aRec, nonce2, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultCoin.NotActive.selector);
        vault.initSecureTransfer(vid, bob, aMain, aRec, dl, sig2);
    }

    function test_SecureTransfer_RevertIfDoubleConfirm() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signInitSecure(alice, vid, bob, aMain, aRec, nonce, dl, aMainPk);
        vm.prank(alice);
        uint256 tid = vault.initSecureTransfer(vid, bob, aMain, aRec, dl, sig);
        vm.prank(bob);
        vault.confirmSecureTransfer(tid);
        vm.prank(bob);
        vm.expectRevert(AnchorVaultCoin.TransferNotPending.selector);
        vault.confirmSecureTransfer(tid);
    }

    function test_SecureTransfer_ReclaimByRecipientAfterCancel() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signInitSecure(alice, vid, bob, aMain, aRec, nonce, dl, aMainPk);
        vm.prank(alice);
        uint256 tid = vault.initSecureTransfer(vid, bob, aMain, aRec, dl, sig);
        vm.prank(alice);
        vault.cancelSecureTransfer(tid);
        vm.warp(block.timestamp + 49 hours);
        vm.prank(bob);
        vm.expectRevert(AnchorVaultCoin.TransferNotPending.selector);
        vault.reclaimExpiredTransfer(tid);
    }

    function test_SecureTransfer_ConfirmAfterExpiry_Reverts() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signInitSecure(alice, vid, bob, aMain, aRec, nonce, dl, aMainPk);
        vm.prank(alice);
        uint256 tid = vault.initSecureTransfer(vid, bob, aMain, aRec, dl, sig);
        vm.warp(block.timestamp + 49 hours);
        vm.prank(bob);
        vm.expectRevert(AnchorVaultCoin.TransferExpired.selector);
        vault.confirmSecureTransfer(tid);
    }

    // ═══════════════════════════════════════════════════════════
    // РАЗДЕЛ 5: TRANSFER VAULT EDGE (4 теста)
    // ═══════════════════════════════════════════════════════════

    function test_TransferVault_RevertIfToZero() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signTransfer(alice, vid, address(0), aMain, aRec, nonce, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultCoin.InvalidAddress.selector);
        vault.transferVault(vid, address(0), aMain, aRec, dl, sig, _noAccept());
    }

    function test_TransferVault_RevertIfToSelf() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signTransfer(alice, vid, alice, aMain, aRec, nonce, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultCoin.InvalidAddress.selector);
        vault.transferVault(vid, alice, aMain, aRec, dl, sig, _noAccept());
    }

    function test_TransferVault_RevertIfToVaultAddress() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signTransfer(alice, vid, address(vault), aMain, aRec, nonce, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultCoin.InvalidAddress.selector);
        vault.transferVault(vid, address(vault), aMain, aRec, dl, sig, _noAccept());
    }

    function test_TransferVault_RevertIfRecipientNoEmergency() public {
        address charlie = address(0xCAFE);
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signTransfer(alice, vid, charlie, aMain, aRec, nonce, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultCoin.NoEmergencySet.selector);
        vault.transferVault(vid, charlie, aMain, aRec, dl, sig, _noAccept());
    }

    // ═══════════════════════════════════════════════════════════
    // РАЗДЕЛ 6: MULTI-VAULT / MULTI-USER (8 тестов)
    // ═══════════════════════════════════════════════════════════

    /// @notice Alice открывает сейф, закрывает, открывает новый
    function test_MultiVault_OpenCloseReopen() public {
        uint256 v1 = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, v1);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signEarlyClose(alice, v1, nonce, dl, aRecPk);
        vm.prank(alice);
        vault.earlyClose(v1, dl, sig);

        uint256 v2 = _openAliceVault(200 ether, 1);
        assertTrue(v2 > 0);
        assertEq(vault.activeVaultIdByToken(alice, address(ancr)), v2);
    }

    /// @notice Alice → Bob → Alice передача
    function test_MultiVault_AliceBobAlice() public {
        uint256 v1 = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, v1);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signTransfer(alice, v1, bob, bMain, bRec, nonce, dl, aMainPk);
        bytes memory accSig = _signAccept(alice, v1, bob, bMain, bRec, dl, bobPk);
        vm.prank(alice);
        vault.transferVault(v1, bob, bMain, bRec, dl, sig, accSig);

        uint256 bobVid = vault.activeVaultIdByToken(bob, address(ancr));
        (uint64 bNonce,,) = vault.getVaultAuth(bob, bobVid);
        bytes memory sig2 = _signTransfer(bob, bobVid, alice, aMain, aRec, bNonce, dl, bMainPk);
        bytes memory accSig2 = _signAccept(bob, bobVid, alice, aMain, aRec, dl, alicePk);
        vm.prank(bob);
        vault.transferVault(bobVid, alice, aMain, aRec, dl, sig2, accSig2);

        uint256 aliceVid2 = vault.activeVaultIdByToken(alice, address(ancr));
        assertTrue(aliceVid2 > 0);
    }

    /// @notice Alice + Bob + Charlie — 3 сейфа
    function test_MultiVault_ThreeUsers() public {
        uint256 charliePk = 0xC4A5711E;
        address charlie = vm.addr(charliePk);
        address charlieEm = address(0xCAFE2);
        uint256 cPk = 0xCAFE01;
        vm.prank(creator);
        ancr.transfer(charlie, 1000 ether);
        vm.prank(charlie);
        ancr.approve(address(vault), type(uint256).max);
        vm.prank(charlie);
        vault.setGlobalEmergency(charlieEm);

        _openAliceVault(100 ether, 0);
        _openBobVault(200 ether, 1);

        AnchorVaultCoin.VaultParams memory p = AnchorVaultCoin.VaultParams({
            mainAuthKey: vm.addr(cPk), recoveryAuthKey: vm.addr(cPk + 1), amount: 300 ether
        });
        vm.prank(charlie);
        vault.openVault(address(ancr), p, 2);

        assertTrue(vault.activeVaultIdByToken(alice, address(ancr)) > 0);
        assertTrue(vault.activeVaultIdByToken(bob, address(ancr)) > 0);
        assertTrue(vault.activeVaultIdByToken(charlie, address(ancr)) > 0);
        // ANCV1-4: у каждого сейфа своя ставка открытия по уровню:
        // alice SAFE 50 bps, bob VAULT 150 bps, charlie FORTRESS 200 bps.
        assertEq(
            vault.lockedPrincipal(address(ancr)),
            100 ether + 200 ether + 300 ether
                - ((100 ether * 50) / 10000 + (200 ether * 150) / 10000 + (300 ether * 200) / 10000)
        );
    }

    /// @notice Secure transfer multi-hop: Alice → Bob → Charlie
    function test_MultiVault_SecureMultiHop() public {
        uint256 charliePk = 0xC4A5711E;
        address charlie = vm.addr(charliePk);
        address charlieEm = address(0xCAFE2);
        uint256 cPk = 0xCAFE01;
        vm.prank(creator);
        ancr.transfer(charlie, 1000 ether);
        vm.prank(charlie);
        ancr.approve(address(vault), type(uint256).max);
        vm.prank(charlie);
        vault.setGlobalEmergency(charlieEm);

        uint256 v1 = _openAliceVault(100 ether, 0);

        // Alice → Bob (secure)
        (uint64 nonce,,) = vault.getVaultAuth(alice, v1);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signInitSecure(alice, v1, bob, bMain, bRec, nonce, dl, aMainPk);
        vm.prank(alice);
        uint256 tid1 = vault.initSecureTransfer(v1, bob, bMain, bRec, dl, sig);
        vm.prank(bob);
        vault.confirmSecureTransfer(tid1);

        // Bob → Charlie (transfer)
        uint256 bobVid = vault.activeVaultIdByToken(bob, address(ancr));
        (uint64 bNonce,,) = vault.getVaultAuth(bob, bobVid);
        bytes memory sig2 = _signTransfer(bob, bobVid, charlie, vm.addr(cPk), vm.addr(cPk + 1), bNonce, dl, bMainPk);
        bytes memory accSig = _signAccept(bob, bobVid, charlie, vm.addr(cPk), vm.addr(cPk + 1), dl, charliePk);
        vm.prank(bob);
        vault.transferVault(bobVid, charlie, vm.addr(cPk), vm.addr(cPk + 1), dl, sig2, accSig);

        assertTrue(vault.activeVaultIdByToken(charlie, address(ancr)) > 0);
    }

    /// @notice Deposit into transferred vault
    function test_MultiVault_DepositAfterTransfer() public {
        uint256 v1 = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, v1);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signTransfer(alice, v1, bob, bMain, bRec, nonce, dl, aMainPk);
        bytes memory accSig = _signAccept(alice, v1, bob, bMain, bRec, dl, bobPk);
        vm.prank(alice);
        vault.transferVault(v1, bob, bMain, bRec, dl, sig, accSig);

        uint256 bobVid = vault.activeVaultIdByToken(bob, address(ancr));
        vm.prank(bob);
        vault.depositToVault(bobVid, 50 ether);

        (,, uint120 amount,, ) = vault.getVaultCore(bob, bobVid);
        uint256 fee = (100 ether * 50) / 10000;
        uint256 depositFee = (50 ether * 20) / 10000;
        assertTrue(uint256(amount) > 100 ether - fee + 50 ether - depositFee - 100 ether); // more than transfer net
    }

    /// @notice Secure transfer + panic
    function test_MultiVault_SecureThenPanic() public {
        uint256 v1 = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, v1);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signInitSecure(alice, v1, bob, aMain, aRec, nonce, dl, aMainPk);
        vm.prank(alice);
        uint256 tid = vault.initSecureTransfer(v1, bob, aMain, aRec, dl, sig);
        vm.prank(bob);
        vault.confirmSecureTransfer(tid);

        uint256 bobVid = vault.activeVaultIdByToken(bob, address(ancr));
        vm.prank(bob);
        vault.panicWithdraw(bobVid);

        assertEq(vault.activeVaultIdByToken(bob, address(ancr)), 0);
    }

    /// @notice RecoverToSafe после transfer
    function test_MultiVault_RecoverAfterTransfer() public {
        uint256 v1 = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, v1);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signTransfer(alice, v1, bob, bMain, bRec, nonce, dl, aMainPk);
        bytes memory accSig = _signAccept(alice, v1, bob, bMain, bRec, dl, bobPk);
        vm.prank(alice);
        vault.transferVault(v1, bob, bMain, bRec, dl, sig, accSig);

        uint256 bobVid = vault.activeVaultIdByToken(bob, address(ancr));
        (uint64 bNonce,,) = vault.getVaultAuth(bob, bobVid);
        bytes memory sig2 = _signRecover(bob, bobVid, bNonce, dl, bRecPk);
        vm.prank(bob);
        vault.recoverToSafe(bobVid, dl, sig2);

        assertEq(vault.activeVaultIdByToken(bob, address(ancr)), 0);
    }

    // ═══════════════════════════════════════════════════════════
    // РАЗДЕЛ 7: INVARIANT-TESTS (6 тестов)
    // ═══════════════════════════════════════════════════════════

    /// @notice Solvency: bal >= lockedPrincipal + creatorFees + strategicReserve + rewardPool
    function test_Invariant_Solvency() public {
        ancr.mint(address(vault), 1_000_000 ether);
        vm.prank(creator);
        vault.initializeDistribution();

        uint256 aVid = _openAliceVault(1000 ether, 0);
        uint256 bVid = _openBobVault(2000 ether, 1);

        vm.prank(alice);
        vault.panicWithdraw(aVid);

        (uint64 nonce,,) = vault.getVaultAuth(bob, bVid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signEarlyClose(bob, bVid, nonce, dl, bRecPk);
        vm.prank(bob);
        vault.earlyClose(bVid, dl, sig);

        uint256 bal = ancr.balanceOf(address(vault));
        uint256 lp = vault.lockedPrincipal(address(ancr));
        uint256 cf = vault.creatorFees(address(ancr));
        uint256 rs = vault.strategicReserve(address(ancr));
        uint256 rp = vault.rewardPool(address(ancr));

        assertGe(bal, lp + cf + rs + rp);
    }

    /// @notice LockedPrincipal = sum of all vault amounts
    function test_Invariant_LockedPrincipalSum() public {
        uint256 lpBefore = vault.lockedPrincipal(address(ancr));
        _openAliceVault(100 ether, 0);
        _openBobVault(200 ether, 1);
        uint256 lpAfter = vault.lockedPrincipal(address(ancr));
        // ANCV1-4: ставки открытия по уровням — SAFE 50 bps, VAULT 150 bps.
        uint256 fees = (100 ether * 50) / 10000 + (200 ether * 150) / 10000;
        assertTrue(lpAfter >= lpBefore + 300 ether - fees);
    }

    /// @notice Nonce монотонно растёт
    function test_Invariant_NonceMonotonic() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 n0,,) = vault.getVaultAuth(alice, vid);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signWithdraw(alice, vid, 10 ether, alice, nonce, dl, aMainPk);
        vm.prank(alice);
        vault.withdrawFromVault(vid, 10 ether, alice, dl, sig);
        (uint64 n1,,) = vault.getVaultAuth(alice, vid);
        assertTrue(n1 > n0);
    }

    /// @notice Vault status = 2 after close
    function test_Invariant_StatusAfterClose() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        vm.prank(alice);
        vault.panicWithdraw(vid);
        (,, uint120 amount, uint8 status,) = vault.getVaultCore(alice, vid);
        assertEq(status, 2);
        assertEq(uint256(amount), 0);
    }

    /// @notice ActiveVaultId = 0 after close
    function test_Invariant_ActiveIdAfterClose() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signEarlyClose(alice, vid, nonce, dl, aRecPk);
        vm.prank(alice);
        vault.earlyClose(vid, dl, sig);
        assertEq(vault.activeVaultIdByToken(alice, address(ancr)), 0);
    }

    /// @notice User cannot have 2 vaults for same token
    function test_Invariant_OneVaultPerToken() public {
        _openAliceVault(100 ether, 0);
        AnchorVaultCoin.VaultParams memory p = AnchorVaultCoin.VaultParams({
            mainAuthKey: aMain, recoveryAuthKey: aRec, amount: 200 ether
        });
        vm.prank(alice);
        vm.expectRevert(AnchorVaultCoin.VaultLimitReached.selector);
        vault.openVault(address(ancr), p, 0);
    }

    // ═══════════════════════════════════════════════════════════
    // РАЗДЕЛ 8: EDGE CASES (10 тестов)
    // ═══════════════════════════════════════════════════════════

    /// @notice Нельзя открыть сейф с уровнем 99
    function test_Edge_InvalidLevel() public {
        AnchorVaultCoin.VaultParams memory p = AnchorVaultCoin.VaultParams({
            mainAuthKey: aMain, recoveryAuthKey: aRec, amount: 100 ether
        });
        vm.prank(alice);
        vm.expectRevert(AnchorVaultCoin.InvalidLevel.selector);
        vault.openVault(address(ancr), p, 99);
    }

    /// @notice Нельзя перевести кому попало rescueERC20
    function test_Edge_RescueToVaultAddress() public {
        vm.prank(creator);
        vm.expectRevert(AnchorVaultCoin.InvalidAddress.selector);
        vault.rescueERC20(address(0x1234), address(vault), 1 ether);
    }

    /// @notice RemoveSupportedToken работает только для не-ANCR
    function test_Edge_RemoveNonExistentToken() public {
        address fake = address(0xDEAD);
        vm.prank(creator);
        vault.removeSupportedToken(fake); // не ревертит, просто ставит false
        assertFalse(vault.supportedTokens(fake));
    }

    /// @notice Donate с нулём ревертит
    function test_Edge_DonateZero() public {
        vm.prank(alice);
        vm.expectRevert(AnchorVaultCoin.InvalidAmount.selector);
        vault.donateToRewardPool(address(ancr), 0);
    }

    /// @notice Creator withdraw: cancel без запроса
    function test_Edge_CancelCreatorWithdrawNoRequest() public {
        vm.prank(creator);
        vm.expectRevert(AnchorVaultCoin.NoAdminRequest.selector);
        vault.cancelCreatorWithdraw(address(ancr));
    }

    /// @notice Reserve withdraw: cancel без запроса
    function test_Edge_CancelReserveWithdrawNoRequest() public {
        vm.prank(creator);
        vm.expectRevert(AnchorVaultCoin.NoAdminRequest.selector);
        vault.cancelReserveWithdraw(address(ancr));
    }

    /// @notice Creator withdraw: execute без запроса
    function test_Edge_WithdrawCreatorNoRequest() public {
        vm.prank(creator);
        vm.expectRevert(AnchorVaultCoin.NoAdminRequest.selector);
        vault.withdrawCreatorFees(address(ancr));
    }

    /// @notice Reserve withdraw: execute без запроса
    function test_Edge_WithdrawReserveNoRequest() public {
        vm.prank(creator);
        vm.expectRevert(AnchorVaultCoin.NoAdminRequest.selector);
        vault.withdrawStrategicReserve(address(ancr));
    }

    /// @notice Creator withdraw: amount > fees
    function test_Edge_CreatorWithdrawExceedsFees() public {
        vm.prank(creator);
        vm.expectRevert(AnchorVaultCoin.InvalidAmount.selector);
        vault.requestCreatorWithdraw(address(ancr), creator, 100 ether);
    }

    /// @notice Reserve withdraw: amount > reserve
    function test_Edge_ReserveWithdrawExceedsReserve() public {
        vm.prank(creator);
        vm.expectRevert(AnchorVaultCoin.InvalidAmount.selector);
        vault.requestReserveWithdraw(address(ancr), creator, 100 ether);
    }

    // ═══════════════════════════════════════════════════════════
    // РАЗДЕЛ 9: SIGNATURE EDGE (8 тестов)
    // ═══════════════════════════════════════════════════════════

    /// @notice Подпись с истекшим deadline
    function test_Sig_ExpiredDeadline() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signWithdraw(alice, vid, 10 ether, alice, nonce, dl, aMainPk);
        vm.warp(block.timestamp + 2 hours);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultCoin.SignatureExpired.selector);
        vault.withdrawFromVault(vid, 10 ether, alice, dl, sig);
    }

    /// @notice Подпись неверным ключом (recovery вместо main)
    function test_Sig_WrongKeyForWithdraw() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signWithdraw(alice, vid, 10 ether, alice, nonce, dl, aRecPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultCoin.BadSignature.selector);
        vault.withdrawFromVault(vid, 10 ether, alice, dl, sig);
    }

    /// @notice Подпись main ключом для earlyClose (должен быть recovery)
    function test_Sig_MainKeyForEarlyClose() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signEarlyClose(alice, vid, nonce, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultCoin.BadSignature.selector);
        vault.earlyClose(vid, dl, sig);
    }

    /// @notice Replay подписи с тем же nonce
    function test_Sig_NonceReplay() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signWithdraw(alice, vid, 10 ether, alice, nonce, dl, aMainPk);
        vm.prank(alice);
        vault.withdrawFromVault(vid, 10 ether, alice, dl, sig);
        // Replay
        vm.prank(alice);
        vm.expectRevert(AnchorVaultCoin.BadSignature.selector);
        vault.withdrawFromVault(vid, 10 ether, alice, dl, sig);
    }

    /// @notice ChainId в подписи — проверка
    function test_Sig_DomainSeparator() public {
        bytes32 ds = vault.domainSeparator();
        bytes32 expected = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("AnchorVaultCoin"),
            keccak256("45"),
            block.chainid,
            address(vault)
        ));
        assertEq(ds, expected);
    }

    /// @notice Подпись для rotateKeys не main ключом (должен recovery)
    function test_Sig_MainKeyForRotate() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signRotateKeys(alice, vid, address(0xAA), address(0xBB), nonce, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultCoin.BadSignature.selector);
        vault.rotateAuthKeys(vid, address(0xAA), address(0xBB), dl, sig);
    }

    /// @notice Подпись для withdraw не тем пользователем
    function test_Sig_WrongUser() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signWithdraw(alice, vid, 10 ether, alice, nonce, dl, aMainPk);
        // Bob вызывает от своего имени
        vm.prank(bob);
        vm.expectRevert(AnchorVaultCoin.BadVaultId.selector);
        vault.withdrawFromVault(vid, 10 ether, alice, dl, sig);
    }

    /// @notice Подпись без deadline (deadline = 0)
    function test_Sig_DeadlineZero() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = 0;
        bytes memory sig = _signWithdraw(alice, vid, 10 ether, alice, nonce, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultCoin.SignatureExpired.selector);
        vault.withdrawFromVault(vid, 10 ether, alice, dl, sig);
    }

    // ═══════════════════════════════════════════════════════════
    // РАЗДЕЛ 10: VOLUNTARY LOCK EDGE (6 тестов)
    // ═══════════════════════════════════════════════════════════

    /// @notice Voluntary lock блокирует earlyClose
    function test_VLock_BlocksEarlyClose() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signSetVoluntaryLock(alice, vid, block.timestamp + 7 days, nonce, dl, aMainPk);
        vm.prank(alice);
        vault.setVoluntaryLock(vid, block.timestamp + 7 days, dl, sig);

        (uint64 nonce2,,) = vault.getVaultAuth(alice, vid);
        bytes memory sig2 = _signEarlyClose(alice, vid, nonce2, dl, aRecPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultCoin.Locked.selector);
        vault.earlyClose(vid, dl, sig2);
    }

    /// @notice Voluntary lock не блокирует panic
    function test_VLock_PanicBypass() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signSetVoluntaryLock(alice, vid, block.timestamp + 7 days, nonce, dl, aMainPk);
        vm.prank(alice);
        vault.setVoluntaryLock(vid, block.timestamp + 7 days, dl, sig);
        vm.prank(alice);
        vault.panicWithdraw(vid);
        (,, uint120 amount,, ) = vault.getVaultCore(alice, vid);
        assertEq(uint256(amount), 0);
    }

    /// @notice Voluntary lock не блокирует setTimelock
    function test_VLock_TimelockAllowed() public {
        uint256 vid = _openAliceVault(100 ether, 1);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sigV = _signSetVoluntaryLock(alice, vid, block.timestamp + 7 days, nonce, dl, aMainPk);
        vm.prank(alice);
        vault.setVoluntaryLock(vid, block.timestamp + 7 days, dl, sigV);

        (uint64 nonce2,,) = vault.getVaultAuth(alice, vid);
        bytes memory sigT = _signSetTimelock(alice, vid, 24, nonce2, dl, aMainPk);
        vm.prank(alice);
        vault.setTimelock(vid, 24, dl, sigT);

        (, , uint16 tl) = vault.getVaultTimings(alice, vid);
        assertEq(tl, 24);
    }

    /// @notice Voluntary lock увеличивается (не уменьшается)
    function test_VLock_OnlyIncreases() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;

        uint256 lock1 = block.timestamp + 7 days;
        bytes memory sig1 = _signSetVoluntaryLock(alice, vid, lock1, nonce, dl, aMainPk);
        vm.prank(alice);
        vault.setVoluntaryLock(vid, lock1, dl, sig1);

        (uint64 nonce2,,) = vault.getVaultAuth(alice, vid);
        uint256 lock2 = block.timestamp + 1 days; // меньше
        bytes memory sig2 = _signSetVoluntaryLock(alice, vid, lock2, nonce2, dl, aMainPk);
        vm.prank(alice);
        vault.setVoluntaryLock(vid, lock2, dl, sig2);

        (, uint48 vLock,) = vault.getVaultTimings(alice, vid);
        assertEq(vLock, lock1); // старый остался
    }

    /// @notice Voluntary lock = max 5 years
    function test_VLock_MaxDuration() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 lockUntil = block.timestamp + 5 * 365 days;
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signSetVoluntaryLock(alice, vid, lockUntil, nonce, dl, aMainPk);
        vm.prank(alice);
        vault.setVoluntaryLock(vid, lockUntil, dl, sig);
        (, uint48 vLock,) = vault.getVaultTimings(alice, vid);
        assertEq(vLock, lockUntil);
    }

    /// @notice Voluntary lock истекает — withdraw работает
    function test_VLock_AfterExpiry() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sigV = _signSetVoluntaryLock(alice, vid, block.timestamp + 2 days, nonce, dl, aMainPk);
        vm.prank(alice);
        vault.setVoluntaryLock(vid, block.timestamp + 2 days, dl, sigV);

        vm.warp(block.timestamp + 3 days);
        dl = block.timestamp + 1 hours; // свежий дедлайн после прыжка во времени

        (uint64 nonce2,,) = vault.getVaultAuth(alice, vid);
        bytes memory sigW = _signWithdraw(alice, vid, 10 ether, alice, nonce2, dl, aMainPk);
        vm.prank(alice);
        vault.withdrawFromVault(vid, 10 ether, alice, dl, sigW);
    }

    // ═══════════════════════════════════════════════════════════
    // РАЗДЕЛ 11: GUARDIAN EDGE (6 тестов)
    // ═══════════════════════════════════════════════════════════

    // Guardian REQUEST pause (2 day delay)
    function test_Guardian_RequestPauseFlow() public {
        vm.prank(guardian);
        vault.requestPause();
        uint256 ts = vault.pauseTimestamp();
        assertTrue(ts > block.timestamp + 1 days);

        vm.warp(ts + 1);
        vm.prank(guardian);
        vault.executePause();
        assertTrue(vault.paused());
    }

    // Guardian emergency pause instant
    function test_Guardian_EmergencyPauseInstant() public {
        vm.prank(guardian);
        vault.emergencyPause();
        assertTrue(vault.paused());
    }

    // Only creator can unpause
    function test_Guardian_CannotUnpause() public {
        vm.prank(guardian);
        vault.emergencyPause();
        vm.prank(guardian);
        vm.expectRevert(AnchorVaultCoin.NotCreator.selector);
        vault.unpause();
    }

    // Only creator can unpause (success case)
    function test_Guardian_CreatorUnpauses() public {
        vm.prank(guardian);
        vault.emergencyPause();
        vm.prank(creator);
        vault.unpause();
        assertFalse(vault.paused());
    }

    // Cancel pause request
    function test_Guardian_CancelPause() public {
        vm.prank(guardian);
        vault.requestPause();
        assertTrue(vault.pauseTimestamp() > 0);
        vm.prank(guardian);
        vault.cancelPauseRequest();
        assertEq(vault.pauseTimestamp(), 0);
    }

    // Execute pause before timeout reverts
    function test_Guardian_CannotExecuteEarly() public {
        vm.prank(guardian);
        vault.requestPause();
        vm.warp(block.timestamp + 1 days);
        vm.prank(guardian);
        vm.expectRevert(AnchorVaultCoin.PauseTimeoutNotReached.selector);
        vault.executePause();
    }

    // ═══════════════════════════════════════════════════════════
    // РАЗДЕЛ 12: RECOVER/EMERGENCY EDGE (6 тестов)
    // ═══════════════════════════════════════════════════════════

    /// @notice RecoverToSafe с рекавери ключом (должен работать)
    function test_Recover_HappyPath() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signRecover(alice, vid, nonce, dl, aRecPk);
        uint256 balBefore = ancr.balanceOf(aliceEmergency);
        vm.prank(alice);
        vault.recoverToSafe(vid, dl, sig);
        uint256 balAfter = ancr.balanceOf(aliceEmergency);
        assertTrue(balAfter > balBefore);
    }

    /// @notice EmergencyWithdrawToAny с рекавери ключом (должен работать)
    function test_EmergencyAny_HappyPath() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signEmergencyAny(alice, vid, bob, nonce, dl, aRecPk);
        uint256 balBefore = ancr.balanceOf(bob);
        vm.prank(alice);
        vault.emergencyWithdrawToAny(vid, bob, dl, sig);
        uint256 balAfter = ancr.balanceOf(bob);
        assertTrue(balAfter > balBefore);
    }

    /// @notice EmergencyWithdrawToAny ревертит если to = vault
    function test_EmergencyAny_RevertIfToVault() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signEmergencyAny(alice, vid, address(vault), nonce, dl, aRecPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultCoin.InvalidAddress.selector);
        vault.emergencyWithdrawToAny(vid, address(vault), dl, sig);
    }

    /// @notice EmergencyWithdrawToAny ревертит если to = 0
    function test_EmergencyAny_RevertIfToZero() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signEmergencyAny(alice, vid, address(0), nonce, dl, aRecPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultCoin.InvalidAddress.selector);
        vault.emergencyWithdrawToAny(vid, address(0), dl, sig);
    }

    /// @notice Panic withdraw to emergency
    function test_Panic_ToEmergency() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        uint256 balBefore = ancr.balanceOf(aliceEmergency);
        vm.prank(alice);
        vault.panicWithdraw(vid);
        uint256 balAfter = ancr.balanceOf(aliceEmergency);
        assertTrue(balAfter > balBefore);
    }

    /// @notice Panic withdraw ревертит если нет emergency
    function test_Panic_RevertIfNoEmergency() public {
        address charlie = address(0xCAFE);
        vm.prank(creator);
        ancr.transfer(charlie, 1000 ether);
        vm.prank(charlie);
        ancr.approve(address(vault), type(uint256).max);

        AnchorVaultCoin.VaultParams memory p = AnchorVaultCoin.VaultParams({
            mainAuthKey: aMain, recoveryAuthKey: aRec, amount: 100 ether
        });
        vm.prank(charlie);
        vm.expectRevert(AnchorVaultCoin.NoEmergencySet.selector);
        vault.openVault(address(ancr), p, 0);
    }

    // ═══════════════════════════════════════════════════════════
    // РАЗДЕЛ 13: WELCOME BONUS EDGE (4 теста)
    // ═══════════════════════════════════════════════════════════

    /// @notice Welcome bonus < MAX_WELCOME_BONUS
    function test_Bonus_SetValid() public {
        vm.prank(creator);
        vault.setWelcomeBonus(0.005 ether, 100);
        assertEq(vault.welcomeBonus(), 0.005 ether);
    }

    /// @notice Welcome bonus > MAX ревертит
    function test_Bonus_SetExceedsMax() public {
        vm.prank(creator);
        vm.expectRevert(AnchorVaultCoin.BonusExceedsLimit.selector);
        vault.setWelcomeBonus(0.01 ether, 100);
    }

    /// @notice Welcome bonus не платится второй раз
    function test_Bonus_NotPaidTwice() public {
        ancr.mint(address(vault), 1_000_000 ether);
        vm.prank(creator);
        vault.initializeDistribution();
        vm.prank(creator);
        vault.setWelcomeBonus(0.005 ether, 100);

        _openAliceVault(100 ether, 0);
        assertTrue(vault.welcomeBonusClaimed(alice));

        // Закрываем и открываем новый сейф
        uint256 vid = vault.activeVaultIdByToken(alice, address(ancr));
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signEarlyClose(alice, vid, nonce, dl, aRecPk);
        vm.prank(alice);
        vault.earlyClose(vid, dl, sig);

        uint256 v2 = _openAliceVault(100 ether, 0);
        // Bonus не выплачен второй раз
        assertTrue(vault.welcomeBonusClaimed(alice)); // всё ещё true
    }

    /// @notice Welcome bonus макс кол-во выплат
    function test_Bonus_MaxClaims() public {
        ancr.mint(address(vault), 1_000_000 ether);
        vm.prank(creator);
        vault.initializeDistribution();
        vm.prank(creator);
        vault.setWelcomeBonus(0.005 ether, 2); // только 2 выплаты

        _openAliceVault(100 ether, 0);
        assertTrue(vault.welcomeBonusClaimed(alice));

        // Закрываем Alice, открываем для Bob
        uint256 vid = vault.activeVaultIdByToken(alice, address(ancr));
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signEarlyClose(alice, vid, nonce, dl, aRecPk);
        vm.prank(alice);
        vault.earlyClose(vid, dl, sig);

        assertFalse(vault.welcomeBonusClaimed(bob));
        uint256 balBefore = ancr.balanceOf(bob);
        _openBobVault(100 ether, 0);
        uint256 balAfter = ancr.balanceOf(bob);
        assertTrue(balBefore - balAfter < 100 ether); // bonus получен
        assertTrue(vault.welcomeBonusClaimed(bob));
        assertEq(vault.welcomeBonusClaims(), 2);
    }

    // ═══════════════════════════════════════════════════════════
    // РАЗДЕЛ 14: CONSTRUCTOR EDGE (6 тестов)
    // ═══════════════════════════════════════════════════════════

    function test_Constructor_RevertIfGuardianEqDeployer() public {
        vm.startPrank(creator);
        vm.expectRevert(AnchorVaultCoin.InvalidAddress.selector);
        new AnchorVaultCoin(address(ancr), creator, payoutWallet);
        vm.stopPrank();
    }

    function test_Constructor_RevertIfANCRZero() public {
        vm.expectRevert(AnchorVaultCoin.ZeroAddress.selector);
        new AnchorVaultCoin(address(0), guardian, payoutWallet);
    }

    function test_Constructor_RevertIfGuardianZero() public {
        vm.expectRevert(AnchorVaultCoin.ZeroAddress.selector);
        new AnchorVaultCoin(address(ancr), address(0), payoutWallet);
    }

    function test_Constructor_RevertIfPayoutZero() public {
        vm.expectRevert(AnchorVaultCoin.ZeroAddress.selector);
        new AnchorVaultCoin(address(ancr), guardian, address(0));
    }

    function test_Constructor_RevertIfPayoutIsVault() public {
        vm.expectRevert(AnchorVaultCoin.InvalidAddress.selector);
        new AnchorVaultCoin(address(ancr), guardian, address(vault));
    }

    function test_Constructor_RevertIfANCRisGuardian() public {
        vm.expectRevert(AnchorVaultCoin.InvalidAddress.selector);
        new AnchorVaultCoin(address(ancr), address(ancr), payoutWallet);
    }

    // ═══════════════════════════════════════════════════════════
    // РАЗДЕЛ 15: STATE CONSISTENCY (5 тестов)
    // ═══════════════════════════════════════════════════════════

    /// @notice После close все поля vault обнуляются
    function test_State_AfterClose() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        vm.prank(alice);
        vault.panicWithdraw(vid);
        (,, uint120 amount, uint8 status,) = vault.getVaultCore(alice, vid);
        assertEq(uint256(amount), 0);
        assertEq(status, 2);
        assertEq(vault.activeVaultIdByToken(alice, address(ancr)), 0);
    }

    /// @notice После transfer старый vault удалён
    function test_State_AfterTransfer() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signTransfer(alice, vid, bob, aMain, aRec, nonce, dl, aMainPk);
        bytes memory accSig = _signAccept(alice, vid, bob, aMain, aRec, dl, bobPk);
        vm.prank(alice);
        vault.transferVault(vid, bob, aMain, aRec, dl, sig, accSig);

        vm.expectRevert(AnchorVaultCoin.BadVaultId.selector);
        vault.getVaultCore(alice, vid);
        assertTrue(vault.activeVaultIdByToken(bob, address(ancr)) > 0);
    }

    /// @notice Nonce увеличивается при каждой операции
    function test_State_NonceIncrement() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 n0,,) = vault.getVaultAuth(alice, vid);

        (uint64 nonce1,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig1 = _signWithdraw(alice, vid, 10 ether, alice, nonce1, dl, aMainPk);
        vm.prank(alice);
        vault.withdrawFromVault(vid, 10 ether, alice, dl, sig1);

        (uint64 n1,,) = vault.getVaultAuth(alice, vid);
        assertEq(n1, n0 + 1);
    }

    /// @notice Creator withdraw + cancel не теряет fees
    function test_State_CreatorCancelFees() public {
        uint256 vid = _openAliceVault(1000 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signEarlyClose(alice, vid, nonce, dl, aRecPk);
        vm.prank(alice);
        vault.earlyClose(vid, dl, sig);

        uint256 cf = vault.creatorFees(address(ancr));
        vm.prank(creator);
        vault.requestCreatorWithdraw(address(ancr), creator, cf / 2);
        vm.prank(creator);
        vault.cancelCreatorWithdraw(address(ancr));

        assertEq(vault.creatorFees(address(ancr)), cf);
    }

    /// @notice Reserve withdraw + cancel
    function test_State_ReserveCancel() public {
        ancr.mint(address(vault), 1_000_000 ether);
        vm.prank(creator);
        vault.initializeDistribution();

        uint256 rs = vault.strategicReserve(address(ancr));
        vm.prank(creator);
        vault.requestReserveWithdraw(address(ancr), creator, rs / 2);
        vm.prank(creator);
        vault.cancelReserveWithdraw(address(ancr));

        assertEq(vault.strategicReserve(address(ancr)), rs);
    }

    /// ANCV1-2: подпись согласия получателя на приём сейфа.
    function _signAccept(address from, uint256 vid, address to, address newMain, address newRec, uint256 deadline, uint256 pk)
        internal view returns (bytes memory)
    {
        bytes32 ah = keccak256(abi.encode(ACCEPT_TRANSFER_TYPEHASH, from, vid, to, newMain, newRec, deadline));
        return _sign(pk, ah);
    }

    /// Заглушка для случаев, где вызов ревертится до проверки согласия.
    function _noAccept() internal pure returns (bytes memory) {
        return new bytes(65);
    }
}
