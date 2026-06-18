// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, console2} from "forge-std/Test.sol";
import {AnchorVaultV45} from "../src/AnchorVaultV45.sol";
import {MockANCR} from "./mocks/MockANCR.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract AnchorVaultV45Test is Test {
    AnchorVaultV45 vault;
    MockANCR ancr;

    address creator = address(0xC0);
    address guardian = address(0x6A);
    address payoutWallet = address(0xBEEF01);
    address alice;
    address aliceEmergency = address(0xE1);
    address bob = address(0xB0B);
    address bobEmergency = address(0xB0BE);

    uint256 aMainPk = 0xA11CE0001;
    uint256 aRecPk  = 0xA11CE0002;
    address aMain;
    address aRec;

    uint256 bMainPk = 0xB0B0001;
    uint256 bRecPk  = 0xB0B0002;
    address bMain;
    address bRec;

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
        alice = address(0xA11CE);
        aMain = vm.addr(aMainPk);
        aRec  = vm.addr(aRecPk);
        bMain = vm.addr(bMainPk);
        bRec  = vm.addr(bRecPk);

        vm.prank(creator);
        ancr = new MockANCR(10_000_000 ether);

        vm.prank(creator);
        vault = new AnchorVaultV45(address(ancr), guardian, payoutWallet);

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

    function _domainSeparator() internal view returns (bytes32) {
        return vault.domainSeparator();
    }

    function _sign(uint256 pk, bytes32 structHash) internal view returns (bytes memory) {
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
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
        AnchorVaultV45.VaultParams memory p = AnchorVaultV45.VaultParams({
            name: "AliceVault", mainAuthKey: aMain, recoveryAuthKey: aRec, amount: amount
        });
        vm.prank(alice);
        vault.openVault(address(ancr), p, level);
        vid = vault.activeVaultIdByToken(alice, address(ancr));
    }

    function _openBobVault(uint256 amount, uint8 level) internal returns (uint256 vid) {
        AnchorVaultV45.VaultParams memory p = AnchorVaultV45.VaultParams({
            name: "BobVault", mainAuthKey: bMain, recoveryAuthKey: bRec, amount: amount
        });
        vm.prank(bob);
        vault.openVault(address(ancr), p, level);
        vid = vault.activeVaultIdByToken(bob, address(ancr));
    }

    function _tol(uint256 val) internal pure returns (uint256) {
        return val / 100;
    }

    function _approxEq(uint256 a, uint256 b, uint256 tol) internal pure {
        if (a > b) {
            assertLe(a - b, tol);
        } else {
            assertLe(b - a, tol);
        }
    }

    // ────────────────────────────────────────────────────────────
    // setTimelock
    // ────────────────────────────────────────────────────────────

    function test_SetTimelock_HappyPath_VAULT() public {
        uint256 vid = _openAliceVault(100 ether, 1);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signSetTimelock(alice, vid, 48, nonce, dl, aMainPk);
        vm.prank(alice);
        vault.setTimelock(vid, 48, dl, sig);
        (, , uint16 tl) = vault.getVaultTimings(alice, vid);
        assertEq(tl, 48);
    }

    function test_SetTimelock_RevertIfExceedsLevelMax() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signSetTimelock(alice, vid, 1, nonce, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.TimelockTooLong.selector);
        vault.setTimelock(vid, 1, dl, sig);
    }

    function test_SetTimelock_ZeroIsAllowedForVAULT() public {
        uint256 vid = _openAliceVault(100 ether, 1);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signSetTimelock(alice, vid, 0, nonce, dl, aMainPk);
        vm.prank(alice);
        vault.setTimelock(vid, 0, dl, sig);
        (, , uint16 tl) = vault.getVaultTimings(alice, vid);
        assertEq(tl, 0);
    }

    function test_SetTimelock_FORTRESS_MaxAllowed() public {
        uint256 vid = _openAliceVault(100 ether, 2);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signSetTimelock(alice, vid, 168, nonce, dl, aMainPk);
        vm.prank(alice);
        vault.setTimelock(vid, 168, dl, sig);
        (, , uint16 tl) = vault.getVaultTimings(alice, vid);
        assertEq(tl, 168);
    }

    function test_SetTimelock_RevertIfSignedByRecoveryKey() public {
        uint256 vid = _openAliceVault(100 ether, 1);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signSetTimelock(alice, vid, 24, nonce, dl, aRecPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.BadSignature.selector);
        vault.setTimelock(vid, 24, dl, sig);
    }

    function test_SetTimelock_RevertTooLong() public {
        uint256 vid = _openAliceVault(100 ether, 1);
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signSetTimelock(alice, vid, 73, n, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.TimelockTooLong.selector);
        vault.setTimelock(vid, 73, dl, sig);
    }

    function test_SetTimelock_RevertIfNotActive() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        vm.prank(alice);
        vault.panicWithdraw(vid);
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signSetTimelock(alice, vid, 1, n, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.NotActive.selector);
        vault.setTimelock(vid, 1, dl, sig);
    }

    // ────────────────────────────────────────────────────────────
    // setVoluntaryLock
    // ────────────────────────────────────────────────────────────

    function test_SetVoluntaryLock_HappyPath() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 lockUntil = block.timestamp + 7 days;
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signSetVoluntaryLock(alice, vid, lockUntil, nonce, dl, aMainPk);
        vm.prank(alice);
        vault.setVoluntaryLock(vid, lockUntil, dl, sig);
        (, uint48 vLock,) = vault.getVaultTimings(alice, vid);
        assertEq(vLock, lockUntil);
    }

    function test_SetVoluntaryLock_RevertIfPastTimestamp() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 lockUntil = block.timestamp;
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signSetVoluntaryLock(alice, vid, lockUntil, nonce, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.InvalidAmount.selector);
        vault.setVoluntaryLock(vid, lockUntil, dl, sig);
    }

    function test_SetVoluntaryLock_RevertIfExceedsMax() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 lockUntil = block.timestamp + 6 * 365 days;
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signSetVoluntaryLock(alice, vid, lockUntil, nonce, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.LockTooLong.selector);
        vault.setVoluntaryLock(vid, lockUntil, dl, sig);
    }

    function test_VoluntaryLock_BlocksWithdraw() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 lockUntil = block.timestamp + 7 days;
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sigV = _signSetVoluntaryLock(alice, vid, lockUntil, nonce, dl, aMainPk);
        vm.prank(alice);
        vault.setVoluntaryLock(vid, lockUntil, dl, sigV);
        (uint64 nonce2,,) = vault.getVaultAuth(alice, vid);
        bytes memory sigW = _signWithdraw(alice, vid, 10 ether, alice, nonce2, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.Locked.selector);
        vault.withdrawFromVault(vid, 10 ether, alice, dl, sigW);
    }

    function test_VoluntaryLock_DoesNotBlockPanicWithdraw() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 lockUntil = block.timestamp + 7 days;
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signSetVoluntaryLock(alice, vid, lockUntil, nonce, dl, aMainPk);
        vm.prank(alice);
        vault.setVoluntaryLock(vid, lockUntil, dl, sig);
        vm.prank(alice);
        vault.panicWithdraw(vid);
    }

    function test_VoluntaryLock_DoesNotBlockEarlyClose() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 lockUntil = block.timestamp + 7 days;
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sigV = _signSetVoluntaryLock(alice, vid, lockUntil, nonce, dl, aMainPk);
        vm.prank(alice);
        vault.setVoluntaryLock(vid, lockUntil, dl, sigV);
        (uint64 n2,,) = vault.getVaultAuth(alice, vid);
        bytes memory sigEC = _signEarlyClose(alice, vid, n2, dl, aRecPk);
        vm.prank(alice);
        vault.earlyClose(vid, dl, sigEC);
        (, , uint120 amt, , uint8 st, ) = vault.getVaultCore(alice, vid);
        assertEq(amt, 0);
        assertEq(st, 2);
    }

    function test_SetVoluntaryLock_RevertInPast() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        vm.warp(10_000);
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        uint256 past = block.timestamp - 1;
        bytes memory sig = _signSetVoluntaryLock(alice, vid, past, n, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.InvalidAmount.selector);
        vault.setVoluntaryLock(vid, past, dl, sig);
    }

    function test_SetVoluntaryLock_RevertTooLong() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        uint256 tooFar = block.timestamp + (5 * 365 days) + 1 days;
        bytes memory sig = _signSetVoluntaryLock(alice, vid, tooFar, n, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.LockTooLong.selector);
        vault.setVoluntaryLock(vid, tooFar, dl, sig);
    }

    // ────────────────────────────────────────────────────────────
    // GlobalEmergency
    // ────────────────────────────────────────────────────────────

    function test_GlobalEmergency_ChangeTimelockIs7Days() public {
        address newEm = address(0xCAFE);
        vm.prank(alice);
        vault.proposeGlobalEmergencyChange(newEm);
        vm.warp(block.timestamp + 6 days);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.EmergencyTimelockNotExpired.selector);
        vault.confirmGlobalEmergencyChange();
        vm.warp(block.timestamp + 1 days);
        vm.prank(alice);
        vault.confirmGlobalEmergencyChange();
        assertEq(vault.globalEmergency(alice), newEm);
    }

    function test_GlobalEmergency_CannotSetAfterChange() public {
        address newEm = address(0xCAFE);
        vm.prank(alice);
        vault.proposeGlobalEmergencyChange(newEm);
        vm.warp(block.timestamp + 8 days);
        vm.prank(alice);
        vault.confirmGlobalEmergencyChange();
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.EmergencyAlreadySet.selector);
        vault.setGlobalEmergency(address(0xDEAD));
    }

    function test_GlobalEmergency_SetFirstTime() public {
        address charlie = makeAddr("charlie");
        vm.prank(charlie);
        vault.setGlobalEmergency(address(0xFEED));
        assertEq(vault.globalEmergency(charlie), address(0xFEED));
    }

    function test_GlobalEmergency_CancelChange() public {
        address newEm = address(0xCAFE);
        vm.prank(alice);
        vault.proposeGlobalEmergencyChange(newEm);
        (, uint48 _unlocksAt) = vault.globalEmergencyChange(alice);
        assertTrue(_unlocksAt > 0);
        vm.prank(alice);
        vault.cancelGlobalEmergencyChange();
        (address _pending2, uint48 _unlocksAt2) = vault.globalEmergencyChange(alice);
        assertEq(_pending2, address(0));
        assertEq(_unlocksAt2, 0);
    }

    function test_GlobalEmergency_RevertIfNoEmergencySet() public {
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.NoEmergencySet.selector);
        vault.proposeGlobalEmergencyChange(alice);
    }

    function test_GlobalEmergency_CancelChange_RevertNoChange() public {
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.NoGlobalEmergencyChange.selector);
        vault.cancelGlobalEmergencyChange();
    }

    function test_GlobalEmergency_Confirm_RevertNoChange() public {
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.NoGlobalEmergencyChange.selector);
        vault.confirmGlobalEmergencyChange();
    }

    function test_GlobalEmergency_SetRevertEmergencyIsContract() public {
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.InvalidAddress.selector);
        vault.setGlobalEmergency(address(vault));
    }

    function test_GlobalEmergency_RevertZeroAddress() public {
        address charlie = makeAddr("charlie");
        vm.prank(charlie);
        vm.expectRevert(AnchorVaultV45.ZeroAddress.selector);
        vault.setGlobalEmergency(address(0));
    }

    // ────────────────────────────────────────────────────────────
    // Auth key validation
    // ────────────────────────────────────────────────────────────

    function test_RotateAuthKeys_HappyPath() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        address newMain = address(0xAA);
        address newRec = address(0xBB);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signRotateKeys(alice, vid, newMain, newRec, nonce, dl, aRecPk);
        vm.prank(alice);
        vault.rotateAuthKeys(vid, newMain, newRec, dl, sig);
        (, address mainAfter, address recAfter) = vault.getVaultAuth(alice, vid);
        assertEq(mainAfter, newMain);
        assertEq(recAfter, newRec);
    }

    function test_RotateAuthKeys_RevertIfKeysEqual() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        address sameKey = address(0xAA);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signRotateKeys(alice, vid, sameKey, sameKey, nonce, dl, aRecPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.BadAuthKey.selector);
        vault.rotateAuthKeys(vid, sameKey, sameKey, dl, sig);
    }

    function test_RotateAuthKeys_RevertIfKeyEqualsOwner() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signRotateKeys(alice, vid, alice, address(0xBB), nonce, dl, aRecPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.BadAuthKey.selector);
        vault.rotateAuthKeys(vid, alice, address(0xBB), dl, sig);
    }

    function test_OpenVault_RevertIfAuthKeysEqual() public {
        AnchorVaultV45.VaultParams memory p = AnchorVaultV45.VaultParams({
            name: "BadKeys", mainAuthKey: aMain, recoveryAuthKey: aMain, amount: 100 ether
        });
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.BadAuthKey.selector);
        vault.openVault(address(ancr), p, 0);
    }

    function test_OpenVault_RevertIfMainKeyZero() public {
        AnchorVaultV45.VaultParams memory p = AnchorVaultV45.VaultParams({
            name: "BadKeys", mainAuthKey: address(0), recoveryAuthKey: aRec, amount: 100 ether
        });
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.BadAuthKey.selector);
        vault.openVault(address(ancr), p, 0);
    }

    function test_OpenVault_RevertIfRecoveryKeyZero() public {
        AnchorVaultV45.VaultParams memory p = AnchorVaultV45.VaultParams({
            name: "BadKeys", mainAuthKey: aMain, recoveryAuthKey: address(0), amount: 100 ether
        });
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.BadAuthKey.selector);
        vault.openVault(address(ancr), p, 0);
    }

    function test_OpenVault_RevertIfMainKeyEqualsContract() public {
        AnchorVaultV45.VaultParams memory p = AnchorVaultV45.VaultParams({
            name: "BadKeys", mainAuthKey: address(vault), recoveryAuthKey: aRec, amount: 100 ether
        });
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.BadAuthKey.selector);
        vault.openVault(address(ancr), p, 0);
    }

    // ────────────────────────────────────────────────────────────
    // Withdraw
    // ────────────────────────────────────────────────────────────

    function test_Withdraw_HappyPath() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        uint256 amount = 10 ether;
        bytes memory sig = _signWithdraw(alice, vid, amount, alice, nonce, dl, aMainPk);
        uint256 balBefore = ancr.balanceOf(alice);
        vm.prank(alice);
        vault.withdrawFromVault(vid, amount, alice, dl, sig);
        uint256 balAfter = ancr.balanceOf(alice);
        uint256 fee = (amount * 50) / 10000;
        uint256 expected = amount - fee;
        _approxEq(balAfter - balBefore, expected, _tol(expected));
    }

    function test_Withdraw_RevertIfExceedsBalance() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signWithdraw(alice, vid, 101 ether, alice, nonce, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.InvalidAmount.selector);
        vault.withdrawFromVault(vid, 101 ether, alice, dl, sig);
    }

    function test_Withdraw_RevertIfToIsVault() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signWithdraw(alice, vid, 1 ether, address(vault), nonce, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.InvalidAddress.selector);
        vault.withdrawFromVault(vid, 1 ether, address(vault), dl, sig);
    }

    function test_Withdraw_RevertIfExpired() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signWithdraw(alice, vid, 1 ether, alice, nonce, dl, aMainPk);
        vm.warp(block.timestamp + 2 hours);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.SignatureExpired.selector);
        vault.withdrawFromVault(vid, 1 ether, alice, dl, sig);
    }

    function test_Withdraw_RevertIfReplay() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signWithdraw(alice, vid, 1 ether, alice, nonce, dl, aMainPk);
        vm.prank(alice);
        vault.withdrawFromVault(vid, 1 ether, alice, dl, sig);
        vm.expectRevert(AnchorVaultV45.BadSignature.selector);
        vm.prank(alice);
        vault.withdrawFromVault(vid, 1 ether, alice, dl, sig);
    }

    function test_Withdraw_RevertZeroAmount() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signWithdraw(alice, vid, 0, alice, nonce, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.InvalidAmount.selector);
        vault.withdrawFromVault(vid, 0, alice, dl, sig);
    }

    function test_Withdraw_RevertExceedsBalance() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (,, uint120 amt,,,) = vault.getVaultCore(alice, vid);
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        uint256 tooMuch = uint256(amt) + 1;
        bytes memory sig = _signWithdraw(alice, vid, tooMuch, alice, n, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.InvalidAmount.selector);
        vault.withdrawFromVault(vid, tooMuch, alice, dl, sig);
    }

    function test_Withdraw_ToZeroAddressReverts() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signWithdraw(alice, vid, 1 ether, address(0), nonce, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.InvalidAddress.selector);
        vault.withdrawFromVault(vid, 1 ether, address(0), dl, sig);
    }

    function test_WithdrawFullVaultClearsActiveVaultId() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        assertEq(vault.activeVaultIdByToken(alice, address(ancr)), vid);
        (, , uint120 amt, , , ) = vault.getVaultCore(alice, vid);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signWithdraw(alice, vid, uint256(amt), alice, nonce, dl, aMainPk);
        vm.prank(alice);
        vault.withdrawFromVault(vid, uint256(amt), alice, dl, sig);
        assertEq(vault.activeVaultIdByToken(alice, address(ancr)), 0);
    }

    function test_Withdraw_RevertBadSig() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signWithdraw(alice, vid, 1 ether, alice, n, dl, aRecPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.BadSignature.selector);
        vault.withdrawFromVault(vid, 1 ether, alice, dl, sig);
    }

    function test_Withdraw_RevertReplayNonce() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signWithdraw(alice, vid, 1 ether, alice, n, dl, aMainPk);
        vm.prank(alice);
        vault.withdrawFromVault(vid, 1 ether, alice, dl, sig);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.BadSignature.selector);
        vault.withdrawFromVault(vid, 1 ether, alice, dl, sig);
    }

    function test_Withdraw_RevertWhenVoluntaryLocked() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        uint256 lockUntil = block.timestamp + 2 days;
        bytes memory lsig = _signSetVoluntaryLock(alice, vid, lockUntil, n, dl, aMainPk);
        vm.prank(alice);
        vault.setVoluntaryLock(vid, lockUntil, dl, lsig);
        (uint64 n2,,) = vault.getVaultAuth(alice, vid);
        bytes memory wsig = _signWithdraw(alice, vid, 1 ether, alice, n2, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.Locked.selector);
        vault.withdrawFromVault(vid, 1 ether, alice, dl, wsig);
    }

    // ────────────────────────────────────────────────────────────
    // EarlyClose / Recover / EmergencyAny / Panic
    // ────────────────────────────────────────────────────────────

    function test_EarlyClose_HappyPath() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signEarlyClose(alice, vid, nonce, dl, aRecPk);
        uint256 balBefore = ancr.balanceOf(alice);
        vm.prank(alice);
        vault.earlyClose(vid, dl, sig);
        uint256 balAfter = ancr.balanceOf(alice);
        uint256 penalty = (100 ether * 500) / 10000;
        uint256 expected = 100 ether - penalty;
        _approxEq(balAfter - balBefore, expected, _tol(expected));
    }

    function test_EarlyClose_RevertIfSignedByMainKey() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signEarlyClose(alice, vid, nonce, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.BadSignature.selector);
        vault.earlyClose(vid, dl, sig);
    }

    function test_EarlyClose_RevertNotActive_AfterClose() public {
        uint256 vid = _openAliceVault(10_000 ether, 0);
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig1 = _signEarlyClose(alice, vid, n, dl, aRecPk);
        vm.prank(alice);
        vault.earlyClose(vid, dl, sig1);
        (uint64 n2,,) = vault.getVaultAuth(alice, vid);
        bytes memory sig2 = _signEarlyClose(alice, vid, n2, dl, aRecPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.NotActive.selector);
        vault.earlyClose(vid, dl, sig2);
    }

    function test_EarlyClose_RevertExpiredDeadline() public {
        uint256 vid = _openAliceVault(10_000 ether, 0);
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signEarlyClose(alice, vid, n, dl, aRecPk);
        vm.warp(dl + 1);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.SignatureExpired.selector);
        vault.earlyClose(vid, dl, sig);
    }

    function test_RecoverToSafe_HappyPath() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signRecover(alice, vid, nonce, dl, aRecPk);
        uint256 balBefore = ancr.balanceOf(aliceEmergency);
        vm.prank(alice);
        vault.recoverToSafe(vid, dl, sig);
        uint256 balAfter = ancr.balanceOf(aliceEmergency);
        uint256 penalty = (100 ether * 1000) / 10000;
        uint256 expected = 100 ether - penalty;
        _approxEq(balAfter - balBefore, expected, _tol(expected));
    }

    function test_EmergencyWithdrawToAny_HappyPath() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signEmergencyAny(alice, vid, bob, nonce, dl, aRecPk);
        uint256 balBefore = ancr.balanceOf(bob);
        vm.prank(alice);
        vault.emergencyWithdrawToAny(vid, bob, dl, sig);
        uint256 balAfter = ancr.balanceOf(bob);
        uint256 penalty = (100 ether * 1500) / 10000;
        uint256 expected = 100 ether - penalty;
        _approxEq(balAfter - balBefore, expected, _tol(expected));
    }

    function test_PanicWithdraw_HappyPath() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        uint256 balBefore = ancr.balanceOf(aliceEmergency);
        vm.prank(alice);
        vault.panicWithdraw(vid);
        uint256 balAfter = ancr.balanceOf(aliceEmergency);
        uint256 penalty = (100 ether * 2000) / 10000;
        uint256 expected = 100 ether - penalty;
        _approxEq(balAfter - balBefore, expected, _tol(expected));
    }

    function test_PanicWithdraw_RevertNotActive_WhenClosed() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        vm.prank(alice);
        vault.panicWithdraw(vid);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.NotActive.selector);
        vault.panicWithdraw(vid);
    }

    function test_PanicWithdraw_RevertNotActive_WhenFrozen() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        _initSecureAliceToBob(vid);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.NotActive.selector);
        vault.panicWithdraw(vid);
    }

    // ────────────────────────────────────────────────────────────
    // initializeDistribution
    // ────────────────────────────────────────────────────────────

    function test_InitializeDistribution_HappyPath() public {
        ancr.mint(address(vault), 1_000_000 ether);
        uint256 balBeforePayout = ancr.balanceOf(payoutWallet);
        uint256 rewardBefore = vault.rewardPool(address(ancr));
        uint256 reserveBefore = vault.strategicReserve(address(ancr));
        vm.prank(creator);
        vault.initializeDistribution();
        assertTrue(vault.distributionInitialized());
        _approxEq(ancr.balanceOf(payoutWallet) - balBeforePayout, 200_000 ether, _tol(200_000 ether));
        _approxEq(vault.rewardPool(address(ancr)) - rewardBefore, 500_000 ether, _tol(500_000 ether));
        _approxEq(vault.strategicReserve(address(ancr)) - reserveBefore, 300_000 ether, _tol(300_000 ether));
    }

    function test_InitializeDistribution_RevertIfAlreadyInitialized() public {
        ancr.mint(address(vault), 1_000_000 ether);
        vm.prank(creator);
        vault.initializeDistribution();
        vm.prank(creator);
        vm.expectRevert(AnchorVaultV45.AlreadyInitialized.selector);
        vault.initializeDistribution();
    }

    function test_InitializeDistribution_RevertInsufficientBalance() public {
        vm.prank(creator);
        vm.expectRevert(AnchorVaultV45.InsufficientBalanceForDistribution.selector);
        vault.initializeDistribution();
    }

    function test_InitializeDistribution_RevertNotCreator() public {
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.NotCreator.selector);
        vault.initializeDistribution();
    }

    // ────────────────────────────────────────────────────────────
    // depositToVault
    // ────────────────────────────────────────────────────────────

    function test_DepositToVault_HappyPath() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (,, uint120 amountBefore,,,) = vault.getVaultCore(alice, vid);
        vm.prank(alice);
        vault.depositToVault(vid, 50 ether);
        (, , uint120 amountAfter, , , ) = vault.getVaultCore(alice, vid);
        uint256 fee = (50 ether * 20) / 10000;
        uint256 expected = uint256(amountBefore) + 50 ether - fee;
        _approxEq(uint256(amountAfter), expected, _tol(expected));
    }

    function test_DepositToVault_RevertIfBelowMinimum() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.DepositBelowMinimum.selector);
        vault.depositToVault(vid, 10**15);
    }

    function test_DepositToVault_RevertIfClosed() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (, , uint120 amt, , , ) = vault.getVaultCore(alice, vid);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signWithdraw(alice, vid, uint256(amt), alice, nonce, dl, aMainPk);
        vm.prank(alice);
        vault.withdrawFromVault(vid, uint256(amt), alice, dl, sig);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.NotActive.selector);
        vault.depositToVault(vid, 10 ether);
    }

    function test_DepositToVault_RevertAmountExceedsUint120() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        uint256 huge = uint256(type(uint120).max) + 1;
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.AmountExceedsUint120.selector);
        vault.depositToVault(vid, huge);
    }

    function test_DepositToVault_RevertNetBelowMinimum() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        uint256 dep = vault.MIN_DEPOSIT();
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.DepositBelowMinimum.selector);
        vault.depositToVault(vid, dep);
    }

    function test_DepositToVault_RevertWhenFrozen() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        _initSecureAliceToBob(vid);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.NotActive.selector);
        vault.depositToVault(vid, 1_000 ether);
    }

    // ────────────────────────────────────────────────────────────
    // Pause flow
    // ────────────────────────────────────────────────────────────

    function test_Pause_RequestPause() public {
        vm.prank(guardian);
        vault.requestPause();
        vm.warp(block.timestamp + 1 days);
        vm.prank(guardian);
        vm.expectRevert(AnchorVaultV45.PauseTimeoutNotReached.selector);
        vault.executePause();
    }

    function test_Pause_EmergencyPause() public {
        vm.prank(guardian);
        vault.emergencyPause();
        assertTrue(vault.paused());
    }

    function test_Pause_Unpause() public {
        vm.prank(guardian);
        vault.emergencyPause();
        assertTrue(vault.paused());
        vm.prank(creator);
        vault.unpause();
        assertFalse(vault.paused());
    }

    function test_Pause_RevertsOpenVault() public {
        vm.prank(guardian);
        vault.emergencyPause();
        AnchorVaultV45.VaultParams memory p = AnchorVaultV45.VaultParams({
            name: "PausedVault", mainAuthKey: aMain, recoveryAuthKey: aRec, amount: 100 ether
        });
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.ContractPaused.selector);
        vault.openVault(address(ancr), p, 0);
    }

    function test_Pause_PanicWithdrawWorks() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        vm.prank(guardian);
        vault.emergencyPause();
        vm.prank(alice);
        vault.panicWithdraw(vid);
    }

    function test_Pause_WithdrawWorksOnPause() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        vm.prank(guardian);
        vault.emergencyPause();
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signWithdraw(alice, vid, 10 ether, alice, nonce, dl, aMainPk);
        vm.prank(alice);
        vault.withdrawFromVault(vid, 10 ether, alice, dl, sig);
    }

    function test_Pause_CancelPauseRequest() public {
        vm.prank(guardian);
        vault.requestPause();
        assertTrue(vault.pauseTimestamp() > 0);
        vm.prank(guardian);
        vault.cancelPauseRequest();
        assertEq(vault.pauseTimestamp(), 0);
    }

    function test_Pause_EmergencyPauseOnPauseRequest() public {
        vm.prank(guardian);
        vault.requestPause();
        vm.prank(guardian);
        vault.emergencyPause();
        assertTrue(vault.paused());
        assertEq(vault.pauseTimestamp(), 0);
    }

    function test_Pause_ExecuteAfterDelay() public {
        vm.prank(guardian);
        vault.requestPause();
        vm.warp(block.timestamp + vault.PAUSE_DELAY());
        vm.prank(guardian);
        vault.executePause();
        assertTrue(vault.paused());
        assertEq(vault.pauseTimestamp(), 0);
    }

    function test_Pause_RevertExecuteBeforeDelay() public {
        vm.prank(guardian);
        vault.requestPause();
        vm.prank(guardian);
        vm.expectRevert(AnchorVaultV45.PauseTimeoutNotReached.selector);
        vault.executePause();
    }

    function test_Pause_RevertExecuteNoRequest() public {
        vm.prank(guardian);
        vm.expectRevert(AnchorVaultV45.NoPauseRequest.selector);
        vault.executePause();
    }

    function test_Pause_RevertRequestWhenPending() public {
        vm.prank(guardian);
        vault.requestPause();
        vm.prank(guardian);
        vm.expectRevert(AnchorVaultV45.AdminRequestPending.selector);
        vault.requestPause();
    }

    function test_Pause_RevertRequestNotGuardian() public {
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.NotGuardian.selector);
        vault.requestPause();
    }

    function test_Pause_RevertUnpauseNotCreator() public {
        vm.prank(guardian);
        vault.emergencyPause();
        vm.prank(guardian);
        vm.expectRevert(AnchorVaultV45.NotCreator.selector);
        vault.unpause();
    }

    function test_Pause_RevertCancelNoRequest() public {
        vm.prank(guardian);
        vm.expectRevert(AnchorVaultV45.NoPauseRequest.selector);
        vault.cancelPauseRequest();
    }

    function test_Pause_RevertCancelNotGuardian() public {
        vm.prank(creator);
        vm.expectRevert(AnchorVaultV45.NotGuardian.selector);
        vault.cancelPauseRequest();
    }

    // ────────────────────────────────────────────────────────────
    // SecureTransfer — init
    // ────────────────────────────────────────────────────────────

    function _initSecureAliceToBob(uint256 vid) internal returns (uint256 tid) {
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signInitSecure(alice, vid, bob, bMain, bRec, n, dl, aMainPk);
        vm.prank(alice);
        tid = vault.initSecureTransfer(vid, bob, bMain, bRec, dl, sig);
    }

    function test_SecureTransfer_HappyPath() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        address newMain = address(0xBAD1);
        address newRec = address(0xBAD2);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signInitSecure(alice, vid, bob, newMain, newRec, nonce, dl, aMainPk);
        uint256 fee = (100 ether * 50) / 10000;
        uint256 net = 100 ether - fee;
        uint256 lpBefore = vault.lockedPrincipal(address(ancr));
        vm.prank(alice);
        uint256 transferId = vault.initSecureTransfer(vid, bob, newMain, newRec, dl, sig);
        (address from, address to, uint256 stVaultId, uint48 expiresAt, uint8 status) = vault.getSecureTransfer(transferId);
        assertEq(from, alice);
        assertEq(to, bob);
        assertEq(stVaultId, vid);
        assertEq(status, 0);
        assertTrue(expiresAt > block.timestamp);
        vm.prank(bob);
        vault.confirmSecureTransfer(transferId);
        assertEq(vault.activeVaultIdByToken(alice, address(ancr)), 0);
        uint256 bobVid = vault.activeVaultIdByToken(bob, address(ancr));
        assertTrue(bobVid > 0);
        (uint64 bId, address bToken, uint120 bAmount, string memory bName, uint8 bStatus, uint8 bLevel) =
            vault.getVaultCore(bob, bobVid);
        assertEq(bToken, address(ancr));
        _approxEq(uint256(bAmount), net, _tol(net));
        assertEq(bStatus, 0);
        assertEq(bLevel, 0);
        (uint64 bNonce, address gotMain, address gotRec) = vault.getVaultAuth(bob, bobVid);
        assertEq(gotMain, newMain);
        assertEq(gotRec, newRec);
        _approxEq(vault.lockedPrincipal(address(ancr)), lpBefore - fee, _tol(lpBefore));
    }

    function test_SecureTransfer_Cancel() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        address newMain = address(0xBAD1);
        address newRec = address(0xBAD2);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signInitSecure(alice, vid, bob, newMain, newRec, nonce, dl, aMainPk);
        vm.prank(alice);
        uint256 transferId = vault.initSecureTransfer(vid, bob, newMain, newRec, dl, sig);
        (, , , , uint8 statusBefore, ) = vault.getVaultCore(alice, vid);
        assertEq(statusBefore, 1);
        vm.prank(alice);
        vault.cancelSecureTransfer(transferId);
        (, , , , uint8 statusAfter, ) = vault.getVaultCore(alice, vid);
        assertEq(statusAfter, 0);
        assertEq(vault.pendingIncomingTransfer(bob, address(ancr)), 0);
        (, , , , uint8 stStatus) = vault.getSecureTransfer(transferId);
        assertEq(stStatus, 2);
    }

    function test_SecureTransfer_ReclaimExpiredBySender() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        address newMain = address(0xBAD1);
        address newRec = address(0xBAD2);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signInitSecure(alice, vid, bob, newMain, newRec, nonce, dl, aMainPk);
        vm.prank(alice);
        uint256 transferId = vault.initSecureTransfer(vid, bob, newMain, newRec, dl, sig);
        vm.warp(block.timestamp + 48 hours + 1 seconds);
        vm.prank(alice);
        vault.reclaimExpiredTransfer(transferId);
        (, , , , uint8 status, ) = vault.getVaultCore(alice, vid);
        assertEq(status, 0);
        assertEq(vault.pendingIncomingTransfer(bob, address(ancr)), 0);
        (, , , , uint8 stStatus) = vault.getSecureTransfer(transferId);
        assertEq(stStatus, 3);
    }

    function test_SecureTransfer_ReclaimExpiredByRecipient() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        address newMain = address(0xBAD1);
        address newRec = address(0xBAD2);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signInitSecure(alice, vid, bob, newMain, newRec, nonce, dl, aMainPk);
        vm.prank(alice);
        uint256 transferId = vault.initSecureTransfer(vid, bob, newMain, newRec, dl, sig);
        vm.warp(block.timestamp + 48 hours + 1 seconds);
        vm.prank(bob);
        vault.reclaimExpiredTransfer(transferId);
        (, , , , uint8 status, ) = vault.getVaultCore(alice, vid);
        assertEq(status, 0);
        (, , , , uint8 stStatus) = vault.getSecureTransfer(transferId);
        assertEq(stStatus, 3);
    }

    function test_SecureTransfer_AutoCancelIfRecipientHasVault() public {
        uint256 aliceVid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, aliceVid);
        address newMain = address(0xBAD1);
        address newRec = address(0xBAD2);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signInitSecure(alice, aliceVid, bob, newMain, newRec, nonce, dl, aMainPk);
        vm.prank(alice);
        uint256 transferId = vault.initSecureTransfer(aliceVid, bob, newMain, newRec, dl, sig);
        uint256 bobVid = _openBobVault(50 ether, 0);
        vm.prank(bob);
        vault.confirmSecureTransfer(transferId);
        (, , , , uint8 status, ) = vault.getVaultCore(alice, aliceVid);
        assertEq(status, 0);
        (, , , , uint8 stStatus) = vault.getSecureTransfer(transferId);
        assertEq(stStatus, 4);
        assertEq(vault.pendingIncomingTransfer(bob, address(ancr)), 0);
    }

    function test_SecureTransfer_RevertIfConfirmedByWrongAddress() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        address newMain = address(0xBAD1);
        address newRec = address(0xBAD2);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signInitSecure(alice, vid, bob, newMain, newRec, nonce, dl, aMainPk);
        vm.prank(alice);
        uint256 transferId = vault.initSecureTransfer(vid, bob, newMain, newRec, dl, sig);
        address eve = address(0xE55);
        vm.prank(eve);
        vm.expectRevert(AnchorVaultV45.NotTransferRecipient.selector);
        vault.confirmSecureTransfer(transferId);
    }

    function test_InitSecureTransfer_Success() public {
        uint256 vid = _openAliceVault(100 ether, 1);
        uint256 tid = _initSecureAliceToBob(vid);
        (address from, address to,,, uint8 status) = vault.getSecureTransfer(tid);
        assertEq(from, alice);
        assertEq(to, bob);
        assertEq(status, 0);
        (,,,, uint8 vstatus,) = vault.getVaultCore(alice, vid);
        assertEq(vstatus, 1);
        assertEq(vault.pendingIncomingTransfer(bob, address(ancr)), tid);
    }

    function test_InitSecureTransfer_RevertToZero() public {
        uint256 vid = _openAliceVault(100 ether, 1);
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signInitSecure(alice, vid, address(0), bMain, bRec, n, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.InvalidAddress.selector);
        vault.initSecureTransfer(vid, address(0), bMain, bRec, dl, sig);
    }

    function test_InitSecureTransfer_RevertToSelf() public {
        uint256 vid = _openAliceVault(100 ether, 1);
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signInitSecure(alice, vid, alice, bMain, bRec, n, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.InvalidAddress.selector);
        vault.initSecureTransfer(vid, alice, bMain, bRec, dl, sig);
    }

    function test_InitSecureTransfer_RevertRecipientHasVault() public {
        uint256 vid = _openAliceVault(100 ether, 1);
        _openBobVault(100 ether, 1);
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signInitSecure(alice, vid, bob, bMain, bRec, n, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.VaultLimitReached.selector);
        vault.initSecureTransfer(vid, bob, bMain, bRec, dl, sig);
    }

    function test_InitSecureTransfer_RevertNoEmergencyOnRecipient() public {
        uint256 vid = _openAliceVault(100 ether, 1);
        address charlie = makeAddr("charlieNoEm");
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signInitSecure(alice, vid, charlie, bMain, bRec, n, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.NoEmergencySet.selector);
        vault.initSecureTransfer(vid, charlie, bMain, bRec, dl, sig);
    }

    function test_InitSecureTransfer_RevertBadSig() public {
        uint256 vid = _openAliceVault(100 ether, 1);
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signInitSecure(alice, vid, bob, bMain, bRec, n, dl, bMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.BadSignature.selector);
        vault.initSecureTransfer(vid, bob, bMain, bRec, dl, sig);
    }

    function test_InitSecureTransfer_RevertExpiredDeadline() public {
        uint256 vid = _openAliceVault(100 ether, 1);
        vm.warp(10_000);
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = 5_000;
        bytes memory sig = _signInitSecure(alice, vid, bob, bMain, bRec, n, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.SignatureExpired.selector);
        vault.initSecureTransfer(vid, bob, bMain, bRec, dl, sig);
    }

    function test_ConfirmSecureTransfer_Success() public {
        uint256 vid = _openAliceVault(100 ether, 1);
        (,, uint120 amtBefore,,,) = vault.getVaultCore(alice, vid);
        uint256 tid = _initSecureAliceToBob(vid);
        vm.prank(bob);
        vault.confirmSecureTransfer(tid);
        (,,,, uint8 status) = vault.getSecureTransfer(tid);
        assertEq(status, 1);
        assertEq(vault.activeVaultIdByToken(alice, address(ancr)), 0);
        uint256 bobVid = vault.activeVaultIdByToken(bob, address(ancr));
        assertTrue(bobVid != 0);
        uint256 fee = (uint256(amtBefore) * 50) / 10000;
        (,, uint120 bobAmt,,,) = vault.getVaultCore(bob, bobVid);
        assertEq(uint256(bobAmt), uint256(amtBefore) - fee);
    }

    function test_ConfirmSecureTransfer_RevertNotRecipient() public {
        uint256 vid = _openAliceVault(100 ether, 1);
        uint256 tid = _initSecureAliceToBob(vid);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.NotTransferRecipient.selector);
        vault.confirmSecureTransfer(tid);
    }

    function test_ConfirmSecureTransfer_RevertExpired() public {
        uint256 vid = _openAliceVault(100 ether, 1);
        uint256 tid = _initSecureAliceToBob(vid);
        vm.warp(block.timestamp + 48 hours + 1);
        vm.prank(bob);
        vm.expectRevert(AnchorVaultV45.TransferExpired.selector);
        vault.confirmSecureTransfer(tid);
    }

    function test_ConfirmSecureTransfer_RevertNotPending() public {
        uint256 vid = _openAliceVault(100 ether, 1);
        uint256 tid = _initSecureAliceToBob(vid);
        vm.prank(bob);
        vault.confirmSecureTransfer(tid);
        vm.prank(bob);
        vm.expectRevert(AnchorVaultV45.TransferNotPending.selector);
        vault.confirmSecureTransfer(tid);
    }

    function test_ConfirmSecureTransfer_RevertNotFound() public {
        vm.prank(bob);
        vm.expectRevert(AnchorVaultV45.TransferNotFound.selector);
        vault.confirmSecureTransfer(999);
    }

    function test_CancelSecureTransfer_Success() public {
        uint256 vid = _openAliceVault(100 ether, 1);
        uint256 tid = _initSecureAliceToBob(vid);
        vm.prank(alice);
        vault.cancelSecureTransfer(tid);
        (,,,, uint8 status) = vault.getSecureTransfer(tid);
        assertEq(status, 2);
        (,,,, uint8 vstatus,) = vault.getVaultCore(alice, vid);
        assertEq(vstatus, 0);
    }

    function test_CancelSecureTransfer_RevertNotSender() public {
        uint256 vid = _openAliceVault(100 ether, 1);
        uint256 tid = _initSecureAliceToBob(vid);
        vm.prank(bob);
        vm.expectRevert(AnchorVaultV45.NotTransferSender.selector);
        vault.cancelSecureTransfer(tid);
    }

    function test_ReclaimExpiredTransfer_Success() public {
        uint256 vid = _openAliceVault(100 ether, 1);
        uint256 tid = _initSecureAliceToBob(vid);
        vm.warp(block.timestamp + 48 hours + 1);
        vm.prank(alice);
        vault.reclaimExpiredTransfer(tid);
        (,,,, uint8 status) = vault.getSecureTransfer(tid);
        assertEq(status, 3);
        (,,,, uint8 vstatus,) = vault.getVaultCore(alice, vid);
        assertEq(vstatus, 0);
    }

    function test_ReclaimExpiredTransfer_RevertStillValid() public {
        uint256 vid = _openAliceVault(100 ether, 1);
        uint256 tid = _initSecureAliceToBob(vid);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.TransferStillValid.selector);
        vault.reclaimExpiredTransfer(tid);
    }

    function test_ReclaimExpiredTransfer_PermissionlessByThirdParty() public {
        uint256 vid = _openAliceVault(100 ether, 1);
        uint256 tid = _initSecureAliceToBob(vid);
        vm.warp(block.timestamp + 48 hours + 1);
        address charlie = makeAddr("charlieX");
        vm.prank(charlie);
        vault.reclaimExpiredTransfer(tid);
        (, , , , uint8 status, ) = vault.getVaultCore(alice, vid);
        assertEq(status, 0);
    }

    function test_ConfirmSecureTransfer_RaceAutoCancel() public {
        uint256 vid = _openAliceVault(100 ether, 1);
        uint256 tid = _initSecureAliceToBob(vid);
        _openBobVault(100 ether, 1);
        vm.prank(bob);
        vault.confirmSecureTransfer(tid);
        (,,,, uint8 status) = vault.getSecureTransfer(tid);
        assertEq(status, 4);
        assertEq(vault.activeVaultIdByToken(alice, address(ancr)), vid);
        (,,,, uint8 vstatus,) = vault.getVaultCore(alice, vid);
        assertEq(vstatus, 0);
    }

    function test_ConfirmSecureTransfer_RevertWhenPaused() public {
        uint256 vid = _openAliceVault(100 ether, 1);
        uint256 tid = _initSecureAliceToBob(vid);
        vm.prank(guardian);
        vault.emergencyPause();
        vm.prank(bob);
        vm.expectRevert(AnchorVaultV45.ContractPaused.selector);
        vault.confirmSecureTransfer(tid);
    }

    function test_SecureTransfer_RejectByRecipient() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        uint256 tid = _initSecureAliceToBob(vid);
        vm.prank(bob);
        vault.rejectIncomingTransfer(tid);
        (, , , , uint8 stStatus) = vault.getSecureTransfer(tid);
        assertEq(stStatus, 2);
        (,,,, uint8 vstatus,) = vault.getVaultCore(alice, vid);
        assertEq(vstatus, 0);
        assertEq(vault.pendingIncomingTransfer(bob, address(ancr)), 0);
    }

    function test_SecureTransfer_RejectByRecipient_RevertNotRecipient() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        uint256 tid = _initSecureAliceToBob(vid);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.NotTransferRecipient.selector);
        vault.rejectIncomingTransfer(tid);
    }

    function test_SecureTransfer_RejectByRecipient_RevertNotFound() public {
        vm.prank(bob);
        vm.expectRevert(AnchorVaultV45.TransferNotFound.selector);
        vault.rejectIncomingTransfer(999);
    }

    function test_SecureTransfer_RejectByRecipient_RevertNotPending() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        uint256 tid = _initSecureAliceToBob(vid);
        vm.prank(bob);
        vault.rejectIncomingTransfer(tid);
        vm.prank(bob);
        vm.expectRevert(AnchorVaultV45.TransferNotPending.selector);
        vault.rejectIncomingTransfer(tid);
    }

    function test_SecureTransfer_CancelAfterConflict() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        uint256 tid = _initSecureAliceToBob(vid);
        _openBobVault(50 ether, 0);
        vm.prank(bob);
        vault.confirmSecureTransfer(tid);
        (, , , , uint8 stStatus) = vault.getSecureTransfer(tid);
        assertEq(stStatus, 4);
        vm.prank(alice);
        vault.cancelSecureTransfer(tid);
        (, , , , stStatus) = vault.getSecureTransfer(tid);
        assertEq(stStatus, 2);
    }

    function test_SecureTransfer_ReclaimExpiredAfterConflict() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        uint256 tid = _initSecureAliceToBob(vid);
        _openBobVault(50 ether, 0);
        vm.prank(bob);
        vault.confirmSecureTransfer(tid);
        (, , , , uint8 stStatus) = vault.getSecureTransfer(tid);
        assertEq(stStatus, 4);
        vm.warp(block.timestamp + 48 hours + 1);
        vm.prank(alice);
        vault.reclaimExpiredTransfer(tid);
        (, , , , stStatus) = vault.getSecureTransfer(tid);
        assertEq(stStatus, 3);
    }

    function test_SecureTransfer_ConfirmFeeSplit() public {
        uint256 vid = _openAliceVault(10_000 ether, 1);
        (, , uint120 P, , , uint8 lvl) = vault.getVaultCore(alice, vid);
        uint256 tid = _initSecureAliceToBob(vid);
        uint256 fee = uint256(P) * vault.SECURE_TRANSFER_FEE_BPS() / 10000;
        uint256 net = uint256(P) - fee;
        uint256 expBurn    = fee * vault.PEN_BURN_BPS_ANCR()    / 10000;
        uint256 expCreator = fee * vault.PEN_CREATOR_BPS_ANCR() / 10000;
        uint256 expReserve = fee * vault.PEN_RESERVE_BPS_ANCR() / 10000;
        uint256 expRewards = fee - (expBurn + expCreator + expReserve);
        uint256 vaultBalBefore = ancr.balanceOf(address(vault));
        uint256 lockedBefore   = vault.lockedPrincipal(address(ancr));
        uint256 creatorBefore  = vault.creatorFees(address(ancr));
        uint256 reserveBefore  = vault.strategicReserve(address(ancr));
        uint256 poolBefore     = vault.rewardPool(address(ancr));
        uint256 burnedBefore   = vault.totalBurnedANCR();
        vm.prank(bob);
        vault.confirmSecureTransfer(tid);
        assertEq(vault.activeVaultIdByToken(alice, address(ancr)), 0);
        uint256 bobVid = vault.activeVaultIdByToken(bob, address(ancr));
        assertTrue(bobVid != 0);
        (, , uint120 bobAmt, , uint8 bobSt, uint8 bobLvl) = vault.getVaultCore(bob, bobVid);
        assertEq(uint256(bobAmt), net);
        assertEq(bobSt, 0);
        assertEq(bobLvl, lvl);
        assertEq(vaultBalBefore - ancr.balanceOf(address(vault)), expBurn);
        assertEq(lockedBefore - vault.lockedPrincipal(address(ancr)), fee);
        assertEq(vault.creatorFees(address(ancr)) - creatorBefore, expCreator);
        assertEq(vault.strategicReserve(address(ancr)) - reserveBefore, expReserve);
        assertEq(vault.rewardPool(address(ancr)) - poolBefore, expRewards);
        assertEq(vault.totalBurnedANCR() - burnedBefore, expBurn);
    }

    function test_SecureTransfer_ReclaimUnfreezesSource() public {
        uint256 vid = _openAliceVault(10_000 ether, 0);
        (, , uint120 amtBefore, , , ) = vault.getVaultCore(alice, vid);
        uint256 tid = _initSecureAliceToBob(vid);
        (, , , , uint8 stFrozen, ) = vault.getVaultCore(alice, vid);
        assertEq(stFrozen, 1);
        vm.warp(block.timestamp + 48 hours + 1);
        vm.prank(alice);
        vault.reclaimExpiredTransfer(tid);
        (, , uint120 amtAfter, , uint8 stAfter, ) = vault.getVaultCore(alice, vid);
        assertEq(stAfter, 0);
        assertEq(uint256(amtAfter), uint256(amtBefore));
        (, , , , uint8 tStatus) = vault.getSecureTransfer(tid);
        assertEq(tStatus, 3);
    }

    // ────────────────────────────────────────────────────────────
    // TransferVault
    // ────────────────────────────────────────────────────────────

    function test_TransferVault_HappyPath() public {
        uint256 vid = _openAliceVault(100 ether, 1);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        address newMain = address(0xCAFE1);
        address newRec = address(0xCAFE2);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signTransfer(alice, vid, bob, newMain, newRec, nonce, dl, aMainPk);
        uint256 lpBefore = vault.lockedPrincipal(address(ancr));
        vm.prank(alice);
        vault.transferVault(vid, bob, newMain, newRec, dl, sig);
        assertEq(vault.activeVaultIdByToken(alice, address(ancr)), 0);
        vm.expectRevert(AnchorVaultV45.BadVaultId.selector);
        vault.getVaultCore(alice, vid);
        uint256 bobVid = vault.activeVaultIdByToken(bob, address(ancr));
        assertTrue(bobVid > 0);
        uint256 fee = (100 ether * 50) / 10000;
        uint256 net = 100 ether - fee;
        (uint64 bId, address bToken, uint120 bAmount, string memory bName, uint8 bStatus, uint8 bLevel) =
            vault.getVaultCore(bob, bobVid);
        assertEq(bToken, address(ancr));
        _approxEq(uint256(bAmount), net, _tol(net));
        assertEq(bStatus, 0);
        assertEq(bLevel, 1);
        (uint64 bNonce, address gotMain, address gotRec) = vault.getVaultAuth(bob, bobVid);
        assertEq(gotMain, newMain);
        assertEq(gotRec, newRec);
        _approxEq(vault.lockedPrincipal(address(ancr)), lpBefore - fee, _tol(lpBefore));
    }

    function test_TransferVault_RevertIfRecipientHasVault() public {
        uint256 vid = _openAliceVault(100 ether, 1);
        _openBobVault(50 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        address newMain = address(0xCAFE1);
        address newRec = address(0xCAFE2);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signTransfer(alice, vid, bob, newMain, newRec, nonce, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.VaultLimitReached.selector);
        vault.transferVault(vid, bob, newMain, newRec, dl, sig);
    }

    function test_TransferVault_RevertSelf() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        address nm = makeAddr("m_self");
        address nr = makeAddr("r_self");
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signTransfer(alice, vid, alice, nm, nr, n, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.InvalidAddress.selector);
        vault.transferVault(vid, alice, nm, nr, dl, sig);
    }

    function test_TransferVault_RevertRecipientNoEmergency() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        address charlie = makeAddr("charlieNoEmTransfer");
        address nm = makeAddr("m_chr");
        address nr = makeAddr("r_chr");
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signTransfer(alice, vid, charlie, nm, nr, n, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.NoEmergencySet.selector);
        vault.transferVault(vid, charlie, nm, nr, dl, sig);
    }

    function test_TransferVault_RevertBadSignature() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        address nm = makeAddr("m_bad");
        address nr = makeAddr("r_bad");
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signTransfer(alice, vid, bob, nm, nr, n, dl, aRecPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.BadSignature.selector);
        vault.transferVault(vid, bob, nm, nr, dl, sig);
    }

    function test_TransferVault_FeeSplit_AndAccounting() public {
        uint256 vid = _openAliceVault(10_000 ether, 1);
        (, , uint120 P, , , uint8 lvl) = vault.getVaultCore(alice, vid);
        uint256 fee        = uint256(P) * vault.TRANSFER_FEE_BPS() / 10000;
        uint256 net        = uint256(P) - fee;
        uint256 expBurn    = fee * vault.PEN_BURN_BPS_ANCR()    / 10000;
        uint256 expCreator = fee * vault.PEN_CREATOR_BPS_ANCR() / 10000;
        uint256 expReserve = fee * vault.PEN_RESERVE_BPS_ANCR() / 10000;
        uint256 expRewards = fee - (expBurn + expCreator + expReserve);
        uint256 vaultBefore   = ancr.balanceOf(address(vault));
        uint256 lockedBefore  = vault.lockedPrincipal(address(ancr));
        uint256 creatorBefore = vault.creatorFees(address(ancr));
        uint256 reserveBefore = vault.strategicReserve(address(ancr));
        uint256 poolBefore    = vault.rewardPool(address(ancr));
        uint256 burnedBefore  = vault.totalBurnedANCR();
        address nm = makeAddr("bobNewMain");
        address nr = makeAddr("bobNewRec");
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signTransfer(alice, vid, bob, nm, nr, n, dl, aMainPk);
        vm.expectEmit(true, true, false, false);
        emit AnchorVaultV45.VaultTransferred(alice, bob, vid, 0);
        vm.prank(alice);
        vault.transferVault(vid, bob, nm, nr, dl, sig);
        assertEq(vault.activeVaultIdByToken(alice, address(ancr)), 0);
        uint256 bobVid = vault.activeVaultIdByToken(bob, address(ancr));
        assertTrue(bobVid != 0);
        (, , uint120 bobAmt, , uint8 bobStatus, uint8 bobLvl) = vault.getVaultCore(bob, bobVid);
        assertEq(uint256(bobAmt), net);
        assertEq(bobStatus, 0);
        assertEq(bobLvl, lvl);
        (, address bobMain, address bobRec) = vault.getVaultAuth(bob, bobVid);
        assertEq(bobMain, nm);
        assertEq(bobRec, nr);
        assertEq(vaultBefore - ancr.balanceOf(address(vault)), expBurn);
        assertEq(lockedBefore - vault.lockedPrincipal(address(ancr)), fee);
        assertEq(vault.creatorFees(address(ancr)) - creatorBefore, expCreator);
        assertEq(vault.strategicReserve(address(ancr)) - reserveBefore, expReserve);
        assertEq(vault.rewardPool(address(ancr)) - poolBefore, expRewards);
        assertEq(vault.totalBurnedANCR() - burnedBefore, expBurn);
    }

    // ────────────────────────────────────────────────────────────
    // Creator/Reserve Withdraw
    // ────────────────────────────────────────────────────────────

    function test_CreatorWithdraw_FullFlow() public {
        uint256 vid = _openAliceVault(1000 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signEarlyClose(alice, vid, nonce, dl, aRecPk);
        vm.prank(alice);
        vault.earlyClose(vid, dl, sig);
        uint256 cf = vault.creatorFees(address(ancr));
        assertTrue(cf > 0);
        uint256 withdrawAmount = cf / 2;
        vm.prank(creator);
        vault.requestCreatorWithdraw(address(ancr), creator, withdrawAmount);
        vm.warp(block.timestamp + 7 days + 1);
        uint256 balBefore = ancr.balanceOf(creator);
        vm.prank(creator);
        vault.withdrawCreatorFees(address(ancr));
        uint256 balAfter = ancr.balanceOf(creator);
        _approxEq(balAfter - balBefore, withdrawAmount, _tol(withdrawAmount));
        _approxEq(vault.creatorFees(address(ancr)), cf - withdrawAmount, _tol(cf));
    }

    function test_CreatorWithdraw_RevertIfNotExpired() public {
        uint256 vid = _openAliceVault(1000 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signEarlyClose(alice, vid, nonce, dl, aRecPk);
        vm.prank(alice);
        vault.earlyClose(vid, dl, sig);
        uint256 cf = vault.creatorFees(address(ancr));
        assertTrue(cf > 0);
        vm.prank(creator);
        vault.requestCreatorWithdraw(address(ancr), creator, cf);
        vm.warp(block.timestamp + 3 days);
        vm.prank(creator);
        vm.expectRevert(AnchorVaultV45.TimelockNotExpired.selector);
        vault.withdrawCreatorFees(address(ancr));
    }

    function test_CreatorWithdraw_Cancel() public {
        uint256 vid = _openAliceVault(1000 ether, 0);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signEarlyClose(alice, vid, nonce, dl, aRecPk);
        vm.prank(alice);
        vault.earlyClose(vid, dl, sig);
        uint256 cf = vault.creatorFees(address(ancr));
        assertTrue(cf > 0);
        vm.prank(creator);
        vault.requestCreatorWithdraw(address(ancr), creator, cf);
        assertTrue(vault.creatorWithdrawalUnlock(address(ancr)) > 0);
        assertEq(vault.creatorWithdrawalTo(address(ancr)), creator);
        _approxEq(vault.creatorWithdrawalAmount(address(ancr)), cf, _tol(cf));
        vm.prank(creator);
        vault.cancelCreatorWithdraw(address(ancr));
        assertEq(vault.creatorWithdrawalUnlock(address(ancr)), 0);
        assertEq(vault.creatorWithdrawalTo(address(ancr)), address(0));
        assertEq(vault.creatorWithdrawalAmount(address(ancr)), 0);
        _approxEq(vault.creatorFees(address(ancr)), cf, _tol(cf));
    }

    function test_CreatorWithdraw_RevertAmountExceedsFees() public {
        _openAliceVault(10_000 ether, 0);
        uint256 fees = vault.creatorFees(address(ancr));
        address dest = makeAddr("cwDest");
        vm.prank(creator);
        vm.expectRevert(AnchorVaultV45.InvalidAmount.selector);
        vault.requestCreatorWithdraw(address(ancr), dest, fees + 1);
    }

    function test_CreatorWithdraw_RevertToZeroAddress() public {
        _openAliceVault(10_000 ether, 0);
        vm.prank(creator);
        vm.expectRevert(AnchorVaultV45.ZeroAddress.selector);
        vault.requestCreatorWithdraw(address(ancr), address(0), 1);
    }

    function test_CreatorWithdraw_RevertRequestPending() public {
        _openAliceVault(10_000 ether, 0);
        address dest = makeAddr("cwDest2");
        vm.prank(creator);
        vault.requestCreatorWithdraw(address(ancr), dest, 1 ether);
        vm.prank(creator);
        vm.expectRevert(AnchorVaultV45.AdminRequestPending.selector);
        vault.requestCreatorWithdraw(address(ancr), dest, 1 ether);
    }

    function test_CreatorWithdraw_RevertWithdrawNoRequest() public {
        vm.prank(creator);
        vm.expectRevert(AnchorVaultV45.NoAdminRequest.selector);
        vault.withdrawCreatorFees(address(ancr));
    }

    function test_CreatorWithdraw_RevertNotCreator() public {
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.NotCreator.selector);
        vault.requestCreatorWithdraw(address(ancr), alice, 1);
    }

    function test_ReserveWithdraw_FullFlow() public {
        ancr.mint(address(vault), 1_000_000 ether);
        vm.prank(creator);
        vault.initializeDistribution();
        uint256 reserveBefore = vault.strategicReserve(address(ancr));
        _approxEq(reserveBefore, 300_000 ether, _tol(300_000 ether));
        uint256 withdrawAmount = 100_000 ether;
        vm.prank(creator);
        vault.requestReserveWithdraw(address(ancr), creator, withdrawAmount);
        vm.warp(block.timestamp + 7 days + 1);
        uint256 balBefore = ancr.balanceOf(creator);
        vm.prank(creator);
        vault.withdrawStrategicReserve(address(ancr));
        uint256 balAfter = ancr.balanceOf(creator);
        _approxEq(balAfter - balBefore, withdrawAmount, _tol(withdrawAmount));
        _approxEq(vault.strategicReserve(address(ancr)), reserveBefore - withdrawAmount, _tol(reserveBefore));
    }

    function test_ReserveWithdraw_Cancel() public {
        ancr.mint(address(vault), 1_000_000 ether);
        vm.prank(creator);
        vault.initializeDistribution();
        uint256 rs = vault.strategicReserve(address(ancr));
        vm.prank(creator);
        vault.requestReserveWithdraw(address(ancr), creator, rs);
        assertTrue(vault.reserveWithdrawalUnlock(address(ancr)) > 0);
        vm.prank(creator);
        vault.cancelReserveWithdraw(address(ancr));
        assertEq(vault.reserveWithdrawalUnlock(address(ancr)), 0);
        assertEq(vault.reserveWithdrawalTo(address(ancr)), address(0));
        assertEq(vault.reserveWithdrawalAmount(address(ancr)), 0);
        _approxEq(vault.strategicReserve(address(ancr)), rs, _tol(rs));
    }

    function test_ReserveWithdraw_RevertIfNotExpired() public {
        _openAliceVault(10_000 ether, 0);
        address dest = makeAddr("rwDest");
        vm.prank(creator);
        vault.requestReserveWithdraw(address(ancr), dest, 1 ether);
        vm.prank(creator);
        vm.expectRevert(AnchorVaultV45.TimelockNotExpired.selector);
        vault.withdrawStrategicReserve(address(ancr));
    }

    function test_ReserveWithdraw_RevertAmountExceedsReserve() public {
        _openAliceVault(10_000 ether, 0);
        uint256 reserve = vault.strategicReserve(address(ancr));
        address dest = makeAddr("rwDest2");
        vm.prank(creator);
        vm.expectRevert(AnchorVaultV45.InvalidAmount.selector);
        vault.requestReserveWithdraw(address(ancr), dest, reserve + 1);
    }

    function test_ReserveWithdraw_RevertWithdrawNoRequest() public {
        vm.prank(creator);
        vm.expectRevert(AnchorVaultV45.NoAdminRequest.selector);
        vault.withdrawStrategicReserve(address(ancr));
    }

    function test_ReserveWithdraw_RevertRequestPending() public {
        _openAliceVault(10_000 ether, 0);
        address dest = makeAddr("rwDest3");
        vm.prank(creator);
        vault.requestReserveWithdraw(address(ancr), dest, 1 ether);
        vm.prank(creator);
        vm.expectRevert(AnchorVaultV45.AdminRequestPending.selector);
        vault.requestReserveWithdraw(address(ancr), dest, 1 ether);
    }

    // ────────────────────────────────────────────────────────────
    // RescueERC20
    // ────────────────────────────────────────────────────────────

    function test_RescueERC20_RevertIfANCR() public {
        vm.prank(creator);
        vm.expectRevert(AnchorVaultV45.InvalidAddress.selector);
        vault.rescueERC20(address(ancr), creator, 1 ether);
    }

    function test_RescueERC20_RevertIfNotCreator() public {
        address fakeToken = address(0x1234);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.NotCreator.selector);
        vault.rescueERC20(fakeToken, alice, 1 ether);
    }

    function test_RescueERC20_RevertIfZeroAmount() public {
        address fakeToken = address(0x1234);
        vm.prank(creator);
        vm.expectRevert(AnchorVaultV45.InvalidAmount.selector);
        vault.rescueERC20(fakeToken, creator, 0);
    }

    function test_RescueERC20_HappyPath_Surplus() public {
        MockANCR other = new MockANCR(0);
        other.mint(address(vault), 5 ether);
        uint256 toBefore = other.balanceOf(creator);
        vm.prank(creator);
        vault.rescueERC20(address(other), creator, 5 ether);
        assertEq(other.balanceOf(creator) - toBefore, 5 ether);
        assertEq(other.balanceOf(address(vault)), 0);
    }

    function test_RescueERC20_RevertIfExceedsSurplus() public {
        MockANCR other = new MockANCR(0);
        other.mint(address(vault), 100 ether);
        vm.prank(creator);
        vm.expectRevert();
        vault.rescueERC20(address(other), creator, 100 ether + 1);
    }

    function test_RescueERC20_CannotTouchPrincipal() public {
        MockANCR other = new MockANCR(0);
        vm.prank(creator);
        vault.addSupportedToken(address(other));
        other.mint(alice, 200 ether);
        vm.prank(alice);
        other.approve(address(vault), type(uint256).max);
        AnchorVaultV45.VaultParams memory p = AnchorVaultV45.VaultParams({
            name: "OtherVault", mainAuthKey: aMain, recoveryAuthKey: aRec, amount: 100 ether
        });
        vm.prank(alice);
        vault.openVault(address(other), p, 0);
        other.mint(address(vault), 5 ether);
        vm.prank(creator);
        vault.rescueERC20(address(other), creator, 5 ether);
    }

    // ────────────────────────────────────────────────────────────
    // Unsupported token operations
    // ────────────────────────────────────────────────────────────

    function test_OpenVault_RevertIfTokenNotSupported() public {
        address unsupportedToken = address(0xDEAD);
        AnchorVaultV45.VaultParams memory p = AnchorVaultV45.VaultParams({
            name: "BadToken", mainAuthKey: aMain, recoveryAuthKey: aRec, amount: 100 ether
        });
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.TokenNotSupported.selector);
        vault.openVault(unsupportedToken, p, 0);
    }

    function test_DonateToRewardPool_RevertIfTokenNotSupported() public {
        address unsupportedToken = address(0xDEAD);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.TokenNotSupported.selector);
        vault.donateToRewardPool(unsupportedToken, 100 ether);
    }

    // ────────────────────────────────────────────────────────────
    // Role transfer
    // ────────────────────────────────────────────────────────────

    function test_TransferCreatorship_HappyPath() public {
        address newCreator = address(0xCAFE);
        vm.prank(creator);
        vault.transferCreatorship(newCreator);
        assertEq(vault.pendingCreator(), newCreator);
        vm.warp(block.timestamp + 7 days + 1);
        vm.prank(newCreator);
        vault.acceptCreatorship();
        assertEq(vault.creator(), newCreator);
    }

    function test_TransferCreatorship_RevertIfGuardian() public {
        vm.prank(creator);
        vm.expectRevert(AnchorVaultV45.InvalidAddress.selector);
        vault.transferCreatorship(guardian);
    }

    function test_TransferCreatorship_RevertIfAcceptTooEarly() public {
        address newCreator = address(0xCAFE);
        vm.prank(creator);
        vault.transferCreatorship(newCreator);
        vm.warp(block.timestamp + 3 days);
        vm.prank(newCreator);
        vm.expectRevert(AnchorVaultV45.CooldownNotExpired.selector);
        vault.acceptCreatorship();
    }

    function test_TransferCreatorship_RevertToZero() public {
        vm.prank(creator);
        vm.expectRevert(AnchorVaultV45.ZeroAddress.selector);
        vault.transferCreatorship(address(0));
    }

    function test_TransferCreatorship_Cancel() public {
        address newCreator = makeAddr("newCreator");
        vm.prank(creator);
        vault.transferCreatorship(newCreator);
        assertEq(vault.pendingCreator(), newCreator);
        vm.prank(creator);
        vault.cancelCreatorshipTransfer();
        assertEq(vault.pendingCreator(), address(0));
        assertEq(vault.creatorshipRequestedAt(), 0);
    }

    function test_TransferCreatorship_Cancel_RevertNoPending() public {
        vm.prank(creator);
        vm.expectRevert(AnchorVaultV45.NotPendingRole.selector);
        vault.cancelCreatorshipTransfer();
    }

    function test_TransferCreatorship_Cancel_RevertNotCreator() public {
        address newCreator = makeAddr("newCreatorX");
        vm.prank(creator);
        vault.transferCreatorship(newCreator);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.NotCreator.selector);
        vault.cancelCreatorshipTransfer();
    }

    function test_TransferGuardianship_HappyPath() public {
        address newGuardian = address(0xCAFE);
        vm.prank(creator);
        vault.transferGuardianship(newGuardian);
        assertEq(vault.pendingGuardian(), newGuardian);
        vm.warp(block.timestamp + 2 days + 1);
        vm.prank(newGuardian);
        vault.acceptGuardianship();
        assertEq(vault.guardian(), newGuardian);
    }

    function test_TransferGuardianship_RevertIfCreator() public {
        vm.prank(creator);
        vm.expectRevert(AnchorVaultV45.InvalidAddress.selector);
        vault.transferGuardianship(creator);
    }

    function test_TransferGuardianship_RevertAcceptTooEarly() public {
        address newGuardian = makeAddr("newGuardian2");
        vm.prank(creator);
        vault.transferGuardianship(newGuardian);
        vm.prank(newGuardian);
        vm.expectRevert(AnchorVaultV45.CooldownNotExpired.selector);
        vault.acceptGuardianship();
    }

    function test_TransferGuardianship_Cancel() public {
        address newGuardian = makeAddr("newGuardian");
        vm.prank(creator);
        vault.transferGuardianship(newGuardian);
        assertEq(vault.pendingGuardian(), newGuardian);
        vm.prank(creator);
        vault.cancelGuardianshipTransfer();
        assertEq(vault.pendingGuardian(), address(0));
        assertEq(vault.guardianshipRequestedAt(), 0);
    }

    function test_TransferGuardianship_Cancel_RevertNoPending() public {
        vm.prank(creator);
        vm.expectRevert(AnchorVaultV45.NotPendingRole.selector);
        vault.cancelGuardianshipTransfer();
    }

    function test_TransferGuardianship_Cancel_RevertNotCreator() public {
        address newGuardian = makeAddr("newGuardianX");
        vm.prank(creator);
        vault.transferGuardianship(newGuardian);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.NotCreator.selector);
        vault.cancelGuardianshipTransfer();
    }

    function test_Creatorship_AcceptAfterCooldown_OldLosesAccess() public {
        address newCreator = makeAddr("newCreator");
        vm.prank(creator);
        vault.transferCreatorship(newCreator);
        vm.warp(block.timestamp + vault.CREATOR_COOLDOWN());
        vm.prank(newCreator);
        vault.acceptCreatorship();
        assertEq(vault.creator(), newCreator);
        assertEq(vault.pendingCreator(), address(0));
        vm.prank(creator);
        vm.expectRevert(AnchorVaultV45.NotCreator.selector);
        vault.unpause();
        vm.prank(newCreator);
        vault.unpause();
    }

    function test_Creatorship_RevertAcceptByWrong() public {
        address newCreator = makeAddr("newCreator2");
        vm.prank(creator);
        vault.transferCreatorship(newCreator);
        vm.warp(block.timestamp + vault.CREATOR_COOLDOWN());
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.NotPendingRole.selector);
        vault.acceptCreatorship();
    }

    function test_Guardianship_AcceptAfterCooldown() public {
        address newGuardian = makeAddr("newGuardian");
        vm.prank(creator);
        vault.transferGuardianship(newGuardian);
        vm.warp(block.timestamp + vault.GUARDIAN_COOLDOWN());
        vm.prank(newGuardian);
        vault.acceptGuardianship();
        assertEq(vault.guardian(), newGuardian);
        assertEq(vault.pendingGuardian(), address(0));
    }

    function test_Guardianship_RevertAcceptTooEarly() public {
        address newGuardian = makeAddr("newGuardian2");
        vm.prank(creator);
        vault.transferGuardianship(newGuardian);
        vm.prank(newGuardian);
        vm.expectRevert(AnchorVaultV45.CooldownNotExpired.selector);
        vault.acceptGuardianship();
    }

    function test_Guardianship_RevertAcceptByWrong() public {
        address newGuardian = makeAddr("newGuardian3");
        vm.prank(creator);
        vault.transferGuardianship(newGuardian);
        vm.warp(block.timestamp + vault.GUARDIAN_COOLDOWN());
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.NotPendingRole.selector);
        vault.acceptGuardianship();
    }

    // ────────────────────────────────────────────────────────────
    // Token management
    // ────────────────────────────────────────────────────────────

    function test_AddSupportedToken_HappyPath_EnablesVault() public {
        vm.prank(creator);
        MockANCR other = new MockANCR(1_000_000 ether);
        vm.prank(creator);
        vault.addSupportedToken(address(other));
        assertTrue(vault.supportedTokens(address(other)));
        vm.prank(creator);
        other.transfer(alice, 100_000 ether);
        vm.prank(alice);
        other.approve(address(vault), type(uint256).max);
        AnchorVaultV45.VaultParams memory p = AnchorVaultV45.VaultParams({
            name: "o", mainAuthKey: aMain, recoveryAuthKey: aRec, amount: 10_000 ether
        });
        vm.prank(alice);
        vault.openVault(address(other), p, 0);
        assertTrue(vault.activeVaultIdByToken(alice, address(other)) != 0);
    }

    function test_AddSupportedToken_RevertDecimalsNot18() public {
        address weird = makeAddr("weird6dec");
        vm.mockCall(weird, abi.encodeWithSignature("decimals()"), abi.encode(uint8(6)));
        vm.prank(creator);
        vm.expectRevert(AnchorVaultV45.TokenNotSupported.selector);
        vault.addSupportedToken(weird);
    }

    function test_AddSupportedToken_RevertNotCreator() public {
        address someToken = makeAddr("someToken");
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.NotCreator.selector);
        vault.addSupportedToken(someToken);
    }

    function test_RemoveSupportedToken_RevertIfANCR() public {
        vm.prank(creator);
        vm.expectRevert(AnchorVaultV45.InvalidAddress.selector);
        vault.removeSupportedToken(address(ancr));
    }

    function test_RemoveSupportedToken_BlocksNewVault() public {
        vm.prank(creator);
        MockANCR other = new MockANCR(1_000_000 ether);
        vm.prank(creator);
        vault.addSupportedToken(address(other));
        vm.prank(creator);
        vault.removeSupportedToken(address(other));
        assertFalse(vault.supportedTokens(address(other)));
        AnchorVaultV45.VaultParams memory p = AnchorVaultV45.VaultParams({
            name: "o", mainAuthKey: aMain, recoveryAuthKey: aRec, amount: 10_000 ether
        });
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.TokenNotSupported.selector);
        vault.openVault(address(other), p, 0);
    }

    function test_WasSupported_TracksRemovedTokens() public {
        vm.prank(creator);
        MockANCR other = new MockANCR(1_000_000 ether);
        vm.prank(creator);
        vault.addSupportedToken(address(other));
        assertTrue(vault.wasSupported(address(other)));
        vm.prank(creator);
        vault.removeSupportedToken(address(other));
        assertFalse(vault.supportedTokens(address(other)));
        assertTrue(vault.wasSupported(address(other)));
    }

    // ────────────────────────────────────────────────────────────
    // Edge cases
    // ────────────────────────────────────────────────────────────

    function test_OpenVault_RevertIfNoEmergencySet() public {
        address charlie = makeAddr("charlie");
        AnchorVaultV45.VaultParams memory p = AnchorVaultV45.VaultParams({
            name: "NoEmVault", mainAuthKey: aMain, recoveryAuthKey: aRec, amount: 100 ether
        });
        vm.prank(charlie);
        vm.expectRevert(AnchorVaultV45.NoEmergencySet.selector);
        vault.openVault(address(ancr), p, 0);
    }

    function test_OpenVault_RevertIfAlreadyHasVaultForToken() public {
        _openAliceVault(100 ether, 0);
        AnchorVaultV45.VaultParams memory p = AnchorVaultV45.VaultParams({
            name: "SecondVault", mainAuthKey: aMain, recoveryAuthKey: aRec, amount: 100 ether
        });
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.VaultLimitReached.selector);
        vault.openVault(address(ancr), p, 0);
    }

    function test_OpenVault_RevertBadLevel() public {
        AnchorVaultV45.VaultParams memory p = AnchorVaultV45.VaultParams({
            name: "BadLvl", mainAuthKey: aMain, recoveryAuthKey: aRec, amount: 100 ether
        });
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.InvalidLevel.selector);
        vault.openVault(address(ancr), p, 3);
    }

    function test_OpenVault_RevertAmountExceedsUint120() public {
        uint256 huge = uint256(type(uint120).max) + 1;
        AnchorVaultV45.VaultParams memory p = AnchorVaultV45.VaultParams({
            name: "huge", mainAuthKey: aMain, recoveryAuthKey: aRec, amount: huge
        });
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.AmountExceedsUint120.selector);
        vault.openVault(address(ancr), p, 0);
    }

    function test_OpenVault_RevertBelowMinimum_GrossBelowMin() public {
        uint256 amt = vault.MIN_DEPOSIT() - 1;
        AnchorVaultV45.VaultParams memory p = AnchorVaultV45.VaultParams({
            name: "lo", mainAuthKey: aMain, recoveryAuthKey: aRec, amount: amt
        });
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.DepositBelowMinimum.selector);
        vault.openVault(address(ancr), p, 0);
    }

    function test_OpenVault_RevertBelowMinimum_NetAfterFee() public {
        uint256 amt = vault.MIN_DEPOSIT();
        AnchorVaultV45.VaultParams memory p = AnchorVaultV45.VaultParams({
            name: "net", mainAuthKey: aMain, recoveryAuthKey: aRec, amount: amt
        });
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.DepositBelowMinimum.selector);
        vault.openVault(address(ancr), p, 0);
    }

    function test_OpenVault_NameTooLong() public {
        string memory longName = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        AnchorVaultV45.VaultParams memory p = AnchorVaultV45.VaultParams({
            name: longName, mainAuthKey: aMain, recoveryAuthKey: aRec, amount: 100 ether
        });
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.NameTooLong.selector);
        vault.openVault(address(ancr), p, 0);
    }

    function test_OpenVault_64CharNameAllowed() public {
        string memory exactName = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        AnchorVaultV45.VaultParams memory p = AnchorVaultV45.VaultParams({
            name: exactName, mainAuthKey: aMain, recoveryAuthKey: aRec, amount: 100 ether
        });
        vm.prank(alice);
        vault.openVault(address(ancr), p, 0);
        uint256 vid = vault.activeVaultIdByToken(alice, address(ancr));
        (,,, string memory name,,) = vault.getVaultCore(alice, vid);
        assertEq(bytes(name).length, 64);
    }

    function test_EmergencyWithdrawToAny_RevertToContract() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signEmergencyAny(alice, vid, address(vault), n, dl, aRecPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.InvalidAddress.selector);
        vault.emergencyWithdrawToAny(vid, address(vault), dl, sig);
    }

    function test_EmergencyWithdrawToAny_RevertZeroAddress() public {
        uint256 vid = _openAliceVault(10_000 ether, 0);
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signEmergencyAny(alice, vid, address(0), n, dl, aRecPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.InvalidAddress.selector);
        vault.emergencyWithdrawToAny(vid, address(0), dl, sig);
    }

    function test_TimelockBlocksWithdraw() public {
        uint256 vid = _openAliceVault(100 ether, 1);
        uint256 dl = type(uint256).max;
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        bytes memory sigTl = _signSetTimelock(alice, vid, 48, n, dl, aMainPk);
        vm.prank(alice);
        vault.setTimelock(vid, 48, dl, sigTl);
        (uint64 n2,,) = vault.getVaultAuth(alice, vid);
        bytes memory sigW = _signWithdraw(alice, vid, 10 ether, alice, n2, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.VaultTimelocked.selector);
        vault.withdrawFromVault(vid, 10 ether, alice, dl, sigW);
        vm.warp(block.timestamp + 48 hours + 1);
        (uint64 n3,,) = vault.getVaultAuth(alice, vid);
        bytes memory sigW2 = _signWithdraw(alice, vid, 10 ether, alice, n3, dl, aMainPk);
        vm.prank(alice);
        vault.withdrawFromVault(vid, 10 ether, alice, dl, sigW2);
    }

    function test_DonateToRewardPool_HappyPath() public {
        uint256 rewardBefore = vault.rewardPool(address(ancr));
        uint256 amount = 1000 ether;
        vm.prank(alice);
        vault.donateToRewardPool(address(ancr), amount);
        _approxEq(vault.rewardPool(address(ancr)) - rewardBefore, amount, _tol(amount));
    }

    function test_DonateToRewardPool_RevertZeroAmount() public {
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.InvalidAmount.selector);
        vault.donateToRewardPool(address(ancr), 0);
    }

    function test_DonateToRewardPool_RevertNotANCR() public {
        address weird = makeAddr("weird");
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.TokenNotSupported.selector);
        vault.donateToRewardPool(weird, 100);
    }

    function test_RecoverToSafe_RevertNoEmergencySet() public {
        address charlie = makeAddr("charlieNoEm");
        vm.prank(charlie);
        vm.expectRevert(AnchorVaultV45.NoEmergencySet.selector);
        vault.recoverToSafe(1, type(uint256).max, "");
    }

    function test_PanicWithdraw_RevertNoEmergencySet() public {
        address charlie = makeAddr("charlieNoEm2");
        vm.prank(charlie);
        vm.expectRevert(AnchorVaultV45.NoEmergencySet.selector);
        vault.panicWithdraw(1);
    }

    function test_RecoverToSafe_UsesLiveEmergency() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        address newEm = address(0xCAFE);
        vm.prank(alice);
        vault.proposeGlobalEmergencyChange(newEm);
        vm.warp(block.timestamp + 8 days);
        vm.prank(alice);
        vault.confirmGlobalEmergencyChange();
        assertEq(vault.globalEmergency(alice), newEm);
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signRecover(alice, vid, nonce, dl, aRecPk);
        uint256 newBefore = ancr.balanceOf(newEm);
        uint256 oldBefore = ancr.balanceOf(aliceEmergency);
        vm.prank(alice);
        vault.recoverToSafe(vid, dl, sig);
        assertTrue(ancr.balanceOf(newEm) > newBefore);
        assertEq(ancr.balanceOf(aliceEmergency), oldBefore);
    }

    // ────────────────────────────────────────────────────────────
    // lockedPrincipal invariant checks
    // ────────────────────────────────────────────────────────────

    function test_LockedPrincipal_WithdrawPartial() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        uint256 lpBefore = vault.lockedPrincipal(address(ancr));
        _approxEq(lpBefore, 100 ether, _tol(100 ether));
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signWithdraw(alice, vid, 30 ether, alice, nonce, dl, aMainPk);
        vm.prank(alice);
        vault.withdrawFromVault(vid, 30 ether, alice, dl, sig);
        uint256 lpAfter = vault.lockedPrincipal(address(ancr));
        _approxEq(lpAfter, 70 ether, _tol(70 ether));
    }

    function test_LockedPrincipal_PanicWithdraw() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (, , uint120 amt, , , ) = vault.getVaultCore(alice, vid);
        uint256 lpBefore = vault.lockedPrincipal(address(ancr));
        vm.prank(alice);
        vault.panicWithdraw(vid);
        uint256 lpAfter = vault.lockedPrincipal(address(ancr));
        assertEq(lpAfter, lpBefore - uint256(amt));
    }

    function test_LockedPrincipal_EarlyClose() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (, , uint120 amt, , , ) = vault.getVaultCore(alice, vid);
        uint256 lpBefore = vault.lockedPrincipal(address(ancr));
        (uint64 nonce,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signEarlyClose(alice, vid, nonce, dl, aRecPk);
        vm.prank(alice);
        vault.earlyClose(vid, dl, sig);
        uint256 lpAfter = vault.lockedPrincipal(address(ancr));
        assertEq(lpAfter, lpBefore - uint256(amt));
    }

    function test_LockedPrincipal_ZeroForUnknownToken() public view {
        assertEq(vault.lockedPrincipal(address(0xDEAD)), 0);
    }

    function test_LockedPrincipal_TracksOpenVault() public {
        uint256 before = vault.lockedPrincipal(address(ancr));
        _openAliceVault(100 ether, 0);
        uint256 afterOpen = vault.lockedPrincipal(address(ancr));
        assertGt(afterOpen, before);
        uint256 net = 100 ether - (100 ether * vault.OPEN_VAULT_FEE_BPS()) / 10000;
        _approxEq(afterOpen - before, net, _tol(net));
    }

    // ────────────────────────────────────────────────────────────
    // Constructor validation
    // ────────────────────────────────────────────────────────────

    function test_Constructor_RevertIfGuardianEqualsDeployer() public {
        vm.expectRevert(AnchorVaultV45.InvalidAddress.selector);
        new AnchorVaultV45(address(ancr), address(this), payoutWallet);
    }

    function test_Constructor_RevertIfZeroAddress() public {
        vm.expectRevert(AnchorVaultV45.ZeroAddress.selector);
        new AnchorVaultV45(address(0), guardian, payoutWallet);
        vm.expectRevert(AnchorVaultV45.ZeroAddress.selector);
        new AnchorVaultV45(address(ancr), address(0), payoutWallet);
        vm.expectRevert(AnchorVaultV45.ZeroAddress.selector);
        new AnchorVaultV45(address(ancr), guardian, address(0));
    }

    function test_Constructor_RevertIfAncrEqualsDeployer() public {
        vm.expectRevert(AnchorVaultV45.InvalidAddress.selector);
        new AnchorVaultV45(address(this), guardian, payoutWallet);
    }

    function test_Constructor_RevertIfPayoutIsContract() public {
        vm.expectRevert(AnchorVaultV45.InvalidAddress.selector);
        new AnchorVaultV45(address(ancr), guardian, address(vault));
    }

    // ────────────────────────────────────────────────────────────
    // Welcome bonus
    // ────────────────────────────────────────────────────────────

    function test_WelcomeBonus_PaidOnFirstVault() public {
        ancr.mint(address(vault), 1_000_000 ether);
        vm.prank(creator);
        vault.initializeDistribution();
        uint256 bonus = 0.005 ether;
        vm.prank(creator);
        vault.setWelcomeBonus(bonus, 100);
        uint256 balBefore = ancr.balanceOf(alice);
        _openAliceVault(100 ether, 0);
        uint256 balAfter = ancr.balanceOf(alice);
        _approxEq(balBefore - balAfter, 100 ether - bonus, _tol(100 ether));
    }

    function test_WelcomeBonus_NotPaidWhenNotConfigured() public {
        uint256 vid = _openBobVault(100 ether, 0);
        assertEq(vault.welcomeBonusClaimed(bob), false);
        assertEq(vault.welcomeBonusClaims(), 0);
    }

    function test_WelcomeBonus_NotPaidWhenPoolInsufficient() public {
        vm.prank(creator);
        vault.setWelcomeBonus(0.005 ether, 1000);
        uint256 balBefore = ancr.balanceOf(bob);
        _openBobVault(1 ether, 0);
        assertEq(vault.welcomeBonusClaimed(bob), false);
        assertEq(vault.welcomeBonusClaims(), 0);
        assertEq(ancr.balanceOf(bob), balBefore - 1 ether);
    }

    function test_WelcomeBonus_RevertExceedsLimit() public {
        uint256 over = vault.MAX_WELCOME_BONUS() + 1;
        vm.prank(creator);
        vm.expectRevert(AnchorVaultV45.BonusExceedsLimit.selector);
        vault.setWelcomeBonus(over, 10);
    }

    function test_WelcomeBonus_OnlyPaidOncePerUser() public {
        ancr.mint(address(vault), 1_000_000 ether);
        vm.prank(creator);
        vault.initializeDistribution();
        vm.prank(creator);
        vault.setWelcomeBonus(0.005 ether, 100);
        _openAliceVault(100 ether, 0);
        assertTrue(vault.welcomeBonusClaimed(alice));
        _openBobVault(100 ether, 0);
        assertTrue(vault.welcomeBonusClaimed(bob));
        assertEq(vault.welcomeBonusClaims(), 2);
    }

    // ────────────────────────────────────────────────────────────
    // Close & Payout — детальное распределение
    // ────────────────────────────────────────────────────────────

    function test_EarlyClose_ANCR_FeeSplit_Full() public {
        uint256 vid = _openAliceVault(10_000 ether, 0);
        (, , uint120 P, , , ) = vault.getVaultCore(alice, vid);
        uint256 penalty    = uint256(P) * vault.EARLY_CLOSE_FEE_BPS() / 10000;
        uint256 payout     = uint256(P) - penalty;
        uint256 expBurn    = penalty * vault.PEN_BURN_BPS_ANCR()    / 10000;
        uint256 expCreator = penalty * vault.PEN_CREATOR_BPS_ANCR() / 10000;
        uint256 expReserve = penalty * vault.PEN_RESERVE_BPS_ANCR() / 10000;
        uint256 expRewards = penalty - (expBurn + expCreator + expReserve);
        uint256 aliceBefore   = ancr.balanceOf(alice);
        uint256 vaultBefore   = ancr.balanceOf(address(vault));
        uint256 creatorBefore = vault.creatorFees(address(ancr));
        uint256 reserveBefore = vault.strategicReserve(address(ancr));
        uint256 poolBefore    = vault.rewardPool(address(ancr));
        uint256 burnedBefore  = vault.totalBurnedANCR();
        uint256 lockedBefore  = vault.lockedPrincipal(address(ancr));
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signEarlyClose(alice, vid, n, dl, aRecPk);
        vm.expectEmit(true, false, false, true);
        emit AnchorVaultV45.VaultEarlyClosed(alice, vid, payout, penalty);
        vm.prank(alice);
        vault.earlyClose(vid, dl, sig);
        assertEq(ancr.balanceOf(alice) - aliceBefore, payout);
        assertEq(vaultBefore - ancr.balanceOf(address(vault)), payout + expBurn);
        assertEq(vault.creatorFees(address(ancr)) - creatorBefore, expCreator);
        assertEq(vault.strategicReserve(address(ancr)) - reserveBefore, expReserve);
        assertEq(vault.rewardPool(address(ancr)) - poolBefore, expRewards);
        assertEq(vault.totalBurnedANCR() - burnedBefore, expBurn);
        assertEq(lockedBefore - vault.lockedPrincipal(address(ancr)), uint256(P));
        (, , uint120 amtAfter, , uint8 stAfter, ) = vault.getVaultCore(alice, vid);
        assertEq(amtAfter, 0);
        assertEq(stAfter, 2);
        assertEq(vault.activeVaultIdByToken(alice, address(ancr)), 0);
        (uint64 n2,,) = vault.getVaultAuth(alice, vid);
        assertEq(n2, n + 1);
    }

    function test_EarlyClose_OtherToken_FeeSplit_NoBurn() public {
        vm.prank(creator);
        MockANCR other = new MockANCR(1_000_000 ether);
        vm.prank(creator);
        vault.addSupportedToken(address(other));
        vm.prank(creator);
        other.transfer(alice, 100_000 ether);
        vm.prank(alice);
        other.approve(address(vault), type(uint256).max);
        AnchorVaultV45.VaultParams memory p = AnchorVaultV45.VaultParams({
            name: "AliceOther", mainAuthKey: aMain, recoveryAuthKey: aRec, amount: 10_000 ether
        });
        vm.prank(alice);
        vault.openVault(address(other), p, 0);
        uint256 vid = vault.activeVaultIdByToken(alice, address(other));
        (, , uint120 P, , , ) = vault.getVaultCore(alice, vid);
        uint256 penalty    = uint256(P) * vault.EARLY_CLOSE_FEE_BPS() / 10000;
        uint256 payout     = uint256(P) - penalty;
        uint256 expCreator = penalty / 2;
        uint256 expReserve = penalty - expCreator;
        uint256 expRewards = penalty - (expCreator + expReserve);
        uint256 burnedBefore  = vault.totalBurnedANCR();
        uint256 creatorBefore = vault.creatorFees(address(other));
        uint256 reserveBefore = vault.strategicReserve(address(other));
        uint256 poolBefore    = vault.rewardPool(address(other));
        uint256 aliceBefore   = other.balanceOf(alice);
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signEarlyClose(alice, vid, n, dl, aRecPk);
        vm.prank(alice);
        vault.earlyClose(vid, dl, sig);
        assertEq(other.balanceOf(alice) - aliceBefore, payout);
        assertEq(vault.creatorFees(address(other)) - creatorBefore, expCreator);
        assertEq(vault.strategicReserve(address(other)) - reserveBefore, expReserve);
        assertEq(vault.rewardPool(address(other)) - poolBefore, expRewards);
        assertEq(vault.totalBurnedANCR(), burnedBefore);
    }

    function test_RecoverToSafe_FeeSplit_PayoutToEmergency() public {
        uint256 vid = _openAliceVault(10_000 ether, 0);
        (, , uint120 P, , , ) = vault.getVaultCore(alice, vid);
        uint256 penalty    = uint256(P) * vault.RECOVER_TO_SAFE_FEE_BPS() / 10000;
        uint256 payout     = uint256(P) - penalty;
        uint256 expBurn    = penalty * vault.PEN_BURN_BPS_ANCR()    / 10000;
        uint256 expCreator = penalty * vault.PEN_CREATOR_BPS_ANCR() / 10000;
        uint256 expReserve = penalty * vault.PEN_RESERVE_BPS_ANCR() / 10000;
        uint256 expRewards = penalty - (expBurn + expCreator + expReserve);
        uint256 emBefore      = ancr.balanceOf(aliceEmergency);
        uint256 creatorBefore = vault.creatorFees(address(ancr));
        uint256 reserveBefore = vault.strategicReserve(address(ancr));
        uint256 poolBefore    = vault.rewardPool(address(ancr));
        uint256 burnedBefore  = vault.totalBurnedANCR();
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signRecover(alice, vid, n, dl, aRecPk);
        vm.expectEmit(true, true, false, true);
        emit AnchorVaultV45.VaultRecovered(alice, vid, aliceEmergency, payout, penalty);
        vm.prank(alice);
        vault.recoverToSafe(vid, dl, sig);
        assertEq(ancr.balanceOf(aliceEmergency) - emBefore, payout);
        assertEq(vault.creatorFees(address(ancr)) - creatorBefore, expCreator);
        assertEq(vault.strategicReserve(address(ancr)) - reserveBefore, expReserve);
        assertEq(vault.rewardPool(address(ancr)) - poolBefore, expRewards);
        assertEq(vault.totalBurnedANCR() - burnedBefore, expBurn);
        (, , uint120 amtAfter, , uint8 st, ) = vault.getVaultCore(alice, vid);
        assertEq(amtAfter, 0);
        assertEq(st, 2);
    }

    function test_RecoverToSafe_RevertBadSignature_MainKey() public {
        uint256 vid = _openAliceVault(10_000 ether, 0);
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signRecover(alice, vid, n, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.BadSignature.selector);
        vault.recoverToSafe(vid, dl, sig);
    }

    function test_EmergencyWithdrawToAny_FeeSplit_PayoutToDest() public {
        uint256 vid = _openAliceVault(10_000 ether, 0);
        address dest = makeAddr("emDest");
        (, , uint120 P, , , ) = vault.getVaultCore(alice, vid);
        uint256 penalty    = uint256(P) * vault.EMERGENCY_ANY_FEE_BPS() / 10000;
        uint256 payout     = uint256(P) - penalty;
        uint256 expBurn    = penalty * vault.PEN_BURN_BPS_ANCR()    / 10000;
        uint256 expCreator = penalty * vault.PEN_CREATOR_BPS_ANCR() / 10000;
        uint256 expReserve = penalty * vault.PEN_RESERVE_BPS_ANCR() / 10000;
        uint256 expRewards = penalty - (expBurn + expCreator + expReserve);
        uint256 destBefore    = ancr.balanceOf(dest);
        uint256 creatorBefore = vault.creatorFees(address(ancr));
        uint256 reserveBefore = vault.strategicReserve(address(ancr));
        uint256 poolBefore    = vault.rewardPool(address(ancr));
        uint256 burnedBefore  = vault.totalBurnedANCR();
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signEmergencyAny(alice, vid, dest, n, dl, aRecPk);
        vm.expectEmit(true, true, false, true);
        emit AnchorVaultV45.EmergencyWithdrawToAny(alice, vid, dest, payout, penalty);
        vm.prank(alice);
        vault.emergencyWithdrawToAny(vid, dest, dl, sig);
        assertEq(ancr.balanceOf(dest) - destBefore, payout);
        assertEq(vault.creatorFees(address(ancr)) - creatorBefore, expCreator);
        assertEq(vault.strategicReserve(address(ancr)) - reserveBefore, expReserve);
        assertEq(vault.rewardPool(address(ancr)) - poolBefore, expRewards);
        assertEq(vault.totalBurnedANCR() - burnedBefore, expBurn);
    }

    function test_PanicWithdraw_FeeSplit_PayoutToGlobalEmergency() public {
        uint256 vid = _openAliceVault(10_000 ether, 0);
        (, , uint120 P, , , ) = vault.getVaultCore(alice, vid);
        uint256 penalty    = uint256(P) * vault.PANIC_FEE_BPS() / 10000;
        uint256 payout     = uint256(P) - penalty;
        uint256 expBurn    = penalty * vault.PEN_BURN_BPS_ANCR()    / 10000;
        uint256 expCreator = penalty * vault.PEN_CREATOR_BPS_ANCR() / 10000;
        uint256 expReserve = penalty * vault.PEN_RESERVE_BPS_ANCR() / 10000;
        uint256 expRewards = penalty - (expBurn + expCreator + expReserve);
        uint256 emBefore      = ancr.balanceOf(aliceEmergency);
        uint256 creatorBefore = vault.creatorFees(address(ancr));
        uint256 reserveBefore = vault.strategicReserve(address(ancr));
        uint256 poolBefore    = vault.rewardPool(address(ancr));
        uint256 burnedBefore  = vault.totalBurnedANCR();
        uint256 lockedBefore  = vault.lockedPrincipal(address(ancr));
        vm.expectEmit(true, true, true, true);
        emit AnchorVaultV45.PanicWithdraw(alice, vid, aliceEmergency, payout, penalty);
        vm.prank(alice);
        vault.panicWithdraw(vid);
        assertEq(ancr.balanceOf(aliceEmergency) - emBefore, payout);
        assertEq(vault.creatorFees(address(ancr)) - creatorBefore, expCreator);
        assertEq(vault.strategicReserve(address(ancr)) - reserveBefore, expReserve);
        assertEq(vault.rewardPool(address(ancr)) - poolBefore, expRewards);
        assertEq(vault.totalBurnedANCR() - burnedBefore, expBurn);
        assertEq(lockedBefore - vault.lockedPrincipal(address(ancr)), uint256(P));
        (, , uint120 amtAfter, , uint8 st, ) = vault.getVaultCore(alice, vid);
        assertEq(amtAfter, 0);
        assertEq(st, 2);
    }

    function test_PanicWithdraw_WhilePaused_PenaltyAllToRewardPool() public {
        uint256 vid = _openAliceVault(10_000 ether, 0);
        (, , uint120 P, , , ) = vault.getVaultCore(alice, vid);
        uint256 penalty = uint256(P) * vault.PANIC_FEE_BPS() / 10000;
        uint256 payout  = uint256(P) - penalty;
        vm.prank(guardian);
        vault.emergencyPause();
        uint256 emBefore      = ancr.balanceOf(aliceEmergency);
        uint256 poolBefore    = vault.rewardPool(address(ancr));
        uint256 creatorBefore = vault.creatorFees(address(ancr));
        uint256 reserveBefore = vault.strategicReserve(address(ancr));
        uint256 burnedBefore  = vault.totalBurnedANCR();
        vm.expectEmit(true, false, false, true);
        emit AnchorVaultV45.PenaltyToRewardPool(address(ancr), penalty);
        vm.prank(alice);
        vault.panicWithdraw(vid);
        assertEq(ancr.balanceOf(aliceEmergency) - emBefore, payout);
        assertEq(vault.rewardPool(address(ancr)) - poolBefore, penalty);
        assertEq(vault.creatorFees(address(ancr)), creatorBefore);
        assertEq(vault.strategicReserve(address(ancr)), reserveBefore);
        assertEq(vault.totalBurnedANCR(), burnedBefore);
    }

    // ────────────────────────────────────────────────────────────
    // Rotate auth keys — поведенческие
    // ────────────────────────────────────────────────────────────

    function test_RotateAuthKeys_NewMainCanWithdraw_OldCannot() public {
        uint256 vid = _openAliceVault(10_000 ether, 0);
        uint256 newMainPk = 0xA11CE1111;
        uint256 newRecPk  = 0xA11CE2222;
        address newMain = vm.addr(newMainPk);
        address newRec  = vm.addr(newRecPk);
        (uint64 n0,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory rsig = _signRotateKeys(alice, vid, newMain, newRec, n0, dl, aRecPk);
        vm.expectEmit(true, false, false, true);
        emit AnchorVaultV45.AuthKeysRotated(alice, vid);
        vm.prank(alice);
        vault.rotateAuthKeys(vid, newMain, newRec, dl, rsig);
        (uint64 n1, address m1, address r1) = vault.getVaultAuth(alice, vid);
        assertEq(m1, newMain);
        assertEq(r1, newRec);
        assertEq(n1, n0 + 1);
        bytes memory badSig  = _signWithdraw(alice, vid, 1 ether, alice, n1, dl, aMainPk);
        bytes memory goodSig = _signWithdraw(alice, vid, 1 ether, alice, n1, dl, newMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.BadSignature.selector);
        vault.withdrawFromVault(vid, 1 ether, alice, dl, badSig);
        vm.prank(alice);
        vault.withdrawFromVault(vid, 1 ether, alice, dl, goodSig);
    }

    function test_RotateAuthKeys_RevertBadSignature_MainKey() public {
        uint256 vid = _openAliceVault(10_000 ether, 0);
        address nm = makeAddr("rotNewMain");
        address nr = makeAddr("rotNewRec");
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signRotateKeys(alice, vid, nm, nr, n, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.BadSignature.selector);
        vault.rotateAuthKeys(vid, nm, nr, dl, sig);
    }

    // ────────────────────────────────────────────────────────────
    // Solvency invariant
    // ────────────────────────────────────────────────────────────

    function test_SolvencyInvariant() public {
        ancr.mint(address(vault), 1_000_000 ether);
        vm.prank(creator);
        vault.initializeDistribution();
        uint256 aVid = _openAliceVault(1000 ether, 1);
        uint256 bVid = _openBobVault(2000 ether, 2);
        (uint64 nonceA,,) = vault.getVaultAuth(alice, aVid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sigA = _signEarlyClose(alice, aVid, nonceA, dl, aRecPk);
        vm.prank(alice);
        vault.earlyClose(aVid, dl, sigA);
        vm.prank(bob);
        vault.panicWithdraw(bVid);
        uint256 bal = ancr.balanceOf(address(vault));
        uint256 lp = vault.lockedPrincipal(address(ancr));
        uint256 cf = vault.creatorFees(address(ancr));
        uint256 rs = vault.strategicReserve(address(ancr));
        uint256 rp = vault.rewardPool(address(ancr));
        assertGe(bal, lp + cf + rs + rp);
    }

    function _assertSolventANCR() internal view {
        uint256 bal = ancr.balanceOf(address(vault));
        uint256 liab = vault.lockedPrincipal(address(ancr))
            + vault.creatorFees(address(ancr))
            + vault.strategicReserve(address(ancr))
            + vault.rewardPool(address(ancr));
        assertGe(bal, liab);
    }

    function test_SolventANCR_AfterOpen() public {
        _openAliceVault(100 ether, 1);
        _assertSolventANCR();
    }

    function test_SolventANCR_AfterDualVaults() public {
        _openAliceVault(100 ether, 1);
        _openBobVault(50 ether, 2);
        _assertSolventANCR();
    }

    function test_SolventANCR_AfterWithdraw() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        uint256 dl = type(uint256).max;
        (uint64 n0,,) = vault.getVaultAuth(alice, vid);
        bytes memory sig = _signWithdraw(alice, vid, 20 ether, alice, n0, dl, aMainPk);
        vm.prank(alice);
        vault.withdrawFromVault(vid, 20 ether, alice, dl, sig);
        _assertSolventANCR();
    }

    function test_SolventANCR_Initial() public view {
        _assertSolventANCR();
    }

    // ────────────────────────────────────────────────────────────
    // Burn to dead address if burn() fails
    // ────────────────────────────────────────────────────────────

    function test_BurnToDeadAddressIfBurnFails() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        uint256 burnedBefore = vault.totalBurnedANCR();
        vm.prank(alice);
        vault.panicWithdraw(vid);
        assertTrue(vault.totalBurnedANCR() > burnedBefore);
    }

    // ────────────────────────────────────────────────────────────
    // Penalty on pause goes to rewardPool
    // ────────────────────────────────────────────────────────────

    function test_PenaltyOnPauseGoesToRewardPool() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (, , uint120 amt, , , ) = vault.getVaultCore(alice, vid);
        vm.prank(guardian);
        vault.emergencyPause();
        uint256 rpBefore = vault.rewardPool(address(ancr));
        vm.prank(alice);
        vault.panicWithdraw(vid);
        uint256 rpAfter = vault.rewardPool(address(ancr));
        uint256 penalty = (uint256(amt) * 2000) / 10000;
        assertEq(rpAfter - rpBefore, penalty);
    }

    // ────────────────────────────────────────────────────────────
    // EIP-712 негативы
    // ────────────────────────────────────────────────────────────

    function test_EIP712_WithdrawExpiredDeadline() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        vm.warp(10_000);
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = 5_000;
        bytes memory sig = _signWithdraw(alice, vid, 1 ether, alice, n, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.SignatureExpired.selector);
        vault.withdrawFromVault(vid, 1 ether, alice, dl, sig);
    }

    function test_EIP712_WithdrawBadSig() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signWithdraw(alice, vid, 1 ether, alice, n, dl, aRecPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.BadSignature.selector);
        vault.withdrawFromVault(vid, 1 ether, alice, dl, sig);
    }

    function test_EIP712_WithdrawReplayNonce() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signWithdraw(alice, vid, 1 ether, alice, n, dl, aMainPk);
        vm.prank(alice);
        vault.withdrawFromVault(vid, 1 ether, alice, dl, sig);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.BadSignature.selector);
        vault.withdrawFromVault(vid, 1 ether, alice, dl, sig);
    }

    function test_EIP712_EarlyCloseWithMainKey() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signEarlyClose(alice, vid, n, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.BadSignature.selector);
        vault.earlyClose(vid, dl, sig);
    }

    function test_EIP712_RotateKeysWithMainKey() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        address nm = makeAddr("newMain");
        address nr = makeAddr("newRec");
        bytes memory sig = _signRotateKeys(alice, vid, nm, nr, n, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.BadSignature.selector);
        vault.rotateAuthKeys(vid, nm, nr, dl, sig);
    }

    function test_EIP712_SetTimelockWithRecoveryKey() public {
        uint256 vid = _openAliceVault(100 ether, 1);
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signSetTimelock(alice, vid, 24, n, dl, aRecPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.BadSignature.selector);
        vault.setTimelock(vid, 24, dl, sig);
    }

    // ────────────────────────────────────────────────────────────
    // Replay & Forgery
    // ────────────────────────────────────────────────────────────

    function test_Replay_WithdrawSigCannotBeReused() public {
        uint256 vid = _openAliceVault(10_000 ether, 0);
        uint256 dl = type(uint256).max;
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        bytes memory sig = _signWithdraw(alice, vid, 100 ether, alice, n, dl, aMainPk);
        vm.prank(alice);
        vault.withdrawFromVault(vid, 100 ether, alice, dl, sig);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.BadSignature.selector);
        vault.withdrawFromVault(vid, 100 ether, alice, dl, sig);
    }

    function test_Forgery_WithdrawTamperedAmount() public {
        uint256 vid = _openAliceVault(10_000 ether, 0);
        uint256 dl = type(uint256).max;
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        bytes memory sig = _signWithdraw(alice, vid, 100 ether, alice, n, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.BadSignature.selector);
        vault.withdrawFromVault(vid, 200 ether, alice, dl, sig);
    }

    function test_Forgery_WithdrawWrongSignerKey() public {
        uint256 vid = _openAliceVault(10_000 ether, 0);
        uint256 dl = type(uint256).max;
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        bytes memory sig = _signWithdraw(alice, vid, 100 ether, alice, n, dl, uint256(0xBADC0FFEE));
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.BadSignature.selector);
        vault.withdrawFromVault(vid, 100 ether, alice, dl, sig);
    }

    function test_CrossChainReplay_WithdrawDifferentChainId() public {
        uint256 vid = _openAliceVault(10_000 ether, 0);
        uint256 dl = type(uint256).max;
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        bytes memory sig = _signWithdraw(alice, vid, 100 ether, alice, n, dl, aMainPk);
        vm.chainId(block.chainid + 1);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.BadSignature.selector);
        vault.withdrawFromVault(vid, 100 ether, alice, dl, sig);
    }

    function test_Forgery_TransferTamperedKeys() public {
        uint256 vid = _openAliceVault(10_000 ether, 0);
        uint256 dl = type(uint256).max;
        address k1 = makeAddr("tk1");
        address k2 = makeAddr("tk2");
        address k3 = makeAddr("tk3");
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        bytes memory sig = _signTransfer(alice, vid, bob, k1, k2, n, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.BadSignature.selector);
        vault.transferVault(vid, bob, k3, k2, dl, sig);
    }

    function test_CrossOwner_CannotUseOthersVaultId() public {
        uint256 aliceVid = _openAliceVault(10_000 ether, 0);
        uint256 dl = type(uint256).max;
        bytes memory sig = _signWithdraw(bob, aliceVid, 1 ether, bob, 0, dl, bMainPk);
        vm.prank(bob);
        vm.expectRevert(AnchorVaultV45.BadVaultId.selector);
        vault.withdrawFromVault(aliceVid, 1 ether, bob, dl, sig);
    }

    // ────────────────────────────────────────────────────────────
    // View getters
    // ────────────────────────────────────────────────────────────

    function test_GetMaxTimelockForLevel_SAFE() public view {
        assertEq(vault.SAFE_MAX_TIMELOCK_HOURS(), 0);
    }
    function test_GetMaxTimelockForLevel_VAULT() public view {
        assertEq(vault.VAULT_MAX_TIMELOCK_HOURS(), 72);
    }
    function test_GetMaxTimelockForLevel_FORTRESS() public view {
        assertEq(vault.FORTRESS_MAX_TIMELOCK_HOURS(), 168);
    }

    function test_GetDepositFeeForLevel_SAFE() public view {
        assertEq(vault.SAFE_DEPOSIT_FEE_BPS(), 50);
    }
    function test_GetDepositFeeForLevel_VAULT() public view {
        assertEq(vault.VAULT_DEPOSIT_FEE_BPS(), 150);
    }
    function test_GetDepositFeeForLevel_FORTRESS() public view {
        assertEq(vault.FORTRESS_DEPOSIT_FEE_BPS(), 200);
    }

    function test_GetVaultTimings_AfterOpen() public {
        uint256 vid = _openAliceVault(100 ether, 1);
        (uint48 depAt, uint48 vlock, uint16 tlh) = vault.getVaultTimings(alice, vid);
        assertEq(uint256(depAt), block.timestamp);
        assertEq(uint256(vlock), 0);
        assertEq(uint256(tlh), 0);
    }

    function test_GetVaultAuth_AfterOpen() public {
        uint256 vid = _openAliceVault(100 ether, 1);
        (uint64 nonce, address main, address rec) = vault.getVaultAuth(alice, vid);
        assertEq(uint256(nonce), 0);
        assertEq(main, aMain);
        assertEq(rec, aRec);
    }

    function test_GetVaultAuth_NonceIncrementsAfterWithdraw() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 n0,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = type(uint256).max;
        bytes memory sig = _signWithdraw(alice, vid, 10 ether, alice, n0, dl, aMainPk);
        vm.prank(alice);
        vault.withdrawFromVault(vid, 10 ether, alice, dl, sig);
        (uint64 n1,,) = vault.getVaultAuth(alice, vid);
        assertEq(uint256(n1), uint256(n0) + 1);
    }

    function test_DomainSeparator_NonZeroAndStable() public view {
        bytes32 ds = vault.domainSeparator();
        assertTrue(ds != bytes32(0));
        assertEq(ds, vault.domainSeparator());
    }

    function test_GetCore_ReturnsCorrectData() public {
        uint256 vid = _openAliceVault(100 ether, 2);
        (uint64 id, address tk, uint120 amt, string memory n, uint8 st, uint8 lvl) = vault.getVaultCore(alice, vid);
        assertEq(id, uint64(vid));
        assertEq(tk, address(ancr));
        uint256 net = 100 ether - (100 ether * 20) / 10000;
        _approxEq(uint256(amt), net, _tol(net));
        assertEq(st, 0);
        assertEq(lvl, 2);
    }

    function test_GetVaultCore_RevertBadVaultId() public {
        vm.expectRevert(AnchorVaultV45.BadVaultId.selector);
        vault.getVaultCore(alice, 999);
    }

    function test_GetVaultTimings_RevertBadVaultId() public {
        vm.expectRevert(AnchorVaultV45.BadVaultId.selector);
        vault.getVaultTimings(alice, 999);
    }

    function test_GetVaultAuth_RevertBadVaultId() public {
        vm.expectRevert(AnchorVaultV45.BadVaultId.selector);
        vault.getVaultAuth(alice, 999);
    }

    // ────────────────────────────────────────────────────────────
    // Deposit fee splits by level
    // ────────────────────────────────────────────────────────────

    function _depositFeeCase(uint8 level, uint256 feeBps) internal {
        uint256 vid = _openAliceVault(10_000 ether, level);
        (, , uint120 amtBefore, , , ) = vault.getVaultCore(alice, vid);
        uint256 dep = 5_000 ether;
        uint256 fee = dep * feeBps / 10000;
        uint256 net = dep - fee;
        uint256 expBurn    = fee * vault.PEN_BURN_BPS_ANCR()    / 10000;
        uint256 expCreator = fee * vault.PEN_CREATOR_BPS_ANCR() / 10000;
        uint256 expReserve = fee * vault.PEN_RESERVE_BPS_ANCR() / 10000;
        uint256 expRewards = fee - (expBurn + expCreator + expReserve);
        uint256 lockedBefore  = vault.lockedPrincipal(address(ancr));
        uint256 creatorBefore = vault.creatorFees(address(ancr));
        uint256 reserveBefore = vault.strategicReserve(address(ancr));
        uint256 poolBefore    = vault.rewardPool(address(ancr));
        uint256 burnedBefore  = vault.totalBurnedANCR();
        vm.prank(alice);
        vault.depositToVault(vid, dep);
        (, , uint120 amtAfter, , , ) = vault.getVaultCore(alice, vid);
        assertEq(uint256(amtAfter), uint256(amtBefore) + net);
        assertEq(vault.lockedPrincipal(address(ancr)) - lockedBefore, net);
        assertEq(vault.creatorFees(address(ancr)) - creatorBefore, expCreator);
        assertEq(vault.strategicReserve(address(ancr)) - reserveBefore, expReserve);
        assertEq(vault.rewardPool(address(ancr)) - poolBefore, expRewards);
        assertEq(vault.totalBurnedANCR() - burnedBefore, expBurn);
    }

    function test_Deposit_SAFE_FeeAndNet() public {
        _depositFeeCase(0, vault.SAFE_DEPOSIT_FEE_BPS());
    }

    function test_Deposit_VAULT_FeeAndNet() public {
        _depositFeeCase(1, vault.VAULT_DEPOSIT_FEE_BPS());
    }

    function test_Deposit_FORTRESS_FeeAndNet() public {
        _depositFeeCase(2, vault.FORTRESS_DEPOSIT_FEE_BPS());
    }

    // ────────────────────────────────────────────────────────────
    // Reentrancy guard
    // ────────────────────────────────────────────────────────────

    function test_Reentrancy_WithdrawGuardBlocksReentry() public {
        ReentrantAttacker mal = new ReentrantAttacker();
        vm.prank(creator);
        vault.addSupportedToken(address(mal));
        mal.transfer(alice, 100_000 ether);
        vm.prank(alice);
        mal.approve(address(vault), type(uint256).max);
        AnchorVaultV45.VaultParams memory p = AnchorVaultV45.VaultParams({
            name: "mal", mainAuthKey: aMain, recoveryAuthKey: aRec, amount: 10_000 ether
        });
        vm.prank(alice);
        vault.openVault(address(mal), p, 0);
        uint256 vid = vault.activeVaultIdByToken(alice, address(mal));
        (, , uint120 amt0, , , ) = vault.getVaultCore(alice, vid);
        mal.arm(address(vault), abi.encodeWithSelector(AnchorVaultV45.panicWithdraw.selector, vid));
        uint256 wAmount = 1_000 ether;
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = type(uint256).max;
        bytes memory sig = _signWithdraw(alice, vid, wAmount, alice, n, dl, aMainPk);
        vm.prank(alice);
        vault.withdrawFromVault(vid, wAmount, alice, dl, sig);
        (, , uint120 amtAfter, , uint8 st, ) = vault.getVaultCore(alice, vid);
        assertEq(st, 0);
        assertEq(uint256(amtAfter), uint256(amt0) - wAmount);
    }

    function test_Reentrancy_NoDoubleWithdraw() public {
        ReentrantAttacker mal = new ReentrantAttacker();
        vm.prank(creator);
        vault.addSupportedToken(address(mal));
        mal.transfer(alice, 100_000 ether);
        vm.prank(alice);
        mal.approve(address(vault), type(uint256).max);
        AnchorVaultV45.VaultParams memory p = AnchorVaultV45.VaultParams({
            name: "mal2", mainAuthKey: aMain, recoveryAuthKey: aRec, amount: 10_000 ether
        });
        vm.prank(alice);
        vault.openVault(address(mal), p, 0);
        uint256 vid = vault.activeVaultIdByToken(alice, address(mal));
        (, , uint120 amt0, , , ) = vault.getVaultCore(alice, vid);
        uint256 wAmount = 1_000 ether;
        uint256 dl = type(uint256).max;
        mal.arm(address(vault), abi.encodeWithSelector(AnchorVaultV45.withdrawFromVault.selector, vid, wAmount, alice, dl, bytes("")));
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        bytes memory sig = _signWithdraw(alice, vid, wAmount, alice, n, dl, aMainPk);
        vm.prank(alice);
        vault.withdrawFromVault(vid, wAmount, alice, dl, sig);
        (, , uint120 amtAfter, , , ) = vault.getVaultCore(alice, vid);
        assertEq(uint256(amtAfter), uint256(amt0) - wAmount);
    }

    // ────────────────────────────────────────────────────────────
    // Vault level checks
    // ────────────────────────────────────────────────────────────

    function test_OpenVault_SAFE_Level0() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (,,,,, uint8 lvl) = vault.getVaultCore(alice, vid);
        assertEq(lvl, 0);
    }

    function test_OpenVault_VAULT_Level1() public {
        uint256 vid = _openAliceVault(100 ether, 1);
        (,,,,, uint8 lvl) = vault.getVaultCore(alice, vid);
        assertEq(lvl, 1);
    }

    function test_OpenVault_FORTRESS_Level2() public {
        uint256 vid = _openAliceVault(100 ether, 2);
        (,,,,, uint8 lvl) = vault.getVaultCore(alice, vid);
        assertEq(lvl, 2);
    }

    function test_OpenVault_SAFE_HasNoTimelock() public {
        uint256 vid = _openAliceVault(100 ether, 0);
        (uint64 n,,) = vault.getVaultAuth(alice, vid);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signSetTimelock(alice, vid, 1, n, dl, aMainPk);
        vm.prank(alice);
        vm.expectRevert(AnchorVaultV45.TimelockTooLong.selector);
        vault.setTimelock(vid, 1, dl, sig);
    }

    // ────────────────────────────────────────────────────────────
    // User vault count
    // ────────────────────────────────────────────────────────────

    function test_UserVaultCount_Increments() public {
        assertEq(vault.userVaultCount(alice), 0);
        _openAliceVault(100 ether, 0);
        assertEq(vault.userVaultCount(alice), 1);
    }

    function test_UserVaultCount_BobIncrementsAfterAlice() public {
        _openAliceVault(100 ether, 0);
        _openBobVault(50 ether, 1);
        assertEq(vault.userVaultCount(bob), 1);
    }

    // ────────────────────────────────────────────────────────────
    // Sequence
    // ────────────────────────────────────────────────────────────

    function test_Sequence_OpenCloseReopen() public {
        uint256 vid1 = _openAliceVault(100 ether, 0);
        vm.prank(alice);
        vault.panicWithdraw(vid1);
        assertEq(vault.activeVaultIdByToken(alice, address(ancr)), 0);
        uint256 vid2 = _openAliceVault(200 ether, 1);
        assertTrue(vid2 > vid1);
        (, , uint120 amt2, , , ) = vault.getVaultCore(alice, vid2);
        uint256 net2 = 200 ether - (200 ether * vault.OPEN_VAULT_FEE_BPS()) / 10000;
        _approxEq(uint256(amt2), net2, _tol(net2));
    }
}

// Самодостаточный атакующий ERC20 для reentrancy-тестов.
contract ReentrantAttacker is ERC20 {
    address public atkTarget;
    bytes public atkData;
    bool public armed;

    constructor() ERC20("ReentrantAttacker", "RATK") {
        _mint(msg.sender, 1_000_000 ether);
    }

    function arm(address target_, bytes calldata data_) external {
        atkTarget = target_;
        atkData = data_;
        armed = true;
    }

    function _update(address from, address to, uint256 value) internal override {
        super._update(from, to, value);
        if (armed && atkTarget != address(0)) {
            armed = false;
            (bool ok, ) = atkTarget.call(atkData);
            ok;
        }
    }
}
