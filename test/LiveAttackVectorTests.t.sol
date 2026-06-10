// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, console2} from "forge-std/Test.sol";
import {AnchorVaultV45} from "../src/AnchorVaultV45.sol";
import {MockANCR} from "./mocks/MockANCR.sol";
import {ReentrancyToken} from "./mocks/ReentrancyToken.sol";

contract LiveAttackVectorTests is Test {
    AnchorVaultV45 vault;
    MockANCR ancr;

    address creator = address(0xC0);
    address guardian = address(0x6A);
    address payoutWallet = address(0xBEEF01);

    address alice = address(0xA11CE);
    address aliceEmergency = address(0xE1);
    address bob = address(0xB0B);
    address bobEmergency = address(0xB0BE);
    address attacker = address(0xBAD);

    uint256 aMainPk = 0xA11CE0001;
    uint256 aRecPk  = 0xA11CE0002;
    address aMain;
    address aRec;

    uint256 bMainPk = 0xB0B0001;
    uint256 bRecPk  = 0xB0B0002;
    address bMain;
    address bRec;

    uint256 atkMainPk = 0xBAD00001;
    uint256 atkRecPk  = 0xBAD00002;
    address atkMain;
    address atkRec;

    bytes32 constant WITHDRAW_TYPEHASH =
        keccak256("Withdraw(address owner,uint256 vaultId,uint256 amount,address to,uint64 nonce,uint256 deadline)");
    bytes32 constant EARLY_CLOSE_TYPEHASH =
        keccak256("EarlyClose(address owner,uint256 vaultId,uint64 nonce,uint256 deadline)");
    bytes32 constant TRANSFER_TYPEHASH =
        keccak256("TransferVault(address owner,uint256 vaultId,address to,address newMainKey,address newRecoveryKey,uint64 nonce,uint256 deadline)");
    bytes32 constant INIT_SECURE_TYPEHASH =
        keccak256("InitSecureTransfer(address owner,uint256 vaultId,address to,address newMainKey,address newRecoveryKey,uint64 nonce,uint256 deadline)");

    function setUp() public {
        aMain = vm.addr(aMainPk);
        aRec  = vm.addr(aRecPk);
        bMain = vm.addr(bMainPk);
        bRec  = vm.addr(bRecPk);
        atkMain = vm.addr(atkMainPk);
        atkRec  = vm.addr(atkRecPk);

        vm.prank(creator);
        ancr = new MockANCR(10_000_000 ether);

        vm.prank(creator);
        vault = new AnchorVaultV45(address(ancr), guardian, payoutWallet);

        vm.prank(creator);
        ancr.transfer(alice, 100_000 ether);
        vm.prank(creator);
        ancr.transfer(bob, 100_000 ether);
        vm.prank(creator);
        ancr.transfer(attacker, 100_000 ether);

        vm.prank(alice);
        ancr.approve(address(vault), type(uint256).max);
        vm.prank(bob);
        ancr.approve(address(vault), type(uint256).max);
        vm.prank(attacker);
        ancr.approve(address(vault), type(uint256).max);
        vm.prank(creator);
        ancr.approve(address(vault), type(uint256).max);

        vm.prank(alice);
        vault.setGlobalEmergency(aliceEmergency);
        vm.prank(bob);
        vault.setGlobalEmergency(bobEmergency);
        vm.prank(attacker);
        vault.setGlobalEmergency(address(0xBADE));

        deal(address(ancr), address(vault), 1_000_000 ether);
        vm.prank(creator);
        vault.initializeDistribution();
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

    function _signEarlyClose(address owner, uint256 vid, uint64 nonce, uint256 deadline, uint256 pk)
        internal view returns (bytes memory)
    {
        bytes32 sh = keccak256(abi.encode(EARLY_CLOSE_TYPEHASH, owner, vid, nonce, deadline));
        return _sign(pk, sh);
    }

    function _openVault(address user, uint256 pkMain, uint256 pkRec, uint256 amount, uint8 level) internal returns (uint256 vid) {
        address mainKey = vm.addr(pkMain);
        address recKey = vm.addr(pkRec);
        AnchorVaultV45.VaultParams memory p = AnchorVaultV45.VaultParams({
            name: "Vault", mainAuthKey: mainKey, recoveryAuthKey: recKey, amount: amount
        });
        vm.prank(user);
        vault.openVault(address(ancr), p, level);
        vid = vault.activeVaultIdByToken(user, address(ancr));
    }

    function test_Attack_InverseFinance_LockedPrincipalDesync() public {
        uint256 initialLP = vault.lockedPrincipal(address(ancr));

        uint256 v1 = _openVault(attacker, atkMainPk, atkRecPk, 1000 ether, 0);
        uint256 v2 = _openVault(attacker, atkMainPk, atkRecPk, 2000 ether, 1);
        uint256 v3 = _openVault(attacker, atkMainPk, atkRecPk, 3000 ether, 2);

        uint256 lpAfterOpen = vault.lockedPrincipal(address(ancr));
        assertTrue(lpAfterOpen > initialLP, "lockedPrincipal should increase after opens");

        (uint64 n1,,) = vault.getVaultAuth(attacker, v1);
        bytes memory sig1 = _signEarlyClose(attacker, v1, n1, block.timestamp + 1 hours, atkRecPk);

        (uint64 n2,,) = vault.getVaultAuth(attacker, v2);
        bytes memory sig2 = _signEarlyClose(attacker, v2, n2, block.timestamp + 1 hours, atkRecPk);

        (uint64 n3,,) = vault.getVaultAuth(attacker, v3);
        bytes memory sig3 = _signEarlyClose(attacker, v3, n3, block.timestamp + 1 hours, atkRecPk);

        vm.prank(attacker);
        vault.earlyClose(v1, block.timestamp + 1 hours, sig1);

        vm.prank(attacker);
        vault.earlyClose(v2, block.timestamp + 1 hours, sig2);

        vm.prank(attacker);
        vault.earlyClose(v3, block.timestamp + 1 hours, sig3);

        uint256 lpAfterClose = vault.lockedPrincipal(address(ancr));

        assertLe(lpAfterClose, initialLP, "lockedPrincipal should not exceed initial after all vaults closed");
        assertGe(lpAfterClose, 0, "lockedPrincipal should never be negative");

        uint256 bal = ancr.balanceOf(address(vault));
        uint256 lp = vault.lockedPrincipal(address(ancr));
        uint256 cf = vault.creatorFees(address(ancr));
        uint256 rs = vault.strategicReserve(address(ancr));
        uint256 rp = vault.rewardPool(address(ancr));

        assertGe(bal, lp + cf + rs + rp, "Solvency invariant violated after mass close");
    }

    function test_Attack_InverseFinance_RapidDepositWithdraw() public {
        uint256 vid = _openVault(attacker, atkMainPk, atkRecPk, 1000 ether, 0);

        for (uint256 i = 0; i < 5; i++) {
            vm.prank(attacker);
            vault.depositToVault(vid, 500 ether);

            (uint64 nonce,,) = vault.getVaultAuth(attacker, vid);
            uint256 amountToWithdraw = 300 ether;
            bytes memory sig = _signWithdraw(attacker, vid, amountToWithdraw, attacker, nonce, block.timestamp + 1 hours, atkMainPk);
            vm.prank(attacker);
            vault.withdrawFromVault(vid, amountToWithdraw, attacker, block.timestamp + 1 hours, sig);
        }

        uint256 bal = ancr.balanceOf(address(vault));
        uint256 lp = vault.lockedPrincipal(address(ancr));
        uint256 cf = vault.creatorFees(address(ancr));
        uint256 rs = vault.strategicReserve(address(ancr));
        uint256 rp = vault.rewardPool(address(ancr));

        assertGe(bal, lp + cf + rs + rp, "Solvency invariant violated after rapid deposit/withdraw cycles");
    }

    function test_Attack_InverseFinance_MassOpenCloseRoundTrip() public {
        uint256 attackAmount = 50_000 ether;

        vm.prank(creator);
        ancr.transfer(attacker, attackAmount);

        uint256[] memory vids = new uint256[](5);
        uint256[] memory amounts = new uint256[](5);
        amounts[0] = 1000 ether;
        amounts[1] = 2000 ether;
        amounts[2] = 3000 ether;
        amounts[3] = 4000 ether;
        amounts[4] = 5000 ether;

        for (uint256 i = 0; i < 5; i++) {
            address mainKey = vm.addr(atkMainPk);
            address recKey = vm.addr(atkRecPk);
            AnchorVaultV45.VaultParams memory p = AnchorVaultV45.VaultParams({
                name: "FlashVault", mainAuthKey: mainKey, recoveryAuthKey: recKey, amount: amounts[i]
            });
            vm.prank(attacker);
            vault.openVault(address(ancr), p, uint8(i % 3));
            vids[i] = vault.activeVaultIdByToken(attacker, address(ancr));
        }

        for (uint256 i = 0; i < 5; i++) {
            (uint64 nonce,,) = vault.getVaultAuth(attacker, vids[i]);
            bytes memory sig = _signEarlyClose(attacker, vids[i], nonce, block.timestamp + 1 hours, atkRecPk);
            vm.prank(attacker);
            vault.earlyClose(vids[i], block.timestamp + 1 hours, sig);
        }

        uint256 bal = ancr.balanceOf(address(vault));
        uint256 lp = vault.lockedPrincipal(address(ancr));
        uint256 cf = vault.creatorFees(address(ancr));
        uint256 rs = vault.strategicReserve(address(ancr));
        uint256 rp = vault.rewardPool(address(ancr));

        assertGe(bal, lp + cf + rs + rp, "Solvency invariant violated after mass open/close round-trip");
    }

    function test_Attack_ElephantMoney_ReentrancyOpenVault() public {
        ReentrancyToken rToken = new ReentrancyToken(address(vault), address(ancr));
        vm.prank(creator);
        vault.addSupportedToken(address(rToken));

        rToken.mint(attacker, 100_000 ether);
        vm.prank(attacker);
        rToken.approve(address(vault), type(uint256).max);

        vm.prank(attacker);
        vault.setGlobalEmergency(address(0xBADE));

        uint256 attackAmount = 1000 ether;

        AnchorVaultV45.VaultParams memory p = AnchorVaultV45.VaultParams({
            name: "ReentrantVault",
            mainAuthKey: aMain,
            recoveryAuthKey: aRec,
            amount: attackAmount
        });

        rToken.setReenterData(attacker, aMain, aRec, attackAmount);

        vm.prank(attacker);
        vm.expectRevert(AnchorVaultV45.VaultLimitReached.selector);
        vault.openVault(address(rToken), p, 0);

        assertLe(vault.userVaultCount(attacker), 1, "Only one vault should exist");
    }

    function test_Attack_ElephantMoney_ReentrancyDeposit() public {
        uint256 vid = _openVault(attacker, atkMainPk, atkRecPk, 1000 ether, 0);

        ReentrancyToken rToken = new ReentrancyToken(address(vault), address(ancr));
        vm.prank(creator);
        vault.addSupportedToken(address(rToken));

        rToken.setReenterDeposit(attacker, vid, 100 ether);

        uint256 attackAmount = 500 ether;
        rToken.mint(attacker, attackAmount);
        vm.prank(attacker);
        rToken.approve(address(vault), type(uint256).max);

        AnchorVaultV45.VaultParams memory p = AnchorVaultV45.VaultParams({
            name: "ReentrantDeposit",
            mainAuthKey: aMain,
            recoveryAuthKey: aRec,
            amount: attackAmount
        });

        vm.prank(attacker);
        vault.openVault(address(rToken), p, 0);

        uint256 lp = vault.lockedPrincipal(address(ancr));
        assertApproxEqAbs(lp, 1000 ether, 1000 ether / 100, "lockedPrincipal should be consistent");
    }

    function test_Attack_HarvestFinance_WelcomeBonusInflation() public {
        uint256 bonusAmount = 0.01 ether;
        vm.prank(creator);
        vault.setWelcomeBonus(bonusAmount, 100);

        vm.prank(creator);
        ancr.transfer(attacker, 500_000 ether);
        vm.prank(attacker);
        vault.donateToRewardPool(address(ancr), 500_000 ether);

        uint256 balBefore = ancr.balanceOf(attacker);
        _openVault(attacker, atkMainPk, atkRecPk, 100 ether, 0);
        uint256 balAfter = ancr.balanceOf(attacker);

        assertTrue(vault.welcomeBonusClaimed(attacker), "Welcome bonus should be claimed");
    }

    function test_Attack_HarvestFinance_MultipleWelcomeBonusFarm() public {
        uint256 bonusAmount = 0.01 ether;
        vm.prank(creator);
        vault.setWelcomeBonus(bonusAmount, 3);

        address user1 = address(0x1111);
        address user2 = address(0x2222);
        address user3 = address(0x3333);
        address user4 = address(0x4444);

        vm.prank(creator);
        ancr.transfer(user1, 1000 ether);
        vm.prank(creator);
        ancr.transfer(user2, 1000 ether);
        vm.prank(creator);
        ancr.transfer(user3, 1000 ether);
        vm.prank(creator);
        ancr.transfer(user4, 1000 ether);

        vm.prank(user1);
        ancr.approve(address(vault), type(uint256).max);
        vm.prank(user2);
        ancr.approve(address(vault), type(uint256).max);
        vm.prank(user3);
        ancr.approve(address(vault), type(uint256).max);
        vm.prank(user4);
        ancr.approve(address(vault), type(uint256).max);

        for (uint256 i = 0; i < 4; i++) {
            address u = user1;
            uint256 pk = 0x111;
            if (i == 1) { u = user2; pk = 0x222; }
            if (i == 2) { u = user3; pk = 0x333; }
            if (i == 3) { u = user4; pk = 0x444; }

            vm.prank(u);
            vault.setGlobalEmergency(address(uint160(uint256(keccak256(abi.encode(u, 0xE0))))));

            address mainK = vm.addr(pk);
            address recK = vm.addr(pk + 1);
            AnchorVaultV45.VaultParams memory p = AnchorVaultV45.VaultParams({
                name: "Sybil", mainAuthKey: mainK, recoveryAuthKey: recK, amount: 100 ether
            });
            vm.prank(u);
            vault.openVault(address(ancr), p, 0);
        }

        assertTrue(vault.welcomeBonusClaimed(user1), "User1 should get bonus");
        assertTrue(vault.welcomeBonusClaimed(user2), "User2 should get bonus");
        assertTrue(vault.welcomeBonusClaimed(user3), "User3 should get bonus");
        assertFalse(vault.welcomeBonusClaimed(user4), "User4 should NOT get bonus (overflow)");
        assertEq(vault.welcomeBonusClaims(), 3, "Exactly 3 bonuses paid");
    }

    function test_Attack_HarvestFinance_RewardPoolSolvency() public {
        vm.prank(creator);
        ancr.transfer(attacker, 2_000_000 ether);
        vm.prank(attacker);
        vault.donateToRewardPool(address(ancr), 2_000_000 ether);

        uint256 bal = ancr.balanceOf(address(vault));
        uint256 lp = vault.lockedPrincipal(address(ancr));
        uint256 cf = vault.creatorFees(address(ancr));
        uint256 rs = vault.strategicReserve(address(ancr));
        uint256 rp = vault.rewardPool(address(ancr));

        assertGe(bal, lp + cf + rs + rp, "Solvency must hold after whale donation");

        uint256 vid = _openVault(attacker, atkMainPk, atkRecPk, 5000 ether, 0);

        (uint64 nonce,,) = vault.getVaultAuth(attacker, vid);
        bytes memory sig = _signEarlyClose(attacker, vid, nonce, block.timestamp + 1 hours, atkRecPk);
        vm.prank(attacker);
        vault.earlyClose(vid, block.timestamp + 1 hours, sig);

        bal = ancr.balanceOf(address(vault));
        lp = vault.lockedPrincipal(address(ancr));
        cf = vault.creatorFees(address(ancr));
        rs = vault.strategicReserve(address(ancr));
        rp = vault.rewardPool(address(ancr));

        assertGe(bal, lp + cf + rs + rp, "Solvency must hold after close with inflated rewardPool");
    }
}
