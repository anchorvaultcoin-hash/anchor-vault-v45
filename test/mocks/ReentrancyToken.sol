// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {AnchorVaultCoin} from "../../src/AnchorVaultCoin.sol";
import {MockANCR} from "./MockANCR.sol";

/**
 * @dev Токен с callback-реентерией — симулирует ElephantMoney-стиль атаки.
 *      При transferFrom вызывает openVault или depositToVault на AnchorVaultCoin.
 */
contract ReentrancyToken is MockANCR {
    AnchorVaultCoin public targetVault;
    address public underlyingToken;

    bool public doReenter;
    address public reenterUser;
    address public reenterMain;
    address public reenterRec;
    uint256 public reenterAmount;
    bool public reenterDeposit;
    uint256 public reenterVid;

    constructor(address _vault, address _underlying) MockANCR(0) {
        targetVault = AnchorVaultCoin(payable(_vault));
        underlyingToken = _underlying;
    }

    function setReenterData(address user, address main, address rec, uint256 amt) external {
        doReenter = true;
        reenterUser = user;
        reenterMain = main;
        reenterRec = rec;
        reenterAmount = amt;
        reenterDeposit = false;
    }

    function setReenterDeposit(address user, uint256 vid, uint256 amt) external {
        doReenter = true;
        reenterUser = user;
        reenterMain = address(0);
        reenterRec = address(0);
        reenterAmount = amt;
        reenterDeposit = true;
        reenterVid = vid;
    }

    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        bool result = super.transferFrom(from, to, amount);

        if (doReenter && to == address(targetVault)) {
            doReenter = false;
            if (reenterDeposit) {
                targetVault.depositToVault(reenterVid, reenterAmount);
            } else {
                AnchorVaultCoin.VaultParams memory p = AnchorVaultCoin.VaultParams({
                    mainAuthKey: reenterMain,
                    recoveryAuthKey: reenterRec,
                    amount: reenterAmount
                });
                targetVault.openVault(underlyingToken, p, 0);
            }
        }
        return result;
    }
}
