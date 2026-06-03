// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Script} from "forge-std/Script.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract TransferANCR is Script {
    function run() external {
        address token = 0xaC66CB296865876484F911E8d9b78779C3458241;
        address vault = 0xaB15bDb665ed8Fc7FB02FdE31339a4e1Ffe1c15E;
        uint256 amount = 1_000_000 ether;
        vm.startBroadcast();
        IERC20(token).transfer(vault, amount);
        vm.stopBroadcast();
    }
}
