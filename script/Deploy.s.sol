// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import {Script, console2} from "forge-std/Script.sol";
import {AnchorVaultV45} from "../src/AnchorVaultV45.sol";

contract Deploy is Script {
    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address guardian = vm.envAddress("GUARDIAN_ADDRESS");
        address ancrToken = vm.envAddress("ANCR_TOKEN");

        vm.startBroadcast(deployerPrivateKey);

        AnchorVaultV45 vault = new AnchorVaultV45(ancrToken, guardian);
        address vaultAddress = address(vault);

        console2.log("AnchorVaultV45 deployed at:", vaultAddress);

        vm.stopBroadcast();
    }
}
