// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {AnchorVaultV45} from "../src/AnchorVaultV45.sol";

/// @notice Deploy script. Constructor args are read from environment variables,
///         so no addresses or keys are ever committed to the repo.
///   ANCR_TOKEN, GUARDIAN, PAYOUT_WALLET  -> set in your shell / CI secret store.
contract Deploy is Script {
    function run() external returns (AnchorVaultV45 vault) {
        address ancr     = vm.envAddress("ANCR_TOKEN");
        address guardian = vm.envAddress("GUARDIAN");
        address payout   = vm.envAddress("PAYOUT_WALLET");

        vm.startBroadcast();
        vault = new AnchorVaultV45(ancr, guardian, payout);
        vm.stopBroadcast();
    }
}
