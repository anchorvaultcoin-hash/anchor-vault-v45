// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";
import {AnchorVaultV45} from "../src/AnchorVaultV45.sol";
// import {AnchorDistributor} from "../src/AnchorDistributor.sol";
import {MockANCR} from "../test/mocks/MockANCR.sol";

/**
 * @notice Деплой в Sepolia (ТЕСТНЕТ).
 *
 *  Перед запуском заполни .env (см. .env.example):
 *    SEPOLIA_RPC_URL   — RPC (Alchemy/Infura/публичный)
 *    PRIVATE_KEY       — приватный ключ ТЕСТОВОГО кошелька (НЕ основного!)
 *    GUARDIAN_ADDRESS  — адрес guardian (НЕ деплоер)
 *    ETHERSCAN_API_KEY — для верификации (опц.)
 *
 *  Запуск:
 *    forge script script/Deploy.s.sol:Deploy \
 *      --rpc-url sepolia --broadcast --verify -vvvv
 *
 *  Скрипт деплоит: MockANCR (тестовый токен) → AnchorVaultV45.
 *  Деплоер становится creator. GUARDIAN_ADDRESS — guardian (должен отличаться).
 */
contract Deploy is Script {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address guardian = vm.envAddress("GUARDIAN_ADDRESS");
        address payoutWallet = vm.envAddress("PAYOUT_WALLET");
        address deployer = vm.addr(pk);

        require(guardian != deployer, "guardian must differ from deployer");
        require(payoutWallet != address(0), "payout wallet not set");

        vm.startBroadcast(pk);

        // 1) Тестовый токен ANCR (10 млн), весь баланс — деплоеру
        MockANCR ancr = new MockANCR(10_000_000 ether);
        console2.log("MockANCR:        ", address(ancr));

        // 2) Хранилище
        AnchorVaultV45 vault = new AnchorVaultV45(address(ancr), guardian, payoutWallet);
        console2.log("AnchorVaultV45:  ", address(vault));
        console2.log("  creator:       ", deployer);
        console2.log("  guardian:      ", guardian);
        console2.log("  VERSION:       ", vault.VERSION());

        // 3) (опц.) Distributor — раскомментируй при необходимости
        // AnchorDistributor dist = new AnchorDistributor(address(ancr));
        // console2.log("AnchorDistributor:", address(dist));

        vm.stopBroadcast();

        console2.log("\n=== DEPLOY IN SEPOLIA COMPLETED ===");
        console2.log("Next: see TESTNET_CHECKLIST.md");
    }
}
