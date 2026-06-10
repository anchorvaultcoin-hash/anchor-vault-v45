// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IBurnable} from "../../src/AnchorVaultV45.sol";

contract MockANCR is ERC20, IBurnable {
    constructor(uint256 initialSupply) ERC20("Mock ANCR", "ANCR") {
        _mint(msg.sender, initialSupply);
    }

    function burn(uint256 amount) external override {
        _burn(msg.sender, amount);
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
