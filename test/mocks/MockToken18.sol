// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @notice Минимальный ERC-20 с 18 decimals для тестов (без burn, без callback)
contract MockToken18 is ERC20 {
    constructor(string memory _name, string memory _symbol) ERC20(_name, _symbol) {}
    function mint(address to, uint256 amount) external { _mint(to, amount); }
    function burn(uint256 amount) external { _burn(msg.sender, amount); }
}