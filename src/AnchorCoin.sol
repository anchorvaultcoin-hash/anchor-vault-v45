// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Burnable} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";

/// @title  AnchorCoin (ANCR)
/// @notice Fixed supply: 2,000,000 ANCR minted once in the constructor.
///         No mint function, no owner — total supply can never be increased.
///         burn/burnFrom are intentionally kept: AnchorVaultV45._burnIfNeeded relies on them.
contract AnchorCoin is ERC20, ERC20Burnable {
    error ZeroHolder();

    uint256 public constant INITIAL_SUPPLY = 2_000_000 ether;

    constructor(address initialHolder) ERC20("AnchorCoin", "ANCR") {
        if (initialHolder == address(0)) revert ZeroHolder();
        _mint(initialHolder, INITIAL_SUPPLY);
    }
}
