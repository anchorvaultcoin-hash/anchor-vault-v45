// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Burnable} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract AnchorCoin is ERC20, ERC20Burnable, Ownable {
    constructor(address initialHolder)
        ERC20("AnchorCoin", "ANCR")
        Ownable(initialHolder)
    {
        _mint(initialHolder, 10_000_000 ether);
    }

    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }
}
