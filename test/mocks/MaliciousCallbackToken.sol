// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @notice Мок для Extended-тестов. Конструктор принимает адрес vault.
///   18 decimals обязательны (иначе addSupportedToken ревертит). Обычный ERC20:
///   transfer/transferFrom не делают колбэков — реентерия через них невозможна.
contract MaliciousCallbackToken is ERC20 {
    address public vault;

    constructor(address _vault) ERC20("MaliciousCallbackToken", "MCT") {
        vault = _vault;
    }

    function decimals() public pure override returns (uint8) {
        return 18;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
