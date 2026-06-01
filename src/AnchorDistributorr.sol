// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title AnchorDistributor
 * @notice Одноразовая раздача ANCR. Намеренно ОТДЕЛЁН от AnchorVaultV45:
 *         раздача не имеет отношения к логике сейфа и не должна раздувать
 *         аудируемую поверхность доверенного контракта.
 *
 *  ПОРЯДОК ДЕПЛОЯ (без chicken-and-egg, без transferFrom в конструкторе):
 *   1. Задеплоить AnchorDistributor(ancrToken).
 *   2. Перевести нужный объём ANCR на адрес этого контракта (обычный transfer).
 *   3. Вызвать distribute(recipients, amounts) — один раз, только деплоером.
 *   4. Любой остаток вернуть через sweep().
 */
contract AnchorDistributor {
    using SafeERC20 for IERC20;

    error NotDeployer();
    error AlreadyDistributed();
    error LengthMismatch();
    error EmptyList();
    error ZeroRecipient();
    error ZeroAmount();
    error InsufficientBalance();
    error NothingToSweep();

    event Distributed(uint256 recipientCount, uint256 totalAmount);
    event Swept(address indexed to, uint256 amount);

    IERC20  public immutable token;
    address public immutable deployer;
    bool    public distributed;

    constructor(address _token) {
        require(_token != address(0), "zero token");
        token = IERC20(_token);
        deployer = msg.sender;
    }

    /// @notice Раздаёт уже находящиеся на контракте токены. Запускается ровно один раз.
    function distribute(address[] calldata recipients, uint256[] calldata amounts) external {
        if (msg.sender != deployer) revert NotDeployer();
        if (distributed) revert AlreadyDistributed();
        if (recipients.length != amounts.length) revert LengthMismatch();
        if (recipients.length == 0) revert EmptyList();

        distributed = true; // эффект до внешних вызовов — защита от повторного входа

        uint256 total;
        for (uint256 i = 0; i < amounts.length; ++i) {
            if (recipients[i] == address(0)) revert ZeroRecipient();
            if (amounts[i] == 0) revert ZeroAmount();
            total += amounts[i];
        }
        if (token.balanceOf(address(this)) < total) revert InsufficientBalance();

        for (uint256 i = 0; i < recipients.length; ++i) {
            token.safeTransfer(recipients[i], amounts[i]);
        }
        emit Distributed(recipients.length, total);
    }

    /// @notice Возврат остатка (или всех средств, если distribute так и не вызвали).
    function sweep(address to) external {
        if (msg.sender != deployer) revert NotDeployer();
        if (to == address(0)) revert ZeroRecipient();
        uint256 bal = token.balanceOf(address(this));
        if (bal == 0) revert NothingToSweep();
        token.safeTransfer(to, bal);
        emit Swept(to, bal);
    }
}
