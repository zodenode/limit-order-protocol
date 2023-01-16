// SPDX-License-Identifier: MIT

pragma solidity 0.8.17;

import "@openzeppelin/contracts/interfaces/IERC1271.sol";
import "@1inch/solidity-utils/contracts/interfaces/IWETH.sol";

import "@openzeppelin/contracts/utils/Address.sol";
import "@1inch/solidity-utils/contracts/libraries/ECDSA.sol";

contract EthOrders is IERC1271 {
    using Address for address payable;

    error NotEnoughBalance();

    IWETH public immutable weth;

    mapping(address => uint256) private _balances;

    constructor(IERC20 weth_) {
        weth = IWETH(address(weth_));
    }

    receive() external payable {
        _depositFor(msg.sender);
    }

    function deposit() external payable {
        return _depositFor(msg.sender);
    }

    function depositFor(address account) external payable {
        return _depositFor(account);
    }

    function _depositFor(address account) private {
        _balances[account] += msg.value;
        weth.deposit{ value: msg.value }();
    }

    function withdraw(uint256 amount) external {
        return _withdrawTo(payable(msg.sender), amount);
    }

    function withdrawTo(address payable account, uint256 amount) external {
        return _withdrawTo(account, amount);
    }

    function _withdrawTo(address payable to, uint256 amount) private {
        if (_balances[msg.sender] < amount) revert NotEnoughBalance();
        _balances[msg.sender] -= amount;
        weth.withdraw(amount);
        to.sendValue(amount);
    }




    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4 magicValue) {
        address signer = ECDSA.recover(hash, signature);

        return this.isValidSignature.selector;
    }
}
