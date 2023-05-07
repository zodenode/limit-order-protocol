// SPDX-License-Identifier: MIT

pragma solidity 0.8.19;

import "@1inch/solidity-utils/contracts/libraries/ECDSA.sol";
import "@1inch/solidity-utils/contracts/libraries/AddressLib.sol";

import "./interfaces/IOrderMixin.sol";
import "./libraries/MakerTraitsLib.sol";
import "./libraries/ExtensionLib.sol";
import "./helpers/AmountCalculator.sol";

/**
 * @title OrderLib
 * @notice A library for handling orders, including hashing, amount calculations, and extension validation.
 */
library OrderLib {
    using AddressLib for Address;
    using MakerTraitsLib for MakerTraits;
    using ExtensionLib for bytes;

    error WrongGetter();
    error GetAmountCallFailed();
    error MissingOrderExtension();
    error UnexpectedOrderExtension();
    error ExtensionInvalid();

    bytes32 constant internal _LIMIT_ORDER_TYPEHASH = keccak256(
        "Order("
            "uint256 salt,"
            "address maker,"
            "address makerAsset,"
            "address takerAsset,"
            "uint256 makingAmount,"
            "uint256 takingAmount,"
            "uint256 makerTraits"
        ")"
    );

    /**
     * @notice Calculate the hash of an order.
     * @param order The order struct.
     * @param domainSeparator The EIP-712 domain separator.
     * @return result The order hash.
     */
    function hash(IOrderMixin.Order calldata order, bytes32 domainSeparator) internal pure returns(bytes32 result) {
        bytes32 typehash = _LIMIT_ORDER_TYPEHASH;
        assembly ("memory-safe") { // solhint-disable-line no-inline-assembly
            let ptr := mload(0x40)

            // keccak256(abi.encode(_LIMIT_ORDER_TYPEHASH, order));
            mstore(ptr, typehash)
            calldatacopy(add(ptr, 0x20), order, 0xe0)
            result := keccak256(ptr, 0x100)
        }
        result = ECDSA.toTypedDataHash(domainSeparator, result);
    }

    /**
     * @notice Calculate the making amount based on the requested taking amount.
     * @param order The order struct.
     * @param extension The extension data.
     * @param requestedTakingAmount The requested taking amount.
     * @param remainingMakingAmount The remaining making amount.
     * @param orderHash The order hash.
     * @return The calculated making amount.
     */
    function calculateMakingAmount(
        IOrderMixin.Order calldata order,
        bytes calldata extension,
        uint256 requestedTakingAmount,
        uint256 remainingMakingAmount,
        bytes32 orderHash
    ) internal view returns(uint256) {
        bytes calldata getter = extension.makingAmountGetter();
        if (getter.length == 0) {
            // Linear proportion
            return AmountCalculator.getMakingAmount(order.makingAmount, order.takingAmount, requestedTakingAmount);
        }
        return _callGetter(getter, requestedTakingAmount, remainingMakingAmount, orderHash);
    }

    /**
     * @notice Calculate the taking amount based on the requested making amount.
     * @param order The order struct.
     * @param extension The extension data.
     * @param requestedMakingAmount The requested making amount.
     * @param remainingMakingAmount The remaining making amount.
     * @param orderHash The order hash.
     * @return The calculated taking amount.
     */

    function calculateTakingAmount(
        IOrderMixin.Order calldata order,
        bytes calldata extension,
        uint256 requestedMakingAmount,
        uint256 remainingMakingAmount,
        bytes32 orderHash
    ) internal view returns(uint256) {
        bytes calldata getter = extension.takingAmountGetter();
        if (getter.length == 0) {
            // Linear proportion
            return AmountCalculator.getTakingAmount(order.makingAmount, order.takingAmount, requestedMakingAmount);
        }
        return _callGetter(getter, requestedMakingAmount, remainingMakingAmount, orderHash);
    }

    /**
     * @dev Call the getter function for calculating the making/taking amount.
     * @param getter The getter function address and data.
     * @param requestedAmount The requested making or taking amount.
     * @param remainingMakingAmount The remaining making amount.
     * @param orderHash The order hash.
     * @return The calculated making/taking amount.
     */
    function _callGetter(
        bytes calldata getter,
        uint256 requestedAmount,
        uint256 remainingMakingAmount,
        bytes32 orderHash
    ) private view returns(uint256) {
        if (getter.length < 20) revert WrongGetter();

        (bool success, bytes memory result) = address(bytes20(getter)).staticcall(abi.encodePacked(getter[20:], requestedAmount, remainingMakingAmount, orderHash));
        if (!success || result.length != 32) revert GetAmountCallFailed();
        return abi.decode(result, (uint256));
    }

    /**
     * @notice Validate the order extension.
     * @param order The order struct.
     * @param extension The extension data.
     */
    function validateExtension(IOrderMixin.Order calldata order, bytes calldata extension) internal pure {
        if (order.makerTraits.hasExtension()) {
            if (extension.length == 0) revert MissingOrderExtension();
            // Lowest 160 bits of the order salt must be equal to the lowest 160 bits of the extension hash
            if (uint256(keccak256(extension)) & type(uint160).max != order.salt & type(uint160).max) revert ExtensionInvalid();
        } else {
            if (extension.length > 0) revert UnexpectedOrderExtension();
        }
    }
}
