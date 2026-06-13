// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Permissive verifier for local testnet/development deployments.
/// @dev This is only for exercising the bridge path on ephemeral Anvil networks.
contract DevZKVerifier {
    function verifyProof(
        uint256[8] calldata,
        uint256[] calldata
    ) external pure returns (bool) {
        return true;
    }

    function batchVerify(
        uint256[8][] calldata,
        uint256[][] calldata
    ) external pure returns (bool) {
        return true;
    }
}