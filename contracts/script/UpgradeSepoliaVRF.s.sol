// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../VRF.sol";

/// @notice Deploys a new VRF contract (ISSUE-009 fix) wired to the existing governance.
/// @dev Registry keeps its immutable VRF pointer; on-chain selection is consumed via
///      chain-spec `contracts.vrf` and direct VRF calls under governance.
///
/// Usage:
///   forge script contracts/script/UpgradeSepoliaVRF.s.sol:UpgradeSepoliaVRF \
///     --rpc-url $SEPOLIA_RPC_URL --private-key $DEPLOYER_KEY --broadcast --chain-id 11155111 -vvv
contract UpgradeSepoliaVRF is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("DEPLOYER_KEY");
        address governance = vm.envAddress("CREG_GOVERNANCE_ADDR");
        address coordinator = vm.envOr("VRF_COORDINATOR", address(1));
        bytes32 keyHash = vm.envOr("VRF_KEY_HASH", bytes32(uint256(0)));
        uint64 subId = uint64(vm.envOr("VRF_SUBSCRIPTION_ID", uint256(0)));
        address previousVrf = vm.envOr("CREG_VRF_ADDR", address(0));

        require(block.chainid == 11155111, "This script is for Sepolia (11155111)");

        console.log("=== Sepolia VRF Upgrade (ISSUE-009) ===");
        console.log("Governance:  ", governance);
        console.log("Previous VRF:", previousVrf);
        console.log("Coordinator: ", coordinator);

        vm.startBroadcast(deployerKey);
        VRF vrf = new VRF(coordinator, keyHash, subId, governance);
        vm.stopBroadcast();

        console.log("New VRF:     ", address(vrf));

        string memory artifact = string(abi.encodePacked(
            '{\n',
            '  "chainId": "', vm.toString(block.chainid), '",\n',
            '  "upgradedAt": "', vm.toString(block.timestamp), '",\n',
            '  "governance": "', vm.toString(governance), '",\n',
            '  "previousVrf": "', vm.toString(previousVrf), '",\n',
            '  "vrf": "', vm.toString(address(vrf)), '"\n',
            '}'
        ));

        try vm.createDir("contracts/deployments", true) {} catch {}
        vm.writeFile("contracts/deployments/vrf-upgrade-latest.json", artifact);
        console.log("Wrote contracts/deployments/vrf-upgrade-latest.json");
    }
}
