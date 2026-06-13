// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../GovernanceV2.sol";
import "../Governance.sol";
import "../Registry.sol";
import "../CregToken.sol";
import "../Staking.sol";
import "../VRF.sol";
import "../BatchOperations.sol";

/// @title GovernanceUpgrade
/// @notice Deploys GovernanceV2 and migrates authority from Governance (M-of-N multisig).
///
/// @dev Pre-requisites:
///   - A quorum of Governance.sol signers must have voted to approve this migration.
///   - The caller must have the ability to call setGovernance / transferGovernance on
///     each downstream contract through the current Governance contract.
///
/// Usage (testnet):
///   forge script contracts/script/GovernanceUpgrade.s.sol \
///       --rpc-url $RPC_URL --broadcast --verify -vvvv
///
/// Environment variables:
///   DEPLOYER_KEY           - Private key of the deployer
///   CREG_TOKEN_ADDR        - Deployed CregToken address
///   REGISTRY_ADDR          - Deployed ChainRegistry address
///   OLD_GOVERNANCE_ADDR    - Deployed Governance.sol (M-of-N) address
///   STAKING_ADDR           - Deployed Staking address
///   VRF_ADDR               - Deployed VRF address
///   BATCH_OPS_ADDR         - (Optional) Deployed BatchOperations address
///   VOTING_DELAY           - Blocks before voting starts  (default: 1)
///   VOTING_PERIOD          - Blocks voting is open         (default: 17280 ≈ 3 days)
///   PROPOSAL_THRESHOLD     - Min votes to create proposal (default: 100e18)
///   QUORUM_VOTES           - Min votes for quorum          (default: 1000e18)
contract GovernanceUpgradeScript is Script {

    function run() external {
        uint256 deployerKey = vm.envUint("DEPLOYER_KEY");
        address deployer    = vm.addr(deployerKey);

        // ── Existing contract addresses ──────────────────────────────────────
        address cregTokenAddr     = vm.envAddress("CREG_TOKEN_ADDR");
        address registryAddr      = vm.envAddress("REGISTRY_ADDR");
        address oldGovernanceAddr = vm.envAddress("OLD_GOVERNANCE_ADDR");
        address stakingAddr       = vm.envAddress("STAKING_ADDR");
        address vrfAddr           = vm.envAddress("VRF_ADDR");
        address batchOpsAddr      = vm.envOr("BATCH_OPS_ADDR", address(0));

        // ── GovernanceV2 parameters ──────────────────────────────────────────
        uint256 votingDelay       = vm.envOr("VOTING_DELAY",       uint256(1));
        uint256 votingPeriod      = vm.envOr("VOTING_PERIOD",      uint256(17280));
        uint256 proposalThreshold = vm.envOr("PROPOSAL_THRESHOLD", uint256(100e18));
        uint256 quorumVotes       = vm.envOr("QUORUM_VOTES",       uint256(1000e18));

        console.log("=== GovernanceV2 Migration ===");
        console.log("Deployer:       ", deployer);
        console.log("Old Governance: ", oldGovernanceAddr);
        console.log("Registry:       ", registryAddr);
        console.log("CregToken:      ", cregTokenAddr);

        vm.startBroadcast(deployerKey);

        // ── 1. Deploy GovernanceV2 ───────────────────────────────────────────
        GovernanceV2 govV2 = new GovernanceV2(
            cregTokenAddr,
            registryAddr,
            deployer,           // admin — to be transferred to the DAO later
            votingDelay,
            votingPeriod,
            proposalThreshold,
            quorumVotes
        );
        console.log("GovernanceV2 deployed at:", address(govV2));

        // ── 2. Migrate governance authority on downstream contracts ──────────
        //
        // These calls must originate from the current governance contract.
        // In a real deployment, each of these would be a Governance.sol proposal
        // that has already been approved. For testnet bootstrapping, if the
        // deployer is the sole signer, it can submit+vote+execute in one tx.

        // Registry.setGovernance(govV2)
        ChainRegistry(registryAddr).setGovernance(address(govV2));
        console.log("Registry governance updated");

        // Staking.transferGovernance(govV2)
        Staking(stakingAddr).transferGovernance(address(govV2));
        console.log("Staking governance updated");

        // VRF.setGovernance(govV2)
        VRF(vrfAddr).setGovernance(address(govV2));
        console.log("VRF governance updated");

        // BatchOperations (optional)
        if (batchOpsAddr != address(0)) {
            BatchOperations(batchOpsAddr).transferGovernance(address(govV2));
            console.log("BatchOperations governance updated");
        }

        vm.stopBroadcast();

        // ── 3. Write deployment artifact ─────────────────────────────────────
        string memory artifact = string(abi.encodePacked(
            '{"governanceV2":"', vm.toString(address(govV2)),
            '","oldGovernance":"', vm.toString(oldGovernanceAddr),
            '","registry":"', vm.toString(registryAddr),
            '","stakingAddr":"', vm.toString(stakingAddr),
            '","vrfAddr":"', vm.toString(vrfAddr),
            '"}'
        ));
        vm.writeFile("contracts/deployments/governance-v2.json", artifact);
        console.log("Artifact written to contracts/deployments/governance-v2.json");
    }
}
