// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../Governance.sol";
import "../Staking.sol";
import "../Reputation.sol";
import "../VRF.sol";
import "../Registry.sol";
import "../Appeal.sol";
import "../ZKVerifier.sol";
import "../CregToken.sol";
import "../ValidatorRewards.sol";
import "../PinningRewards.sol";
import "../testnet/DevZKVerifier.sol";

/// @notice Deploys the full chain-registry contract suite.
/// @dev forge script contracts/script/Deploy.s.sol --rpc-url $RPC_URL --broadcast --verify -vvvv
contract DeployChainRegistry is Script {

    uint256 internal constant GENESIS_VALIDATOR_STAKE = 1000 ether;

    Governance    public governance;
    Staking       public staking;
    Reputation    public reputation;
    VRF           public vrf;
    ChainRegistry public registry;
    Appeal        public appeal;
    address       public zkVerifier;
    CregToken     public cregToken;
    ValidatorRewards public validatorRewards;
    PinningRewards public pinningRewards;

    function run() external {
        uint256 deployerKey = vm.envUint("DEPLOYER_KEY");
        address deployer    = vm.addr(deployerKey);
        bool testnetMode = vm.envOr("TESTNET_MODE", false) || vm.envOr("CREG_TESTNET", false);
        address[] memory signers   = _parseSigners(deployer, testnetMode);
        uint256          threshold = vm.envOr("GOVERNANCE_THRESHOLD", uint256(1));

        console.log("=== Chain Registry Deployment ===");
        console.log("Deployer:  ", deployer);
        console.log("Signers:   ", signers.length);
        console.log("Threshold: ", threshold);

        vm.startBroadcast(deployerKey);

        governance = new Governance(signers, threshold);
        reputation = new Reputation(address(governance));
        vrf        = new VRF(address(1), bytes32(0), 0, address(governance));

        // CregToken must be deployed before Staking — Staking holds a reference to it.
        // All 42M max supply tokens go to deployer for local dev; adjust for production.
        cregToken = new CregToken(deployer, deployer, deployer, deployer);

        // Fund the faucet (Anvil account #1) with 20M tCREG so drip works immediately.
        // Reserve GENESIS_VALIDATOR_STAKE on the deployer so _seedFirstValidator can
        // stake the bridge signer without an out-of-balance revert.
        address faucetAddr = vm.envOr("FAUCET_ADDRESS", address(0x70997970C51812dc3A010C7d01b50e0d17dc79C8));
        uint256 faucetAmount = 20_000_000 ether - (testnetMode ? GENESIS_VALIDATOR_STAKE : 0);
        cregToken.transfer(faucetAddr, faucetAmount);

        // Staking now requires the CregToken address for CREG-based staking.
        staking    = new Staking(address(governance), address(cregToken));
        validatorRewards = new ValidatorRewards(
            address(staking),
            address(cregToken),
            address(governance),
            deployer
        );
        pinningRewards = new PinningRewards(address(cregToken));

        // Local Anvil deployments use a permissive verifier so the bridge path
        // can exercise rollup settlement without a production Groth16 key set.
        require(testnetMode, "DevZKVerifier requires TESTNET_MODE=true");
        require(block.chainid == 31337, "DevZKVerifier only allowed on Anvil chain 31337");
        zkVerifier = address(new DevZKVerifier());

        registry   = new ChainRegistry(
            address(staking),
            address(reputation),
            address(vrf),
            address(governance),
            zkVerifier
        );

        appeal = new Appeal(address(registry), address(staking), address(reputation), address(governance));

        // Wire contracts together — setContracts replaces the old setRegistry.
        staking.setContracts(address(registry), address(reputation));
        reputation.setRegistry(address(registry));
        cregToken.approve(address(validatorRewards), type(uint256).max);
        cregToken.transferOwnership(address(governance));

        vm.stopBroadcast();

        if (testnetMode) {
            _seedFirstValidator(deployerKey, deployer);
        }

        console.log("Governance:", address(governance));
        console.log("Staking:   ", address(staking));
        console.log("Reputation:", address(reputation));
        console.log("VRF:       ", address(vrf));
        console.log("ZKVerifier:", zkVerifier);
        console.log("Registry:  ", address(registry));
        console.log("Appeal:    ", address(appeal));
        console.log("CregToken: ", address(cregToken));
        console.log("ValRewards:", address(validatorRewards));
        console.log("PinRewards:", address(pinningRewards));

        _writeManifest(deployer);
        console.log("=== Deployment complete ===");
    }

    function _parseSigners(address deployer, bool testnetMode) internal view returns (address[] memory) {
        try vm.envString("GENESIS_SIGNERS") returns (string memory raw) {
            if (bytes(raw).length > 0) {
                return vm.parseJsonAddressArray(raw, "$");
            }
        } catch {}

        if (testnetMode) {
            try vm.envUint("CREG_BRIDGE_KEY") returns (uint256 bridgeKey) {
                address bridgeSigner = vm.addr(bridgeKey);
                if (bridgeSigner != deployer) {
                    address[] memory s = new address[](2);
                    s[0] = deployer;
                    s[1] = bridgeSigner;
                    return s;
                }
            } catch {}
        }

        address[] memory s = new address[](1);
        s[0] = deployer;
        return s;
    }

    /// @notice Stakes and admits the bridge signer as the first validator so that
    ///         consensus-based admission has a non-empty active set to bootstrap from.
    /// @dev    Without this, a fresh testnet chain has zero active validators, and
    ///         approveByConsensus requires >=2/3 of the active set to sign, which is
    ///         unreachable. We use the emergency governance path here (threshold=1 on
    ///         testnet auto-executes on first vote) and leave the path enabled so ops
    ///         can recover if the seeded validator ever goes offline. Skipped if the
    ///         bridge signer is unset or equals the deployer.
    function _seedFirstValidator(uint256 deployerKey, address deployer) internal {
        uint256 bridgeKey;
        try vm.envUint("CREG_BRIDGE_KEY") returns (uint256 k) {
            bridgeKey = k;
        } catch {
            console.log("Seed skipped: CREG_BRIDGE_KEY unset");
            return;
        }
        address bridgeSigner = vm.addr(bridgeKey);
        if (bridgeSigner == deployer) {
            console.log("Seed skipped: bridge signer equals deployer");
            return;
        }

        vm.startBroadcast(deployerKey);
        cregToken.transfer(bridgeSigner, GENESIS_VALIDATOR_STAKE);
        vm.stopBroadcast();

        vm.startBroadcast(bridgeKey);
        cregToken.approve(address(staking), GENESIS_VALIDATOR_STAKE);
        staking.applyToBeValidator(GENESIS_VALIDATOR_STAKE);
        vm.stopBroadcast();

        vm.startBroadcast(deployerKey);
        bytes memory cd = abi.encodeWithSelector(
            Staking.approveValidator.selector,
            bridgeSigner
        );
        uint256 proposalId = governance.submit(
            address(staking),
            cd,
            "genesis: seed first validator via emergency governance"
        );
        governance.vote(proposalId, true);
        vm.stopBroadcast();

        console.log("Genesis validator seeded:", bridgeSigner);
        console.log("Stake (tCREG):           ", GENESIS_VALIDATOR_STAKE / 1 ether);
    }

    function _writeManifest(address deployer) internal {
        string memory canonicalPath = "contracts/deployments/latest.json";
        string memory testnetPath = "testnet/artifacts/testnet-contracts.json";
        string memory m = string.concat(
            '{\n',
            '  "deployer":   "', vm.toString(deployer),           '",\n',
            '  "governance": "', vm.toString(address(governance)), '",\n',
            '  "staking":    "', vm.toString(address(staking)),    '",\n',
            '  "reputation": "', vm.toString(address(reputation)), '",\n',
            '  "vrf":        "', vm.toString(address(vrf)),        '",\n',
            '  "zkVerifier": "', vm.toString(zkVerifier), '",\n',
            '  "registry":   "', vm.toString(address(registry)),   '",\n',
            '  "appeal":     "', vm.toString(address(appeal)),     '",\n',
            '  "cregToken":  "', vm.toString(address(cregToken)),  '",\n',
            '  "validatorRewards": "', vm.toString(address(validatorRewards)), '",\n',
            '  "pinningRewards": "', vm.toString(address(pinningRewards)), '",\n',
            '  "validatorRewardsTreasury": "', vm.toString(deployer), '",\n',
            '  "chainId":    "', vm.toString(block.chainid),       '",\n',
            '  "deployedAt": "', vm.toString(block.timestamp),     '"\n',
            '}'
        );

        try vm.envString("DEPLOYMENT_MANIFEST_PATH") returns (string memory configuredPath) {
            if (bytes(configuredPath).length > 0) {
                canonicalPath = configuredPath;
            }
        } catch {}

        try vm.createDir("contracts/deployments", true) {} catch {}
        try vm.createDir("testnet/artifacts", true) {} catch {}

        _tryWriteManifest(canonicalPath, m);
        if (keccak256(bytes(testnetPath)) != keccak256(bytes(canonicalPath))) {
            _tryWriteManifest(testnetPath, m);
        }
    }

    function _tryWriteManifest(string memory outputPath, string memory manifest) internal {
        try vm.writeFile(outputPath, manifest) {
            console.log("Manifest:", outputPath);
        } catch {
            console.log("Manifest write skipped:", outputPath);
        }
    }
}
