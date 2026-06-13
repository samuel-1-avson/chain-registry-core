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

contract DeployAnvil is Script {
    uint256 internal constant GENESIS_VALIDATOR_STAKE = 1000 ether;

    function run() external {
        uint256 deployerKey = vm.envUint("DEPLOYER_KEY");
        address deployer = vm.addr(deployerKey);
        uint256 threshold = vm.envOr("GOVERNANCE_THRESHOLD", uint256(1));

        console.log("=== Chain Registry Anvil Deployment ===");
        console.log("Deployer:  ", deployer);
        console.log("Chain ID:  ", block.chainid);

        vm.startBroadcast(deployerKey);

        Governance governance = new Governance(
            _makeSigners(deployer), threshold
        );
        Reputation reputation = new Reputation(address(governance));
        VRF vrf = new VRF(address(1), bytes32(0), 0, address(governance));
        CregToken cregToken = new CregToken(deployer, deployer, deployer, deployer);
        Staking staking = new Staking(address(governance), address(cregToken));
        ValidatorRewards validatorRewards = new ValidatorRewards(
            address(staking), address(cregToken), address(governance), deployer
        );
        PinningRewards pinningRewards = new PinningRewards(address(cregToken));
        ZKVerifier zkVerifier = new ZKVerifier(
            [uint256(1), uint256(2)],
            [uint256(3), uint256(4)],
            [uint256(5), uint256(6)],
            [uint256(7), uint256(8)],
            [uint256(9), uint256(10)],
            [uint256(11), uint256(12)],
            [uint256(13), uint256(14)],
            new uint256[2][](0)
        );
        ChainRegistry registry = new ChainRegistry(
            address(staking), address(reputation), address(vrf),
            address(governance), address(zkVerifier)
        );
        Appeal appeal = new Appeal(
            address(registry), address(staking), address(reputation), address(governance)
        );

        staking.setContracts(address(registry), address(reputation));
        reputation.setRegistry(address(registry));
        cregToken.approve(address(validatorRewards), type(uint256).max);
        cregToken.transferOwnership(address(governance));

        vm.stopBroadcast();

        console.log("Governance:", address(governance));
        console.log("Staking:   ", address(staking));
        console.log("Reputation:", address(reputation));
        console.log("VRF:       ", address(vrf));
        console.log("ZKVerifier:", address(zkVerifier));
        console.log("Registry:  ", address(registry));
        console.log("Appeal:    ", address(appeal));
        console.log("CregToken: ", address(cregToken));
        console.log("ValRewards:", address(validatorRewards));
        console.log("PinRewards:", address(pinningRewards));

        _writeManifest(deployer, address(governance), address(staking), address(reputation),
            address(vrf), address(zkVerifier), address(registry), address(appeal),
            address(cregToken), address(validatorRewards), address(pinningRewards));
    }

    function _makeSigners(address deployer) internal pure returns (address[] memory) {
        address[] memory s = new address[](1);
        s[0] = deployer;
        return s;
    }

    function _writeManifest(address deployer, address governance, address staking,
        address reputation, address vrf, address zkVerifier, address registry,
        address appeal, address cregToken, address validatorRewards, address pinningRewards
    ) internal {
        string memory m = string.concat(
            '{\n',
            '  "chainId":    "', vm.toString(block.chainid),       '",\n',
            '  "deployedAt": "', vm.toString(block.timestamp),     '",\n',
            '  "deployer":   "', vm.toString(deployer),           '",\n',
            '  "governance": "', vm.toString(governance), '",\n',
            '  "staking":    "', vm.toString(staking),    '",\n',
            '  "reputation": "', vm.toString(reputation), '",\n',
            '  "vrf":        "', vm.toString(vrf),        '",\n',
            '  "zkVerifier": "', vm.toString(zkVerifier), '",\n',
            '  "registry":   "', vm.toString(registry),   '",\n',
            '  "appeal":     "', vm.toString(appeal),     '",\n',
            '  "cregToken":  "', vm.toString(cregToken),  '",\n',
            '  "validatorRewards": "', vm.toString(validatorRewards), '",\n',
            '  "pinningRewards": "', vm.toString(pinningRewards), '"\n',
            '}'
        );
        try vm.createDir("contracts/deployments", true) {} catch {}
        try vm.writeFile("contracts/deployments/anvil-latest.json", m) {
            console.log("Manifest: contracts/deployments/anvil-latest.json");
        } catch {}
    }
}
