// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../VRF.sol";
import "../Governance.sol";

/// @dev Minimal mock coordinator for local / forge tests.
contract MockVRFCoordinator {
    uint256 private _nextRequestId = 1;

    function requestRandomWords(
        bytes32,
        uint64,
        uint16,
        uint32,
        uint32
    ) external returns (uint256 requestId) {
        requestId = _nextRequestId++;
    }

    function fulfill(VRF consumer, uint256 requestId, uint256 randomWord) external {
        uint256[] memory words = new uint256[](1);
        words[0] = randomWord;
        consumer.rawFulfillRandomWords(requestId, words);
    }
}

contract VRFTest is Test {
    MockVRFCoordinator coordinator;
    Governance governance;
    VRF vrf;

    address[] validators;

    function setUp() public {
        coordinator = new MockVRFCoordinator();
        address[] memory signers = new address[](1);
        signers[0] = address(this);
        governance = new Governance(signers, 1);
        vrf = new VRF(
            address(coordinator),
            bytes32(uint256(1)),
            1,
            address(governance)
        );

        validators = new address[](10);
        for (uint i = 0; i < 10; i++) {
            validators[i] = address(uint160(0x1000 + i));
        }
    }

    function test_fulfillRandomWordsStoresSelection() public {
        string memory pkg = "npm:express@4.18.2";

        vm.prank(address(governance));
        uint256 requestId = vrf.requestValidatorSelection(pkg, validators);

        coordinator.fulfill(vrf, requestId, 42);

        assertTrue(vrf.isSelectionComplete(pkg));
        address[] memory selected = vrf.getSelectedValidators(pkg);
        assertEq(selected.length, vrf.validatorsPerPackage());

        // All selected addresses must come from the active set.
        for (uint i = 0; i < selected.length; i++) {
            bool found;
            for (uint j = 0; j < validators.length; j++) {
                if (selected[i] == validators[j]) {
                    found = true;
                    break;
                }
            }
            assertTrue(found, "selected validator not in active set");
        }
    }

    function test_fulfillRandomWordsMatchesManualSeed() public {
        string memory pkg = "npm:lodash@4.17.21";
        uint256 seed = 999;

        vm.startPrank(address(governance));
        uint256 requestId = vrf.requestValidatorSelection(pkg, validators);
        vm.stopPrank();

        coordinator.fulfill(vrf, requestId, seed);

        vm.prank(address(governance));
        address[] memory manual = vrf.selectValidatorsWithSeed("npm:other@1.0.0", validators, seed);

        address[] memory fromVrf = vrf.getSelectedValidators(pkg);
        assertEq(fromVrf.length, manual.length);
        for (uint i = 0; i < fromVrf.length; i++) {
            assertEq(fromVrf[i], manual[i]);
        }
    }

    function test_fulfillTwiceReverts() public {
        vm.prank(address(governance));
        uint256 requestId = vrf.requestValidatorSelection("npm:a@1.0.0", validators);

        coordinator.fulfill(vrf, requestId, 1);

        vm.expectRevert(abi.encodeWithSelector(VRF.NoPendingRequest.selector, requestId));
        coordinator.fulfill(vrf, requestId, 2);
    }

    function test_onlyCoordinatorCanFulfill() public {
        vm.prank(address(governance));
        uint256 requestId = vrf.requestValidatorSelection("npm:b@1.0.0", validators);

        uint256[] memory words = new uint256[](1);
        words[0] = 7;

        vm.expectRevert("Only coordinator can fulfill");
        vrf.rawFulfillRandomWords(requestId, words);
    }

    function test_rejectsDuplicateSelectionRequest() public {
        string memory pkg = "npm:c@1.0.0";

        vm.prank(address(governance));
        uint256 requestId = vrf.requestValidatorSelection(pkg, validators);
        coordinator.fulfill(vrf, requestId, 5);

        vm.prank(address(governance));
        vm.expectRevert(
            abi.encodeWithSelector(VRF.SelectionAlreadyComplete.selector, keccak256(bytes(pkg)))
        );
        vrf.requestValidatorSelection(pkg, validators);
    }
}
