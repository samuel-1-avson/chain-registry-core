// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../Appeal.sol";
import "../Registry.sol";
import "../Staking.sol";
import "../Reputation.sol";
import "../VRF.sol";
import "../Governance.sol";
import "../ZKVerifier.sol";
import "../CregToken.sol";

contract AppealTest is Test {

    Appeal        appeal;
    ChainRegistry registry;
    Staking       staking;
    Reputation    reputation;
    VRF           vrf;
    Governance    governance;
    ZKVerifier    zkVerifier;
    CregToken     cregToken;

    address publisher = makeAddr("publisher");
    address panelist1 = makeAddr("panelist1");
    address panelist2 = makeAddr("panelist2");
    address panelist3 = makeAddr("panelist3");
    address govSigner = makeAddr("govSigner");

    string constant CANONICAL = "npm:bad-package@1.0.0";

    function setUp() public {
        address[] memory signers = new address[](1);
        signers[0] = govSigner;
        governance = new Governance(signers, 1);

        // Deploy CregToken — all supply to this test contract.
        cregToken  = new CregToken(address(this), address(this), address(this), address(this));

        staking    = new Staking(address(governance), address(cregToken));
        reputation = new Reputation(address(governance));
        vrf        = new VRF(address(1), bytes32(0), 0, address(governance));

        // Deploy a dummy ZK verifier.
        uint256[2] memory zeros = [uint256(0), 0];
        uint256[2][] memory ic = new uint256[2][](2);
        ic[0] = [uint256(0), 0];
        ic[1] = [uint256(0), 0];
        zkVerifier = new ZKVerifier(zeros, zeros, zeros, zeros, zeros, zeros, zeros, ic);

        registry   = new ChainRegistry(
            address(staking),
            address(reputation),
            address(vrf),
            address(governance),
            address(zkVerifier)
        );

        staking.setContracts(address(registry), address(reputation));
        reputation.setRegistry(address(registry));

        appeal = new Appeal(address(registry), address(staking), address(reputation), address(governance));

        // Add panelists.
        vm.startPrank(address(governance));
        appeal.addPanelist(panelist1);
        appeal.addPanelist(panelist2);
        appeal.addPanelist(panelist3);
        vm.stopPrank();

        vm.deal(publisher, 10 ether);
        vm.deal(panelist1, 1 ether);
        vm.deal(panelist2, 1 ether);
        vm.deal(panelist3, 1 ether);
    }

    function test_SubmitAppealRequiresBond() public {
        vm.prank(publisher);
        vm.expectRevert();
        appeal.appeal{value: 0.001 ether}(CANONICAL, "I'm innocent");
    }

    function test_SubmitAppealSucceeds() public {
        vm.prank(publisher);
        uint256 id = appeal.appeal{value: 0.1 ether}(CANONICAL, "No malicious code");

        (string memory canonical,,, Appeal.AppealStatus status,,,) = appeal.getAppeal(id);
        assertEq(canonical, CANONICAL);
        assertEq(uint(status), uint(Appeal.AppealStatus.Pending));
    }

    function test_PanelApprovalReturnsBond() public {
        vm.prank(publisher);
        uint256 id = appeal.appeal{value: 0.1 ether}(CANONICAL, "False positive");
        uint256 balBefore = publisher.balance;

        // Three panelists approve.
        vm.prank(panelist1); appeal.vote{value: 0.01 ether}(id, true);
        vm.prank(panelist2); appeal.vote{value: 0.01 ether}(id, true);
        vm.prank(panelist3); appeal.vote{value: 0.01 ether}(id, true);

        (,,, Appeal.AppealStatus status,,,) = appeal.getAppeal(id);
        assertEq(uint(status), uint(Appeal.AppealStatus.Approved));
        // Bond returned to publisher.
        assertGt(publisher.balance, balBefore);
    }

    function test_PanelRejectionSlashesBond() public {
        uint256 govBalBefore = address(governance).balance;

        vm.prank(publisher);
        uint256 id = appeal.appeal{value: 0.1 ether}(CANONICAL, "Trying my luck");

        vm.prank(panelist1); appeal.vote{value: 0.01 ether}(id, false);
        vm.prank(panelist2); appeal.vote{value: 0.01 ether}(id, false);
        vm.prank(panelist3); appeal.vote{value: 0.01 ether}(id, false);

        (,,, Appeal.AppealStatus status,,,) = appeal.getAppeal(id);
        assertEq(uint(status), uint(Appeal.AppealStatus.Rejected));
        assertEq(address(governance).balance, govBalBefore + 0.1 ether);
    }

    function test_CannotVoteTwice() public {
        vm.prank(publisher);
        uint256 id = appeal.appeal{value: 0.1 ether}(CANONICAL, "Please reconsider");

        vm.prank(panelist1);
        appeal.vote{value: 0.01 ether}(id, true);

        vm.prank(panelist1);
        vm.expectRevert();
        appeal.vote{value: 0.01 ether}(id, true);
    }

    function test_NonPanelistCannotVote() public {
        vm.prank(publisher);
        uint256 id = appeal.appeal{value: 0.1 ether}(CANONICAL, "Help");

        vm.prank(makeAddr("random"));
        vm.expectRevert();
        appeal.vote(id, true);
    }

    function test_AppealExpiresAfterWindow() public {
        vm.prank(publisher);
        uint256 id = appeal.appeal{value: 0.1 ether}(CANONICAL, "Waiting...");

        // Fast-forward past the 7-day window.
        vm.warp(block.timestamp + 8 days);
        appeal.expireAppeal(id);

        (,,, Appeal.AppealStatus status,,,) = appeal.getAppeal(id);
        assertEq(uint(status), uint(Appeal.AppealStatus.Expired));
    }

    function test_CannotExpireBeforeWindow() public {
        vm.prank(publisher);
        uint256 id = appeal.appeal{value: 0.1 ether}(CANONICAL, "Fresh appeal");

        vm.expectRevert();
        appeal.expireAppeal(id);
    }

    function test_OnlyGovernanceCanAddPanelist() public {
        vm.prank(makeAddr("rando"));
        vm.expectRevert();
        appeal.addPanelist(makeAddr("new-panelist"));
    }

    function testFuzz_AppealBondAlwaysAboveMin(uint96 bond) public {
        vm.assume(bond >= appeal.MIN_APPEAL_BOND());
        vm.assume(bond <= 5 ether);
        vm.deal(publisher, uint256(bond) + 0.01 ether);

        vm.prank(publisher);
        uint256 id = appeal.appeal{value: bond}(CANONICAL, "Fuzz test");
        (,, uint256 storedBond,,,, ) = appeal.getAppeal(id);
        assertEq(storedBond, bond);
    }

    function test_ReentrancyBlockedDuringVoteResolution() public {
        ReentrantPanelist reentrant = new ReentrantPanelist(appeal);
        vm.deal(address(reentrant), 1 ether);

        vm.prank(address(governance));
        appeal.addPanelist(address(reentrant));

        vm.prank(publisher);
        uint256 id = appeal.appeal{value: 0.1 ether}(CANONICAL, "reentrancy probe");

        vm.prank(panelist1);
        appeal.vote{value: 0.01 ether}(id, true);
        vm.prank(panelist2);
        appeal.vote{value: 0.01 ether}(id, true);

        vm.expectRevert("Panelist bond refund failed");
        reentrant.voteApprove{value: 0.01 ether}(id);
    }

    function test_ReentrancyBlockedDuringPublisherBondRefund() public {
        ReentrantPublisher pub = new ReentrantPublisher(appeal);
        vm.deal(address(pub), 2 ether);

        uint256 id = pub.submitAppeal{value: 0.1 ether}(CANONICAL, "bond refund probe");

        vm.prank(panelist1);
        appeal.vote{value: 0.01 ether}(id, true);
        vm.prank(panelist2);
        appeal.vote{value: 0.01 ether}(id, true);

        pub.armReenter();
        vm.expectRevert("Bond refund failed");
        vm.prank(panelist3);
        appeal.vote{value: 0.01 ether}(id, true);
    }
}

/// @dev Re-enters appeal() from its receive hook when the appeal bond is refunded.
contract ReentrantPublisher {
    Appeal appeal;
    string canonical;
    bool reenter;

    constructor(Appeal _appeal) {
        appeal = _appeal;
    }

    function submitAppeal(string calldata canonical_, string calldata statement)
        external
        payable
        returns (uint256 id)
    {
        canonical = canonical_;
        return appeal.appeal{value: msg.value}(canonical_, statement);
    }

    function armReenter() external {
        reenter = true;
    }

    receive() external payable {
        if (reenter) {
            reenter = false;
            appeal.appeal{value: 0.1 ether}(canonical, "reenter during refund");
        }
    }
}

/// @dev Re-enters vote() from its receive hook during bond distribution.
contract ReentrantPanelist {
    Appeal appeal;
    uint256 targetId;
    bool reenter;

    constructor(Appeal _appeal) {
        appeal = _appeal;
    }

    function voteApprove(uint256 id) external payable {
        targetId = id;
        reenter = true;
        appeal.vote{value: msg.value}(id, true);
    }

    receive() external payable {
        if (reenter) {
            reenter = false;
            appeal.vote{value: 0.01 ether}(targetId, true);
        }
    }
}
