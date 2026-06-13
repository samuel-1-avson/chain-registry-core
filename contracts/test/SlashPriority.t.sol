// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../Staking.sol";
import "../Governance.sol";
import "../Reputation.sol";
import "../CregToken.sol";

/// @notice Tests for ISSUE-028: _executeSlash validator-first priority
/// and ISSUE-031: Governance.removeSigner array cleanup.
contract SlashPriorityTest is Test {

    Staking    staking;
    Governance governance;
    CregToken  cregToken;
    Reputation reputation;

    address constant GOV_SIGNER = address(0xA11CE);
    address constant REGISTRY   = address(0xBEEF);

    address val; // dual-role: validator + publisher
    address pub; // publisher-only

    uint256 constant VAL_STAKE = 200e18;
    uint256 constant PUB_STAKE = 100e18;

    function setUp() public {
        address[] memory signers = new address[](1);
        signers[0] = GOV_SIGNER;
        governance = new Governance(signers, 1);
        cregToken  = new CregToken(address(this), address(this), address(this), address(this));
        staking    = new Staking(address(governance), address(cregToken));
        reputation = new Reputation(address(governance));
        staking.setContracts(REGISTRY, address(reputation));

        val = makeAddr("validator");
        pub = makeAddr("publisher");

        // Fund both accounts.
        cregToken.transfer(val, VAL_STAKE + PUB_STAKE + 1000e18);
        cregToken.transfer(pub, PUB_STAKE);

        // val: stake as publisher AND as validator.
        vm.startPrank(val);
        cregToken.approve(address(staking), VAL_STAKE + PUB_STAKE);
        staking.stakeAsPublisher(PUB_STAKE);
        staking.applyToBeValidator(VAL_STAKE);
        vm.stopPrank();

        // Approve val as validator.
        // approveValidator checks msg.sender == governance (the contract), not an EOA signer.
        vm.prank(address(governance));
        staking.approveValidator(val);

        // pub: stake as publisher only.
        vm.prank(pub);
        cregToken.approve(address(staking), PUB_STAKE);
        vm.prank(pub);
        staking.stakeAsPublisher(PUB_STAKE);
    }

    // ── ISSUE-028: dual-role validator slash priority ─────────────────────────

    // Helper: read validator stake from the tuple returned by the public mapping getter.
    // Tuple: (uint256 stake, ValidatorState state, uint256 unbondingAt, uint256 slashCount, uint256 ejectedAt, uint256 appliedAt)
    function _valStake(address who) internal view returns (uint256 s) {
        (s,,,,,) = staking.validators(who);
    }
    function _valSlashCount(address who) internal view returns (uint256 c) {
        (,,, c,,) = staking.validators(who);
    }

    /// For an active validator, validator stake is slashed first (not publisher).
    function test_dualRole_slashHitsValidatorStakeFirst() public {
        uint256 slashAmt       = 50e18;
        uint256 valStakeBefore = _valStake(val);
        uint256 pubStakeBefore = staking.publisherStakes(val);

        vm.prank(REGISTRY);
        staking.slash(val, slashAmt, "misbehaviour");

        assertEq(_valStake(val),               valStakeBefore - slashAmt, "validator stake must decrease");
        assertEq(staking.publisherStakes(val), pubStakeBefore,             "publisher stake must be untouched");
    }

    /// slashCount must be incremented when validator stake is slashed.
    function test_dualRole_slashCountIncremented() public {
        assertEq(_valSlashCount(val), 0, "slashCount starts at 0");

        vm.prank(REGISTRY);
        staking.slash(val, 50e18, "misbehaviour");

        assertEq(_valSlashCount(val), 1, "slashCount must be 1 after slash");
    }

    /// Publisher-only account still gets slashed from publisher stake.
    function test_publisherOnly_slashHitsPublisherStake() public {
        uint256 slashAmt       = 20e18;
        uint256 pubStakeBefore = staking.publisherStakes(pub);

        vm.prank(REGISTRY);
        staking.slash(pub, slashAmt, "bad publish");

        assertEq(staking.publisherStakes(pub), pubStakeBefore - slashAmt);
    }

    /// slashSeverity base must use validator stake for active validators.
    function test_slashSeverity_baseIsValidatorStakeForActiveValidator() public {
        uint256 valStakeBefore = _valStake(val);
        uint256 pubStakeBefore = staking.publisherStakes(val);

        // Low severity = 2% of the base stake (SLASH_LOW_PCT = 2).
        vm.prank(REGISTRY);
        staking.slashSeverity(val, Staking.Severity.Low, "low sev");

        uint256 expectedSlash = valStakeBefore * 2 / 100;
        assertApproxEqAbs(_valStake(val), valStakeBefore - expectedSlash, 1e15,
            "validator stake reduced by 10%");
        assertEq(staking.publisherStakes(val), pubStakeBefore, "publisher stake untouched");
    }
}

/// @notice Tests for the governance-authorized external slasher allowlist
///         (PackageInsurance ACL fix). An external contract (e.g.
///         PackageInsurance) may only slash once governance authorizes it.
contract AuthorizedSlasherTest is Test {

    Staking    staking;
    Governance governance;
    CregToken  cregToken;
    Reputation reputation;

    address constant GOV_SIGNER = address(0xA11CE);
    address constant REGISTRY   = address(0xBEEF);

    address pub;
    address insurance; // stand-in for a deployed PackageInsurance contract
    uint256 constant PUB_STAKE = 100e18;

    function setUp() public {
        address[] memory signers = new address[](1);
        signers[0] = GOV_SIGNER;
        governance = new Governance(signers, 1);
        cregToken  = new CregToken(address(this), address(this), address(this), address(this));
        staking    = new Staking(address(governance), address(cregToken));
        reputation = new Reputation(address(governance));
        staking.setContracts(REGISTRY, address(reputation));

        pub = makeAddr("publisher");
        insurance = makeAddr("insurance");

        cregToken.transfer(pub, PUB_STAKE);
        vm.prank(pub);
        cregToken.approve(address(staking), PUB_STAKE);
        vm.prank(pub);
        staking.stakeAsPublisher(PUB_STAKE);
    }

    /// An un-authorized external caller cannot slash.
    function test_unauthorizedCannotSlash() public {
        vm.prank(insurance);
        vm.expectRevert();
        staking.slash(pub, 10e18, "insurance claim");
    }

    /// Only governance may manage the slasher allowlist.
    function test_onlyGovernanceCanSetSlasher() public {
        vm.prank(insurance);
        vm.expectRevert();
        staking.setSlasher(insurance, true);
    }

    /// Once authorized, the external slasher can slash publisher stake.
    function test_authorizedSlasherCanSlash() public {
        vm.prank(address(governance));
        staking.setSlasher(insurance, true);
        assertTrue(staking.authorizedSlashers(insurance), "slasher must be authorized");

        uint256 stakeBefore = staking.publisherStakes(pub);
        vm.prank(insurance);
        staking.slash(pub, 10e18, "insurance claim");
        assertEq(
            staking.publisherStakes(pub),
            stakeBefore - 10e18,
            "authorized slasher must reduce stake"
        );
    }

    /// Revoking authorization restores the original ACL.
    function test_revokedSlasherCannotSlash() public {
        vm.prank(address(governance));
        staking.setSlasher(insurance, true);
        vm.prank(address(governance));
        staking.setSlasher(insurance, false);

        vm.prank(insurance);
        vm.expectRevert();
        staking.slash(pub, 10e18, "insurance claim");
    }
}

/// @notice Tests for ISSUE-031: Governance.removeSigner array cleanup.
contract GovernanceSignerArrayTest is Test {

    Governance gov;

    address signer1 = makeAddr("s1");
    address signer2 = makeAddr("s2");
    address signer3 = makeAddr("s3");

    function setUp() public {
        address[] memory signers = new address[](3);
        signers[0] = signer1;
        signers[1] = signer2;
        signers[2] = signer3;
        gov = new Governance(signers, 2);
    }

    /// After removeSigner, signerCount() must drop by 1.
    function test_removeSigner_decreasesSignerCount() public {
        assertEq(gov.signerCount(), 3);
        vm.prank(address(gov)); // must come from governance itself
        gov.removeSigner(signer3);
        assertEq(gov.signerCount(), 2, "signerCount must reflect removal");
    }

    /// Removed signer must not appear in the signers[] array.
    function test_removeSigner_purgesFromArray() public {
        vm.prank(address(gov));
        gov.removeSigner(signer1);

        uint256 count = gov.signerCount();
        for (uint256 i = 0; i < count; i++) {
            assertFalse(gov.signers(i) == signer1, "removed signer must not be in array");
        }
    }

    /// isSigner mapping must be cleared.
    function test_removeSigner_clearsMappingEntry() public {
        assertTrue(gov.isSigner(signer2));
        vm.prank(address(gov));
        gov.removeSigner(signer2);
        assertFalse(gov.isSigner(signer2), "isSigner must be false after removal");
    }

    /// Removing when it would break threshold must revert.
    function test_removeSigner_revertsWhenBreaksThreshold() public {
        // threshold=2, only 3 signers → removing one still leaves 2 ≥ threshold.
        // Remove a second signer first to get to 2.
        vm.prank(address(gov));
        gov.removeSigner(signer3);
        // Now 2 signers, threshold=2. Removing one more would leave 1 < 2.
        vm.prank(address(gov));
        vm.expectRevert("Would break threshold");
        gov.removeSigner(signer1);
    }

    /// updateThreshold uses the correct (post-removal) signers length.
    function test_updateThreshold_usesCorrectLength() public {
        vm.prank(address(gov));
        gov.removeSigner(signer3);
        assertEq(gov.signerCount(), 2);

        // newThreshold=2 must be valid (≤ signerCount=2).
        vm.prank(address(gov));
        gov.updateThreshold(2);

        // newThreshold=3 must revert (> signerCount=2).
        vm.prank(address(gov));
        vm.expectRevert("Invalid threshold");
        gov.updateThreshold(3);
    }
}
