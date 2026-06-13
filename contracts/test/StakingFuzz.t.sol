// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../Staking.sol";
import "../Governance.sol";
import "../Reputation.sol";
import "../CregToken.sol";

/// @notice Fuzz and invariant tests for the Staking contract (CREG token-based).
/// Run with: forge test --match-contract StakingFuzzTest -vvv
contract StakingFuzzTest is Test {

    Staking    staking;
    Governance governance;
    CregToken  cregToken;
    Reputation reputation;

    address constant GOV_SIGNER = address(0xA11CE);
    address deployer;

    function setUp() public {
        deployer = address(this);

        // Deploy governance with single signer for testing.
        address[] memory signers = new address[](1);
        signers[0] = GOV_SIGNER;
        governance = new Governance(signers, 1);

        // Deploy CregToken — all supply goes to deployer.
        cregToken  = new CregToken(deployer, deployer, deployer, deployer);

        // Deploy staking with CREG token.
        staking    = new Staking(address(governance), address(cregToken));

        // Deploy reputation.
        reputation = new Reputation(address(governance));

        // Wire contracts.
        address mockRegistry = address(0xBEEF);
        staking.setContracts(mockRegistry, address(reputation));
    }

    function test_onlyOwnerCanSetContracts() public {
        Staking freshStaking = new Staking(address(governance), address(cregToken));

        vm.prank(makeAddr("attacker"));
        vm.expectRevert("Ownable: caller is not the owner");
        freshStaking.setContracts(address(0xBEEF), address(reputation));
    }

    // ── Helper: give CREG tokens and approve staking ─────────────────────────

    function _fundAndApprove(address who, uint256 amount) internal {
        cregToken.transfer(who, amount);
        vm.prank(who);
        cregToken.approve(address(staking), amount);
    }

    // ── Fuzz: Publisher stake + unstake ───────────────────────────────────────

    /// @dev For any amount at or above the minimum, staking should always succeed.
    function testFuzz_PublisherStakeAlwaysSucceeds(uint96 amount) public {
        vm.assume(amount >= staking.minPublisherStake());
        vm.assume(amount <= 50_000 * 10**18); // Cap at 50k CREG
        address publisher = makeAddr("fuzz-publisher");
        _fundAndApprove(publisher, uint256(amount));

        vm.prank(publisher);
        staking.stakeAsPublisher(amount);

        assertEq(staking.stakedBalance(publisher), amount);
    }

    /// @dev Below the minimum, staking must always revert.
    function testFuzz_PublisherStakeBelowMinReverts(uint96 amount) public {
        vm.assume(amount < staking.minPublisherStake());
        address publisher = makeAddr("fuzz-publisher-low");
        _fundAndApprove(publisher, uint256(amount) + 1);

        vm.prank(publisher);
        vm.expectRevert();
        staking.stakeAsPublisher(amount);
    }

    // ── Fuzz: Validator stake ─────────────────────────────────────────────────

    function testFuzz_ValidatorStakeApplyAndApprove(uint96 amount) public {
        vm.assume(amount >= staking.minValidatorStake());
        vm.assume(amount <= 10_000 * 10**18); // Cap at 10k
        address validator = makeAddr("fuzz-validator");
        _fundAndApprove(validator, uint256(amount));

        vm.prank(validator);
        staking.applyToBeValidator(amount);

        // Governance approves.
        vm.prank(GOV_SIGNER);
        governance.submit(
            address(staking),
            abi.encodeCall(staking.approveValidator, (validator)),
            "Approve validator"
        );
        vm.prank(GOV_SIGNER);
        governance.vote(0, true);

        assertTrue(staking.isActiveValidator(validator));
    }

    // ── Fuzz: Unbonding period respected ─────────────────────────────────────

    function testFuzz_WithdrawBeforeUnbondingReverts(uint32 elapsed) public {
        vm.assume(elapsed < staking.UNBONDING_PERIOD());

        address validator = makeAddr("fuzz-unbond");
        _fundAndApprove(validator, 200 * 10**18);

        vm.prank(validator);
        staking.applyToBeValidator(200 * 10**18);

        // Approve via governance.
        vm.prank(GOV_SIGNER);
        governance.submit(
            address(staking),
            abi.encodeCall(staking.approveValidator, (validator)),
            "Approve"
        );
        vm.prank(GOV_SIGNER);
        governance.vote(0, true);

        vm.prank(validator);
        staking.initiateUnbonding();

        vm.warp(block.timestamp + elapsed);
        vm.prank(validator);
        vm.expectRevert();
        staking.withdrawValidatorStake();
    }

    function testFuzz_WithdrawAfterUnbondingSucceeds(uint32 extra) public {
        vm.assume(extra > 0 && extra < 365 days);
        uint256 stake = 200 * 10**18;

        address validator = makeAddr("fuzz-unbond-ok");
        _fundAndApprove(validator, stake);

        vm.prank(validator);
        staking.applyToBeValidator(stake);

        // Approve via governance.
        vm.prank(GOV_SIGNER);
        governance.submit(
            address(staking),
            abi.encodeCall(staking.approveValidator, (validator)),
            "Approve"
        );
        vm.prank(GOV_SIGNER);
        governance.vote(0, true);

        vm.prank(validator);
        staking.initiateUnbonding();

        vm.warp(block.timestamp + staking.UNBONDING_PERIOD() + extra);

        uint256 balBefore = cregToken.balanceOf(validator);
        vm.prank(validator);
        staking.withdrawValidatorStake();

        assertGt(cregToken.balanceOf(validator), balBefore);
    }

    // ── Fuzz: Active validator count ─────────────────────────────────────────

    function testFuzz_ActiveValidatorCountIncrements(uint8 joinCount) public {
        vm.assume(joinCount >= 1 && joinCount <= 5);
        uint256 countBefore = staking.activeValidatorCount();

        for (uint i = 0; i < joinCount; i++) {
            address val = makeAddr(string.concat("inv-val-", vm.toString(i)));
            _fundAndApprove(val, 200 * 10**18);

            vm.prank(val);
            staking.applyToBeValidator(200 * 10**18);

            // Approve each validator.
            vm.prank(GOV_SIGNER);
            governance.submit(
                address(staking),
                abi.encodeCall(staking.approveValidator, (val)),
                string.concat("Approve ", vm.toString(i))
            );
            vm.prank(GOV_SIGNER);
            governance.vote(i, true);
        }

        assertEq(staking.activeValidatorCount(), countBefore + joinCount);
    }
}
