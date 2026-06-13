// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../Staking.sol";
import "../Reputation.sol";
import "../Governance.sol";
import "../CregToken.sol";

contract StakingPermitTest is Test {
    Staking staking;
    Reputation reputation;
    Governance governance;
    CregToken cregToken;

    uint256 publisherKey = uint256(keccak256("publisher-key"));
    uint256 validatorKey = uint256(keccak256("validator-key"));
    address publisher;
    address validator;
    address relayer = makeAddr("relayer");

    bytes32 constant PERMIT_TYPEHASH = keccak256(
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    );

    function setUp() public {
        publisher = vm.addr(publisherKey);
        validator = vm.addr(validatorKey);

        address[] memory signers = new address[](1);
        signers[0] = address(this);

        governance = new Governance(signers, 1);
        cregToken = new CregToken(address(this), address(this), address(this), address(this));
        staking = new Staking(address(governance), address(cregToken));
        reputation = new Reputation(address(governance));
        staking.setContracts(address(0xBEEF), address(reputation));

        cregToken.transfer(publisher, 500 ether);
        cregToken.transfer(validator, 500 ether);
    }

    function test_stakeAsPublisherWithPermitCreditsPublisher() public {
        uint256 amount = 10 ether;
        uint256 deadline = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 s) = _signPermit(publisherKey, publisher, address(staking), amount, deadline);

        vm.prank(relayer);
        staking.stakeAsPublisherWithPermit(publisher, amount, deadline, v, r, s);

        assertEq(staking.stakedBalance(publisher), amount);
        assertEq(cregToken.balanceOf(publisher), 500 ether - amount);
        assertEq(cregToken.allowance(publisher, address(staking)), 0);
    }

    function test_applyToBeValidatorWithPermitCreatesPendingValidator() public {
        uint256 amount = 150 ether;
        uint256 deadline = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 s) = _signPermit(validatorKey, validator, address(staking), amount, deadline);

        vm.prank(relayer);
        staking.applyToBeValidatorWithPermit(validator, amount, deadline, v, r, s);

        (uint256 stake, Staking.ValidatorState state,,,,) = staking.validators(validator);
        assertEq(stake, amount);
        assertEq(uint8(state), uint8(Staking.ValidatorState.Pending));
        assertEq(cregToken.balanceOf(validator), 500 ether - amount);
    }

    function _signPermit(
        uint256 signerKey,
        address owner,
        address spender,
        uint256 value,
        uint256 deadline
    ) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        uint256 nonce = cregToken.nonces(owner);
        bytes32 structHash = keccak256(
            abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonce, deadline)
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", cregToken.DOMAIN_SEPARATOR(), structHash)
        );
        return vm.sign(signerKey, digest);
    }
}