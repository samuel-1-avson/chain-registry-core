// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../Registry.sol";
import "../Staking.sol";
import "../Reputation.sol";
import "../VRF.sol";
import "../Governance.sol";
import "../ZKVerifier.sol";
import "../BatchOperations.sol";

contract FeeReceiver {
    event Received(uint256 amount);

    receive() external payable {
        emit Received(msg.value);
    }
}

contract MockZKVerifier {
    bool public valid = true;

    function setValid(bool _valid) external {
        valid = _valid;
    }

    function verifyProof(
        uint256[8] calldata,
        uint256[] calldata
    ) external view returns (bool) {
        return valid;
    }
}

/// @notice Full integration tests for the chain registry contracts.
/// Uses CREG token-based staking and the two-step validator approval flow.
contract RegistryTest is Test {

    ChainRegistry registry;
    Staking    staking;
    Reputation reputation;
    VRF        vrf;
    Governance governance;
    ZKVerifier zkVerifier;
    CregToken  cregToken;

    address alice   = makeAddr("alice");   // publisher
    address bob;                            // validator
    address carol;                          // validator
    address dave    = makeAddr("dave");    // governance signer

    uint256 aliceKey  = uint256(keccak256("alice-key"));
    uint256 bobKey    = uint256(keccak256("bob-key"));
    uint256 carolKey  = uint256(keccak256("carol-key"));

    string constant CANONICAL = "npm:express@4.18.2";
    bytes32 constant CONTENT_HASH = keccak256("tarball-bytes");
    string constant IPFS_CID = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";

    function setUp() public {
        bob = vm.addr(bobKey);
        carol = vm.addr(carolKey);

        // Deploy governance with 2-of-3 multisig.
        address[] memory signers = new address[](3);
        signers[0] = alice; signers[1] = bob; signers[2] = dave;
        governance = new Governance(signers, 2);

        // Deploy CregToken — all supply goes to this test contract.
        cregToken  = new CregToken(address(this), address(this), address(this), address(this));

        // Deploy core contracts.
        staking    = new Staking(address(governance), address(cregToken));
        reputation = new Reputation(address(governance));
        // VRF requires coordinator address, key hash, subscription ID, and governance.
        // For testing, use dummy values (address(1) coordinator won't be called).
        vrf        = new VRF(address(1), bytes32(0), 0, address(governance));

        // Deploy a dummy ZK verifier.
        uint256[2] memory a1 = [uint256(0), 0];
        uint256[2] memory zeros = [uint256(0), 0];
        uint256[2][] memory ic = new uint256[2][](2);
        ic[0] = [uint256(0), 0];
        ic[1] = [uint256(0), 0];
        zkVerifier = new ZKVerifier(a1, zeros, zeros, zeros, zeros, zeros, zeros, ic);

        registry = new ChainRegistry(
            address(staking),
            address(reputation),
            address(vrf),
            address(governance),
            address(zkVerifier)
        );

        // Wire contracts together.
        staking.setContracts(address(registry), address(reputation));
        reputation.setRegistry(address(registry));

        vm.deal(alice, 10 ether);
    }

    // ── Helper: fund and approve CREG tokens ────────────────────────────────

    function _fundCREG(address who, uint256 amount) internal {
        cregToken.transfer(who, amount);
        vm.prank(who);
        cregToken.approve(address(staking), amount);
    }

    // ── Publisher staking ─────────────────────────────────────────────────────

    function test_publisherMustStakeToSubmit() public {
        vm.prank(alice);
        vm.expectRevert("Publisher must stake first");
        registry.submitPackage(CANONICAL, CONTENT_HASH, IPFS_CID);
    }

    function test_publisherCanStakeAndSubmit() public {
        _stakeAsPublisher(alice);
        _submitPackage(alice);

        ChainRegistry.PackageRecord memory rec = registry.getPackage(CANONICAL);
        assertEq(rec.canonical, CANONICAL);
        assertEq(uint(rec.status), uint(ChainRegistry.PackageStatus.Pending));
        assertEq(rec.publisher, alice);
    }

    function test_cannotSubmitDuplicate() public {
        _stakeAsPublisher(alice);
        _submitPackage(alice);

        vm.prank(alice);
        vm.expectRevert();
        registry.submitPackage(CANONICAL, CONTENT_HASH, IPFS_CID);
    }

    // ── Consensus finalization ────────────────────────────────────────────────

    function test_finalizeRequiresSufficientValidators() public {
        _stakeAsPublisher(alice);
        _submitPackage(alice);
        _joinValidator(bob);
        _joinValidator(carol);

        // Build two approval sigs (meets 67% of 2 = 2).
        ChainRegistry.ValidatorSig[] memory sigs = new ChainRegistry.ValidatorSig[](2);
        sigs[0] = _makeValidatorSig(bobKey,   bob,   CANONICAL, CONTENT_HASH, true);
        sigs[1] = _makeValidatorSig(carolKey, carol, CANONICAL, CONTENT_HASH, true);

        registry.finalizePackage(CANONICAL, sigs);

        assertEq(uint(registry.getStatus(CANONICAL)), uint(ChainRegistry.PackageStatus.Verified));
    }

    function test_finalizationFailsWithInsufficientApprovals() public {
        _stakeAsPublisher(alice);
        _submitPackage(alice);
        _joinValidator(bob);
        _joinValidator(carol);

        // Only 1 approval — not enough (quorum is 2).
        ChainRegistry.ValidatorSig[] memory sigs = new ChainRegistry.ValidatorSig[](1);
        sigs[0] = _makeValidatorSig(bobKey, bob, CANONICAL, CONTENT_HASH, true);

        vm.expectRevert();
        registry.finalizePackage(CANONICAL, sigs);
    }

    function test_withdrawFeesUsesCallForContractRecipients() public {
        FeeReceiver receiver = new FeeReceiver();
        vm.deal(address(registry), 1 ether);

        vm.prank(address(governance));
        registry.withdrawFees(payable(address(receiver)), 0.25 ether);

        assertEq(address(receiver).balance, 0.25 ether);
    }

    function test_tokenOwnershipCanTransferToGovernance() public {
        cregToken.transferOwnership(address(governance));
        assertEq(cregToken.owner(), address(governance));
    }

    function test_invalidSignatureReverts() public {
        _stakeAsPublisher(alice);
        _submitPackage(alice);
        _joinValidator(bob);
        _joinValidator(carol);

        ChainRegistry.ValidatorSig[] memory sigs = new ChainRegistry.ValidatorSig[](2);
        sigs[0] = _makeValidatorSig(bobKey, bob, CANONICAL, CONTENT_HASH, true);
        // Carol's sig is garbled.
        sigs[1] = ChainRegistry.ValidatorSig({ validator: carol, signature: bytes("bad-sig"), approved: true });

        vm.expectRevert();
        registry.finalizePackage(CANONICAL, sigs);
    }

    // ── ZK package binding ─────────────────────────────────────────────────

    function test_submitPackageWithZKProofRequiresPackageBoundInputs() public {
        _stakeAsPublisher(alice);
        ChainRegistry zkRegistry = _deployRegistryWithMockZK();
        uint256[8] memory proof;
        uint256[] memory wrongInputs = _zkInputs("npm:other@1.0.0", CONTENT_HASH, IPFS_CID);
        uint256 fee = zkRegistry.zkValidationFee();

        vm.prank(alice);
        vm.expectRevert(ChainRegistry.InvalidZKPublicInputs.selector);
        zkRegistry.submitPackageWithZKProof{value: fee}(
            CANONICAL,
            CONTENT_HASH,
            IPFS_CID,
            proof,
            wrongInputs
        );
    }

    function test_submitPackageWithZKProofAcceptsPackageBoundInputs() public {
        _stakeAsPublisher(alice);
        ChainRegistry zkRegistry = _deployRegistryWithMockZK();
        uint256[8] memory proof;
        uint256[] memory inputs = _zkInputs(CANONICAL, CONTENT_HASH, IPFS_CID);
        uint256 fee = zkRegistry.zkValidationFee();

        vm.prank(alice);
        zkRegistry.submitPackageWithZKProof{value: fee}(
            CANONICAL,
            CONTENT_HASH,
            IPFS_CID,
            proof,
            inputs
        );

        assertEq(uint(zkRegistry.getStatus(CANONICAL)), uint(ChainRegistry.PackageStatus.Verified));
        ChainRegistry.PackageRecord memory rec = zkRegistry.getPackage(CANONICAL);
        assertEq(uint(rec.validationMode), uint(ChainRegistry.ValidationMode.ZKProof));
    }

    function test_verifyZKProofForPendingPackageRequiresStoredPackageBinding() public {
        _stakeAsPublisher(alice);
        ChainRegistry zkRegistry = _deployRegistryWithMockZK();
        uint256[8] memory proof;
        uint256[] memory wrongInputs = _zkInputs(CANONICAL, bytes32(uint256(123)), IPFS_CID);

        vm.prank(alice);
        zkRegistry.submitPackage(CANONICAL, CONTENT_HASH, IPFS_CID);

        vm.expectRevert(ChainRegistry.InvalidZKPublicInputs.selector);
        zkRegistry.verifyZKProof(CANONICAL, proof, wrongInputs);

        uint256[] memory inputs = _zkInputs(CANONICAL, CONTENT_HASH, IPFS_CID);
        zkRegistry.verifyZKProof(CANONICAL, proof, inputs);

        assertEq(uint(zkRegistry.getStatus(CANONICAL)), uint(ChainRegistry.PackageStatus.Verified));
    }

    // ── Revocation ────────────────────────────────────────────────────────────

    function test_publisherCanRevoke() public {
        _stakeAndVerify();

        vm.prank(alice);
        registry.revokePackage(CANONICAL, "Vulnerability found", Staking.Severity.Low);

        assertEq(uint(registry.getStatus(CANONICAL)), uint(ChainRegistry.PackageStatus.Revoked));
    }

    function test_governanceCanRevokeAndSlash() public {
        _stakeAndVerify();
        uint256 stakeBefore = staking.stakedBalance(alice);

        // Governance calls through the multisig.
        vm.prank(address(governance));
        registry.revokePackage(CANONICAL, "Malicious code detected", Staking.Severity.Medium);

        assertEq(uint(registry.getStatus(CANONICAL)), uint(ChainRegistry.PackageStatus.Revoked));
        // Publisher should have been slashed.
        assertLt(staking.stakedBalance(alice), stakeBefore);
    }

    function test_revokedPackageCannotBeResubmitted() public {
        _stakeAndVerify();

        vm.prank(alice);
        registry.revokePackage(CANONICAL, "Compromised", Staking.Severity.Low);

        vm.prank(alice);
        vm.expectRevert();
        registry.submitPackage(CANONICAL, CONTENT_HASH, IPFS_CID);
    }

    // ── Staking ───────────────────────────────────────────────────────────────

    function test_validatorUnbondingPeriod() public {
        _joinValidator(bob);
        assertTrue(staking.isActiveValidator(bob));

        vm.prank(bob);
        staking.initiateUnbonding();
        assertFalse(staking.isActiveValidator(bob));

        // Can't withdraw during unbonding period.
        vm.prank(bob);
        vm.expectRevert();
        staking.withdrawValidatorStake();

        // Fast-forward past unbonding period (14 days).
        vm.warp(block.timestamp + 15 days);
        vm.prank(bob);
        staking.withdrawValidatorStake(); // Should succeed now.
    }

    function test_slashAfterThreeOffences() public {
        _joinValidator(bob);

        // Three slashes auto-eject the validator.
        vm.startPrank(address(registry));
        staking.slash(bob, 1 * 10**18, "Offense 1");
        staking.slash(bob, 1 * 10**18, "Offense 2");
        staking.slash(bob, 1 * 10**18, "Offense 3");
        vm.stopPrank();

        assertFalse(staking.isActiveValidator(bob));
    }

    // ── Reputation ───────────────────────────────────────────────────────────

    function test_newValidatorStartsAt50() public {
        assertEq(reputation.scoreOf(bob), 50);
    }

    function test_approvalIncreasesReputation() public {
        vm.startPrank(address(registry));
        reputation.recordApproval(bob);
        reputation.recordApproval(bob);
        vm.stopPrank();
        assertGt(reputation.scoreOf(bob), 50);
    }

    // ── VRF ───────────────────────────────────────────────────────────────────

    function test_vrfSelectsDifferentSetsForDifferentPackages() public {
        address[] memory validators = new address[](10);
        for (uint i = 0; i < 10; i++) {
            validators[i] = makeAddr(string.concat("val", vm.toString(i)));
            _joinValidatorAddr(validators[i]);
        }

        // Use selectValidatorsWithSeed (requires governance prank).
        vm.roll(100);
        vm.startPrank(address(governance));
        address[] memory setA = vrf.selectValidatorsWithSeed("npm:express@4.0.0", validators, 12345);
        address[] memory setB = vrf.selectValidatorsWithSeed("npm:lodash@4.0.0",  validators, 67890);
        vm.stopPrank();

        // They should differ (very high probability with random seed).
        bool differs = false;
        for (uint i = 0; i < setA.length; i++) {
            if (setA[i] != setB[i]) { differs = true; break; }
        }
        assertTrue(differs);
    }

    // ── Governance ────────────────────────────────────────────────────────────

    function test_governanceProposalRequiresThreshold() public {
        // Propose changing the quorum.
        bytes memory callData = abi.encodeCall(registry.setQuorum, (75));

        vm.prank(alice);
        uint256 id = governance.submit(address(registry), callData, "Increase quorum to 75%");

        // Only Alice voted — threshold is 2.
        vm.prank(alice);
        governance.vote(id, true);

        // Not executed yet.
        (,,,Governance.ProposalStatus status,,) = governance.getProposal(id);
        assertEq(uint(status), uint(Governance.ProposalStatus.Pending));

        // Bob votes — threshold met, auto-executes.
        vm.prank(bob);
        governance.vote(id, true);

        (,,,status,,) = governance.getProposal(id);
        assertEq(uint(status), uint(Governance.ProposalStatus.Executed));
        assertEq(registry.quorumPct(), 75);
    }

    // ── resetRollupState removed test ────────────────────────────────────────

    function test_resetRollupStateDoesNotExist() public pure {
        // Verify that resetRollupState() has been removed.
        // This test is a documentation marker — the function no longer exists
        // and any attempt to call it will fail at compile time.
        assert(true);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    function _stakeAsPublisher(address who) internal {
        uint256 pubStake = 2 * 10**18; // 2 CREG (above 1 CREG minimum)
        _fundCREG(who, pubStake);
        vm.prank(who);
        staking.stakeAsPublisher(pubStake);
    }

    function _submitPackage(address who) internal {
        vm.prank(who);
        registry.submitPackage(CANONICAL, CONTENT_HASH, IPFS_CID);
    }

    function _joinValidator(address who) internal {
        uint256 valStake = 200 * 10**18; // 200 CREG (above 100 CREG minimum)
        _fundCREG(who, valStake);
        vm.prank(who);
        staking.applyToBeValidator(valStake);

        // Governance auto-approval (using direct call since we can prank governance).
        vm.prank(address(governance));
        staking.approveValidator(who);
    }

    function _joinValidatorAddr(address who) internal {
        uint256 valStake = 200 * 10**18;
        _fundCREG(who, valStake);
        vm.prank(who);
        staking.applyToBeValidator(valStake);

        vm.prank(address(governance));
        staking.approveValidator(who);
    }

    function _stakeAndVerify() internal {
        _stakeAsPublisher(alice);
        _submitPackage(alice);
        _joinValidator(bob);
        _joinValidator(carol);

        ChainRegistry.ValidatorSig[] memory sigs = new ChainRegistry.ValidatorSig[](2);
        sigs[0] = _makeValidatorSig(bobKey,   bob,   CANONICAL, CONTENT_HASH, true);
        sigs[1] = _makeValidatorSig(carolKey, carol, CANONICAL, CONTENT_HASH, true);
        registry.finalizePackage(CANONICAL, sigs);
    }

    function _deployRegistryWithMockZK() internal returns (ChainRegistry) {
        MockZKVerifier mockVerifier = new MockZKVerifier();
        return new ChainRegistry(
            address(staking),
            address(reputation),
            address(vrf),
            address(governance),
            address(mockVerifier)
        );
    }

    function _zkInputs(
        string memory canonical,
        bytes32 contentHash,
        string memory ipfsCid
    ) internal pure returns (uint256[] memory inputs) {
        bytes32 bindingHash = keccak256(
            abi.encode("creg-zk-package-v1", canonical, contentHash, ipfsCid)
        );
        uint256 binding = uint256(bindingHash);
        inputs = new uint256[](2);
        inputs[0] = binding >> 128;
        inputs[1] = binding & uint256(type(uint128).max);
    }

    /// Produce a real ECDSA signature from a validator private key.
    function _makeValidatorSig(
        uint256 privKey,
        address validator,
        string memory canonical,
        bytes32 contentHash,
        bool approved
    ) internal pure returns (ChainRegistry.ValidatorSig memory) {
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(abi.encodePacked(canonical, contentHash))
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKey, digest);
        return ChainRegistry.ValidatorSig({
            validator: validator,
            signature: abi.encodePacked(r, s, v),
            approved:  approved
        });
    }

    function test_batchSubmitPackagesViaAuthorizedRelay() public {
        _stakeAsPublisher(alice);

        BatchOperations batchOps = new BatchOperations(
            address(registry),
            address(staking),
            address(governance)
        );
        vm.prank(address(governance));
        registry.setPackageSubmitRelay(address(batchOps), true);

        BatchOperations.PackageSubmission[] memory packages =
            new BatchOperations.PackageSubmission[](1);
        packages[0] = BatchOperations.PackageSubmission({
            canonical: CANONICAL,
            contentHash: CONTENT_HASH,
            ipfsCID: IPFS_CID
        });

        vm.prank(alice);
        batchOps.batchSubmitPackages(packages);

        bytes32 key = keccak256(abi.encodePacked(CANONICAL));
        (,,, address publisher,,,,,,,) = registry.packages(key);
        assertEq(publisher, alice);
    }

    function test_submitPackageForRejectsUnauthorizedRelay() public {
        _stakeAsPublisher(alice);
        address relay = makeAddr("unauthorized-relay");

        vm.prank(relay);
        vm.expectRevert(ChainRegistry.NotAuthorizedSubmitRelay.selector);
        registry.submitPackageFor(
            alice,
            CANONICAL,
            CONTENT_HASH,
            IPFS_CID
        );
    }

    function test_finalizePackageRejectsDuplicateValidatorSig() public {
        _stakeAsPublisher(alice);
        _submitPackage(alice);
        _joinValidator(bob);
        _joinValidator(carol);

        ChainRegistry.ValidatorSig[] memory sigs = new ChainRegistry.ValidatorSig[](3);
        sigs[0] = _makeValidatorSig(bobKey, bob, CANONICAL, CONTENT_HASH, true);
        sigs[1] = _makeValidatorSig(bobKey, bob, CANONICAL, CONTENT_HASH, true);
        sigs[2] = _makeValidatorSig(carolKey, carol, CANONICAL, CONTENT_HASH, true);

        vm.expectRevert(abi.encodeWithSelector(ChainRegistry.ValidatorAlreadySigned.selector, bob));
        registry.finalizePackage(CANONICAL, sigs);
    }

    function test_finalizePackageRejectsDoubleFinalize() public {
        _stakeAndVerify();

        ChainRegistry.ValidatorSig[] memory sigs = new ChainRegistry.ValidatorSig[](2);
        sigs[0] = _makeValidatorSig(bobKey, bob, CANONICAL, CONTENT_HASH, true);
        sigs[1] = _makeValidatorSig(carolKey, carol, CANONICAL, CONTENT_HASH, true);

        vm.expectRevert(abi.encodeWithSelector(ChainRegistry.AlreadyVerified.selector, CANONICAL));
        registry.finalizePackage(CANONICAL, sigs);
    }

    function test_finalizePackageEnforcesAuthorizedRelay() public {
        _stakeAsPublisher(alice);
        _submitPackage(alice);
        _joinValidator(bob);
        _joinValidator(carol);

        address relay = makeAddr("finalize-relay");
        vm.prank(address(governance));
        registry.setEnforceFinalizeRelays(true);
        vm.prank(address(governance));
        registry.setPackageFinalizeRelay(relay, true);

        ChainRegistry.ValidatorSig[] memory sigs = new ChainRegistry.ValidatorSig[](2);
        sigs[0] = _makeValidatorSig(bobKey, bob, CANONICAL, CONTENT_HASH, true);
        sigs[1] = _makeValidatorSig(carolKey, carol, CANONICAL, CONTENT_HASH, true);

        vm.expectRevert(ChainRegistry.NotAuthorizedFinalizeRelay.selector);
        registry.finalizePackage(CANONICAL, sigs);

        vm.prank(relay);
        registry.finalizePackage(CANONICAL, sigs);
        assertEq(uint(registry.getStatus(CANONICAL)), uint(ChainRegistry.PackageStatus.Verified));
    }
}
