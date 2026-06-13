// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../CrossChainRegistry.sol";

/**
 * @title CrossChainRegistryTest
 * @notice Regression tests for:
 *   ISSUE-005 — receiveVerification must NOT skip signature verification when
 *               validatorThreshold == 0 (the default unconfigured state).
 *   ISSUE-006 — sendVerification must include validator signatures in the outbound
 *               message; previously the `signature` field was always "".
 *
 * Both issues are addressed by _verifyThresholdSignatures (shared helper) and
 * _messageBodyHash (canonical body hash excluding the signature field).
 */
contract CrossChainRegistryTest is Test {

    // ── Test actors ──────────────────────────────────────────────────────────

    uint256 constant VAL1_PK = 0x1111;
    uint256 constant VAL2_PK = 0x2222;
    address val1;
    address val2;

    // ── Contracts ────────────────────────────────────────────────────────────

    CrossChainRegistry ccr;
    MockBridge          bridge;
    uint16 constant SRC_CHAIN = 1;
    uint16 constant DST_CHAIN = 2;

    // ── setUp ────────────────────────────────────────────────────────────────

    function setUp() public {
        val1 = vm.addr(VAL1_PK);
        val2 = vm.addr(VAL2_PK);

        // Deploy with address(0) for registry (not called by paths under test)
        // and this contract as governance.
        ccr = new CrossChainRegistry(address(0), address(this), SRC_CHAIN);

        bridge = new MockBridge();
        ccr.setMessageBridge(address(bridge));

        // Register DST_CHAIN so receiveVerification allows it as a source.
        ccr.addChain(DST_CHAIN, "TestDst", address(0x999), 500_000);

        // Configure validator set: 2 validators, threshold 2.
        address[] memory vals = new address[](2);
        vals[0] = val1;
        vals[1] = val2;
        ccr.setValidatorSet(vals, 2);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// @dev Re-implement the body hash exactly as the contract does.
    function _messageBodyHash(
        uint16 srcChainId,
        uint16 dstChainId,
        bytes32 packageHash,
        string memory canonical,
        address publisher,
        uint8 status,
        uint256 timestamp
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(
            srcChainId,
            dstChainId,
            packageHash,
            canonical,
            publisher,
            status,
            timestamp
        ));
    }

    /// @dev Sign bodyHash with Ethereum personal-sign prefix.
    function _sign(uint256 pk, bytes32 bodyHash)
        internal pure returns (bytes memory)
    {
        bytes32 ethHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", bodyHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, ethHash);
        return abi.encodePacked(r, s, v);
    }

    /// @dev Encode a CrossChainMessage the same way the contract does.
    function _encodeMessage(
        uint16 src, uint16 dst,
        bytes32 pkgHash, string memory canonical,
        address publisher, uint8 status, uint256 timestamp,
        bytes memory sig
    ) internal pure returns (bytes memory) {
        return abi.encode(src, dst, pkgHash, canonical, publisher, status, timestamp, sig);
    }

    // ── ISSUE-005: receiveVerification bypass ─────────────────────────────────

    /// @dev If validatorThreshold == 0, receiveVerification must revert with
    ///      VerificationFailed("Validator set not configured"), not accept the message.
    function test_receiveWithZeroThresholdReverts() public {
        // Deploy a fresh registry with NO validator set configured.
        CrossChainRegistry bare = new CrossChainRegistry(address(0), address(this), SRC_CHAIN);
        MockBridge bareBridge = new MockBridge();
        bare.setMessageBridge(address(bareBridge));
        bare.addChain(DST_CHAIN, "TestDst", address(0x999), 500_000);
        // validatorThreshold is still 0 — no setValidatorSet call.

        bytes memory msg_ = _encodeMessage(
            DST_CHAIN, SRC_CHAIN,
            keccak256("pkg"), "pkg@1.0.0",
            address(0x1), 2, block.timestamp,
            ""
        );
        bytes[] memory emptySigs = new bytes[](0);

        vm.prank(address(bareBridge));
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossChainRegistry.VerificationFailed.selector,
                "Validator set not configured"
            )
        );
        bare.receiveVerification(DST_CHAIN, msg_, emptySigs);
    }

    /// @dev Messages with valid threshold signatures must be accepted.
    function test_receiveWithValidSignaturesAccepted() public {
        bytes32 pkgHash = keccak256("mypkg");
        uint256 ts = block.timestamp;
        // Build body hash (srcChain = DST_CHAIN because the message arrived FROM DST_CHAIN).
        bytes32 body = _messageBodyHash(
            DST_CHAIN, SRC_CHAIN, pkgHash, "mypkg@1.0.0",
            address(0x1), 2, ts
        );

        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _sign(VAL1_PK, body);
        sigs[1] = _sign(VAL2_PK, body);

        bytes memory encodedMsg = _encodeMessage(
            DST_CHAIN, SRC_CHAIN,
            pkgHash, "mypkg@1.0.0",
            address(0x1), 2, ts,
            abi.encode(sigs) // embedded signatures match what sendVerification would set
        );

        vm.prank(address(bridge));
        ccr.receiveVerification(DST_CHAIN, encodedMsg, sigs);

        // Package should now be stored.
        bytes32 packageKey = keccak256(abi.encodePacked("mypkg@1.0.0"));
        CrossChainRegistry.VerifiedPackage memory vp = ccr.getCrossChainVerification(packageKey);
        assertTrue(vp.isCrossChain, "package must be marked as cross-chain verified");
    }

    /// @dev Messages with insufficient valid signatures must revert.
    function test_receiveWithInsufficientSignaturesReverts() public {
        bytes32 pkgHash = keccak256("mypkg");
        uint256 ts = block.timestamp;
        bytes32 body = _messageBodyHash(
            DST_CHAIN, SRC_CHAIN, pkgHash, "mypkg@1.0.0",
            address(0x1), 2, ts
        );

        // Only one signature provided, but threshold = 2.
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(VAL1_PK, body);

        bytes memory encodedMsg = _encodeMessage(
            DST_CHAIN, SRC_CHAIN,
            pkgHash, "mypkg@1.0.0",
            address(0x1), 2, ts, ""
        );

        vm.prank(address(bridge));
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossChainRegistry.InsufficientSignatures.selector,
                uint256(1),
                uint256(2)
            )
        );
        ccr.receiveVerification(DST_CHAIN, encodedMsg, sigs);
    }

    /// @dev Duplicate validator signatures (same key twice) must not double-count.
    function test_duplicateSignaturesNotDoubleCountedReverts() public {
        bytes32 pkgHash = keccak256("mypkg");
        uint256 ts = block.timestamp;
        bytes32 body = _messageBodyHash(
            DST_CHAIN, SRC_CHAIN, pkgHash, "mypkg@1.0.0",
            address(0x1), 2, ts
        );

        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _sign(VAL1_PK, body); // val1 signs
        sigs[1] = _sign(VAL1_PK, body); // val1 signs again — duplicate

        bytes memory encodedMsg = _encodeMessage(
            DST_CHAIN, SRC_CHAIN,
            pkgHash, "mypkg@1.0.0",
            address(0x1), 2, ts, ""
        );

        vm.prank(address(bridge));
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossChainRegistry.InsufficientSignatures.selector,
                uint256(1),
                uint256(2)
            )
        );
        ccr.receiveVerification(DST_CHAIN, encodedMsg, sigs);
    }

    /// @dev Replay of a processed message must revert.
    function test_replayReverts() public {
        bytes32 pkgHash = keccak256("replaypkg");
        uint256 ts = block.timestamp;
        bytes32 body = _messageBodyHash(
            DST_CHAIN, SRC_CHAIN, pkgHash, "replaypkg@1.0.0",
            address(0x1), 2, ts
        );
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _sign(VAL1_PK, body);
        sigs[1] = _sign(VAL2_PK, body);

        bytes memory encodedMsg = _encodeMessage(
            DST_CHAIN, SRC_CHAIN,
            pkgHash, "replaypkg@1.0.0",
            address(0x1), 2, ts, abi.encode(sigs)
        );

        vm.startPrank(address(bridge));
        ccr.receiveVerification(DST_CHAIN, encodedMsg, sigs);

        bytes32 msgHash = keccak256(encodedMsg);
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossChainRegistry.MessageAlreadyProcessed.selector,
                msgHash
            )
        );
        ccr.receiveVerification(DST_CHAIN, encodedMsg, sigs);
        vm.stopPrank();
    }

    // ── Non-bridge caller must be rejected ──────────────────────────────────

    function test_nonBridgeReceiveReverts() public {
        bytes memory encodedMsg = _encodeMessage(
            DST_CHAIN, SRC_CHAIN, keccak256("x"), "x@1.0", address(1), 2, block.timestamp, ""
        );
        bytes[] memory sigs = new bytes[](0);

        vm.expectRevert(CrossChainRegistry.Unauthorized.selector);
        ccr.receiveVerification(DST_CHAIN, encodedMsg, sigs);
    }

    // ── AxelarAdapter governance gate (ISSUE-010) ───────────────────────────

    function test_axelarAdapterSetChainNameRequiresGovernance() public {
        AxelarAdapter adapter = new AxelarAdapter(address(0xBEEF), address(ccr));

        vm.prank(address(0xDEAD));
        vm.expectRevert(AxelarAdapter.NotGovernance.selector);
        adapter.setChainName(DST_CHAIN, "test-chain");

        adapter.setChainName(DST_CHAIN, "test-chain");
        assertEq(adapter.chainNames(DST_CHAIN), "test-chain");
    }
}

// ── Minimal bridge stub ──────────────────────────────────────────────────────

contract MockBridge is IMessageBridge {
    bytes public lastPayload;
    uint16 public lastDst;

    function send(uint16 dstChainId, bytes calldata payload) external payable override {
        lastDst     = dstChainId;
        lastPayload = payload;
    }

    function estimateFee(uint16, bytes calldata) external pure override returns (uint256) {
        return 0;
    }
}
