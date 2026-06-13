// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./Registry.sol";

/// @title CrossChainRegistry
/// @notice Cross-chain package verification bridge
/// @dev Enables package verification status to be shared across multiple chains
///      using generic message passing interfaces (LayerZero, Axelar, etc.)
///
/// @dev ⚠️  EXPERIMENTAL — NOT DEPLOYED AND NOT WIRED. This contract is a
///      design scaffold and is intentionally absent from the Sepolia
///      deployment (chain spec `feature_flags.cross_chain = false`). The live
///      L2→L1 path is the rollup-checkpoint bridge in crates/node/src/bridge.rs
///      via Registry.submitRollupBatch — NOT this contract. Do not assume any
///      message-passing wiring exists until it is deployed and referenced.
contract CrossChainRegistry {
    
    // ── Structs ───────────────────────────────────────────────────────────────
    
    struct ChainConfig {
        uint16 chainId;              // LayerZero chain ID
        string chainName;            // Human-readable name
        address registryAddress;     // Registry contract on remote chain
        bool isActive;               // Whether this chain is enabled
        uint256 gasLimit;            // Gas limit for cross-chain messages
    }
    
    struct CrossChainMessage {
        uint16 srcChainId;
        uint16 dstChainId;
        bytes32 packageHash;
        string canonical;
        address publisher;
        uint8 status;                // 0=Unknown, 1=Pending, 2=Verified, 3=Revoked
        uint256 timestamp;
        bytes signature;             // Signature from source chain validator
    }
    
    struct VerifiedPackage {
        string canonical;
        bytes32 contentHash;
        address publisher;
        uint16 sourceChainId;
        uint256 verifiedAt;
        bool isCrossChain;           // True if verified on another chain
    }
    
    // ── Storage ───────────────────────────────────────────────────────────────
    
    /// Chain ID → Chain configuration
    mapping(uint16 => ChainConfig) public chains;
    
    /// Supported chain IDs
    uint16[] public supportedChains;
    
    /// Package key → Verified package info (for cross-chain verified packages)
    mapping(bytes32 => VerifiedPackage) public crossChainPackages;
    
    /// Nonce tracking for each chain to prevent replay attacks
    mapping(uint16 => uint256) public chainNonces;
    
    /// Message hash → processed (prevents double-processing)
    mapping(bytes32 => bool) public processedMessages;
    
    /// Local registry reference
    ChainRegistry public localRegistry;
    
    /// Message bridge adapter (LayerZero, Axelar, etc.)
    address public messageBridge;
    
    /// Governance address
    address public governance;
    
    /// This chain's ID
    uint16 public immutable thisChainId;

    /// Validator set for cross-chain signature verification
    mapping(address => bool) public isValidator;
    address[] public validators;
    uint256 public validatorThreshold;
    
    // ── Events ────────────────────────────────────────────────────────────────
    
    event ChainAdded(uint16 indexed chainId, string name, address registry);
    event ChainRemoved(uint16 indexed chainId);
    event CrossChainVerification(
        bytes32 indexed packageKey,
        uint16 indexed srcChainId,
        string canonical
    );
    event MessageSent(
        uint16 indexed dstChainId,
        bytes32 indexed packageKey,
        uint256 nonce
    );
    event MessageReceived(
        uint16 indexed srcChainId,
        bytes32 indexed packageKey,
        uint256 nonce
    );
    
    // ── Errors ────────────────────────────────────────────────────────────────
    
    error Unauthorized();
    error ChainNotSupported(uint16 chainId);
    error ChainAlreadyExists(uint16 chainId);
    error InvalidMessage();
    error MessageAlreadyProcessed(bytes32 messageHash);
    error VerificationFailed(string reason);
    error InsufficientSignatures(uint256 provided, uint256 required);
    
    // ── Modifiers ─────────────────────────────────────────────────────────────
    
    modifier onlyGovernance() {
        if (msg.sender != governance) revert Unauthorized();
        _;
    }
    
    modifier onlyBridge() {
        if (msg.sender != messageBridge) revert Unauthorized();
        _;
    }
    
    // ── Constructor ───────────────────────────────────────────────────────────
    
    constructor(
        address _localRegistry,
        address _governance,
        uint16 _thisChainId
    ) {
        localRegistry = ChainRegistry(_localRegistry);
        governance = _governance;
        thisChainId = _thisChainId;
    }
    
    // ── Chain Management ──────────────────────────────────────────────────────
    
    /// @notice Add a supported chain
    function addChain(
        uint16 chainId,
        string calldata name,
        address registryAddress,
        uint256 gasLimit
    ) external onlyGovernance {
        if (chains[chainId].isActive) revert ChainAlreadyExists(chainId);
        
        chains[chainId] = ChainConfig({
            chainId: chainId,
            chainName: name,
            registryAddress: registryAddress,
            isActive: true,
            gasLimit: gasLimit
        });
        
        supportedChains.push(chainId);
        
        emit ChainAdded(chainId, name, registryAddress);
    }
    
    /// @notice Remove a supported chain
    function removeChain(uint16 chainId) external onlyGovernance {
        if (!chains[chainId].isActive) revert ChainNotSupported(chainId);
        
        chains[chainId].isActive = false;
        
        // Remove from supportedChains array
        for (uint i = 0; i < supportedChains.length; i++) {
            if (supportedChains[i] == chainId) {
                supportedChains[i] = supportedChains[supportedChains.length - 1];
                supportedChains.pop();
                break;
            }
        }
        
        emit ChainRemoved(chainId);
    }
    
    /// @notice Update the message bridge address
    function setMessageBridge(address _messageBridge) external onlyGovernance {
        messageBridge = _messageBridge;
    }

    /// @notice Set the validator set and threshold for cross-chain signature verification
    function setValidatorSet(
        address[] calldata _validators,
        uint256 _threshold
    ) external onlyGovernance {
        require(_validators.length > 0, "Empty validator set");
        require(_threshold > 0 && _threshold <= _validators.length, "Invalid threshold");

        // Clear old validator set
        for (uint i = 0; i < validators.length; i++) {
            isValidator[validators[i]] = false;
        }
        delete validators;

        // Set new validator set
        for (uint i = 0; i < _validators.length; i++) {
            require(!isValidator[_validators[i]], "Duplicate validator");
            isValidator[_validators[i]] = true;
            validators.push(_validators[i]);
        }
        validatorThreshold = _threshold;
    }
    
    // ── Cross-Chain Messaging ─────────────────────────────────────────────────
    
    /// @notice Send package verification to another chain
    /// @param dstChainId Destination chain ID
    /// @param packageKey Package identifier
    /// @param canonical Package canonical name
    /// @param validatorSignatures ECDSA signatures from ≥ validatorThreshold validators
    ///        over keccak256("\x19Ethereum Signed Message:\n32" || _messageBodyHash(message))
    ///        where the body hash covers all message fields except `signature`.
    ///        Callers should collect signatures off-chain before invoking this function.
    function sendVerification(
        uint16 dstChainId,
        bytes32 packageKey,
        string calldata canonical,
        bytes[] calldata validatorSignatures
    ) external payable {
        if (!chains[dstChainId].isActive) revert ChainNotSupported(dstChainId);

        // Get package info from local registry
        ChainRegistry.PackageRecord memory pkg = localRegistry.getPackage(canonical);

        if (pkg.status != ChainRegistry.PackageStatus.Verified) {
            revert VerificationFailed("Package not verified locally");
        }

        // Build the unsigned message body first.
        uint256 nonce = chainNonces[dstChainId]++;
        CrossChainMessage memory message = CrossChainMessage({
            srcChainId: thisChainId,
            dstChainId: dstChainId,
            packageHash: packageKey,
            canonical: canonical,
            publisher: pkg.publisher,
            status: uint8(pkg.status),
            timestamp: block.timestamp,
            signature: "" // filled below after signature verification
        });

        // Require threshold validator signatures over the message body hash.
        // This prevents any single caller from injecting unilateral cross-chain
        // state changes — the source validator set must co-sign before sending.
        _verifyThresholdSignatures(_messageBodyHash(message), validatorSignatures);

        // Attach the serialized signatures as the message's source-chain proof.
        message.signature = abi.encode(validatorSignatures);

        // Encode and send via bridge
        bytes memory encodedMessage = encodeMessage(message);
        _sendCrossChainMessage(dstChainId, encodedMessage);

        emit MessageSent(dstChainId, packageKey, nonce);
    }
    
    /// @notice Receive verification from another chain
    /// @param srcChainId Source chain ID
    /// @param encodedMessage Encoded CrossChainMessage
    /// @param signatures ECDSA signatures from validators over keccak256(encodedMessage)
    function receiveVerification(
        uint16 srcChainId,
        bytes calldata encodedMessage,
        bytes[] calldata signatures
    ) external onlyBridge {
        if (!chains[srcChainId].isActive) revert ChainNotSupported(srcChainId);

        CrossChainMessage memory message = decodeMessage(encodedMessage);

        // Verify message integrity
        if (message.srcChainId != srcChainId) revert InvalidMessage();
        if (message.dstChainId != thisChainId) revert InvalidMessage();

        // Prevent replay attacks
        bytes32 messageHash = keccak256(encodedMessage);
        if (processedMessages[messageHash]) revert MessageAlreadyProcessed(messageHash);

        // Always verify threshold signatures — never allow zero-threshold bypass.
        // Signatures are verified over the message body hash (all fields except
        // the embedded signature), matching the commitment sendVerification used.
        _verifyThresholdSignatures(_messageBodyHash(message), signatures);

        processedMessages[messageHash] = true;

        // Store cross-chain verification
        bytes32 packageKey = keccak256(abi.encodePacked(message.canonical));
        crossChainPackages[packageKey] = VerifiedPackage({
            canonical: message.canonical,
            contentHash: message.packageHash,
            publisher: message.publisher,
            sourceChainId: srcChainId,
            verifiedAt: block.timestamp,
            isCrossChain: true
        });

        emit MessageReceived(srcChainId, packageKey, chainNonces[srcChainId]);
        emit CrossChainVerification(packageKey, srcChainId, message.canonical);
    }
    
    /// @notice Batch receive multiple verifications
    function batchReceiveVerifications(
        uint16 srcChainId,
        bytes[] calldata encodedMessages,
        bytes[][] calldata signatures
    ) external onlyBridge {
        require(encodedMessages.length == signatures.length, "Length mismatch");
        for (uint i = 0; i < encodedMessages.length; i++) {
            try this.receiveVerification(srcChainId, encodedMessages[i], signatures[i]) {
                // Success
            } catch {
                // Log failure but continue
            }
        }
    }
    
    // ── Queries ───────────────────────────────────────────────────────────────
    
    /// @notice Check if a package is verified on any chain
    function isVerifiedOnAnyChain(bytes32 packageKey) external view returns (bool) {
        // Check local registry
        // Note: Would need canonical from packageKey, simplified here
        return crossChainPackages[packageKey].isCrossChain;
    }
    
    /// @notice Get cross-chain verification info
    function getCrossChainVerification(bytes32 packageKey)
        external view
        returns (VerifiedPackage memory)
    {
        return crossChainPackages[packageKey];
    }
    
    /// @notice Get all supported chains
    function getSupportedChains() external view returns (uint16[] memory) {
        return supportedChains;
    }
    
    /// @notice Estimate gas for cross-chain message
    function estimateGas(uint16 dstChainId) external view returns (uint256) {
        return chains[dstChainId].gasLimit;
    }
    
    // ── Internal Functions ────────────────────────────────────────────────────
    
    /// @notice Encode message for transmission
    function encodeMessage(CrossChainMessage memory message)
        internal pure
        returns (bytes memory)
    {
        return abi.encode(
            message.srcChainId,
            message.dstChainId,
            message.packageHash,
            message.canonical,
            message.publisher,
            message.status,
            message.timestamp,
            message.signature
        );
    }
    
    /// @notice Decode received message
    function decodeMessage(bytes calldata encoded)
        internal pure
        returns (CrossChainMessage memory)
    {
        (
            uint16 srcChainId,
            uint16 dstChainId,
            bytes32 packageHash,
            string memory canonical,
            address publisher,
            uint8 status,
            uint256 timestamp,
            bytes memory signature
        ) = abi.decode(encoded, (uint16, uint16, bytes32, string, address, uint8, uint256, bytes));
        
        return CrossChainMessage({
            srcChainId: srcChainId,
            dstChainId: dstChainId,
            packageHash: packageHash,
            canonical: canonical,
            publisher: publisher,
            status: status,
            timestamp: timestamp,
            signature: signature
        });
    }
    
    /// @notice Compute a canonical hash of a CrossChainMessage body, excluding
    ///         the `signature` field, so both sender and receiver agree on what
    ///         was signed without the circularity of signing the signature itself.
    function _messageBodyHash(CrossChainMessage memory message)
        internal pure
        returns (bytes32)
    {
        return keccak256(abi.encode(
            message.srcChainId,
            message.dstChainId,
            message.packageHash,
            message.canonical,
            message.publisher,
            message.status,
            message.timestamp
        ));
    }

    /// @notice Verify that at least `validatorThreshold` distinct validators
    ///         from the registered set have signed `bodyHash`.
    /// @dev Reverts with VerificationFailed if the validator set is not configured,
    ///      or with InsufficientSignatures if valid sig count is below threshold.
    function _verifyThresholdSignatures(
        bytes32 bodyHash,
        bytes[] calldata sigs
    ) internal view {
        if (validatorThreshold == 0 || validators.length == 0) {
            revert VerificationFailed("Validator set not configured");
        }

        bytes32 ethHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", bodyHash)
        );
        uint256 validSigs = 0;
        address[] memory seen = new address[](sigs.length);
        uint256 seenCount = 0;

        for (uint i = 0; i < sigs.length; i++) {
            if (sigs[i].length != 65) continue;

            bytes32 r_val; bytes32 s_val; uint8 v_val;
            bytes calldata sig = sigs[i];
            assembly {
                r_val := calldataload(sig.offset)
                s_val := calldataload(add(sig.offset, 32))
                v_val := byte(0, calldataload(add(sig.offset, 64)))
            }
            if (v_val < 27) v_val += 27;

            address signer = ecrecover(ethHash, v_val, r_val, s_val);
            if (signer == address(0) || !isValidator[signer]) continue;

            // Deduplicate: each validator counts once.
            bool duplicate = false;
            for (uint j = 0; j < seenCount; j++) {
                if (seen[j] == signer) { duplicate = true; break; }
            }
            if (duplicate) continue;

            seen[seenCount++] = signer;
            validSigs++;
        }

        if (validSigs < validatorThreshold) {
            revert InsufficientSignatures(validSigs, validatorThreshold);
        }
    }

    /// @notice Send message via bridge adapter
    function _sendCrossChainMessage(uint16 dstChainId, bytes memory message) internal {
        require(messageBridge != address(0), "Bridge not configured");
        IMessageBridge(messageBridge).send{value: msg.value}(dstChainId, message);
    }
    }


/// @title IMessageBridge
/// @notice Interface for cross-chain message bridges
interface IMessageBridge {
    /// @notice Send message to another chain
    function send(uint16 dstChainId, bytes calldata payload) external payable;
    
    /// @notice Estimate fee for cross-chain message
    function estimateFee(uint16 dstChainId, bytes calldata payload) external view returns (uint256);
}

/// @title LayerZeroAdapter
/// @notice Adapter for LayerZero cross-chain messaging
contract LayerZeroAdapter is IMessageBridge {
    // LayerZero endpoint address
    address public endpoint;
    
    // CrossChainRegistry address
    address public registry;
    
    constructor(address _endpoint, address _registry) {
        endpoint = _endpoint;
        registry = _registry;
    }
    
    function send(uint16 dstChainId, bytes calldata payload) external payable override {
        // Call LayerZero endpoint
        // Simplified - actual implementation would use LayerZero's interface
        (bool success, ) = endpoint.call{value: msg.value}(
            abi.encodeWithSelector(
                bytes4(keccak256("send(uint16,bytes,address)")),
                dstChainId,
                payload,
                registry
            )
        );
        
        require(success, "LayerZero send failed");
    }
    
    function estimateFee(uint16 dstChainId, bytes calldata payload) external view override returns (uint256) {
        // Call LayerZero estimateFees
        (bool success, bytes memory result) = endpoint.staticcall(
            abi.encodeWithSelector(
                bytes4(keccak256("estimateFees(uint16,address,bytes,bool,bytes)")),
                dstChainId,
                registry,
                payload,
                false,
                ""
            )
        );
        
        if (success && result.length >= 32) {
            return abi.decode(result, (uint256));
        }
        
        return 0;
    }
    
    /// @notice Receive message from LayerZero
    function lzReceive(
        uint16 srcChainId,
        bytes calldata srcAddress,
        uint64 nonce,
        bytes calldata payload
    ) external {
        require(msg.sender == endpoint, "Only endpoint");

        // Decode payload: first portion is encodedMessage, remainder is signatures
        (bytes memory encodedMessage, bytes[] memory signatures) =
            abi.decode(payload, (bytes, bytes[]));

        // Forward to registry with signatures
        CrossChainRegistry(registry).receiveVerification(srcChainId, encodedMessage, signatures);
    }
}

/// @title AxelarAdapter
/// @notice Adapter for Axelar cross-chain messaging
contract AxelarAdapter is IMessageBridge {
    error NotGovernance();

    // Axelar gateway address
    address public gateway;
    
    // CrossChainRegistry address
    address public registry;
    
    // Chain name mapping (Axelar uses string chain names)
    mapping(uint16 => string) public chainNames;
    
    constructor(address _gateway, address _registry) {
        gateway = _gateway;
        registry = _registry;
    }
    
    function send(uint16 dstChainId, bytes calldata payload) external payable override {
        string memory destinationChain = chainNames[dstChainId];
        require(bytes(destinationChain).length > 0, "Unknown chain");
        
        // Call Axelar gateway
        (bool success, ) = gateway.call(
            abi.encodeWithSelector(
                bytes4(keccak256("callContract(string,string,bytes)")),
                destinationChain,
                _toAsciiString(registry),
                payload
            )
        );
        
        require(success, "Axelar send failed");
    }
    
    function estimateFee(uint16 dstChainId, bytes calldata payload) external view override returns (uint256) {
        // Axelar fee estimation
        // Simplified - actual implementation would call Axelar's gas service
        return 0.001 ether; // Placeholder
    }
    
    /// @notice Receive message from Axelar
    function execute(
        bytes32 commandId,
        string calldata sourceChain,
        string calldata sourceAddress,
        bytes calldata payload
    ) external {
        // Verify called by Axelar gateway
        require(msg.sender == gateway, "Only gateway");

        // Decode payload: first portion is encodedMessage, remainder is signatures
        (bytes memory encodedMessage, bytes[] memory signatures) =
            abi.decode(payload, (bytes, bytes[]));

        // Convert chain name to chain ID
        uint16 srcChainId = _chainNameToId(sourceChain);

        // Forward to registry with signatures
        CrossChainRegistry(registry).receiveVerification(srcChainId, encodedMessage, signatures);
    }
    
    /// @notice Set chain name for a chain ID (governance-only).
    function setChainName(uint16 chainId, string calldata name) external {
        if (msg.sender != CrossChainRegistry(registry).governance()) {
            revert NotGovernance();
        }
        chainNames[chainId] = name;
    }
    
    // Helper functions
    function _toAsciiString(address x) internal pure returns (string memory) {
        bytes memory s = new bytes(40);
        for (uint i = 0; i < 20; i++) {
            bytes1 b = bytes1(uint8(uint(uint160(x)) / (2**(8*(19-i)))));
            bytes1 hi = bytes1(uint8(b) / 16);
            bytes1 lo = bytes1(uint8(b) - 16 * uint8(hi));
            s[2*i] = _char(hi);
            s[2*i+1] = _char(lo);
        }
        return string(s);
    }
    
    function _char(bytes1 b) internal pure returns (bytes1 c) {
        if (uint8(b) < 10) return bytes1(uint8(b) + 0x30);
        else return bytes1(uint8(b) + 0x57);
    }
    
    function _chainNameToId(string memory name) internal view returns (uint16) {
        // Simple reverse lookup - in production, use a mapping
        if (keccak256(bytes(name)) == keccak256(bytes("ethereum"))) return 1;
        if (keccak256(bytes(name)) == keccak256(bytes("arbitrum"))) return 110;
        if (keccak256(bytes(name)) == keccak256(bytes("optimism"))) return 111;
        if (keccak256(bytes(name)) == keccak256(bytes("polygon"))) return 109;
        return 0;
    }
}
