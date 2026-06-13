// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Mocked Chainlink VRF interfaces for standalone compilation
interface VRFCoordinatorV2Interface {
    function requestRandomWords(
        bytes32 keyHash,
        uint64 subId,
        uint16 minimumRequestConfirmations,
        uint32 callbackGasLimit,
        uint32 numWords
    ) external returns (uint256 requestId);
}

abstract contract VRFConsumerBaseV2 {
    address private immutable vrfCoordinator;

    constructor(address _vrfCoordinator) {
        vrfCoordinator = _vrfCoordinator;
    }

    function fulfillRandomWords(uint256 requestId, uint256[] memory randomWords) internal virtual;

    function rawFulfillRandomWords(uint256 requestId, uint256[] memory randomWords) external {
        if (msg.sender != vrfCoordinator) revert("Only coordinator can fulfill");
        fulfillRandomWords(requestId, randomWords);
    }
}

/// @title ChainRegistryVRF

/// @notice On-chain verifiable random function for validator selection.
/// @dev Uses Chainlink VRF v2 for cryptographically secure randomness.
///      This prevents miners/block proposers from manipulating validator selection.
contract VRF is VRFConsumerBaseV2 {

    // ── Chainlink VRF Configuration ───────────────────────────────────────────

    VRFCoordinatorV2Interface public immutable vrfCoordinator;
    bytes32 public immutable keyHash;
    uint64 public immutable subscriptionId;
    uint16 public constant REQUEST_CONFIRMATIONS = 3;
    uint32 public constant CALLBACK_GAS_LIMIT = 200000;
    uint32 public constant NUM_WORDS = 1;

    // ── State ─────────────────────────────────────────────────────────────────

    address public governance;
    
    /// How many validators to assign per package submission.
    uint8 public validatorsPerPackage = 7;

    struct PendingVRFRequest {
        string packageCanonical;
        address[] activeValidators;
    }

    /// Pending VRF requests keyed by Chainlink request ID.
    mapping(uint256 => PendingVRFRequest) private pendingVRFRequests;
    
    /// Completed selections: packageHash → selected validators
    mapping(bytes32 => address[]) public selections;
    
    /// Tracks if a selection is complete
    mapping(bytes32 => bool) public selectionComplete;

    // ── Events ────────────────────────────────────────────────────────────────

    event ValidatorsAssigned(bytes32 indexed packageKey, address[] selected);
    event RandomnessRequested(uint256 indexed requestId, string packageCanonical);
    event VRFConfigUpdated(bytes32 keyHash, uint64 subscriptionId);

    // ── Errors ────────────────────────────────────────────────────────────────

    error OnlyGovernance();
    error InvalidVRFResponse();
    error SelectionAlreadyComplete(bytes32 packageKey);
    error NoPendingRequest(uint256 requestId);

    // ── Modifiers ─────────────────────────────────────────────────────────────

    modifier onlyGovernance() {
        if (msg.sender != governance) revert OnlyGovernance();
        _;
    }

    // ── Constructor ───────────────────────────────────────────────────────────

    /// @param _vrfCoordinator Chainlink VRF Coordinator address
    /// @param _keyHash Gas lane key hash
    /// @param _subscriptionId VRF subscription ID
    /// @param _governance Governance address
    constructor(
        address _vrfCoordinator,
        bytes32 _keyHash,
        uint64 _subscriptionId,
        address _governance
    ) VRFConsumerBaseV2(_vrfCoordinator) {
        vrfCoordinator = VRFCoordinatorV2Interface(_vrfCoordinator);
        keyHash = _keyHash;
        subscriptionId = _subscriptionId;
        governance = _governance;
    }

    // ── Validator Selection ───────────────────────────────────────────────────

    /// @notice Request random validator selection for a package.
    /// @dev Initiates a Chainlink VRF request. Validators are selected in fulfillRandomWords.
    /// @param packageCanonical e.g. "npm:express@4.18.2"
    /// @param activeValidators Current active validator addresses
    /// @return requestId The VRF request ID to track the selection
    function requestValidatorSelection(
        string calldata packageCanonical,
        address[] calldata activeValidators
    ) external onlyGovernance returns (uint256 requestId) {
        require(
            activeValidators.length >= validatorsPerPackage,
            "Not enough active validators"
        );

        bytes32 packageKey = keccak256(bytes(packageCanonical));
        
        if (selectionComplete[packageKey]) {
            revert SelectionAlreadyComplete(packageKey);
        }

        requestId = vrfCoordinator.requestRandomWords(
            keyHash,
            subscriptionId,
            REQUEST_CONFIRMATIONS,
            CALLBACK_GAS_LIMIT,
            NUM_WORDS
        );

        pendingVRFRequests[requestId] = PendingVRFRequest({
            packageCanonical: packageCanonical,
            activeValidators: activeValidators
        });

        emit RandomnessRequested(requestId, packageCanonical);
        
        return requestId;
    }

    /// @notice Chainlink VRF callback with random words.
    /// @dev Fisher-Yates shuffle over the validator set stored at request time.
    function fulfillRandomWords(
        uint256 requestId,
        uint256[] memory randomWords
    ) internal override {
        if (randomWords.length == 0) revert InvalidVRFResponse();

        PendingVRFRequest memory pending = pendingVRFRequests[requestId];
        if (bytes(pending.packageCanonical).length == 0) revert NoPendingRequest(requestId);

        delete pendingVRFRequests[requestId];

        bytes32 packageKey = keccak256(bytes(pending.packageCanonical));
        address[] memory selected = _selectValidatorsWithSeed(
            pending.activeValidators,
            randomWords[0]
        );

        selections[packageKey] = selected;
        selectionComplete[packageKey] = true;

        emit ValidatorsAssigned(packageKey, selected);
    }

    /// @notice Select validators using a provided random seed (governance manual path).
    function selectValidatorsWithSeed(
        string calldata packageCanonical,
        address[] calldata activeValidators,
        uint256 randomSeed
    ) external onlyGovernance returns (address[] memory selected) {
        require(
            activeValidators.length >= validatorsPerPackage,
            "Not enough active validators"
        );

        selected = _selectValidatorsWithSeed(activeValidators, randomSeed);

        bytes32 key = keccak256(bytes(packageCanonical));
        selections[key] = selected;
        selectionComplete[key] = true;
        
        emit ValidatorsAssigned(key, selected);
        return selected;
    }

    /// @dev Fisher-Yates shuffle using a VRF seed; returns the first `validatorsPerPackage` entries.
    function _selectValidatorsWithSeed(
        address[] memory activeValidators,
        uint256 randomSeed
    ) internal view returns (address[] memory selected) {
        address[] memory pool = new address[](activeValidators.length);
        for (uint i = 0; i < activeValidators.length; i++) {
            pool[i] = activeValidators[i];
        }

        for (uint i = activeValidators.length - 1; i > 0; i--) {
            uint j = uint(keccak256(abi.encodePacked(randomSeed, i))) % (i + 1);
            address tmp = pool[i];
            pool[i] = pool[j];
            pool[j] = tmp;
        }

        selected = new address[](validatorsPerPackage);
        for (uint i = 0; i < validatorsPerPackage; i++) {
            selected[i] = pool[i];
        }
    }

    /// @notice Get the selected validators for a package.
    function getSelectedValidators(
        string calldata packageCanonical
    ) external view returns (address[] memory) {
        bytes32 key = keccak256(bytes(packageCanonical));
        return selections[key];
    }

    /// @notice Check if validator selection is complete for a package.
    function isSelectionComplete(string calldata packageCanonical) external view returns (bool) {
        return selectionComplete[keccak256(bytes(packageCanonical))];
    }

    // ── Governance ────────────────────────────────────────────────────────────

    function setValidatorsPerPackage(uint8 n) external onlyGovernance {
        require(n >= 3 && n <= 50, "Must be 3-50");
        validatorsPerPackage = n;
    }

    function updateVRFConfig(
        bytes32 _keyHash,
        uint64 _subscriptionId
    ) external onlyGovernance {
        // Note: keyHash and subscriptionId are immutable, 
        // so this would require contract upgrade in practice
        emit VRFConfigUpdated(_keyHash, _subscriptionId);
    }

    function setGovernance(address _governance) external onlyGovernance {
        governance = _governance;
    }
}
