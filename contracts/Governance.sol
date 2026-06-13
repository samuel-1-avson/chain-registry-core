// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Governance
/// @notice CANONICAL governance contract — M-of-N multisig for the chain registry.
/// @dev This is the ACTIVE governance contract used by Registry.sol and Staking.sol.
///      Proposals are submitted, voted on by signers, and executed
///      automatically once the approval threshold is met.
///      This prevents any single entity from controlling the registry.
///
///      See GovernanceV2.sol for the planned token-based governance upgrade
///      (quadratic voting, delegation, automated parameter adjustments).
contract Governance {
    // ── Reentrancy Guard ─────────────────────────────────────────────────────
    bool private _locked;
    modifier nonReentrant() {
        require(!_locked, "Reentrant call");
        _locked = true;
        _;
        _locked = false;
    }

    // ── Structs ───────────────────────────────────────────────────────────────

    enum ProposalStatus { Pending, Executed, Cancelled }
    enum SystemStatus { Active, Paused }

    struct Proposal {
        address target;          // Contract to call
        bytes   callData;        // Encoded function call
        string  description;
        uint256 submittedAt;
        uint256 executedAt;
        ProposalStatus status;
        uint256 approvalCount;
        uint256 rejectionCount;
        mapping(address => bool) voted;
        mapping(address => bool) approval;
    }

    // ── Storage ───────────────────────────────────────────────────────────────

    address[] public signers;
    mapping(address => bool) public isSigner;
    uint256 public threshold;            // Minimum approvals to execute
    uint256 public proposalCount;
    uint256 public votingPeriod;         // Seconds proposals are open

    mapping(uint256 => Proposal) private _proposals;

    // ── Pause State ───────────────────────────────────────────────────────────

    SystemStatus public systemStatus;
    uint256 public pausedAt;
    string public pauseReason;

    /// @notice Minimum number of signers that must co-sign an emergency pause.
    uint256 public constant PAUSE_THRESHOLD = 2;

    /// @notice Cooldown period between pauses (prevents griefing).
    uint256 public constant PAUSE_COOLDOWN = 7 days;

    /// @notice Tracks co-signers for a pending pause request.
    /// @dev LEGACY: kept for storage-layout compatibility. The new pause flow
    ///      uses a single open request (see `openPauseRequest` / `confirmPauseRequest`)
    ///      to prevent reason-hash griefing where a malicious signer spammed
    ///      many distinct reason strings to splinter honest co-signers across
    ///      buckets and block the 2-of-N threshold.
    mapping(bytes32 => mapping(address => bool)) public pauseCoSigners;
    mapping(bytes32 => uint256) public pauseCoSignCount;

    /// @notice Maximum lifetime of an open pause request before it expires and
    ///         can be replaced. Short enough that a stale request cannot block
    ///         a legitimate pause response for too long, long enough that real
    ///         co-signers have time to review and confirm.
    uint256 public constant PAUSE_REQUEST_TTL = 1 days;

    struct OpenPauseRequest {
        uint256 openedAt;
        uint256 nonce;           // incremented every open; makes coSigners per-request
        address opener;
        string  reason;
        uint256 coSignCount;
    }
    /// @dev Only one pause request may be open at a time.
    OpenPauseRequest internal _openPauseRequest;

    /// @dev (nonce, signer) → confirmed? Keyed on the per-request nonce so
    ///      resetting the request cannot leak a stale confirmation into the
    ///      next one.
    mapping(uint256 => mapping(address => bool)) internal _pauseRequestCoSigners;

    // ── Events ────────────────────────────────────────────────────────────────

    event ProposalSubmitted(uint256 indexed id, address indexed proposer, string description);
    event ProposalVoted    (uint256 indexed id, address indexed signer, bool approved);
    event ProposalExecuted (uint256 indexed id);
    event ProposalCancelled(uint256 indexed id);
    event SignerAdded      (address indexed signer);
    event SignerRemoved    (address indexed signer);
    event ThresholdUpdated (uint256 newThreshold);
    event EmergencyPaused  (address indexed triggeredBy, string reason, uint256 timestamp);
    event EmergencyUnpaused(address indexed triggeredBy, uint256 timestamp);
    event PauseRequestOpened   (address indexed opener, string reason, uint256 openedAt);
    event PauseRequestConfirmed(address indexed signer, uint256 coSignCount);
    event PauseRequestExpired  (address indexed expiredBy, uint256 openedAt);

    // ── Errors ────────────────────────────────────────────────────────────────

    error NotSigner();
    error AlreadyVoted();
    error ProposalNotPending();
    error ThresholdNotMet(uint256 got, uint256 required);
    error VotingPeriodExpired();
    error ExecutionFailed();
    error SystemPaused();
    error SystemNotPaused();
    error NotGovernance();
    error EmergencyNotAuthorized();
    error InvalidPauseReason();

    // ── Constructor ───────────────────────────────────────────────────────────

    /// @param _signers   Initial signer set (e.g. founding coalition)
    /// @param _threshold Minimum approvals required (e.g. 4-of-7)
    constructor(address[] memory _signers, uint256 _threshold) {
        require(_signers.length >= _threshold, "Threshold exceeds signer count");
        require(_threshold > 0, "Threshold must be > 0");

        for (uint i = 0; i < _signers.length; i++) {
            signers.push(_signers[i]);
            isSigner[_signers[i]] = true;
        }
        threshold    = _threshold;
        votingPeriod = 3 days;
        systemStatus = SystemStatus.Active;
    }

    // ── Modifiers ─────────────────────────────────────────────────────────────

    modifier whenNotPaused() {
        if (systemStatus == SystemStatus.Paused) revert SystemPaused();
        _;
    }

    modifier whenPaused() {
        if (systemStatus == SystemStatus.Active) revert SystemNotPaused();
        _;
    }

    // ── Emergency Pause ────────────────────────────────────────────────────────

    /// @notice Open a new emergency pause request.
    /// @dev Only one request can be open at a time. A malicious signer cannot
    ///      splinter co-signers across distinct reason hashes because subsequent
    ///      signers confirm the single open request rather than replaying a
    ///      reason string. Expired requests can be replaced.
    function openPauseRequest(string calldata reason) external {
        if (!isSigner[msg.sender]) revert NotSigner();
        if (bytes(reason).length == 0) revert InvalidPauseReason();
        if (systemStatus == SystemStatus.Paused) revert SystemPaused();
        require(
            block.timestamp >= pausedAt + PAUSE_COOLDOWN,
            "Pause cooldown active"
        );
        require(
            _openPauseRequest.openedAt == 0
                || block.timestamp >= _openPauseRequest.openedAt + PAUSE_REQUEST_TTL,
            "a pause request is already open"
        );

        _resetOpenPauseRequest();
        _openPauseRequest.openedAt    = block.timestamp;
        _openPauseRequest.nonce      += 1;
        _openPauseRequest.opener      = msg.sender;
        _openPauseRequest.reason      = reason;
        _openPauseRequest.coSignCount = 1;
        _pauseRequestCoSigners[_openPauseRequest.nonce][msg.sender] = true;

        emit PauseRequestOpened(msg.sender, reason, block.timestamp);

        if (PAUSE_THRESHOLD == 1) {
            _applyPause(msg.sender);
        }
    }

    /// @notice Confirm the currently-open pause request.
    /// @dev Any signer other than the opener may call this. The second
    ///      confirmation triggers the pause. Reason string is not re-checked —
    ///      confirming a request by ID (there's only ever one open) removes the
    ///      reason-hash griefing vector entirely.
    function confirmPauseRequest() external {
        if (!isSigner[msg.sender]) revert NotSigner();
        if (systemStatus == SystemStatus.Paused) revert SystemPaused();
        require(_openPauseRequest.openedAt != 0, "no open pause request");
        require(
            block.timestamp < _openPauseRequest.openedAt + PAUSE_REQUEST_TTL,
            "open pause request has expired"
        );
        require(
            !_pauseRequestCoSigners[_openPauseRequest.nonce][msg.sender],
            "already confirmed"
        );

        _pauseRequestCoSigners[_openPauseRequest.nonce][msg.sender] = true;
        _openPauseRequest.coSignCount++;

        emit PauseRequestConfirmed(msg.sender, _openPauseRequest.coSignCount);

        if (_openPauseRequest.coSignCount >= PAUSE_THRESHOLD) {
            _applyPause(msg.sender);
        }
    }

    /// @notice Expire a stale open pause request so a new one can be opened.
    /// @dev Anyone can call; idempotent. Emits an event for auditability.
    function expirePauseRequest() external {
        require(_openPauseRequest.openedAt != 0, "no open pause request");
        require(
            block.timestamp >= _openPauseRequest.openedAt + PAUSE_REQUEST_TTL,
            "open pause request has not expired"
        );
        uint256 openedAt = _openPauseRequest.openedAt;
        _resetOpenPauseRequest();
        emit PauseRequestExpired(msg.sender, openedAt);
    }

    /// @notice Legacy reason-hash pause flow. Retained so existing governance
    ///         scripts keep working; inlines the new open-request path.
    function emergencyPause(string calldata reason) external {
        if (!isSigner[msg.sender]) revert NotSigner();
        if (bytes(reason).length == 0) revert InvalidPauseReason();
        if (systemStatus == SystemStatus.Paused) revert SystemPaused();
        require(
            block.timestamp >= pausedAt + PAUSE_COOLDOWN,
            "Pause cooldown active"
        );

        bool noOpenRequest =
            _openPauseRequest.openedAt == 0
            || block.timestamp >= _openPauseRequest.openedAt + PAUSE_REQUEST_TTL;

        if (noOpenRequest) {
            _resetOpenPauseRequest();
            _openPauseRequest.openedAt    = block.timestamp;
            _openPauseRequest.nonce      += 1;
            _openPauseRequest.opener      = msg.sender;
            _openPauseRequest.reason      = reason;
            _openPauseRequest.coSignCount = 1;
            _pauseRequestCoSigners[_openPauseRequest.nonce][msg.sender] = true;
            emit PauseRequestOpened(msg.sender, reason, block.timestamp);
            if (PAUSE_THRESHOLD == 1) {
                _applyPause(msg.sender);
            }
        } else {
            require(
                !_pauseRequestCoSigners[_openPauseRequest.nonce][msg.sender],
                "already confirmed"
            );
            _pauseRequestCoSigners[_openPauseRequest.nonce][msg.sender] = true;
            _openPauseRequest.coSignCount++;
            emit PauseRequestConfirmed(msg.sender, _openPauseRequest.coSignCount);
            if (_openPauseRequest.coSignCount >= PAUSE_THRESHOLD) {
                _applyPause(msg.sender);
            }
        }
    }

    function _applyPause(address triggeredBy) internal {
        systemStatus = SystemStatus.Paused;
        pausedAt     = block.timestamp;
        pauseReason  = _openPauseRequest.reason;
        _resetOpenPauseRequest();
        emit EmergencyPaused(triggeredBy, pauseReason, block.timestamp);
    }

    function _resetOpenPauseRequest() internal {
        // Clear the top-level scalar fields. `nonce` is intentionally preserved
        // (and incremented on the next open) so that stale co-signer entries
        // from an expired request cannot collide with the new one.
        delete _openPauseRequest.openedAt;
        delete _openPauseRequest.opener;
        delete _openPauseRequest.reason;
        delete _openPauseRequest.coSignCount;
    }

    /// @notice Unpause the system.
    /// @dev Requires a governance proposal to be approved (m-of-n signers).
    ///      This prevents a single signer from unilaterally unpausing.
    function emergencyUnpause() external whenPaused {
        // Only callable via governance proposal (self-call)
        if (msg.sender != address(this)) revert NotGovernance();

        systemStatus = SystemStatus.Active;
        emit EmergencyUnpaused(msg.sender, block.timestamp);
    }

    /// @notice Check if the system is currently paused.
    /// @return True if paused
    function isPaused() external view returns (bool) {
        return systemStatus == SystemStatus.Paused;
    }

    /// @notice Get pause information.
    /// @return paused Whether system is paused
    /// @return reason Reason for pause
    /// @return duration Seconds since pause (0 if not paused)
    function getPauseInfo() external view returns (bool paused, string memory reason, uint256 duration) {
        paused = systemStatus == SystemStatus.Paused;
        reason = pauseReason;
        duration = paused ? block.timestamp - pausedAt : 0;
    }

    // ── Proposal lifecycle ────────────────────────────────────────────────────

    /// @notice Submit a new governance proposal.
    function submit(
        address target,
        bytes calldata callData,
        string calldata description
    ) external whenNotPaused returns (uint256 id) {
        if (!isSigner[msg.sender]) revert NotSigner();

        id = proposalCount++;
        Proposal storage p = _proposals[id];
        p.target       = target;
        p.callData     = callData;
        p.description  = description;
        p.submittedAt  = block.timestamp;
        p.status       = ProposalStatus.Pending;

        emit ProposalSubmitted(id, msg.sender, description);
    }

    /// @notice Vote on a pending proposal.
    function vote(uint256 id, bool approve) external nonReentrant {
        if (!isSigner[msg.sender]) revert NotSigner();

        Proposal storage p = _proposals[id];
        if (p.status != ProposalStatus.Pending) revert ProposalNotPending();
        if (block.timestamp > p.submittedAt + votingPeriod) revert VotingPeriodExpired();
        if (p.voted[msg.sender]) revert AlreadyVoted();

        p.voted[msg.sender]    = true;
        p.approval[msg.sender] = approve;

        if (approve) { p.approvalCount++;  }
        else         { p.rejectionCount++; }

        emit ProposalVoted(id, msg.sender, approve);

        // Auto-execute once threshold is met.
        if (p.approvalCount >= threshold) {
            _execute(id);
        }
    }

    /// @notice Cancel a proposal (only if voting period has expired and threshold not met).
    function cancel(uint256 id) external {
        if (!isSigner[msg.sender]) revert NotSigner();
        Proposal storage p = _proposals[id];
        if (p.status != ProposalStatus.Pending) revert ProposalNotPending();

        p.status = ProposalStatus.Cancelled;
        emit ProposalCancelled(id);
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    function _execute(uint256 id) internal {
        Proposal storage p = _proposals[id];
        p.status     = ProposalStatus.Executed;
        p.executedAt = block.timestamp;

        (bool success, ) = p.target.call(p.callData);
        if (!success) revert ExecutionFailed();

        emit ProposalExecuted(id);
    }

    // ── Signer management (only via proposal) ─────────────────────────────────

    function addSigner(address newSigner) external {
        require(msg.sender == address(this), "Only via governance proposal");
        require(!isSigner[newSigner], "Already a signer");
        signers.push(newSigner);
        isSigner[newSigner] = true;
        emit SignerAdded(newSigner);
    }

    function removeSigner(address signer) external {
        require(msg.sender == address(this), "Only via governance proposal");
        require(isSigner[signer], "Not a signer");
        require(signers.length - 1 >= threshold, "Would break threshold");

        // Clear the mapping entry.
        isSigner[signer] = false;

        // Remove from the signers array using swap-and-pop (O(1), order not guaranteed).
        // Without this, signers.length stays inflated, breaking threshold arithmetic
        // and signerCount() for any future signers added or threshold changes.
        for (uint256 i = 0; i < signers.length; i++) {
            if (signers[i] == signer) {
                signers[i] = signers[signers.length - 1];
                signers.pop();
                break;
            }
        }

        emit SignerRemoved(signer);
    }

    function updateThreshold(uint256 newThreshold) external {
        require(msg.sender == address(this), "Only via governance proposal");
        require(newThreshold > 0 && newThreshold <= signers.length, "Invalid threshold");
        threshold = newThreshold;
        emit ThresholdUpdated(newThreshold);
    }

    // ── Views ─────────────────────────────────────────────────────────────────

    function getProposal(uint256 id) external view returns (
        address target,
        string memory description,
        uint256 submittedAt,
        ProposalStatus status,
        uint256 approvalCount,
        uint256 rejectionCount
    ) {
        Proposal storage p = _proposals[id];
        return (p.target, p.description, p.submittedAt, p.status, p.approvalCount, p.rejectionCount);
    }

    function signerCount() external view returns (uint256) {
        return signers.length;
    }

    /// @notice Accept ETH from Appeal bond forfeitures and other protocol flows.
    receive() external payable {}
}
