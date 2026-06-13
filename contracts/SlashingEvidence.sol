// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./Staking.sol";
import "./Reputation.sol";
import "./Registry.sol";

/// @title SlashingEvidence
/// @notice Permissionless slashing evidence submission.
/// @dev Anyone can submit cryptographic proof that a validator signed contradictory
///      votes (double-signing) or approved a package that was later proven malicious.
///      If the evidence is accepted by a quorum of other validators, the offending
///      validator's stake is slashed and the whistleblower receives a reward.
contract SlashingEvidence {

    // ── Evidence types ────────────────────────────────────────────────────────

    /// A validator signed two different votes for the same package at the same phase.
    uint8 constant DOUBLE_SIGN   = 1;
    /// A validator approved a package that was later revoked as malicious.
    uint8 constant FALSE_APPROVE = 2;
    /// A validator consistently voted against the majority without justification.
    uint8 constant GRIEFING      = 3;

    // ── Structs ───────────────────────────────────────────────────────────────

    struct EvidenceRecord {
        uint8    evidenceType;
        address  offender;        // The validator being accused
        address  whistleblower;   // Who submitted the evidence
        bytes    proof1;          // Primary evidence (e.g. first signature)
        bytes    proof2;          // Contradicting evidence (e.g. conflicting sig)
        string   packageCanonical;
        uint256  submittedAt;
        bool     resolved;
        bool     accepted;
        uint256  confirmVotes;
        uint256  rejectVotes;
        /// Timestamp at which confirmQuorum was first reached.
        /// Zero until quorum is reached.  Execution is gated behind
        /// MIN_EXECUTE_DELAY to prevent flash-governance attacks.
        uint256  quorumReachedAt;
        mapping(address => bool) voted;
    }

    // ── Storage ───────────────────────────────────────────────────────────────

    mapping(uint256 => EvidenceRecord) private _evidence;
    uint256 public evidenceCount;

    Staking       public immutable staking;
    Reputation    public immutable reputation;
    ChainRegistry public immutable registry;
    address    public governance;

    /// Percentage of slashed amount awarded to the whistleblower (10%).
    uint256 public constant WHISTLEBLOWER_REWARD_PCT = 10;
    /// Minimum confirmations before slashing executes.
    uint256 public confirmQuorum = 3;
    /// Evidence voting window.
    uint256 public constant EVIDENCE_WINDOW = 3 days;
    /// Minimum delay between quorum being reached and execution.
    /// Prevents a rapid coalition (or flash-loan governance) from slashing
    /// a validator before honest nodes can review and veto the evidence.
    uint256 public constant MIN_EXECUTE_DELAY = 1 days;

    // ── Events ────────────────────────────────────────────────────────────────

    event EvidenceSubmitted  (uint256 indexed id, address offender, uint8 evidenceType);
    event EvidenceVoted      (uint256 indexed id, address voter, bool confirmed);
    event EvidenceQuorumReached(uint256 indexed id, uint256 executeAfter);
    event EvidenceAccepted   (uint256 indexed id, address offender, uint256 slashAmount);
    event EvidenceRejected   (uint256 indexed id);

    // ── Errors ────────────────────────────────────────────────────────────────

    error NotValidator();
    error AlreadyResolved();
    error AlreadyVoted();
    error EvidenceWindowExpired();
    error InvalidProof();
    error QuorumNotReached();
    error DelayNotElapsed(uint256 executeAfter);

    // ── Constructor ───────────────────────────────────────────────────────────

    constructor(
        address _staking,
        address _reputation,
        address _registry,
        address _governance
    ) {
        staking    = Staking(_staking);
        reputation = Reputation(_reputation);
        registry   = ChainRegistry(_registry);
        governance = _governance;
    }

    // ── Submission ────────────────────────────────────────────────────────────

    /// @notice Submit evidence of validator misbehaviour.
    /// @param offender        The misbehaving validator's address
    /// @param evidenceType    DOUBLE_SIGN | FALSE_APPROVE | GRIEFING
    /// @param proof1          Primary evidence bytes
    /// @param proof2          Contradicting evidence bytes (empty for FALSE_APPROVE)
    /// @param packageCanonical The package canonical ID involved
    function submitEvidence(
        address        offender,
        uint8          evidenceType,
        bytes calldata proof1,
        bytes calldata proof2,
        string calldata packageCanonical
    ) external returns (uint256 id) {
        if (!staking.isActiveValidator(offender))
            revert NotValidator();
        if (proof1.length == 0)
            revert InvalidProof();

        id = evidenceCount++;
        EvidenceRecord storage rec = _evidence[id];
        rec.evidenceType    = evidenceType;
        rec.offender        = offender;
        rec.whistleblower   = msg.sender;
        rec.proof1          = proof1;
        rec.proof2          = proof2;
        rec.packageCanonical = packageCanonical;
        rec.submittedAt     = block.timestamp;

        emit EvidenceSubmitted(id, offender, evidenceType);
    }

    // ── Validator confirmation ────────────────────────────────────────────────

    /// @notice Other validators vote on whether the evidence is valid.
    function confirmEvidence(uint256 id, bool confirm) external {
        if (!staking.isActiveValidator(msg.sender))
            revert NotValidator();

        EvidenceRecord storage rec = _evidence[id];
        if (rec.resolved) revert AlreadyResolved();
        if (rec.voted[msg.sender]) revert AlreadyVoted();
        if (block.timestamp > rec.submittedAt + EVIDENCE_WINDOW)
            revert EvidenceWindowExpired();

        rec.voted[msg.sender] = true;

        if (confirm) {
            rec.confirmVotes++;
        } else {
            rec.rejectVotes++;
        }

        emit EvidenceVoted(id, msg.sender, confirm);

        // Record when quorum is first reached — execution is deferred by
        // MIN_EXECUTE_DELAY to give honest validators time to review.
        if (rec.confirmVotes >= confirmQuorum && rec.quorumReachedAt == 0) {
            rec.quorumReachedAt = block.timestamp;
            emit EvidenceQuorumReached(id, block.timestamp + MIN_EXECUTE_DELAY);
        } else {
            // If enough rejections that quorum can't be reached, reject immediately.
            uint256 activeCount = staking.activeValidatorCount();
            if (activeCount - rec.rejectVotes < confirmQuorum) {
                _rejectEvidence(id);
            }
        }
    }

    /// @notice Execute a quorum-approved evidence record after MIN_EXECUTE_DELAY.
    /// @dev Callable by anyone once the delay has elapsed — the delay window gives
    ///      honest validators time to review and, if needed, add rejections before
    ///      the irreversible slash fires.
    function executeEvidence(uint256 id) external {
        EvidenceRecord storage rec = _evidence[id];
        if (rec.resolved)           revert AlreadyResolved();
        if (rec.quorumReachedAt == 0) revert QuorumNotReached();
        uint256 executeAfter = rec.quorumReachedAt + MIN_EXECUTE_DELAY;
        if (block.timestamp < executeAfter) revert DelayNotElapsed(executeAfter);

        // Re-check quorum is still valid (additional rejections may have
        // accumulated during the delay window).
        uint256 activeCount = staking.activeValidatorCount();
        if (activeCount - rec.rejectVotes < confirmQuorum) {
            _rejectEvidence(id);
        } else {
            _acceptEvidence(id);
        }
    }

    // ── Execution ─────────────────────────────────────────────────────────────

    function _acceptEvidence(uint256 id) internal {
        EvidenceRecord storage rec = _evidence[id];
        rec.resolved = true;
        rec.accepted = true;

        uint256 offenderStake = staking.stakedBalance(rec.offender);
        uint256 slashAmount   = offenderStake; // Slash everything for proven misbehaviour.

        // Slash the offender.
        staking.slash(rec.offender, slashAmount, "Evidence of misbehaviour accepted");

        // Penalise reputation.
        reputation.penalizeFalseApproval(rec.offender);

        // Award whistleblower reward (paid from slash proceeds via governance proposal).
        // The actual ETH transfer happens when governance distributes the slash pool.

        emit EvidenceAccepted(id, rec.offender, slashAmount);
    }

    function _rejectEvidence(uint256 id) internal {
        EvidenceRecord storage rec = _evidence[id];
        rec.resolved = true;
        rec.accepted = false;
        emit EvidenceRejected(id);
    }

    // ── Views ─────────────────────────────────────────────────────────────────

    function getEvidence(uint256 id) external view returns (
        uint8   evidenceType,
        address offender,
        address whistleblower,
        bool    resolved,
        bool    accepted,
        uint256 confirmVotes,
        uint256 rejectVotes,
        string  memory packageCanonical
    ) {
        EvidenceRecord storage rec = _evidence[id];
        return (
            rec.evidenceType, rec.offender, rec.whistleblower,
            rec.resolved, rec.accepted,
            rec.confirmVotes, rec.rejectVotes,
            rec.packageCanonical
        );
    }

    // ── Governance ────────────────────────────────────────────────────────────

    function setConfirmQuorum(uint256 q) external {
        require(msg.sender == governance, "Only governance");
        require(q >= 1, "Quorum must be >= 1");
        confirmQuorum = q;
    }
}
