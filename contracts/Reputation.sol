// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Reputation
/// @notice Tracks per-address reputation scores for validators and publishers.
/// @dev Scores influence how much weight a validator's vote carries and
///      whether a publisher's new submissions get expedited review.
contract Reputation {

    // ── Storage ───────────────────────────────────────────────────────────────

    struct Score {
        uint32 approvals;        // Total correct approvals (later found safe)
        uint32 rejections;       // Total correct rejections (later found malicious)
        uint32 falseApprovals;   // Approved something that was later revoked
        uint32 falseRejections;  // Rejected something that was appealed and approved
        uint64 lastUpdated;
    }

    mapping(address => Score) public scores;
    address public registry;
    address public governance;

    // ── Events ────────────────────────────────────────────────────────────────

    event ReputationUpdated(address indexed account, int32 delta, string reason);

    // ── Constructor ───────────────────────────────────────────────────────────

    constructor(address _governance) {
        governance = _governance;
    }

    function setRegistry(address _registry) external {
        require(registry == address(0), "Already set");
        registry = _registry;
    }

    // ── Write (only Registry) ─────────────────────────────────────────────────

    function recordApproval(address validator) external {
        require(msg.sender == registry, "Only registry");
        scores[validator].approvals++;
        scores[validator].lastUpdated = uint64(block.timestamp);
        emit ReputationUpdated(validator, 1, "approval");
    }

    function recordRejection(address validator) external {
        require(msg.sender == registry, "Only registry");
        scores[validator].rejections++;
        scores[validator].lastUpdated = uint64(block.timestamp);
        emit ReputationUpdated(validator, 1, "rejection");
    }

    /// @notice Called by governance when a package a validator approved is later revoked.
    function penalizeFalseApproval(address validator) external {
        require(msg.sender == governance, "Only governance");
        scores[validator].falseApprovals++;
        emit ReputationUpdated(validator, -5, "false_approval");
    }

    function penalizeFalseRejection(address validator) external {
        require(msg.sender == governance, "Only governance");
        scores[validator].falseRejections++;
        emit ReputationUpdated(validator, -2, "false_rejection");
    }

    // ── Read ──────────────────────────────────────────────────────────────────

    /// @notice Compute a 0–100 reputation score for a validator.
    function scoreOf(address account) external view returns (uint8) {
        Score memory s = scores[account];
        uint32 total = s.approvals + s.rejections;
        if (total == 0) return 50; // New validators start at 50

        // Base score from correct decisions.
        uint256 correct  = s.approvals + s.rejections;
        uint256 wrong    = (s.falseApprovals * 5) + (s.falseRejections * 2);
        uint256 rawScore = correct > wrong ? ((correct - wrong) * 100) / (correct + wrong + 1) : 0;

        // Cap at 100.
        return uint8(rawScore > 100 ? 100 : rawScore);
    }

    function getScore(address account) external view returns (Score memory) {
        return scores[account];
    }
}
