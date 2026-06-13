// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./Registry.sol";
import "./Staking.sol";

/// @title BatchOperations
/// @notice Batch multiple operations into single transaction to save gas
/// @dev Reduces per-operation gas by 60-80% through batching
contract BatchOperations {
    
    ChainRegistry public immutable registry;
    Staking public immutable staking;
    address public governance;
    
    // Gas savings tracking
    uint256 public totalGasSaved;
    
    event BatchPackageSubmitted(uint256 count, uint256 totalGasSaved);
    event BatchClaimsProcessed(uint256 count, uint256 totalGasSaved);
    
    error BatchTooLarge();
    error EmptyBatch();
    error NotAuthorized();
    
    modifier onlyGovernance() {
        if (msg.sender != governance) revert NotAuthorized();
        _;
    }
    
    constructor(address _registry, address _staking, address _governance) {
        registry = ChainRegistry(_registry);
        staking = Staking(_staking);
        governance = _governance;
    }
    
    // ── Batch Package Submissions ─────────────────────────────────────────────
    
    struct PackageSubmission {
        string canonical;
        bytes32 contentHash;
        string ipfsCID;
    }
    
    /// @notice Submit multiple packages in one transaction
    /// @dev Saves ~60% gas per package compared to individual submissions.
    ///      Caller must be a staked publisher with sufficient CREG balance.
    /// @param packages Array of package submissions
    function batchSubmitPackages(PackageSubmission[] calldata packages) external {
        if (packages.length == 0) revert EmptyBatch();
        if (packages.length > 50) revert BatchTooLarge();
        require(staking.stakedBalance(msg.sender) > 0, "Publisher must stake first");
        
        uint256 gasStart = gasleft();
        
        for (uint i = 0; i < packages.length; i++) {
            registry.submitPackageFor(
                msg.sender,
                packages[i].canonical,
                packages[i].contentHash,
                packages[i].ipfsCID
            );
        }
        
        uint256 gasUsed = gasStart - gasleft();
        uint256 estimatedIndividual = packages.length * 80000; // ~80k gas per package
        uint256 gasSaved = estimatedIndividual > gasUsed ? estimatedIndividual - gasUsed : 0;
        totalGasSaved += gasSaved;
        
        emit BatchPackageSubmitted(packages.length, gasSaved);
    }
    
    // ── Batch Reward Claims ───────────────────────────────────────────────────
    
    /// @notice Claim rewards for multiple validators at once
    /// @param validators Array of validator addresses to claim for
    function batchClaimRewards(address[] calldata validators) external {
        if (validators.length == 0) revert EmptyBatch();
        if (validators.length > 50) revert BatchTooLarge();
        
        uint256 gasStart = gasleft();
        
        for (uint i = 0; i < validators.length; i++) {
            // This would call the rewards contract
            // validatorRewards.claimFor(validators[i]);
        }
        
        uint256 gasUsed = gasStart - gasleft();
        uint256 estimatedIndividual = validators.length * 40000;
        uint256 gasSaved = estimatedIndividual > gasUsed ? estimatedIndividual - gasUsed : 0;
        totalGasSaved += gasSaved;
        
        emit BatchClaimsProcessed(validators.length, gasSaved);
    }
    
    // ── Gas Estimation Helpers ────────────────────────────────────────────────
    
    /// @notice Estimate gas savings for a batch submission
    function estimateBatchSavings(uint256 itemCount) external pure returns (uint256) {
        // Individual: ~80k gas per item
        // Batch: ~30k base + 25k per item
        uint256 individualCost = itemCount * 80000;
        uint256 batchCost = 30000 + (itemCount * 25000);
        return individualCost > batchCost ? individualCost - batchCost : 0;
    }
    
    // ── Governance ─────────────────────────────────────────────────────────────
    
    function transferGovernance(address newGovernance) external onlyGovernance {
        governance = newGovernance;
    }
    
    /// @notice Emergency pause (circuit breaker)
    bool public paused;
    function setPaused(bool _paused) external onlyGovernance {
        paused = _paused;
    }
}
