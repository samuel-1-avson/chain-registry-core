// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./Staking.sol";
import "./CregToken.sol";

/// @title ValidatorRewards
/// @notice Work-based reward system for validators - ONLY rewards actual verification work
/// @dev Validators are rewarded ONLY when they prove they verified a package (good or bad).
///      NO time-based rewards (no block rewards). NO daily limits. Pay for proven work only.
///
/// REWARD MECHANISM (Mechanical Consensus):
/// 1. Validator votes on package (approve/reject) - NO reward yet
/// 2. Package reaches consensus and is finalized - Rewards distributed to participating validators
/// 3. Reward amount based on: 
///    - Number of packages verified
///    - Correctness of vote (higher reward for correct votes)
///    - Reputation score multiplier
///    - Stake weight (optional)
///
/// This creates a true "Proof of Verification" system where validators must do work to earn.
contract ValidatorRewards {
    
    // ── Constants ─────────────────────────────────────────────────────────────
    
    /// @notice Base reward per package verified (0.5 CREG)
    /// @dev Paid only when validator proves they participated in consensus
    uint256 public constant BASE_PACKAGE_REWARD = 0.5 ether;
    
    /// @notice Bonus for validators who voted correctly (package verified = approved good, or rejected bad)
    uint256 public constant CORRECT_VOTE_BONUS = 0.3 ether;
    
    /// @notice Penalty for validators who voted incorrectly (0.1 CREG deducted from reward)
    /// @dev Still get base reward but less bonus
    uint256 public constant INCORRECT_VOTE_PENALTY = 0.1 ether;
    
    /// @notice Minimum reward per verified package (can't go below this)
    uint256 public constant MIN_PACKAGE_REWARD = 0.1 ether;
    
    // ── Storage ───────────────────────────────────────────────────────────────
    
    Staking public immutable staking;
    CregToken public immutable cregToken;
    address public governance;
    address public treasury;
    
    /// @notice Tracks validator rewards (validator => pending reward)
    mapping(address => uint256) public pendingRewards;
    
    /// @notice Tracks packages verified by each validator (validator => count)
    mapping(address => uint256) public packagesVerified;
    
    /// @notice Tracks correct votes by validator (validator => correct count)
    mapping(address => uint256) public correctVotes;
    
    /// @notice Tracks incorrect votes by validator (validator => incorrect count)
    mapping(address => uint256) public incorrectVotes;
    
    /// @notice Total rewards distributed
    uint256 public totalRewardsDistributed;
    
    /// @notice Total packages verified through this system
    uint256 public totalPackagesVerified;
    
    // ── Events ─────────────────────────────────────────────────────────────────
    
    event WorkReward(
        address indexed validator, 
        uint256 amount, 
        string packageCanonical,
        bool votedCorrectly,
        uint256 reputationBonus
    );
    event RewardsClaimed(address indexed validator, uint256 amount);
    event TreasuryFunded(address indexed source, uint256 amount);
    
    // ── Errors ─────────────────────────────────────────────────────────────────
    
    error NotAuthorized();
    error NotActiveValidator();
    error NoRewardsToClaim();
    error InvalidVoteDistribution();
    
    // ── Constructor ────────────────────────────────────────────────────────────
    
    constructor(
        address _staking,
        address _cregToken,
        address _governance,
        address _treasury
    ) {
        staking = Staking(_staking);
        cregToken = CregToken(_cregToken);
        governance = _governance;
        treasury = _treasury;
    }
    
    // ── Work-Based Reward Distribution ─────────────────────────────────────────
    
    /// @notice Distribute rewards to validators who verified a package.
    /// @dev Called by Registry when package reaches consensus. 
    ///      Rewards are based on PROOF OF WORK (actual verification).
    /// @param packageCanonical The canonical ID of the verified package
    /// @param validators Array of validator addresses who participated in verification
    /// @param approvals Array of bool indicating if each validator approved (true) or rejected (false)
    /// @param packageWasGood Boolean indicating if the package was actually good (true) or bad/false positive (false)
    /// @param reputationScores Array of reputation scores (0-100) for each validator
    function distributeWorkRewards(
        string calldata packageCanonical,
        address[] calldata validators,
        bool[] calldata approvals,
        bool packageWasGood,
        uint256[] calldata reputationScores
    ) external {
        if (msg.sender != governance && msg.sender != address(staking)) revert NotAuthorized();
        if (validators.length != approvals.length || validators.length != reputationScores.length) 
            revert InvalidVoteDistribution();
        if (validators.length == 0) revert InvalidVoteDistribution();
        
        totalPackagesVerified++;
        
        // Distribute rewards to each validator who did work
        for (uint i = 0; i < validators.length; i++) {
            _processValidatorReward(
                validators[i], 
                approvals[i], 
                packageWasGood, 
                reputationScores[i], 
                packageCanonical
            );
        }
    }
    
    /// @dev Process reward for a single validator (extracted to avoid stack-too-deep)
    function _processValidatorReward(
        address validator,
        bool validatorApproved,
        bool packageWasGood,
        uint256 repScore,
        string calldata packageCanonical
    ) internal {
        if (!staking.isActiveValidator(validator)) return;
        
        bool votedCorrectly = (packageWasGood && validatorApproved) || (!packageWasGood && !validatorApproved);
        uint256 reward = _calculateWorkReward(votedCorrectly, repScore);
        
        pendingRewards[validator] += reward;
        packagesVerified[validator]++;
        
        if (votedCorrectly) {
            correctVotes[validator]++;
        } else {
            incorrectVotes[validator]++;
        }
        
        totalRewardsDistributed += reward;
        require(cregToken.transferFrom(treasury, address(this), reward), "Treasury transfer failed");
        
        emit WorkReward(validator, reward, packageCanonical, votedCorrectly, repScore);
    }
    
    /// @notice Calculate reward for a single verification.
    /// @param votedCorrectly Whether the validator voted correctly
    /// @param reputationScore Validator's reputation score (0-100)
    /// @return reward Amount of CREG earned
    function _calculateWorkReward(bool votedCorrectly, uint256 reputationScore) 
        internal 
        pure 
        returns (uint256 reward) 
    {
        // Base reward for doing the work (verifying)
        reward = BASE_PACKAGE_REWARD;
        
        if (votedCorrectly) {
            // Bonus for correct vote
            reward += CORRECT_VOTE_BONUS;
            
            // Additional bonus based on reputation (0-20% extra)
            uint256 repBonus = (BASE_PACKAGE_REWARD * reputationScore) / 500; // max 20%
            reward += repBonus;
        } else {
            // Penalty for incorrect vote
            if (reward > INCORRECT_VOTE_PENALTY) {
                reward -= INCORRECT_VOTE_PENALTY;
            } else {
                reward = MIN_PACKAGE_REWARD; // Floor
            }
        }
        
        return reward;
    }
    
    /// @notice Simplified version: equal base reward, no reputation bonus
    /// @dev Used when reputation system is not available or for testing
    function distributeSimpleWorkRewards(
        string calldata packageCanonical,
        address[] calldata validators,
        bool[] calldata approvals,
        bool packageWasGood
    ) external {
        if (msg.sender != governance && msg.sender != address(staking)) revert NotAuthorized();
        if (validators.length != approvals.length) revert InvalidVoteDistribution();
        if (validators.length == 0) revert InvalidVoteDistribution();
        
        totalPackagesVerified++;
        uint256 rewardPerValidator = BASE_PACKAGE_REWARD / validators.length;
        if (rewardPerValidator < MIN_PACKAGE_REWARD) rewardPerValidator = MIN_PACKAGE_REWARD;
        
        uint256 totalReward = rewardPerValidator * validators.length;
        require(cregToken.transferFrom(treasury, address(this), totalReward), "Treasury transfer failed");
        
        for (uint i = 0; i < validators.length; i++) {
            _processSimpleReward(
                validators[i],
                approvals[i],
                packageWasGood,
                rewardPerValidator,
                packageCanonical
            );
        }
        
        totalRewardsDistributed += totalReward;
    }
    
    /// @dev Process simple reward for a single validator (extracted to avoid stack-too-deep)
    function _processSimpleReward(
        address validator,
        bool validatorApproved,
        bool packageWasGood,
        uint256 rewardPerValidator,
        string calldata packageCanonical
    ) internal {
        if (!staking.isActiveValidator(validator)) return;
        
        bool votedCorrectly = (packageWasGood && validatorApproved) || (!packageWasGood && !validatorApproved);
        
        uint256 reward = votedCorrectly ? rewardPerValidator + CORRECT_VOTE_BONUS : rewardPerValidator - INCORRECT_VOTE_PENALTY;
        if (reward < MIN_PACKAGE_REWARD) reward = MIN_PACKAGE_REWARD;
        
        pendingRewards[validator] += reward;
        packagesVerified[validator]++;
        
        if (votedCorrectly) {
            correctVotes[validator]++;
        } else {
            incorrectVotes[validator]++;
        }
        
        emit WorkReward(validator, reward, packageCanonical, votedCorrectly, 50);
    }
    
    // ── Claim Rewards ──────────────────────────────────────────────────────────
    
    /// @notice Validators claim their accumulated rewards from verified work
    function claimRewards() external {
        uint256 amount = pendingRewards[msg.sender];
        if (amount == 0) revert NoRewardsToClaim();
        
        pendingRewards[msg.sender] = 0;
        
        require(cregToken.transfer(msg.sender, amount), "Reward transfer failed");
        
        emit RewardsClaimed(msg.sender, amount);
    }
    
    /// @notice View pending rewards for a validator
    function getPendingRewards(address validator) external view returns (uint256) {
        return pendingRewards[validator];
    }
    
    // ── View Functions ────────────────────────────────────────────────────────
    
    /// @notice Get validator statistics
    function getValidatorStats(address validator) external view returns (
        uint256 _packagesVerified,
        uint256 _correctVotes,
        uint256 _incorrectVotes,
        uint256 accuracyRate
    ) {
        _packagesVerified = packagesVerified[validator];
        _correctVotes = correctVotes[validator];
        _incorrectVotes = incorrectVotes[validator];
        
        uint256 total = _correctVotes + _incorrectVotes;
        accuracyRate = total > 0 ? (_correctVotes * 100) / total : 0;
    }
    
    /// @notice Estimate earnings based on verification volume
    /// @param packagesPerDay Number of packages validator expects to verify daily
    /// @param accuracyPercent Expected accuracy rate (0-100)
    /// @param reputationScore Validator's reputation score (0-100)
    function estimateEarnings(
        uint256 packagesPerDay,
        uint256 accuracyPercent,
        uint256 reputationScore
    ) external pure returns (uint256 daily, uint256 monthly, uint256 yearly) {
        // Calculate average reward per package based on accuracy
        uint256 avgReward = BASE_PACKAGE_REWARD;
        
        if (accuracyPercent >= 80) {
            // High accuracy - get bonuses
            avgReward += CORRECT_VOTE_BONUS;
            avgReward += (BASE_PACKAGE_REWARD * reputationScore) / 500; // rep bonus
        } else if (accuracyPercent >= 50) {
            // Medium accuracy - partial bonus
            avgReward += CORRECT_VOTE_BONUS / 2;
        } else {
            // Low accuracy - penalty
            avgReward = avgReward > INCORRECT_VOTE_PENALTY ? avgReward - INCORRECT_VOTE_PENALTY : MIN_PACKAGE_REWARD;
        }
        
        daily = packagesPerDay * avgReward;
        monthly = daily * 30;
        yearly = daily * 365;
    }
    
    // ── Admin Functions ───────────────────────────────────────────────────────
    
    /// @notice Fund the treasury (called by governance or token contract)
    function fundTreasury(uint256 amount) external {
        require(cregToken.transferFrom(msg.sender, treasury, amount), "Funding failed");
        emit TreasuryFunded(msg.sender, amount);
    }
    
    /// @notice Update treasury address
    function setTreasury(address newTreasury) external {
        if (msg.sender != governance) revert NotAuthorized();
        treasury = newTreasury;
    }
    
    /// @notice Emergency withdrawal of stuck tokens (governance only)
    function emergencyWithdraw(address token, uint256 amount) external {
        if (msg.sender != governance) revert NotAuthorized();
        require(CregToken(token).transfer(governance, amount), "Emergency withdraw failed");
    }
}
