// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title PinningRewards
 * @notice Economic incentive system for IPFS content pinning
 * @dev Rewards mirror nodes for storing and serving package content
 *
 * Architecture:
 * - Nodes register as "pinners" with stake
 * - They report which CIDs they are pinning
 * - Random sampling verifies actual pinning via IPFS DHT lookups
 * - Rewards distributed based on:
 *   - Amount of data pinned (GB)
 *   - Duration of pinning (days)
 *   - Successful verification rate
 *   - Content popularity (access count)
 */
contract PinningRewards is AccessControl, ReentrancyGuard {
    
    bytes32 public constant REWARDS_ADMIN = keccak256("REWARDS_ADMIN");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    
    IERC20 public immutable cregToken;
    
    // ============ Data Structures ============
    
    struct Pinner {
        bool isRegistered;
        uint256 stakedAmount;
        uint256 totalPinnedSize;  // in bytes
        uint256 successfulVerifications;
        uint256 failedVerifications;
        uint256 lastRewardClaim;
        uint256 cumulativeRewards;
    }
    
    struct Pin {
        address pinner;
        uint256 size;             // Content size in bytes
        uint256 pinnedAt;         // Timestamp when first pinned
        uint256 lastVerified;     // Last successful verification
        uint256 accessCount;      // How many times content was served
        bool isActive;
    }
    
    struct Verification {
        bytes32 cid;
        address pinner;
        uint256 timestamp;
        bool success;
        bytes32 proofHash;        // Hash of verification proof data
    }
    
    // ============ State ============
    
    // Minimum stake to become a pinner (1000 CREG)
    uint256 public constant MIN_STAKE = 1000e18;
    
    // Rewards per GB per day (configurable)
    uint256 public rewardPerGBPerDay = 1e16; // 0.01 CREG per GB per day
    
    // Bonus multiplier for popular content (>1000 accesses)
    uint256 public popularContentMultiplier = 200; // 2x bonus (200%)
    
    // Penalty for failed verification
    uint256 public verificationFailurePenalty = 100; // 1% stake slashed
    
    // Verification cooldown (prevent spam)
    uint256 public verificationCooldown = 1 hours;
    
    // Mapping: pinner address => Pinner info
    mapping(address => Pinner) public pinners;
    
    // Mapping: CID hash => Pin info (only tracks active pins)
    mapping(bytes32 => Pin) public pins;
    
    // Mapping: pinner => list of pinned CIDs
    mapping(address => bytes32[]) public pinnerCids;
    
    // Mapping: CID => list of pinners (for redundancy tracking)
    mapping(bytes32 => address[]) public cidPinners;
    
    // Verification history
    Verification[] public verifications;
    mapping(address => uint256) public lastVerificationTime;
    
    // Total rewards distributed
    uint256 public totalRewardsDistributed;
    
    // Rewards pool (funded by governance)
    uint256 public rewardsPool;
    
    // ============ Events ============
    
    event PinnerRegistered(address indexed pinner, uint256 stake);
    event PinnerUnregistered(address indexed pinner, uint256 stakeReturned);
    event PinRegistered(address indexed pinner, bytes32 indexed cid, uint256 size);
    event PinUnregistered(address indexed pinner, bytes32 indexed cid);
    event ContentVerified(address indexed pinner, bytes32 indexed cid, bool success);
    event RewardsClaimed(address indexed pinner, uint256 amount);
    event RewardsPoolFunded(uint256 amount);
    event RewardRateUpdated(uint256 newRate);
    
    // ============ Constructor ============
    
    constructor(address _cregToken) {
        cregToken = IERC20(_cregToken);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(REWARDS_ADMIN, msg.sender);
        _grantRole(VERIFIER_ROLE, msg.sender);
    }
    
    // ============ Pinner Registration ============
    
    /**
     * @notice Register as a pinner with minimum stake
     */
    function registerPinner(uint256 stakeAmount) external nonReentrant {
        require(!pinners[msg.sender].isRegistered, "Already registered");
        require(stakeAmount >= MIN_STAKE, "Insufficient stake");
        
        // Transfer stake
        require(cregToken.transferFrom(msg.sender, address(this), stakeAmount), "Stake transfer failed");
        
        pinners[msg.sender] = Pinner({
            isRegistered: true,
            stakedAmount: stakeAmount,
            totalPinnedSize: 0,
            successfulVerifications: 0,
            failedVerifications: 0,
            lastRewardClaim: block.timestamp,
            cumulativeRewards: 0
        });
        
        emit PinnerRegistered(msg.sender, stakeAmount);
    }
    
    /**
     * @notice Unregister as a pinner and reclaim stake
     * @dev Must have no active pins
     */
    function unregisterPinner() external nonReentrant {
        Pinner storage pinner = pinners[msg.sender];
        require(pinner.isRegistered, "Not registered");
        require(pinnerCids[msg.sender].length == 0, "Has active pins");
        
        uint256 stakeToReturn = pinner.stakedAmount;
        
        // Claim any pending rewards first
        _claimRewards(msg.sender);
        
        delete pinners[msg.sender];
        
        require(cregToken.transfer(msg.sender, stakeToReturn), "Stake return failed");
        
        emit PinnerUnregistered(msg.sender, stakeToReturn);
    }
    
    // ============ Pin Management ============
    
    /**
     * @notice Register a CID as being pinned by the caller
     */
    function registerPin(bytes32 cid, uint256 size) external {
        Pinner storage pinner = pinners[msg.sender];
        require(pinner.isRegistered, "Not a registered pinner");
        require(size > 0, "Invalid size");
        require(!pins[cid].isActive || pins[cid].pinner != msg.sender, "Already pinning this CID");
        
        pins[cid] = Pin({
            pinner: msg.sender,
            size: size,
            pinnedAt: block.timestamp,
            lastVerified: 0,
            accessCount: 0,
            isActive: true
        });
        
        pinnerCids[msg.sender].push(cid);
        cidPinners[cid].push(msg.sender);
        pinner.totalPinnedSize += size;
        
        emit PinRegistered(msg.sender, cid, size);
    }
    
    /**
     * @notice Unregister a pin (node stopped pinning)
     */
    function unregisterPin(bytes32 cid) external {
        Pin storage pin = pins[cid];
        require(pin.isActive, "Pin not active");
        require(pin.pinner == msg.sender, "Not your pin");
        
        pin.isActive = false;
        pinners[msg.sender].totalPinnedSize -= pin.size;
        
        // Remove from pinnerCids array
        _removeCidFromPinner(msg.sender, cid);
        
        emit PinUnregistered(msg.sender, cid);
    }
    
    /**
     * @notice Report content access (called by nodes when serving content)
     */
    function reportAccess(bytes32 cid) external {
        Pin storage pin = pins[cid];
        require(pin.isActive, "Pin not active");
        
        pin.accessCount++;
    }
    
    // ============ Verification ============
    
    /**
     * @notice Submit verification result for a pinner's content
     * @dev Only callable by verifiers (can be automated oracles)
     */
    function submitVerification(
        address pinner,
        bytes32 cid,
        bool success,
        bytes32 proofHash
    ) external onlyRole(VERIFIER_ROLE) {
        require(block.timestamp >= lastVerificationTime[pinner] + verificationCooldown, "Cooldown active");
        
        Pin storage pin = pins[cid];
        require(pin.isActive && pin.pinner == pinner, "Invalid pin");
        
        Pinner storage pinnerData = pinners[pinner];
        
        verifications.push(Verification({
            cid: cid,
            pinner: pinner,
            timestamp: block.timestamp,
            success: success,
            proofHash: proofHash
        }));
        
        lastVerificationTime[pinner] = block.timestamp;
        
        if (success) {
            pinnerData.successfulVerifications++;
            pin.lastVerified = block.timestamp;
        } else {
            pinnerData.failedVerifications++;
            // Slash stake for failed verification
            uint256 penalty = (pinnerData.stakedAmount * verificationFailurePenalty) / 10000;
            pinnerData.stakedAmount -= penalty;
            rewardsPool += penalty; // Add penalty to rewards pool
        }
        
        emit ContentVerified(pinner, cid, success);
    }
    
    // ============ Rewards ============
    
    /**
     * @notice Calculate pending rewards for a pinner
     */
    function calculateRewards(address pinnerAddr) public view returns (uint256) {
        Pinner storage pinner = pinners[pinnerAddr];
        if (!pinner.isRegistered) return 0;
        
        uint256 totalReward = 0;
        uint256 timeDelta = block.timestamp - pinner.lastRewardClaim;
        
        bytes32[] storage cids = pinnerCids[pinnerAddr];
        for (uint i = 0; i < cids.length; i++) {
            Pin storage pin = pins[cids[i]];
            if (!pin.isActive) continue;
            
            // Base reward: size (bytes) * time (days) * rate per GB per day / 1e9
            uint256 daysPinned = timeDelta / 1 days;
            
            // Multiply first to prevent truncation of sub-GB packages
            uint256 baseReward = (pin.size * daysPinned * rewardPerGBPerDay) / 1e9;
            
            // Popularity bonus
            if (pin.accessCount > 1000) {
                baseReward = (baseReward * popularContentMultiplier) / 100;
            }
            
            // Verification reliability factor
            uint256 totalVerifications = pinner.successfulVerifications + pinner.failedVerifications;
            if (totalVerifications > 0) {
                uint256 reliability = (pinner.successfulVerifications * 100) / totalVerifications;
                baseReward = (baseReward * reliability) / 100;
            }
            
            totalReward += baseReward;
        }
        
        return totalReward;
    }
    
    /**
     * @notice Claim accumulated rewards
     */
    function claimRewards() external nonReentrant {
        _claimRewards(msg.sender);
    }
    
    function _claimRewards(address pinnerAddr) internal {
        uint256 rewards = calculateRewards(pinnerAddr);
        require(rewards > 0, "No rewards to claim");
        require(rewards <= rewardsPool, "Insufficient rewards pool");
        
        Pinner storage pinner = pinners[pinnerAddr];
        pinner.lastRewardClaim = block.timestamp;
        pinner.cumulativeRewards += rewards;
        rewardsPool -= rewards;
        totalRewardsDistributed += rewards;
        
        require(cregToken.transfer(pinnerAddr, rewards), "Reward transfer failed");
        
        emit RewardsClaimed(pinnerAddr, rewards);
    }
    
    // ============ Admin Functions ============
    
    /**
     * @notice Fund the rewards pool
     */
    function fundRewardsPool(uint256 amount) external {
        require(cregToken.transferFrom(msg.sender, address(this), amount), "Transfer failed");
        rewardsPool += amount;
        emit RewardsPoolFunded(amount);
    }
    
    /**
     * @notice Update reward rate
     */
    function setRewardRate(uint256 newRate) external onlyRole(REWARDS_ADMIN) {
        rewardPerGBPerDay = newRate;
        emit RewardRateUpdated(newRate);
    }
    
    /**
     * @notice Update verification parameters
     */
    function setVerificationParams(
        uint256 _cooldown,
        uint256 _penalty,
        uint256 _multiplier
    ) external onlyRole(REWARDS_ADMIN) {
        verificationCooldown = _cooldown;
        verificationFailurePenalty = _penalty;
        popularContentMultiplier = _multiplier;
    }
    
    // ============ View Functions ============
    
    function getPinnerInfo(address pinner) external view returns (Pinner memory) {
        return pinners[pinner];
    }
    
    function getPinInfo(bytes32 cid) external view returns (Pin memory) {
        return pins[cid];
    }
    
    function getPinnerCids(address pinner) external view returns (bytes32[] memory) {
        return pinnerCids[pinner];
    }
    
    function getCidPinners(bytes32 cid) external view returns (address[] memory) {
        return cidPinners[cid];
    }
    
    function getVerificationCount() external view returns (uint256) {
        return verifications.length;
    }
    
    // ============ Internal Helpers ============
    
    function _removeCidFromPinner(address pinner, bytes32 cid) internal {
        bytes32[] storage cids = pinnerCids[pinner];
        for (uint i = 0; i < cids.length; i++) {
            if (cids[i] == cid) {
                cids[i] = cids[cids.length - 1];
                cids.pop();
                break;
            }
        }
    }
}
