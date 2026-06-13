// SPDX-License-Identifier: MIT
// Testnet Staking Contract - Relaxed parameters for testing
pragma solidity ^0.8.20;

import "./TestCregToken.sol";

/**
 * @title TestStaking
 * @notice Testnet version of Staking contract with relaxed requirements
 * @dev DO NOT USE IN PRODUCTION - For testing only!
 */
contract TestStaking {
    /// @notice Test CREG token
    TestCregToken public cregToken;
    
    /// @notice Validator states
    enum ValidatorState { None, Pending, Active, Exiting, Slashed }
    
    /// @notice Validator entry
    struct ValidatorEntry {
        uint256 stake;
        ValidatorState state;
        uint256 unbondingAt; // 0 if not unbonding
        uint256 slashCount;
        bytes32 metadataHash; // Optional metadata
    }
    
    /// @notice Publisher stake
    struct PublisherEntry {
        uint256 stake;
        uint256 packagesPublished;
        bool isActive;
    }
    
    /// @notice Staking parameters (relaxed for testnet)
    uint256 public minPublisherStake = 0.001 ether; // 0.001 tCREG (was 0.1)
    uint256 public minValidatorStake = 0.1 ether;   // 0.1 tCREG (was 10)
    uint256 public unbondingPeriod = 300;              // 5 minutes for testnet (mainnet: 14 days)
    
    /// @notice Mappings
    mapping(address => ValidatorEntry) public validators;
    mapping(address => PublisherEntry) public publishers;
    address[] public validatorList;
    address[] public publisherList;
    
    /// @notice Operator can perform admin actions
    address public operator;
    
    /// @notice Slash pool - accumulates slashed tokens for redistribution
    uint256 public slashPool;
    
    /// @notice Events
    event PublisherStaked(address indexed publisher, uint256 amount);
    event PublisherUnstaked(address indexed publisher, uint256 amount);
    event ValidatorApplied(address indexed validator, uint256 amount);
    event ValidatorActivated(address indexed validator);
    event ValidatorExited(address indexed validator);
    event ValidatorWithdrawn(address indexed validator, uint256 amount);
    event Slashed(address indexed validator, uint256 amount);
    event SlashPoolDistributed(uint256 totalDistributed, uint256 recipientCount);
    
    modifier onlyOperator() {
        require(msg.sender == operator, "Not operator");
        _;
    }
    
    constructor(address _cregToken) {
        cregToken = TestCregToken(_cregToken);
        operator = msg.sender;
    }
    
    // ============ Publisher Functions ============
    
    /**
     * @notice Stake as publisher (minimum 0.001 tCREG)
     * @param amount Amount to stake
     */
    function stakeAsPublisher(uint256 amount) external {
        require(amount >= minPublisherStake, "Below minimum publisher stake");
        
        cregToken.transferFrom(msg.sender, address(this), amount);
        
        PublisherEntry storage pub = publishers[msg.sender];
        if (!pub.isActive) {
            pub.isActive = true;
            publisherList.push(msg.sender);
        }
        pub.stake += amount;
        
        emit PublisherStaked(msg.sender, amount);
    }
    
    /**
     * @notice Unstake as publisher (instant on testnet)
     * @param amount Amount to unstake
     */
    function unstakeAsPublisher(uint256 amount) external {
        PublisherEntry storage pub = publishers[msg.sender];
        require(pub.stake >= amount, "Insufficient stake");
        
        pub.stake -= amount;
        if (pub.stake == 0) {
            pub.isActive = false;
        }
        
        cregToken.transfer(msg.sender, amount);
        emit PublisherUnstaked(msg.sender, amount);
    }
    
    /**
     * @notice Get publisher stake
     */
    function getPublisherStake(address publisher) external view returns (uint256) {
        return publishers[publisher].stake;
    }
    
    /**
     * @notice Check if address is active publisher
     */
    function isPublisher(address addr) external view returns (bool) {
        return publishers[addr].isActive;
    }
    
    // ============ Validator Functions ============
    
    /**
     * @notice Apply to become validator (minimum 0.1 tCREG)
     * @param amount Amount to stake
     */
    function applyToBeValidator(uint256 amount) external {
        require(amount >= minValidatorStake, "Below minimum validator stake");
        require(validators[msg.sender].state == ValidatorState.None, "Already registered");
        
        cregToken.transferFrom(msg.sender, address(this), amount);
        
        validators[msg.sender] = ValidatorEntry({
            stake: amount,
            state: ValidatorState.Pending,
            unbondingAt: 0,
            slashCount: 0,
            metadataHash: 0
        });
        
        validatorList.push(msg.sender);
        
        emit ValidatorApplied(msg.sender, amount);
    }
    
    /**
     * @notice Operator activates a pending validator
     */
    function activateValidator(address validator) external onlyOperator {
        ValidatorEntry storage v = validators[validator];
        require(v.state == ValidatorState.Pending, "Not pending");
        v.state = ValidatorState.Active;
        emit ValidatorActivated(validator);
    }
    
    /**
     * @notice Exit validator role and begin unbonding period
     */
    function exitValidator() external {
        ValidatorEntry storage v = validators[msg.sender];
        require(v.state == ValidatorState.Active, "Not active validator");
        
        v.state = ValidatorState.Exiting;
        v.unbondingAt = block.timestamp + unbondingPeriod;
        
        emit ValidatorExited(msg.sender);
    }
    
    /**
     * @notice Withdraw validator stake after unbonding period completes
     */
    function withdrawValidatorStake() external {
        ValidatorEntry storage v = validators[msg.sender];
        require(
            v.state == ValidatorState.Exiting || 
            v.state == ValidatorState.Slashed,
            "Not in exiting or slashed state"
        );
        require(
            block.timestamp >= v.unbondingAt,
            "Unbonding period not complete"
        );
        
        uint256 amount = v.stake;
        v.stake = 0;
        v.state = ValidatorState.None;
        
        cregToken.transfer(msg.sender, amount);
        
        emit ValidatorWithdrawn(msg.sender, amount);
    }
    
    /**
     * @notice Add more stake to existing validator
     */
    function addStake(uint256 amount) external {
        ValidatorEntry storage v = validators[msg.sender];
        require(v.state == ValidatorState.Active || v.state == ValidatorState.Pending, "Not registered");
        
        cregToken.transferFrom(msg.sender, address(this), amount);
        v.stake += amount;
    }
    
    /**
     * @notice Get validator info
     */
    function getValidatorInfo(address validator) external view returns (
        uint256 stake,
        ValidatorState state,
        uint256 unbondingAt,
        uint256 slashCount
    ) {
        ValidatorEntry storage v = validators[validator];
        return (v.stake, v.state, v.unbondingAt, v.slashCount);
    }
    
    /**
     * @notice Check if address is active validator
     */
    function isActiveValidator(address addr) external view returns (bool) {
        return validators[addr].state == ValidatorState.Active;
    }
    
    // ============ Admin Functions ============
    
    /**
     * @notice Slash a validator (remove portion of stake, add to slash pool)
     */
    function slash(address validator, uint256 amount) external onlyOperator {
        ValidatorEntry storage v = validators[validator];
        require(v.stake >= amount, "Amount exceeds stake");
        
        v.stake -= amount;
        v.slashCount++;
        
        if (v.slashCount >= 3) {
            v.state = ValidatorState.Slashed;
            v.unbondingAt = block.timestamp + unbondingPeriod;
        }
        
        // Accumulate to slash pool for redistribution (mainnet parity)
        slashPool += amount;
        
        emit Slashed(validator, amount);
    }
    
    /**
     * @notice Distribute accumulated slash pool to active validators
     * @dev Mirrors mainnet Staking.sol distributeSlashPool logic
     */
    function distributeSlashPool() external onlyOperator {
        require(slashPool > 0, "No slashed funds to distribute");
        
        // Count active validators
        uint256 activeCount = 0;
        for (uint i = 0; i < validatorList.length; i++) {
            if (validators[validatorList[i]].state == ValidatorState.Active) {
                activeCount++;
            }
        }
        require(activeCount > 0, "No active validators");
        
        uint256 sharePerValidator = slashPool / activeCount;
        uint256 distributed = 0;
        
        for (uint i = 0; i < validatorList.length; i++) {
            if (validators[validatorList[i]].state == ValidatorState.Active) {
                validators[validatorList[i]].stake += sharePerValidator;
                distributed += sharePerValidator;
            }
        }
        
        // Any dust remains in the pool for next distribution
        slashPool -= distributed;
        
        emit SlashPoolDistributed(distributed, activeCount);
    }
    
    /**
     * @notice Update staking parameters
     */
    function setMinPublisherStake(uint256 newMin) external onlyOperator {
        minPublisherStake = newMin;
    }
    
    function setMinValidatorStake(uint256 newMin) external onlyOperator {
        minValidatorStake = newMin;
    }
    
    function setUnbondingPeriod(uint256 newPeriod) external onlyOperator {
        unbondingPeriod = newPeriod;
    }
    
    function setOperator(address newOperator) external onlyOperator {
        operator = newOperator;
    }
    
    // ============ View Functions ============
    
    function getActiveValidators() external view returns (address[] memory) {
        uint256 count = 0;
        for (uint i = 0; i < validatorList.length; i++) {
            if (validators[validatorList[i]].state == ValidatorState.Active) {
                count++;
            }
        }
        
        address[] memory active = new address[](count);
        uint256 idx = 0;
        for (uint i = 0; i < validatorList.length; i++) {
            if (validators[validatorList[i]].state == ValidatorState.Active) {
                active[idx++] = validatorList[i];
            }
        }
        return active;
    }
    
    function getPublisherCount() external view returns (uint256) {
        return publisherList.length;
    }
    
    function getValidatorCount() external view returns (uint256) {
        return validatorList.length;
    }
}
