// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SimpleStaking {
    address public token;
    address public governance;
    mapping(address => uint256) public publisherStakes;
    mapping(address => uint256) public validatorStakes;
    mapping(address => bool) public isActiveValidator;
    uint256 public minPublisherStake = 1 ether;
    uint256 public minValidatorStake = 100 ether;
    
    event PublisherStaked(address indexed publisher, uint256 amount);
    event ValidatorStaked(address indexed validator, uint256 amount);
    
    function setToken(address _token) external {
        require(token == address(0), "Already set");
        token = _token;
        governance = msg.sender;
    }
    
    function stakeAsPublisher(uint256 amount) external {
        require(amount >= minPublisherStake, "Below minimum");
        publisherStakes[msg.sender] += amount;
        emit PublisherStaked(msg.sender, amount);
    }
    
    function applyToBeValidator(uint256 amount) external {
        require(amount >= minValidatorStake, "Below minimum");
        validatorStakes[msg.sender] += amount;
        emit ValidatorStaked(msg.sender, amount);
    }
    
    function approveValidator(address validator) external {
        require(msg.sender == governance, "Not authorized");
        isActiveValidator[validator] = true;
    }
    
    function stakedBalance(address publisher) external view returns (uint256) {
        return publisherStakes[publisher];
    }
}
