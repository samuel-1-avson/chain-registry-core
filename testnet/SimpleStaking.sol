// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IToken {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract SimpleStaking {
    IToken public token;
    address public governance;
    mapping(address => uint256) public publisherStakes;
    mapping(address => uint256) public validatorStakes;
    mapping(address => bool) public isActiveValidator;
    uint256 public minPublisherStake = 1 ether;
    uint256 public minValidatorStake = 100 ether;
    
    event PublisherStaked(address indexed publisher, uint256 amount);
    event ValidatorStaked(address indexed validator, uint256 amount);
    
    constructor(address _token) {
        token = IToken(_token);
        governance = msg.sender;
    }
    
    function stakeAsPublisher(uint256 amount) external {
        require(amount >= minPublisherStake, "Below minimum");
        require(token.transferFrom(msg.sender, address(this), amount), "Transfer failed");
        publisherStakes[msg.sender] += amount;
        emit PublisherStaked(msg.sender, amount);
    }
    
    function applyToBeValidator(uint256 amount) external {
        require(amount >= minValidatorStake, "Below minimum");
        require(token.transferFrom(msg.sender, address(this), amount), "Transfer failed");
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
