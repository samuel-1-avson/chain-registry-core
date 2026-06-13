// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Simple test token without external dependencies
contract SimpleToken {
    string public name = "Test CREG Token";
    string public symbol = "tCREG";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    
    address public owner;
    address public faucet;
    
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event FaucetMint(address indexed to, uint256 amount);
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    constructor() {
        owner = msg.sender;
        // Mint 10M tokens to deployer
        _mint(msg.sender, 10_000_000 * 10**18);
    }
    
    function _mint(address to, uint256 amount) internal {
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }
    
    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }
    
    function setFaucet(address _faucet) external onlyOwner {
        faucet = _faucet;
    }
    
    function faucetDrip(address to, uint256 amount) external {
        require(msg.sender == faucet, "Only faucet");
        _mint(to, amount);
        emit FaucetMint(to, amount);
    }
    
    function transfer(address to, uint256 amount) public returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }
    
    function approve(address spender, uint256 amount) public returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }
    
    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        require(balanceOf[from] >= amount, "Insufficient balance");
        require(allowance[from][msg.sender] >= amount, "Insufficient allowance");
        balanceOf[from] -= amount;
        allowance[from][msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
}

// Simple staking contract
contract SimpleStaking {
    SimpleToken public token;
    address public governance;
    
    struct Validator {
        uint256 stake;
        bool isActive;
    }
    
    mapping(address => uint256) public publisherStakes;
    mapping(address => Validator) public validators;
    
    uint256 public minPublisherStake = 1 * 10**18; // 1 token
    uint256 public minValidatorStake = 100 * 10**18; // 100 tokens
    
    event PublisherStaked(address indexed publisher, uint256 amount);
    event ValidatorStaked(address indexed validator, uint256 amount);
    
    constructor(address _token) {
        token = SimpleToken(_token);
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
        validators[msg.sender] = Validator(amount, false);
        emit ValidatorStaked(msg.sender, amount);
    }
    
    function approveValidator(address validator) external {
        require(msg.sender == governance, "Not authorized");
        validators[validator].isActive = true;
    }
    
    function isActiveValidator(address addr) external view returns (bool) {
        return validators[addr].isActive;
    }
    
    function stakedBalance(address publisher) external view returns (uint256) {
        return publisherStakes[publisher];
    }
}
