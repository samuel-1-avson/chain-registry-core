// SPDX-License-Identifier: MIT
// Testnet CREG Token - Mintable for testing purposes only
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title TestCregToken
 * @notice Testnet version of CREG token with unlimited minting capability
 * @dev DO NOT USE IN PRODUCTION - For testing only!
 */
contract TestCregToken is ERC20, Ownable {
    /// @notice Token decimals (18 for compatibility)
    uint8 private constant _decimals = 18;
    
    /// @notice Maximum mint amount per transaction (prevent accidental huge mints)
    uint256 public maxMintAmount = 1000000 * 10**18; // 1M tCREG
    
    /// @notice Mint cooldown per address (prevent spam)
    mapping(address => uint256) public lastMintTime;
    uint256 public mintCooldown = 1 minutes;
    
    /// @notice Faucet contract address (can mint without cooldown)
    address public faucet;
    
    /// @notice Events
    event FaucetMint(address indexed to, uint256 amount);
    event FaucetAddressUpdated(address indexed oldFaucet, address indexed newFaucet);
    event MaxMintAmountUpdated(uint256 oldAmount, uint256 newAmount);
    event MintCooldownUpdated(uint256 oldCooldown, uint256 newCooldown);
    
    constructor(
        string memory name,
        string memory symbol
    ) ERC20(name, symbol) Ownable() {
        // Initial supply for testing: 10M tCREG
        _mint(msg.sender, 10_000_000 * 10**18);
    }
    
    function decimals() public pure override returns (uint8) {
        return _decimals;
    }
    
    /**
     * @notice Mint tokens to a specified address (owner only)
     * @param to Address to receive tokens
     * @param amount Amount to mint
     */
    function mint(address to, uint256 amount) external onlyOwner {
        require(amount <= maxMintAmount, "Amount exceeds max mint limit");
        _mint(to, amount);
    }
    
    /**
     * @notice Request tokens from faucet (anyone can call, with cooldown)
     * @param amount Amount to request
     */
    function faucetMint(uint256 amount) external {
        require(msg.sender != faucet, "Use faucet contract instead");
        require(amount <= 10000 * 10**18, "Max 10k tCREG per request");
        require(
            block.timestamp >= lastMintTime[msg.sender] + mintCooldown,
            "Please wait for cooldown"
        );
        
        lastMintTime[msg.sender] = block.timestamp;
        _mint(msg.sender, amount);
        
        emit FaucetMint(msg.sender, amount);
    }
    
    /**
     * @notice Faucet contract can mint without restrictions
     * @param to Address to receive tokens
     * @param amount Amount to mint
     */
    function faucetDrip(address to, uint256 amount) external {
        require(msg.sender == faucet, "Only faucet can drip");
        require(amount <= 10000 * 10**18, "Max 10k tCREG per drip");
        _mint(to, amount);
        emit FaucetMint(to, amount);
    }
    
    // Admin functions
    
    function setFaucet(address _faucet) external onlyOwner {
        emit FaucetAddressUpdated(faucet, _faucet);
        faucet = _faucet;
    }
    
    function setMaxMintAmount(uint256 _maxMintAmount) external onlyOwner {
        emit MaxMintAmountUpdated(maxMintAmount, _maxMintAmount);
        maxMintAmount = _maxMintAmount;
    }
    
    function setMintCooldown(uint256 _mintCooldown) external onlyOwner {
        emit MintCooldownUpdated(mintCooldown, _mintCooldown);
        mintCooldown = _mintCooldown;
    }
    
    /**
     * @notice Burn tokens (anyone can burn their own)
     * @param amount Amount to burn
     */
    function burn(uint256 amount) external {
        _burn(msg.sender, amount);
    }
}
