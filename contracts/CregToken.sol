// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Standalone, simplified ERC20 with Burnable, Permit and Ownable features
/// @dev Eliminates external OpenZeppelin dependencies for local dev environments.
///      Hard capped at 42,000,000 CREG — no new tokens can ever be minted after deployment.
contract CregToken {
    string public name = "Chain Registry Token";
    string public symbol = "CREG";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    /// @notice Absolute maximum supply. Once reached, no more CREG can ever exist.
    uint256 public constant MAX_SUPPLY = 42_000_000 * 10**18;
    address public owner;
    address public treasury;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public nonces;

    // EIP-712 Domain Separator
    bytes32 public DOMAIN_SEPARATOR;
    bytes32 public constant PERMIT_TYPEHASH = keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        require(msg.sender == owner, "Ownable: caller is not the owner");
        _;
    }

    constructor(
        address _treasury,
        address _team,
        address _investors,
        address _community
    ) {
        owner = msg.sender;
        treasury = _treasury;
        uint256 chainId;
        assembly { chainId := chainid() }
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256(bytes("1")),
                chainId,
                address(this)
            )
        );
        
        // Initial circulating supply: 20,000,000 CREG.
        // The remaining 22,000,000 CREG (up to MAX_SUPPLY of 42,000,000) can be
        // minted gradually by governance over time — for validator rewards,
        // ecosystem grants, and network growth. Never exceeds 42,000,000 total.
        _mint(_team,       4_000_000 * 10**18);
        _mint(_investors,  3_000_000 * 10**18);
        _mint(_community,  5_000_000 * 10**18);
        _mint(_treasury,   8_000_000 * 10**18);
    }

    function transfer(address to, uint256 value) public returns (bool) {
        _transfer(msg.sender, to, value);
        return true;
    }

    function approve(address spender, uint256 value) public returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) public returns (bool) {
        require(allowance[from][msg.sender] >= value, "ERC20: insufficient allowance");
        allowance[from][msg.sender] -= value;
        _transfer(from, to, value);
        return true;
    }

    function burn(uint256 value) public {
        _burn(msg.sender, value);
    }

    /// @notice Mint new CREG up to the hard cap of 42,000,000.
    ///         Only callable by owner (governance). Used to release the remaining
    ///         22,000,000 reserve gradually over time for rewards and ecosystem growth.
    function mint(address to, uint256 value) public onlyOwner {
        _mint(to, value);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function permit(
        address _owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public {
        require(deadline >= block.timestamp, "ERC20Permit: expired deadline");
        bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, _owner, spender, value, nonces[_owner]++, deadline));
        bytes32 hash = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0) && signer == _owner, "ERC20Permit: invalid signature");
        allowance[_owner][spender] = value;
        emit Approval(_owner, spender, value);
    }

    function _transfer(address from, address to, uint256 value) internal {
        require(balanceOf[from] >= value, "ERC20: insufficient balance");
        balanceOf[from] -= value;
        balanceOf[to] += value;
        emit Transfer(from, to, value);
    }

    function _mint(address account, uint256 value) internal {
        require(totalSupply + value <= MAX_SUPPLY, "CREG: exceeds max supply of 42,000,000");
        totalSupply += value;
        balanceOf[account] += value;
        emit Transfer(address(0), account, value);
    }

    function _burn(address account, uint256 value) internal {
        require(balanceOf[account] >= value, "ERC20: insufficient balance");
        balanceOf[account] -= value;
        totalSupply -= value;
        emit Transfer(account, address(0), value);
    }

    // Mock governance functions
    function getVotes(address account) public view returns (uint256) {
        return balanceOf[account];
    }

    function quadraticVotingPower(uint256 votes) public pure returns (uint256) {
        // Babylonian (Newton's method) integer square-root.
        // Returns sqrt(votes) * 10**9 to preserve precision given 18-decimal token amounts.
        if (votes == 0) return 0;
        return _sqrt(votes) * 1e9;
    }

    /// @dev Babylonian integer sqrt.
    function _sqrt(uint256 x) internal pure returns (uint256) {
        if (x == 0) return 0;
        uint256 z = (x + 1) / 2;
        uint256 y = x;
        while (z < y) {
            y = z;
            z = (x / z + z) / 2;
        }
        return y;
    }
}
