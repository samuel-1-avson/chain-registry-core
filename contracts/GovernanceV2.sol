// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./CregToken.sol";
import "./Registry.sol";

library ECDSA {
    function recover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        return ecrecover(hash, v, r, s);
    }
}

/// @title GovernanceV2
/// @notice FUTURE UPGRADE — Token-based governance with quadratic voting.
/// @dev ⚠️  NOT YET ACTIVE. The current canonical governance is Governance.sol (M-of-N multisig).
///      This contract will be activated via a governance proposal to migrate authority.
///
///      Features (when activated):
///      - Quadratic voting to prevent plutocracy
///      - Delegation support
///      - Automated parameter adjustments
///      - Gasless voting via EIP-712 signatures
contract GovernanceV2 {
    
    // ── Enums ─────────────────────────────────────────────────────────────────

    enum ProposalState {
        Pending,    // Waiting for voting to start
        Active,     // Voting in progress
        Canceled,   // Canceled by proposer/admin
        Defeated,   // Failed (not enough votes or against > for)
        Succeeded,  // Passed (for > against, quorum met)
        Queued,     // Waiting for execution delay
        Expired,    // Execution grace period passed
        Executed    // Successfully executed
    }

    // ── Structs ───────────────────────────────────────────────────────────────
    
    struct Proposal {
        uint256 id;
        address proposer;
        string description;
        bytes callData;
        address targetContract;
        uint256 forVotes;
        uint256 againstVotes;
        uint256 abstainVotes;
        uint256 startBlock;
        uint256 endBlock;
        uint256 votingEndTimestamp;    // Set when voting closes for time-based checks
        bool executed;
        bool canceled;
        mapping(address => Receipt) receipts;
    }
    
    struct Receipt {
        bool hasVoted;
        uint8 support; // 0=against, 1=for, 2=abstain
        uint256 votes;
    }
    
    struct ProposalParams {
        uint256 votingDelay;        // Blocks before voting starts
        uint256 votingPeriod;       // Blocks voting is open
        uint256 proposalThreshold;  // Min votes to create proposal
        uint256 quorumVotes;        // Min votes for proposal to pass
    }
    
    struct AutomatedParameter {
        string name;
        uint256 currentValue;
        uint256 targetValue;
        uint256 changeRate;         // Max change per day (basis points)
        uint256 lastUpdate;
        bool active;
    }
    
    // ── Storage ───────────────────────────────────────────────────────────────
    
    /// Proposal ID → Proposal
    mapping(uint256 => Proposal) public proposals;
    
    /// Proposal ID → Automated parameter (if applicable)
    mapping(uint256 => AutomatedParameter) public automatedParams;
    
    /// All proposal IDs
    uint256[] public proposalIds;
    
    /// Proposal counter
    uint256 public proposalCount;
    
    /// Governance parameters
    ProposalParams public params;
    
    /// Token contract
    CregToken public cregToken;
    
    /// Registry contract
    ChainRegistry public registry;
    
    /// Pending admin for transfer
    address public pendingAdmin;
    
    /// Current admin
    address public admin;
    
    /// Whitelisted proposers (can propose without threshold)
    mapping(address => bool) public proposerWhitelist;
    
    /// Quadratic voting enabled
    bool public quadraticVotingEnabled;
    
    /// Execution delay after successful vote
    uint256 public constant EXECUTION_DELAY = 2 days;
    
    /// Grace period for execution
    uint256 public constant EXECUTION_GRACE_PERIOD = 14 days;
    
    /// Max automated parameters
    uint256 public constant MAX_AUTO_PARAMS = 20;
    
    /// Active automated parameters
    uint256 public autoParamCount;
    
    // ── Events ────────────────────────────────────────────────────────────────
    
    event ProposalCreated(
        uint256 indexed id,
        address indexed proposer,
        address indexed target,
        string description
    );
    event VoteCast(
        address indexed voter,
        uint256 indexed proposalId,
        uint8 support,
        uint256 votes
    );
    event ProposalExecuted(uint256 indexed id);
    event ProposalCanceled(uint256 indexed id);
    event AutomatedParameterUpdated(string name, uint256 newValue);
    event ParameterAdjustment(uint256 indexed proposalId, uint256 oldValue, uint256 newValue);
    
    // ── Errors ────────────────────────────────────────────────────────────────
    
    error InvalidProposal();
    error VotingClosed();
    error VotingNotStarted();
    error AlreadyVoted();
    error QuorumNotReached();
    error ProposalNotSucceeded();
    error ProposalExpired();
    error ExecutionFailed();
    error Unauthorized();
    error InvalidParameter();
    error TooManyAutoParams();
    
    // ── Modifiers ─────────────────────────────────────────────────────────────
    
    modifier onlyAdmin() {
        if (msg.sender != admin) revert Unauthorized();
        _;
    }
    
    modifier onlyProposer() {
        if (!canPropose(msg.sender)) revert Unauthorized();
        _;
    }
    
    // ── Constructor ───────────────────────────────────────────────────────────
    
    constructor(
        address _cregToken,
        address _registry,
        address _admin,
        uint256 _votingDelay,
        uint256 _votingPeriod,
        uint256 _proposalThreshold,
        uint256 _quorumVotes
    ) {
        cregToken = CregToken(_cregToken);
        registry = ChainRegistry(_registry);
        admin = _admin;
        
        params = ProposalParams({
            votingDelay: _votingDelay,
            votingPeriod: _votingPeriod,
            proposalThreshold: _proposalThreshold,
            quorumVotes: _quorumVotes
        });
        
        quadraticVotingEnabled = true;
    }
    
    // ── Proposal Creation ─────────────────────────────────────────────────────
    
    /// @notice Create a new governance proposal
    /// @param target Contract to call if proposal passes
    /// @param callData Encoded function call
    /// @param description Proposal description
    function propose(
        address target,
        bytes memory callData,
        string memory description
    ) public onlyProposer returns (uint256) {
        
        uint256 startBlock = block.number + params.votingDelay;
        uint256 endBlock = startBlock + params.votingPeriod;
        
        proposalCount++;
        uint256 proposalId = proposalCount;
        
        Proposal storage p = proposals[proposalId];
        p.id = proposalId;
        p.proposer = msg.sender;
        p.description = description;
        p.callData = callData;
        p.targetContract = target;
        p.startBlock = startBlock;
        p.endBlock = endBlock;
        
        proposalIds.push(proposalId);
        
        emit ProposalCreated(proposalId, msg.sender, target, description);
        
        return proposalId;
    }
    
    /// @notice Create a proposal with automated parameter adjustment
    function proposeAutoAdjustment(
        string calldata paramName,
        uint256 targetValue,
        uint256 changeRate, // Basis points per day
        string calldata description
    ) external onlyProposer returns (uint256) {
        
        if (autoParamCount >= MAX_AUTO_PARAMS) revert TooManyAutoParams();
        
        uint256 proposalId = propose(
            address(this),
            abi.encodeWithSelector(
                this.executeAutoAdjustment.selector,
                paramName,
                targetValue,
                changeRate
            ),
            description
        );
        
        automatedParams[proposalId] = AutomatedParameter({
            name: paramName,
            currentValue: 0, // Will be set on execution
            targetValue: targetValue,
            changeRate: changeRate,
            lastUpdate: block.timestamp,
            active: true
        });
        
        autoParamCount++;
        
        return proposalId;
    }
    
    // ── Voting ────────────────────────────────────────────────────────────────
    
    /// @notice Cast a vote on a proposal
    /// @param proposalId Proposal ID
    /// @param support 0=against, 1=for, 2=abstain
    function castVote(uint256 proposalId, uint8 support) external {
        return _castVote(msg.sender, proposalId, support);
    }
    
    /// @notice Cast a vote with reason
    function castVoteWithReason(
        uint256 proposalId,
        uint8 support,
        string calldata reason
    ) external {
        _castVote(msg.sender, proposalId, support);
        // Reason is just for events/logs
    }
    
    /// @notice Cast vote by signature (gasless)
    function castVoteBySig(
        uint256 proposalId,
        uint8 support,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 domainSeparator = keccak256(abi.encode(
            keccak256("GovernanceV2 Vote"),
            block.chainid,
            address(this)
        ));
        
        bytes32 structHash = keccak256(abi.encode(
            keccak256("Vote(uint256 proposalId,uint8 support)"),
            proposalId,
            support
        ));
        
        bytes32 hash = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        address signer = ECDSA.recover(hash, v, r, s);
        
        _castVote(signer, proposalId, support);
    }
    
    function _castVote(address voter, uint256 proposalId, uint8 support) internal {
        Proposal storage p = proposals[proposalId];
        
        if (block.number < p.startBlock) revert VotingNotStarted();
        if (block.number > p.endBlock) revert VotingClosed();
        if (support > 2) revert InvalidProposal();
        if (p.receipts[voter].hasVoted) revert AlreadyVoted();
        
        // Get voting power
        uint256 votes = cregToken.getVotes(voter);
        
        // Apply quadratic voting if enabled
        if (quadraticVotingEnabled) {
            votes = cregToken.quadraticVotingPower(votes);
        }
        
        p.receipts[voter] = Receipt({
            hasVoted: true,
            support: support,
            votes: votes
        });
        
        if (support == 0) {
            p.againstVotes += votes;
        } else if (support == 1) {
            p.forVotes += votes;
        } else {
            p.abstainVotes += votes;
        }
        
        emit VoteCast(voter, proposalId, support, votes);
    }
    
    // ── Proposal Execution ────────────────────────────────────────────────────
    
    /// @notice Execute a successful proposal
    function execute(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        
        if (p.executed) revert InvalidProposal();
        if (p.canceled) revert InvalidProposal();
        if (block.number <= p.endBlock) revert VotingNotStarted(); // Still voting

        // Snapshot the voting-end timestamp on first post-vote interaction
        if (p.votingEndTimestamp == 0) {
            p.votingEndTimestamp = block.timestamp;
        }

        if (p.forVotes + p.againstVotes + p.abstainVotes < params.quorumVotes) {
            revert QuorumNotReached();
        }
        if (p.forVotes <= p.againstVotes) revert ProposalNotSucceeded();

        // Time-based checks use votingEndTimestamp (not block.number)
        if (block.timestamp < p.votingEndTimestamp + EXECUTION_DELAY) revert VotingNotStarted();
        if (block.timestamp > p.votingEndTimestamp + EXECUTION_DELAY + EXECUTION_GRACE_PERIOD) {
            revert ProposalExpired();
        }
        
        p.executed = true;
        
        // Execute the proposal
        (bool success, ) = p.targetContract.call(p.callData);
        if (!success) revert ExecutionFailed();
        
        emit ProposalExecuted(proposalId);
    }
    
    /// @notice Execute automated parameter adjustment
    function executeAutoAdjustment(
        string calldata paramName,
        uint256 targetValue,
        uint256 changeRate
    ) external {
        // This is called by execute() - verify caller is this contract
        require(msg.sender == address(this), "Only governance");
        
        // In production, this would adjust various protocol parameters
        // For now, emit an event
        emit AutomatedParameterUpdated(paramName, targetValue);
    }
    
    /// @notice Apply gradual parameter changes (can be called by anyone)
    function applyGradualChange(uint256 proposalId) external {
        AutomatedParameter storage ap = automatedParams[proposalId];
        
        if (!ap.active) revert InvalidParameter();
        if (ap.currentValue == ap.targetValue) revert InvalidParameter();
        
        uint256 timeElapsed = block.timestamp - ap.lastUpdate;
        if (timeElapsed < 1 days) revert InvalidParameter(); // Max once per day
        
        // Calculate max change based on rate
        uint256 maxChange = (ap.currentValue * ap.changeRate * timeElapsed) / (10000 * 1 days);
        
        if (ap.targetValue > ap.currentValue) {
            ap.currentValue = min(ap.currentValue + maxChange, ap.targetValue);
        } else {
            ap.currentValue = max(ap.currentValue - maxChange, ap.targetValue);
        }
        
        ap.lastUpdate = block.timestamp;
        
        emit ParameterAdjustment(proposalId, ap.currentValue, ap.targetValue);
        
        // Deactivate if target reached
        if (ap.currentValue == ap.targetValue) {
            ap.active = false;
            autoParamCount--;
        }
    }
    
    // ── Proposal Management ───────────────────────────────────────────────────
    
    /// @notice Cancel a proposal (only proposer or admin)
    function cancel(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        
        if (msg.sender != p.proposer && msg.sender != admin) revert Unauthorized();
        if (p.executed) revert InvalidProposal();
        
        p.canceled = true;
        
        emit ProposalCanceled(proposalId);
    }
    
    // ── Admin Functions ───────────────────────────────────────────────────────
    
    /// @notice Update governance parameters
    function setParams(ProposalParams calldata newParams) external onlyAdmin {
        params = newParams;
    }
    
    /// @notice Toggle quadratic voting
    function setQuadraticVoting(bool enabled) external onlyAdmin {
        quadraticVotingEnabled = enabled;
    }
    
    /// @notice Whitelist/unwhitelist a proposer
    function setProposerWhitelist(address proposer, bool whitelisted) external onlyAdmin {
        proposerWhitelist[proposer] = whitelisted;
    }
    
    /// @notice Transfer admin rights
    function transferAdmin(address newAdmin) external onlyAdmin {
        pendingAdmin = newAdmin;
    }
    
    /// @notice Accept admin transfer
    function acceptAdmin() external {
        require(msg.sender == pendingAdmin, "Not pending admin");
        admin = pendingAdmin;
        pendingAdmin = address(0);
    }
    
    // ── View Functions ────────────────────────────────────────────────────────
    
    /// @notice Check if an account can create proposals
    function canPropose(address account) public view returns (bool) {
        if (proposerWhitelist[account]) return true;
        
        uint256 votes = cregToken.getVotes(account);
        if (quadraticVotingEnabled) {
            votes = cregToken.quadraticVotingPower(votes);
        }
        
        return votes >= params.proposalThreshold;
    }
    
    /// @notice Get proposal state
    function state(uint256 proposalId) external view returns (ProposalState) {
        Proposal storage p = proposals[proposalId];
        
        if (p.canceled) return ProposalState.Canceled;
        if (p.executed) return ProposalState.Executed;
        if (block.number <= p.startBlock) return ProposalState.Pending;
        if (block.number <= p.endBlock) return ProposalState.Active;
        if (p.forVotes + p.againstVotes + p.abstainVotes < params.quorumVotes) {
            return ProposalState.Defeated;
        }
        if (p.forVotes <= p.againstVotes) return ProposalState.Defeated;

        // For view-only state, estimate the timelock using votingEndTimestamp
        // if available, otherwise approximate with the current timestamp.
        uint256 voteEndTs = p.votingEndTimestamp > 0 ? p.votingEndTimestamp : block.timestamp;
        if (block.timestamp <= voteEndTs + EXECUTION_DELAY) return ProposalState.Succeeded;
        if (block.timestamp <= voteEndTs + EXECUTION_DELAY + EXECUTION_GRACE_PERIOD) {
            return ProposalState.Queued;
        }
        return ProposalState.Expired;
    }
    
    /// @notice Get proposal receipt for voter
    function getReceipt(uint256 proposalId, address voter)
        external view
        returns (Receipt memory)
    {
        return proposals[proposalId].receipts[voter];
    }
    
    /// @notice Get all active proposals
    function getActiveProposals() external view returns (uint256[] memory) {
        uint256[] memory active = new uint256[](proposalIds.length);
        uint256 count = 0;
        
        for (uint i = 0; i < proposalIds.length; i++) {
            if (this.state(proposalIds[i]) == ProposalState.Active) {
                active[count] = proposalIds[i];
                count++;
            }
        }
        
        // Trim array
        uint256[] memory result = new uint256[](count);
        for (uint i = 0; i < count; i++) {
            result[i] = active[i];
        }
        
        return result;
    }
    
    // ── Helpers ───────────────────────────────────────────────────────────────
    
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
    
    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a : b;
    }
}
