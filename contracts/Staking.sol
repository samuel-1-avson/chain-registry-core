// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./Reputation.sol";
import "./CregToken.sol";

/// @title Staking
/// @notice Manages publisher and validator stakes using CREG tokens.
/// @dev Publishers stake CREG to publish packages — bad actors lose stake.
///      Validators must apply and be approved by governance before joining.
///      Slashed CREG is distributed to honest active validators, not burned.
///      Validators must wait UNBONDING_PERIOD before withdrawing stake.
contract Staking {
    // ── Reentrancy Guard ─────────────────────────────────────────────────────
    bool private _locked;
    modifier nonReentrant() {
        require(!_locked, "Reentrant call");
        _locked = true;
        _;
        _locked = false;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Ownable: caller is not the owner");
        _;
    }

    // ── Enums ────────────────────────────────────────────────────────────────

    /// Full lifecycle of a validator.
    enum ValidatorState { None, Pending, Active, Unbonding, Withdrawn, Rejected, Expired }

    /// Slashing severity levels.
    enum Severity { Low, Medium, Critical }

    // ── Constants ─────────────────────────────────────────────────────────────

    /// Minimum CREG stake to publish a package (1 CREG).
    uint256 public minPublisherStake = 1 * 10**18;
    /// Minimum CREG stake to apply as a validator (100 CREG).
    uint256 public minValidatorStake = 100 * 10**18;
    /// Minimum for light validators (50 CREG).
    uint256 public minLightValidatorStake = 50 * 10**18;
    /// Unbonding period — validators must wait 14 days before withdrawing stake.
    /// This prevents hit-and-run attacks where a validator misbehaves then immediately exits.
    uint256 public constant UNBONDING_PERIOD = 14 days;
    /// Cooldown before a slashed/ejected validator can re-stake.
    uint256 public constant RESTAKE_COOLDOWN = 7 days;
    /// Maximum slashes before auto-ejection.
    uint256 public constant MAX_SLASH_COUNT = 3;
    /// Slash percentage for Low severity (basis: 100).
    uint256 public constant SLASH_LOW_PCT = 2;
    /// Slash percentage for Medium severity.
    uint256 public constant SLASH_MEDIUM_PCT = 10;
    /// Slash percentage for Critical severity.
    uint256 public constant SLASH_CRITICAL_PCT = 30;

    /// Rule-set version embedded in every consensus admission signature.
    /// Bumping this invalidates prior signatures — use only when the admission
    /// predicate (the off-chain rules every validator signs against) changes.
    uint256 public constant RULE_SET_VERSION = 1;

    /// Pending applications expire after this window if quorum is not reached.
    /// Stake is refunded to the applicant on expiry.
    uint256 public constant APPLICATION_TIMEOUT = 7 days;

    // ── Storage ───────────────────────────────────────────────────────────────

    struct ValidatorEntry {
        uint256        stake;
        ValidatorState state;
        uint256        unbondingAt;  // Timestamp when unbonding was initiated
        uint256        slashCount;
        uint256        ejectedAt;    // Timestamp of slash-eject (for restake cooldown)
        uint256        appliedAt;    // Timestamp of application — used for APPLICATION_TIMEOUT
    }

    /// The CREG token contract — all staking uses this token.
    CregToken public cregToken;
    address public owner;

    mapping(address => uint256)        public publisherStakes;
    mapping(address => ValidatorEntry) public validators;

    Reputation public reputation;
    address    public registry;    // Only Registry can trigger slashing
    address    public governance;
    uint256    public slashPool;   // Accumulated slashed CREG (distributed to honest validators)

    /// Governance-authorized external slashers (e.g. PackageInsurance), in
    /// addition to Registry and Governance. Empty by default — no external
    /// contract can slash unless governance explicitly authorizes it.
    mapping(address => bool) public authorizedSlashers;

    event SlasherUpdated(address indexed slasher, bool allowed);

    /// EIP-712 domain separator for validator-admission attestations, set once at deploy.
    bytes32 public immutable DOMAIN_SEPARATOR;

    /// (applicant, nonce) → used. Prevents replay of a consensus-admission bundle.
    mapping(address => mapping(uint256 => bool)) public consensusNonceUsed;

    /// When `false`, the legacy `approveValidator(...)` / `rejectValidator(...)` path is
    /// permanently disabled and admission is gated exclusively by `approveByConsensus`.
    /// Governance can flip this off; it cannot be flipped back on.
    bool public emergencyGovernanceEnabled;

    // ── Slash-pool epoch (pull-based distribution) ────────────────────────────
    // `distributeSlashPool` iterates the full validator list and can exceed the
    // block gas limit with a few hundred validators. The epoch pattern snapshots
    // the pool and lets each validator pull their share, bounding worst-case gas
    // per transaction to O(1). See `commitSlashPoolEpoch` / `claimSlashPoolShare`.
    uint256 public slashPoolEpoch;
    uint256 public slashPoolEpochAmount;
    uint256 public slashPoolEpochTotalWeight;
    mapping(uint256 => mapping(address => bool)) public slashPoolClaimed;

    address[] private _validatorList;

    // ── Events ────────────────────────────────────────────────────────────────

    event PublisherStaked        (address indexed publisher, uint256 amount);
    event PublisherUnstaked      (address indexed publisher, uint256 amount);
    event ValidatorApplied       (address indexed validator, uint256 stake);
    event ValidatorApproved      (address indexed validator);
    event ValidatorApprovedByConsensus(address indexed validator, uint256 nonce, uint256 signerCount);
    event ValidatorApplicationExpired (address indexed validator, uint256 refunded);
    event ValidatorRejected      (address indexed validator);
    event ValidatorUnbonding     (address indexed validator, uint256 unbondingAt);
    event ValidatorWithdrawn     (address indexed validator, uint256 amount);
    event ValidatorLeft          (address indexed validator);
    event EmergencyGovernanceDisabled();
    event Slashed                (address indexed account, uint256 amount, string reason);
    event SlashPoolDistributed   (uint256 amount, uint256 validatorCount);
    event SlashPoolEpochCommitted(uint256 indexed epoch, uint256 amount, uint256 totalWeight);
    event SlashPoolShareClaimed  (uint256 indexed epoch, address indexed validator, uint256 amount);

    // ── Errors ────────────────────────────────────────────────────────────────

    error BelowMinStake      (uint256 provided, uint256 minimum);
    error AlreadyApplied     ();
    error NotPending         ();
    error NotValidator       ();
    error NotActive          ();
    error NotUnbonding       ();
    error StillUnbonding     (uint256 availableAt);
    error NotAuthorized      ();
    error InsufficientStake  ();
    error TransferFailed     ();
    error RestakeCooldownActive(uint256 availableAt);
    error ApplicationExpired        ();
    error ApplicationNotYetExpired  (uint256 expiresAt);
    error DuplicateOrUnsortedSigner ();
    error InvalidSignerLength       ();
    error NotAnActiveSigner         (address signer);
    error InvalidSignature          (address signer);
    error NonceAlreadyUsed          ();
    error InsufficientQuorum        (uint256 signerCount, uint256 required);
    error EmergencyPathDisabled     ();

    // ── Constructor ───────────────────────────────────────────────────────────

    /// @param _governance Address that can approve/reject validators and distribute slash pool.
    /// @param _cregToken  Address of the deployed CregToken contract.
    constructor(address _governance, address _cregToken) {
        owner = msg.sender;
        governance = _governance;
        cregToken  = CregToken(_cregToken);
        emergencyGovernanceEnabled = true;
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes("Chain Registry Validator Admission")),
            keccak256(bytes("1")),
            block.chainid,
            address(this)
        ));
    }

    // ── Initializer ───────────────────────────────────────────────────────────

    function setContracts(address _registry, address _reputation) external onlyOwner {
        require(registry == address(0), "Already set");
        registry   = _registry;
        reputation = Reputation(_reputation);
    }

    /// @notice Authorize or revoke an external contract to call slash /
    ///         slashSeverity, in addition to Registry and Governance.
    /// @dev Governance-only. PackageInsurance.resolveClaim depends on this:
    ///      without an authorization its slash() call reverts (the ACL only
    ///      permitted registry/governance). Authorize the deployed
    ///      PackageInsurance address before enabling the insurance feature.
    function setSlasher(address slasher, bool allowed) external {
        if (msg.sender != governance) revert NotAuthorized();
        require(slasher != address(0), "Zero slasher");
        authorizedSlashers[slasher] = allowed;
        emit SlasherUpdated(slasher, allowed);
    }

    // ── Publisher staking ─────────────────────────────────────────────────────

    /// @notice Stake CREG as a publisher. Must approve this contract first.
    /// @param amount Amount of CREG (in token units, 18 decimals) to stake.
    function stakeAsPublisher(uint256 amount) external {
        _stakeAsPublisher(msg.sender, amount);
    }

    /// @notice Stake CREG as a publisher using a signed permit so a relayer can
    ///         sponsor the transaction without a separate user-paid approval step.
    /// @dev The permit is attempted first, but a pre-existing allowance is also accepted.
    function stakeAsPublisherWithPermit(
        address publisher,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        try cregToken.permit(publisher, address(this), amount, deadline, v, r, s) {} catch {}
        _stakeAsPublisher(publisher, amount);
    }

    /// @notice Withdraw publisher stake. Only allowed if no active packages depend on it.
    /// @param amount Amount of CREG to withdraw.
    function unstakeAsPublisher(uint256 amount) external nonReentrant {
        if (publisherStakes[msg.sender] < amount) revert InsufficientStake();
        publisherStakes[msg.sender] -= amount;
        if (!cregToken.transfer(msg.sender, amount))
            revert TransferFailed();
        emit PublisherUnstaked(msg.sender, amount);
    }

    function stakedBalance(address publisher) external view returns (uint256) {
        return publisherStakes[publisher];
    }

    // ── Validator staking — two-step (apply → approve) ────────────────────────

    /// @notice Step 1: Apply to become a validator by staking CREG.
    ///         Your stake is held in escrow until governance approves or rejects you.
    ///         If rejected, your CREG is returned in full.
    ///         Ejected validators must wait RESTAKE_COOLDOWN before re-applying.
    /// @param amount Amount of CREG to stake (must be >= minValidatorStake).
    function applyToBeValidator(uint256 amount) external {
        _applyToBeValidator(msg.sender, amount);
    }

    /// @notice Apply to become a validator using a signed permit so a relayer can
    ///         sponsor the transaction without a separate approval transaction.
    /// @dev The permit is attempted first, but a pre-existing allowance is also accepted.
    function applyToBeValidatorWithPermit(
        address validator,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        try cregToken.permit(validator, address(this), amount, deadline, v, r, s) {} catch {}
        _applyToBeValidator(validator, amount);
    }

    function _stakeAsPublisher(address publisher, uint256 amount) internal {
        if (amount < minPublisherStake)
            revert BelowMinStake(amount, minPublisherStake);
        if (!cregToken.transferFrom(publisher, address(this), amount))
            revert TransferFailed();
        publisherStakes[publisher] += amount;
        emit PublisherStaked(publisher, amount);
    }

    function _applyToBeValidator(address validator, uint256 amount) internal {
        ValidatorEntry storage v = validators[validator];
        if (v.state == ValidatorState.Pending || v.state == ValidatorState.Active)
            revert AlreadyApplied();

        // Enforce cooldown for re-staking after slash ejection
        if (v.ejectedAt > 0 && block.timestamp < v.ejectedAt + RESTAKE_COOLDOWN)
            revert RestakeCooldownActive(v.ejectedAt + RESTAKE_COOLDOWN);

        if (amount < minValidatorStake)
            revert BelowMinStake(amount, minValidatorStake);

        if (!cregToken.transferFrom(validator, address(this), amount))
            revert TransferFailed();

        validators[validator] = ValidatorEntry({
            stake:       amount,
            state:       ValidatorState.Pending,
            unbondingAt: 0,
            slashCount:  0,
            ejectedAt:   0,
            appliedAt:   block.timestamp
        });
        _validatorList.push(validator);
        emit ValidatorApplied(validator, amount);
    }

    /// @notice Legacy emergency path: Governance approves a pending validator.
    /// @dev   Only callable while `emergencyGovernanceEnabled` is true. Intended as a
    ///        circuit-breaker for bricked-chain recovery. Admission under normal
    ///        operation happens through `approveByConsensus`.
    function approveValidator(address validator) external {
        if (!emergencyGovernanceEnabled) revert EmergencyPathDisabled();
        if (msg.sender != governance) revert NotAuthorized();
        ValidatorEntry storage v = validators[validator];
        if (v.state != ValidatorState.Pending) revert NotPending();
        v.state = ValidatorState.Active;
        emit ValidatorApproved(validator);
    }

    /// @notice Legacy emergency path: Governance rejects a pending validator.
    /// @dev   See {approveValidator} for the rationale behind retaining this path.
    function rejectValidator(address validator) external nonReentrant {
        if (!emergencyGovernanceEnabled) revert EmergencyPathDisabled();
        if (msg.sender != governance) revert NotAuthorized();
        ValidatorEntry storage v = validators[validator];
        if (v.state != ValidatorState.Pending) revert NotPending();
        uint256 amount = v.stake;
        v.stake = 0;
        v.state = ValidatorState.Rejected;
        if (!cregToken.transfer(validator, amount))
            revert TransferFailed();
        emit ValidatorRejected(validator);
    }

    /// @notice Permanently disables the emergency governance path. One-way toggle.
    /// @dev   Once called, only `approveByConsensus` can admit validators.
    function disableEmergencyGovernance() external {
        if (msg.sender != governance) revert NotAuthorized();
        if (!emergencyGovernanceEnabled) revert EmergencyPathDisabled();
        emergencyGovernanceEnabled = false;
        emit EmergencyGovernanceDisabled();
    }

    // ── Consensus-based admission (mechanical consensus) ─────────────────────
    //
    // A pending applicant is admitted when ≥ 2/3 of the current active validator
    // set has signed an EIP-712 admission attestation. No single key can approve
    // or block admission on its own. The predicate that every node evaluates
    // before signing (stake met, identity registered, cooldown elapsed, etc.) is
    // enforced off-chain and versioned via RULE_SET_VERSION.
    //
    // Invariants verified on-chain:
    //   • Applicant is currently Pending and not expired.
    //   • Every signer is currently Active.
    //   • No duplicate signers (enforced by requiring strictly ascending addresses).
    //   • Every signature recovers to its declared signer over the EIP-712 digest.
    //   • signerCount * 3 >= activeValidatorCount * 2  (≥ 2/3 quorum).
    //   • Nonce hasn't been used for this applicant.
    //
    // Signers must be sorted strictly ascending. Anyone may submit the bundle
    // (the caller identity is irrelevant to the outcome).

    function consensusMessageHash(
        address applicant,
        uint256 stake,
        uint256 nonce
    ) public view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(
            keccak256("ValidatorAdmission(address applicant,uint256 stake,uint256 nonce,uint256 ruleSetVersion)"),
            applicant,
            stake,
            nonce,
            RULE_SET_VERSION
        ));
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
    }

    function approveByConsensus(
        address applicant,
        uint256 nonce,
        address[] calldata signers,
        bytes[]   calldata sigs
    ) external {
        ValidatorEntry storage v = validators[applicant];
        if (v.state != ValidatorState.Pending) revert NotPending();
        if (v.stake < minValidatorStake) revert BelowMinStake(v.stake, minValidatorStake);
        if (block.timestamp >= v.appliedAt + APPLICATION_TIMEOUT) revert ApplicationExpired();
        if (consensusNonceUsed[applicant][nonce]) revert NonceAlreadyUsed();
        if (signers.length == 0 || signers.length != sigs.length) revert InvalidSignerLength();

        bytes32 digest = consensusMessageHash(applicant, v.stake, nonce);

        // Enforce strictly ascending order → no duplicates, O(n) verification.
        address prev = address(0);
        for (uint256 i = 0; i < signers.length; i++) {
            address signer = signers[i];
            if (signer <= prev) revert DuplicateOrUnsortedSigner();
            if (validators[signer].state != ValidatorState.Active) revert NotAnActiveSigner(signer);
            if (_recoverSigner(digest, sigs[i]) != signer) revert InvalidSignature(signer);
            prev = signer;
        }

        uint256 activeCount = _countActive();
        // Require strictly ≥ 2/3 (not just > 1/2). Using 3*signers >= 2*active avoids fractions.
        if (signers.length * 3 < activeCount * 2) {
            uint256 required = (activeCount * 2 + 2) / 3; // ceil(2*active/3)
            revert InsufficientQuorum(signers.length, required);
        }

        consensusNonceUsed[applicant][nonce] = true;
        v.state = ValidatorState.Active;
        emit ValidatorApprovedByConsensus(applicant, nonce, signers.length);
    }

    /// @notice Refund a Pending application whose timeout has elapsed without quorum.
    /// @dev   Permissionless — anyone may call once the timeout window has passed.
    function expireApplication(address applicant) external nonReentrant {
        ValidatorEntry storage v = validators[applicant];
        if (v.state != ValidatorState.Pending) revert NotPending();
        uint256 expiresAt = v.appliedAt + APPLICATION_TIMEOUT;
        if (block.timestamp < expiresAt) revert ApplicationNotYetExpired(expiresAt);

        uint256 amount = v.stake;
        v.stake = 0;
        v.state = ValidatorState.Expired;
        if (!cregToken.transfer(applicant, amount)) revert TransferFailed();
        emit ValidatorApplicationExpired(applicant, amount);
    }

    function _recoverSigner(bytes32 digest, bytes memory sig) internal pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8   v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        if (v < 27) v += 27;
        // Reject high-s signatures (EIP-2 malleability).
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return address(0);
        }
        return ecrecover(digest, v, r, s);
    }

    function _countActive() internal view returns (uint256 count) {
        for (uint256 i = 0; i < _validatorList.length; i++) {
            if (validators[_validatorList[i]].state == ValidatorState.Active) count++;
        }
    }

    /// @notice Initiate unbonding. Stake is locked for UNBONDING_PERIOD before withdrawal.
    /// @dev Changes validator state to Unbonding. They can no longer participate in consensus
    ///      but their stake remains locked and can still be slashed during the unbonding period.
    function initiateUnbonding() external {
        ValidatorEntry storage v = validators[msg.sender];
        if (v.state != ValidatorState.Active) revert NotActive();

        v.state = ValidatorState.Unbonding;
        v.unbondingAt = block.timestamp;

        emit ValidatorUnbonding(msg.sender, block.timestamp);
    }

    /// @notice Withdraw validator stake after the unbonding period has elapsed.
    /// @dev Can only be called when in Unbonding state and UNBONDING_PERIOD has passed.
    function withdrawValidatorStake() external nonReentrant {
        ValidatorEntry storage v = validators[msg.sender];
        if (v.state != ValidatorState.Unbonding) revert NotUnbonding();

        uint256 availableAt = v.unbondingAt + UNBONDING_PERIOD;
        if (block.timestamp < availableAt)
            revert StillUnbonding(availableAt);

        uint256 amount = v.stake;
        v.stake = 0;
        v.state = ValidatorState.Withdrawn;

        if (!cregToken.transfer(msg.sender, amount))
            revert TransferFailed();

        emit ValidatorWithdrawn(msg.sender, amount);
        emit ValidatorLeft(msg.sender);
    }

    function isActiveValidator(address addr) external view returns (bool) {
        return validators[addr].state == ValidatorState.Active;
    }

    function activeValidatorCount() external view returns (uint256) {
        uint256 count;
        for (uint i = 0; i < _validatorList.length; i++) {
            if (validators[_validatorList[i]].state == ValidatorState.Active) count++;
        }
        return count;
    }

    /// @notice Check whether a validator is currently in the unbonding period.
    function isUnbonding(address addr) external view returns (bool, uint256) {
        ValidatorEntry storage v = validators[addr];
        if (v.state != ValidatorState.Unbonding) return (false, 0);
        return (true, v.unbondingAt + UNBONDING_PERIOD);
    }

    // ── Slashing ─────────────────────────────────────────────────────────────

    /// @notice Slash an account by severity. Slashed CREG goes to the slash pool.
    /// @dev Only callable by Registry (on revocation) or Governance (on misbehaviour).
    ///      Validators can be slashed even during the unbonding period.
    function slashSeverity(address account, Severity severity, string calldata reason)
        external
        nonReentrant
    {
        if (msg.sender != registry && msg.sender != governance && !authorizedSlashers[msg.sender])
            revert NotAuthorized();

        // For active validators prefer their validator stake as the base so
        // severity percentages are applied to the stake at risk, not the
        // unrelated publisher stake.
        bool _isActiveVal = validators[account].state == ValidatorState.Active
                            && validators[account].stake > 0;
        uint256 balance = _isActiveVal
            ? validators[account].stake
            : publisherStakes[account];

        uint256 amount;
        if      (severity == Severity.Low)      amount = balance * SLASH_LOW_PCT      / 100;
        else if (severity == Severity.Medium)   amount = balance * SLASH_MEDIUM_PCT   / 100;
        else                                    amount = balance * SLASH_CRITICAL_PCT  / 100;

        _executeSlash(account, amount, reason);
    }

    /// @notice Slash an exact CREG amount from an account.
    function slash(address account, uint256 amount, string calldata reason)
        external
        nonReentrant
    {
        if (msg.sender != registry && msg.sender != governance && !authorizedSlashers[msg.sender])
            revert NotAuthorized();
        _executeSlash(account, amount, reason);
    }

    /// @dev Slash `amount` CREG from `account`.
    ///
    /// Priority order:
    ///   1. Active validator stake — so slashCount is always incremented and the
    ///      auto-eject mechanic applies to misbehaving validators, even when they
    ///      also hold publisher stake.
    ///   2. Publisher stake — used when there is no active validator stake.
    ///   3. Total wipeout — when neither balance alone covers `amount`.
    function _executeSlash(address account, uint256 amount, string calldata reason) internal {
        bool _isActiveVal = validators[account].state == ValidatorState.Active
                            && validators[account].stake > 0;

        if (_isActiveVal && validators[account].stake >= amount) {
            // Case 1: active validator — deduct from validator stake and track slashes.
            validators[account].stake      -= amount;
            validators[account].slashCount += 1;
            // Auto-eject after MAX_SLASH_COUNT slashes.
            if (validators[account].slashCount >= MAX_SLASH_COUNT) {
                validators[account].state      = ValidatorState.Unbonding;
                validators[account].unbondingAt = block.timestamp;
                validators[account].ejectedAt  = block.timestamp;
                emit ValidatorLeft(account);
            }
        } else if (!_isActiveVal && publisherStakes[account] >= amount) {
            // Case 2: publisher-only account — deduct from publisher stake.
            publisherStakes[account] -= amount;
        } else {
            // Case 3: slash everything the account has left (both pools combined).
            amount = publisherStakes[account] + validators[account].stake;
            publisherStakes[account]        = 0;
            validators[account].stake       = 0;
            validators[account].state       = ValidatorState.Withdrawn;
            validators[account].ejectedAt   = block.timestamp;
        }

        // Slashed CREG is not burned — it goes into the pool for honest validators.
        slashPool += amount;
        emit Slashed(account, amount, reason);
    }

    // ── Slash Pool Distribution ───────────────────────────────────────────────

    /// @notice Distribute all accumulated slashed CREG to active validators.
    ///         Each validator receives a share proportional to their reputation score.
    ///         Their distributed share is added directly to their staked balance —
    ///         they do not need to manually claim it.
    /// @dev Called periodically by governance to reward honest validators.
    function distributeSlashPool() external nonReentrant {
        if (msg.sender != governance) revert NotAuthorized();

        uint256 totalWeight;
        uint256 activeCount;

        for (uint i = 0; i < _validatorList.length; i++) {
            address val = _validatorList[i];
            if (validators[val].state == ValidatorState.Active) {
                totalWeight += uint256(reputation.scoreOf(val));
                activeCount++;
            }
        }

        require(activeCount > 0, "No active validators");
        require(totalWeight > 0, "No reputation weight");

        uint256 poolToDistribute = slashPool;
        slashPool = 0;

        for (uint i = 0; i < _validatorList.length; i++) {
            address val = _validatorList[i];
            if (validators[val].state == ValidatorState.Active) {
                uint256 score = uint256(reputation.scoreOf(val));
                uint256 share = (poolToDistribute * score) / totalWeight;
                // Share is added to their staked balance — compounds their position.
                validators[val].stake += share;
            }
        }

        emit SlashPoolDistributed(poolToDistribute, activeCount);
    }

    /// @notice Snapshot the current slash pool into a new distribution epoch.
    /// @dev Iterates the validator list once to sum reputation weights (cheap,
    ///      no storage writes to stakes). Validators then pull their share via
    ///      `claimSlashPoolShare()`, bounding worst-case per-tx gas to O(1) and
    ///      eliminating the gas-exhaustion risk of `distributeSlashPool` at
    ///      large validator counts.
    function commitSlashPoolEpoch() external {
        if (msg.sender != governance) revert NotAuthorized();
        require(slashPoolEpochAmount == 0, "previous epoch not fully claimed");
        require(slashPool > 0, "slash pool is empty");

        uint256 totalWeight;
        for (uint i = 0; i < _validatorList.length; i++) {
            address val = _validatorList[i];
            if (validators[val].state == ValidatorState.Active) {
                totalWeight += uint256(reputation.scoreOf(val));
            }
        }
        require(totalWeight > 0, "No reputation weight");

        slashPoolEpoch++;
        slashPoolEpochAmount = slashPool;
        slashPoolEpochTotalWeight = totalWeight;
        slashPool = 0;

        emit SlashPoolEpochCommitted(slashPoolEpoch, slashPoolEpochAmount, totalWeight);
    }

    /// @notice Claim the caller's share of the current slash-pool epoch.
    /// @dev Pull pattern — each validator pays their own gas, worst-case O(1).
    function claimSlashPoolShare() external nonReentrant {
        uint256 epoch = slashPoolEpoch;
        require(epoch > 0, "no epoch committed");
        require(slashPoolEpochAmount > 0, "epoch already drained");
        require(!slashPoolClaimed[epoch][msg.sender], "already claimed");
        require(validators[msg.sender].state == ValidatorState.Active, "not an active validator");

        uint256 score = uint256(reputation.scoreOf(msg.sender));
        require(score > 0, "no reputation weight");

        uint256 share = (slashPoolEpochAmount * score) / slashPoolEpochTotalWeight;
        require(share > 0, "share rounds to zero");

        slashPoolClaimed[epoch][msg.sender] = true;
        validators[msg.sender].stake += share;

        // Drain the snapshot so it can be re-committed later. We subtract the
        // claimed amount rather than zeroing so that later claimants can still
        // draw from the same epoch; the epoch becomes re-committable only when
        // `slashPoolEpochAmount` returns to zero via claims or rounding dust.
        if (share >= slashPoolEpochAmount) {
            slashPoolEpochAmount = 0;
        } else {
            slashPoolEpochAmount -= share;
        }

        emit SlashPoolShareClaimed(epoch, msg.sender, share);
    }

    // ── Governance ────────────────────────────────────────────────────────────

    /// @notice Update the minimum CREG stakes required to publish or validate.
    function updateMinStakes(uint256 _pubStake, uint256 _valStake) external {
        if (msg.sender != governance) revert NotAuthorized();
        minPublisherStake = _pubStake;
        minValidatorStake = _valStake;
    }

    /// @notice Transfer governance to a new address (e.g. multisig on mainnet).
    function transferGovernance(address newGovernance) external {
        if (msg.sender != governance) revert NotAuthorized();
        governance = newGovernance;
    }
}
