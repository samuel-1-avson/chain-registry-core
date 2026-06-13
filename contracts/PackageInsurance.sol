// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./Registry.sol";
import "./Staking.sol";
import "./CregToken.sol";

/// @title PackageInsurance
/// @notice Optional insurance for verified packages with risk-based premiums
/// @dev Developers can purchase insurance for packages. If an insured package
///      is compromised, the insurance pool compensates victims from slashed funds.
contract PackageInsurance {
    
    // ── Structs ───────────────────────────────────────────────────────────────
    
    struct Policy {
        uint256 id;
        address insured;
        string packageCanonical;
        bytes32 packageKey;
        uint256 coverageAmount;
        uint256 premium;
        uint256 expiration;
        bool active;
        uint256 createdAt;
    }
    
    struct Claim {
        uint256 id;
        uint256 policyId;
        address claimant;
        uint256 amount;
        string reason;
        bytes evidence;
        ClaimStatus status;
        uint256 submittedAt;
        uint256 resolvedAt;
        address resolver;
    }
    
    struct RiskProfile {
        uint256 baseRiskScore;      // 0-10000 (basis points)
        uint256 ageFactor;          // Risk reduction per month
        uint256 dependencyFactor;   // Risk increase per dependent
        uint256 vulnerabilityFactor; // Risk increase for known issues
        uint256 auditFactor;        // Risk reduction for audits
    }
    
    enum ClaimStatus {
        Pending,
        UnderReview,
        Approved,
        Rejected,
        Paid
    }
    
    // ── Storage ───────────────────────────────────────────────────────────────
    
    /// Policy ID → Policy
    mapping(uint256 => Policy) private _policies;
    
    /// Claim ID → Claim
    mapping(uint256 => Claim) private _claims;
    
    /// Package key → policy IDs
    mapping(bytes32 => uint256[]) public packagePolicies;
    
    /// User → policy IDs
    mapping(address => uint256[]) public userPolicies;
    
    /// Package key → risk profile
    mapping(bytes32 => RiskProfile) public riskProfiles;
    
    /// Insurance pool balance
    uint256 public poolBalance;
    
    /// Total coverage issued
    uint256 public totalCoverage;
    
    /// Policy counter
    uint256 public policyCount;
    
    /// Claim counter
    uint256 public claimCount;
    
    /// Registry reference
    ChainRegistry public registry;
    
    /// Staking reference (for slashing)
    Staking public staking;
    
    /// CREG token for premium payments
    CregToken public cregToken;
    
    /// Governance/admin
    address public governance;
    
    /// Base premium rate (1% = 100 bps)
    uint256 public basePremiumRate = 100;
    
    /// Maximum coverage per policy
    uint256 public maxCoverage = 100 ether;
    
    /// Minimum coverage per policy
    uint256 public minCoverage = 0.1 ether;

    /// Maximum payout per single claim (prevents pool drain from one claim)
    uint256 public maxPayoutPerClaim = 50 ether;

    /// Maximum pool utilization ratio (bps).  New policies are blocked once
    /// totalCoverage / poolBalance exceeds this ratio.  10000 = 100%.
    uint256 public maxPoolUtilizationBps = 8000;
    
    /// Policy duration (1 year)
    uint256 public constant POLICY_DURATION = 365 days;
    
    /// Claim review period (7 days)
    uint256 public constant REVIEW_PERIOD = 7 days;
    
    /// Approved resolvers for claims
    mapping(address => bool) public claimResolvers;
    
    // ── Events ────────────────────────────────────────────────────────────────
    
    event PolicyCreated(
        uint256 indexed policyId,
        address indexed insured,
        string packageCanonical,
        uint256 coverage,
        uint256 premium
    );
    event PolicyCanceled(uint256 indexed policyId, uint256 refund);
    event ClaimSubmitted(
        uint256 indexed claimId,
        uint256 indexed policyId,
        address claimant,
        uint256 amount
    );
    event ClaimResolved(
        uint256 indexed claimId,
        ClaimStatus status,
        uint256 payout
    );
    event PremiumPaid(uint256 indexed policyId, uint256 amount);
    event RiskProfileUpdated(bytes32 indexed packageKey, uint256 riskScore);
    event PoolReplenished(uint256 amount);
    event ResolverAdded(address resolver);
    event ResolverRemoved(address resolver);
    
    // ── Errors ────────────────────────────────────────────────────────────────
    
    error InvalidCoverage();
    error InvalidPackage();
    error PolicyNotFound();
    error PolicyExpired();
    error PolicyNotActive();
    error ClaimNotFound();
    error ClaimPeriodExpired();
    error InsufficientPoolBalance();
    error NotPolicyOwner();
    error NotAuthorized();
    error AlreadyClaimed();
    error InvalidEvidence();
    error UnauthorizedResolver();
    error PayoutExceedsMaxClaim();
    error PoolUtilizationExceeded();
    
    // ── Modifiers ─────────────────────────────────────────────────────────────
    
    modifier onlyGovernance() {
        if (msg.sender != governance) revert NotAuthorized();
        _;
    }
    
    modifier onlyResolver() {
        if (!claimResolvers[msg.sender]) revert UnauthorizedResolver();
        _;
    }
    
    // ── Constructor ───────────────────────────────────────────────────────────
    
    constructor(
        address _registry,
        address _staking,
        address _cregToken,
        address _governance
    ) {
        registry = ChainRegistry(_registry);
        staking = Staking(_staking);
        cregToken = CregToken(_cregToken);
        governance = _governance;
    }
    
    // ── Policy Management ─────────────────────────────────────────────────────
    
    /// @notice Purchase insurance for a package
    /// @param packageCanonical Package identifier (e.g., "npm:express@4.18.2")
    /// @param coverageAmount Amount of coverage requested
    function purchaseInsurance(
        string calldata packageCanonical,
        uint256 coverageAmount
    ) external returns (uint256 policyId) {
        
        if (coverageAmount < minCoverage || coverageAmount > maxCoverage) {
            revert InvalidCoverage();
        }
        
        // Verify package is verified in registry
        bytes32 packageKey = keccak256(bytes(packageCanonical));
        if (registry.getStatus(packageCanonical) != ChainRegistry.PackageStatus.Verified) {
            revert InvalidPackage();
        }
        
        // Calculate premium
        uint256 premium = calculatePremium(packageCanonical, coverageAmount);
        
        // Transfer premium from user
        require(
            cregToken.transferFrom(msg.sender, address(this), premium),
            "Premium transfer failed"
        );
        
        poolBalance += premium;
        totalCoverage += coverageAmount;

        // Enforce maximum pool utilization — prevent over-issuance
        if (poolBalance > 0 && (totalCoverage * 10000) / poolBalance > maxPoolUtilizationBps) {
            revert PoolUtilizationExceeded();
        }
        
        // Create policy
        policyCount++;
        policyId = policyCount;
        
        _policies[policyId] = Policy({
            id: policyId,
            insured: msg.sender,
            packageCanonical: packageCanonical,
            packageKey: packageKey,
            coverageAmount: coverageAmount,
            premium: premium,
            expiration: block.timestamp + POLICY_DURATION,
            active: true,
            createdAt: block.timestamp
        });
        
        packagePolicies[packageKey].push(policyId);
        userPolicies[msg.sender].push(policyId);
        
        emit PolicyCreated(
            policyId,
            msg.sender,
            packageCanonical,
            coverageAmount,
            premium
        );
        
        return policyId;
    }
    
    /// @notice Calculate insurance premium for a package
    /// @param packageCanonical Package identifier
    /// @param coverageAmount Coverage amount
    /// @return Premium amount in CREG tokens
    function calculatePremium(
        string memory packageCanonical,
        uint256 coverageAmount
    ) public view returns (uint256) {
        bytes32 packageKey = keccak256(bytes(packageCanonical));
        RiskProfile storage rp = riskProfiles[packageKey];
        
        // Base rate
        uint256 premium = (coverageAmount * basePremiumRate) / 10000;
        
        // Apply risk factors
        uint256 riskMultiplier = 10000; // 100% base
        
        // Age factor (older = cheaper)
        ChainRegistry.PackageRecord memory pkg = registry.getPackage(packageCanonical);
        uint256 age = (block.timestamp - pkg.publishedAt) / 30 days;
        uint256 ageDiscount = age * rp.ageFactor;
        riskMultiplier = riskMultiplier > ageDiscount ? riskMultiplier - ageDiscount : 1000;
        
        // Dependency factor (more dependents = more expensive)
        // In production, get actual dependency count from analytics
        uint256 deps = getDependencyCount(packageCanonical);
        riskMultiplier += deps * rp.dependencyFactor;
        
        // Vulnerability factor
        riskMultiplier += rp.vulnerabilityFactor;
        
        // Audit factor
        uint256 auditDiscount = rp.auditFactor;
        riskMultiplier = riskMultiplier > auditDiscount ? riskMultiplier - auditDiscount : 1000;
        
        // Apply multiplier
        premium = (premium * riskMultiplier) / 10000;
        
        // Add base risk score
        premium = (premium * (10000 + rp.baseRiskScore)) / 10000;
        
        return premium;
    }
    
    /// @notice Cancel a policy and receive partial refund
    function cancelPolicy(uint256 policyId) external {
        Policy storage p = _policies[policyId];
        
        if (p.insured != msg.sender) revert NotPolicyOwner();
        if (!p.active) revert PolicyNotActive();
        
        // Calculate refund (pro-rata)
        uint256 elapsed = block.timestamp - p.createdAt;
        uint256 remaining = p.expiration > block.timestamp ? p.expiration - block.timestamp : 0;
        uint256 refund = (p.premium * remaining) / POLICY_DURATION;
        
        // Apply 10% cancellation fee
        refund = (refund * 90) / 100;
        
        p.active = false;
        totalCoverage -= p.coverageAmount;
        poolBalance -= refund;
        
        // Transfer refund
        require(cregToken.transfer(msg.sender, refund), "Refund failed");
        
        emit PolicyCanceled(policyId, refund);
    }
    
    /// @notice Renew an expiring policy
    function renewPolicy(uint256 policyId) external {
        Policy storage p = _policies[policyId];
        
        if (p.insured != msg.sender) revert NotPolicyOwner();
        if (!p.active && block.timestamp > p.expiration + 30 days) {
            revert PolicyExpired(); // Too late to renew
        }
        
        // Calculate new premium
        uint256 newPremium = calculatePremium(p.packageCanonical, p.coverageAmount);
        
        // Transfer new premium
        require(
            cregToken.transferFrom(msg.sender, address(this), newPremium),
            "Premium transfer failed"
        );
        
        poolBalance += newPremium;
        
        // Update policy
        if (!p.active) {
            totalCoverage += p.coverageAmount;
        }
        p.premium += newPremium;
        p.expiration = block.timestamp + POLICY_DURATION;
        p.active = true;
        
        emit PremiumPaid(policyId, newPremium);
    }
    
    // ── Claims ────────────────────────────────────────────────────────────────
    
    /// @notice Submit a claim for compromised package
    /// @param policyId Policy ID
    /// @param amount Amount being claimed
    /// @param reason Description of the compromise
    /// @param evidence Evidence of compromise (IPFS hash or URL)
    function submitClaim(
        uint256 policyId,
        uint256 amount,
        string calldata reason,
        bytes calldata evidence
    ) external returns (uint256 claimId) {
        Policy storage p = _policies[policyId];
        
        if (!p.active) revert PolicyNotActive();
        if (block.timestamp > p.expiration + REVIEW_PERIOD) revert ClaimPeriodExpired();
        if (amount > p.coverageAmount) revert InvalidCoverage();
        if (evidence.length == 0) revert InvalidEvidence();
        
        // Verify package was actually revoked/compromised
        if (registry.getStatus(p.packageCanonical) != ChainRegistry.PackageStatus.Revoked) {
            revert InvalidPackage();
        }
        
        claimCount++;
        claimId = claimCount;
        
        _claims[claimId] = Claim({
            id: claimId,
            policyId: policyId,
            claimant: msg.sender,
            amount: amount,
            reason: reason,
            evidence: evidence,
            status: ClaimStatus.Pending,
            submittedAt: block.timestamp,
            resolvedAt: 0,
            resolver: address(0)
        });
        
        emit ClaimSubmitted(claimId, policyId, msg.sender, amount);
        
        return claimId;
    }
    
    /// @notice Review and resolve a claim (resolver only)
    function resolveClaim(
        uint256 claimId,
        ClaimStatus status,
        uint256 payout
    ) external onlyResolver {
        Claim storage c = _claims[claimId];
        
        if (c.status != ClaimStatus.Pending && c.status != ClaimStatus.UnderReview) {
            revert ClaimNotFound();
        }
        
        c.status = status;
        c.resolvedAt = block.timestamp;
        c.resolver = msg.sender;
        
        if (status == ClaimStatus.Approved) {
            // Enforce per-claim payout cap
            if (payout > maxPayoutPerClaim) revert PayoutExceedsMaxClaim();
            // Slash publisher stake
            Policy storage p = _policies[c.policyId];
            ChainRegistry.PackageRecord memory pkg = registry.getPackage(p.packageCanonical);
            
            uint256 slashAmount = min(payout, staking.stakedBalance(pkg.publisher));
            if (slashAmount > 0) {
                staking.slash(pkg.publisher, slashAmount, c.reason);
                poolBalance += slashAmount;
            }
            
            // Pay out from pool
            if (payout > poolBalance) revert InsufficientPoolBalance();
            
            poolBalance -= payout;
            totalCoverage -= payout;
            
            c.status = ClaimStatus.Paid;
            require(cregToken.transfer(c.claimant, payout), "Payout failed");
        }
        
        emit ClaimResolved(claimId, status, payout);
    }
    
    /// @notice Update claim status to under review
    function setClaimUnderReview(uint256 claimId) external onlyResolver {
        Claim storage c = _claims[claimId];
        if (c.status != ClaimStatus.Pending) revert ClaimNotFound();
        c.status = ClaimStatus.UnderReview;
    }
    
    // ── Risk Management ───────────────────────────────────────────────────────
    
    /// @notice Update risk profile for a package (governance only)
    function setRiskProfile(
        bytes32 packageKey,
        RiskProfile calldata profile
    ) external onlyGovernance {
        riskProfiles[packageKey] = profile;
        emit RiskProfileUpdated(packageKey, profile.baseRiskScore);
    }
    
    /// @notice Update base premium rate (governance only)
    function setBasePremiumRate(uint256 newRate) external onlyGovernance {
        basePremiumRate = newRate;
    }
    
    /// @notice Replenish insurance pool (from slashed funds or donations)
    function replenishPool(uint256 amount) external {
        require(
            cregToken.transferFrom(msg.sender, address(this), amount),
            "Transfer failed"
        );
        poolBalance += amount;
        emit PoolReplenished(amount);
    }
    
    /// @notice Emergency withdrawal (governance only)
    function emergencyWithdraw(address to, uint256 amount) external onlyGovernance {
        require(amount <= poolBalance, "Insufficient balance");
        poolBalance -= amount;
        require(cregToken.transfer(to, amount), "Transfer failed");
    }
    
    // ── Admin ────────────────────────────────────────────────────────────────
    
    /// @notice Add a claim resolver
    function addResolver(address resolver) external onlyGovernance {
        claimResolvers[resolver] = true;
        emit ResolverAdded(resolver);
    }
    
    /// @notice Remove a claim resolver
    function removeResolver(address resolver) external onlyGovernance {
        claimResolvers[resolver] = false;
        emit ResolverRemoved(resolver);
    }
    
    /// @notice Update coverage limits
    function setCoverageLimits(uint256 _min, uint256 _max) external onlyGovernance {
        minCoverage = _min;
        maxCoverage = _max;
    }

    /// @notice Update max payout per claim
    function setMaxPayoutPerClaim(uint256 _maxPayout) external onlyGovernance {
        maxPayoutPerClaim = _maxPayout;
    }

    /// @notice Update max pool utilization
    function setMaxPoolUtilization(uint256 _maxBps) external onlyGovernance {
        require(_maxBps > 0 && _maxBps <= 10000, "Invalid bps");
        maxPoolUtilizationBps = _maxBps;
    }
    
    // ── View Functions ────────────────────────────────────────────────────────
    
    /// @notice Get a policy by ID
    function getPolicy(uint256 policyId) external view returns (Policy memory) {
        return _policies[policyId];
    }
    
    /// @notice Get a claim by ID
    function getClaim(uint256 claimId) external view returns (Claim memory) {
        return _claims[claimId];
    }
    
    /// @notice Get all policies for a package
    function getPackagePolicies(bytes32 packageKey)
        external view
        returns (uint256[] memory)
    {
        return packagePolicies[packageKey];
    }
    
    /// @notice Get all policies for a user
    function getUserPolicies(address user)
        external view
        returns (uint256[] memory)
    {
        return userPolicies[user];
    }
    
    /// @notice Check if a package has active insurance
    function hasActiveInsurance(bytes32 packageKey) external view returns (bool) {
        uint256[] storage ids = packagePolicies[packageKey];
        for (uint i = 0; i < ids.length; i++) {
            if (_policies[ids[i]].active) {
                return true;
            }
        }
        return false;
    }
    
    /// @notice Get total coverage for a package
    function getTotalCoverage(bytes32 packageKey) external view returns (uint256) {
        uint256 total = 0;
        uint256[] storage ids = packagePolicies[packageKey];
        for (uint i = 0; i < ids.length; i++) {
            Policy storage p = _policies[ids[i]];
            if (p.active) {
                total += p.coverageAmount;
            }
        }
        return total;
    }
    
    /// @notice Get insurance pool health metrics
    function getPoolHealth() external view returns (
        uint256 balance,
        uint256 totalCover,
        uint256 utilization,
        uint256 solvency
    ) {
        balance = poolBalance;
        totalCover = totalCoverage;
        utilization = totalCoverage > 0 ? (poolBalance * 10000) / totalCoverage : 0;
        solvency = totalCoverage > 0 ? (poolBalance * 100) / totalCoverage : 100;
    }
    
    // ── Internal Helpers ─────────────────────────────────────────────────────
    
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
    
    /// @notice Get dependency count for a package from the on-chain Registry.
    /// @dev Falls back to a default estimate (10) when the Registry does not
    ///      yet expose a dependency-count API.
    function getDependencyCount(string memory packageCanonical)
        internal view
        returns (uint256)
    {
        // Attempt to read from the Registry.  If the call reverts (the
        // function does not exist yet), fall back to a conservative default.
        try registry.getDependentCount(packageCanonical) returns (uint256 count) {
            return count;
        } catch {
            return 10; // conservative default until Registry exposes the API
        }
    }
}
