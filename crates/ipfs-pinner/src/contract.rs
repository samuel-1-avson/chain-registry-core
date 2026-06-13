//! Smart contract interface for PinningRewards.sol

use alloy::{
    network::EthereumWallet,
    primitives::{Address, U256},
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
    sol,
};
use anyhow::{Context, Result};
use async_trait::async_trait;

sol!(
    #[sol(rpc)]
    interface IERC20 {
        function approve(address spender, uint256 amount) external returns (bool);
    }

    #[sol(rpc)]
    interface IPinningRewards {
        function cregToken() external view returns (address);
        function registerPinner(uint256 stakeAmount) external;
        function unregisterPinner() external;
        function registerPin(bytes32 cid, uint256 size) external;
        function unregisterPin(bytes32 cid) external;
        function submitVerification(address pinner, bytes32 cid, bool success, bytes32 proofHash) external;
        function calculateRewards(address pinnerAddr) external view returns (uint256);
        function claimRewards() external;
        function getPinnerInfo(address pinner) external view returns (
            bool isRegistered,
            uint256 stakedAmount,
            uint256 totalPinnedSize,
            uint256 successfulVerifications,
            uint256 failedVerifications,
            uint256 lastRewardClaim,
            uint256 cumulativeRewards
        );
        function getPinInfo(bytes32 cid) external view returns (
            address pinner,
            uint256 size,
            uint256 pinnedAt,
            uint256 lastVerified,
            uint256 accessCount,
            bool isActive
        );
        function getPinnerCids(address pinner) external view returns (bytes32[] memory);
        function getCidPinners(bytes32 cid) external view returns (address[] memory);
        function fundRewardsPool(uint256 amount) external;
        function rewardsPool() external view returns (uint256);
    }
);

macro_rules! build_provider {
    ($client:expr) => {{
        let signer = $client.parse_operator_signer()?;
        let wallet = EthereumWallet::from(signer);
        ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(wallet)
            .on_http(
                $client.rpc_url.parse().with_context(|| {
                    format!("Invalid pinning rewards RPC URL: {}", $client.rpc_url)
                })?,
            )
    }};
}

/// Information about a pin from the contract
#[derive(Debug, Clone)]
pub struct ContractPinInfo {
    pub pinner: String,
    pub size: u64,
    pub pinned_at: u64,
    pub last_verified: Option<u64>,
    pub access_count: u64,
    pub is_active: bool,
}

/// Information about a pinner from the contract
#[derive(Debug, Clone)]
pub struct ContractPinnerInfo {
    pub is_registered: bool,
    pub staked_amount: u128,
    pub total_pinned_size: u64,
    pub successful_verifications: u64,
    pub failed_verifications: u64,
    pub last_reward_claim: u64,
    pub cumulative_rewards: u128,
}

/// Interface for the PinningRewards smart contract
#[async_trait]
pub trait PinningContract: Send + Sync {
    /// Check if current node is registered as pinner
    async fn is_registered(&self) -> Result<bool>;

    /// Register as a pinner with stake
    async fn register_pinner(&self, stake: u128) -> Result<()>;

    /// Unregister as pinner
    async fn unregister_pinner(&self) -> Result<()>;

    /// Register a pin on-chain
    async fn register_pin(&self, cid: [u8; 32], size: u64) -> Result<()>;

    /// Unregister a pin
    async fn unregister_pin(&self, cid: [u8; 32]) -> Result<()>;

    /// Submit verification result
    async fn submit_verification(
        &self,
        cid: [u8; 32],
        success: bool,
        proof_hash: [u8; 32],
    ) -> Result<()>;

    /// Calculate pending rewards
    async fn calculate_rewards(&self) -> Result<u128>;

    /// Claim accumulated rewards
    async fn claim_rewards(&self) -> Result<u128>;

    /// Get pinner info
    async fn get_pinner_info(&self, pinner: String) -> Result<ContractPinnerInfo>;

    /// Get pin info
    async fn get_pin_info(&self, cid: [u8; 32]) -> Result<ContractPinInfo>;

    /// Get list of CIDs pinned by this node
    async fn get_pinner_cids(&self) -> Result<Vec<[u8; 32]>>;

    /// Get list of pinners for a CID
    async fn get_cid_pinners(&self, cid: [u8; 32]) -> Result<Vec<String>>;

    /// Fund the rewards pool
    async fn fund_rewards_pool(&self, amount: u128) -> Result<()>;

    /// Get current rewards pool balance
    async fn get_rewards_pool(&self) -> Result<u128>;
}

/// Client implementation using Alloy
pub struct PinningRewardsClient {
    rpc_url: String,
    contract_address: String,
    operator_key: String,
}

impl PinningRewardsClient {
    pub fn new(rpc_url: String, contract_address: String, operator_key: String) -> Self {
        Self {
            rpc_url,
            contract_address,
            operator_key,
        }
    }

    fn parse_contract_address(&self) -> Result<Address> {
        self.contract_address.parse::<Address>().with_context(|| {
            format!(
                "Invalid PinningRewards contract address: {}",
                self.contract_address
            )
        })
    }

    fn parse_operator_signer(&self) -> Result<PrivateKeySigner> {
        self.operator_key
            .parse::<PrivateKeySigner>()
            .context("Invalid pinning operator private key")
    }

    async fn approve_creg(&self, amount: u128) -> Result<()> {
        let provider = build_provider!(self);

        let contract_address = self.parse_contract_address()?;
        let contract = IPinningRewards::new(contract_address, &provider);
        let token_address = contract
            .cregToken()
            .call()
            .await
            .context("Failed to query CREG token address from PinningRewards")?
            ._0;
        let token = IERC20::new(token_address, &provider);

        let pending_tx = token
            .approve(contract_address, U256::from(amount))
            .send()
            .await
            .context("Failed to submit CREG approval transaction")?;

        pending_tx
            .watch()
            .await
            .context("CREG approval transaction confirmation failed")?;

        Ok(())
    }
}

#[async_trait]
impl PinningContract for PinningRewardsClient {
    async fn is_registered(&self) -> Result<bool> {
        let provider = build_provider!(self);
        let operator = self.parse_operator_signer()?.address();

        let contract = IPinningRewards::new(self.parse_contract_address()?, &provider);
        let pinner = contract
            .getPinnerInfo(operator)
            .call()
            .await
            .context("Failed to query pinner registration")?;

        Ok(pinner.isRegistered)
    }

    async fn register_pinner(&self, stake: u128) -> Result<()> {
        self.approve_creg(stake).await?;
        let provider = build_provider!(self);

        let contract = IPinningRewards::new(self.parse_contract_address()?, &provider);
        let pending_tx = contract
            .registerPinner(U256::from(stake))
            .send()
            .await
            .context("Failed to submit pinner registration transaction")?;

        pending_tx
            .watch()
            .await
            .context("Pinner registration confirmation failed")?;

        Ok(())
    }

    async fn unregister_pinner(&self) -> Result<()> {
        let provider = build_provider!(self);

        let contract = IPinningRewards::new(self.parse_contract_address()?, &provider);
        let pending_tx = contract
            .unregisterPinner()
            .send()
            .await
            .context("Failed to submit pinner unregistration transaction")?;

        pending_tx
            .watch()
            .await
            .context("Pinner unregistration confirmation failed")?;

        Ok(())
    }

    async fn register_pin(&self, cid: [u8; 32], size: u64) -> Result<()> {
        let provider = build_provider!(self);

        let contract = IPinningRewards::new(self.parse_contract_address()?, &provider);
        let pending_tx = contract
            .registerPin(cid.into(), U256::from(size))
            .send()
            .await
            .context("Failed to submit registerPin transaction")?;

        pending_tx
            .watch()
            .await
            .context("registerPin confirmation failed")?;

        Ok(())
    }

    async fn unregister_pin(&self, cid: [u8; 32]) -> Result<()> {
        let provider = build_provider!(self);

        let contract = IPinningRewards::new(self.parse_contract_address()?, &provider);
        let pending_tx = contract
            .unregisterPin(cid.into())
            .send()
            .await
            .context("Failed to submit unregisterPin transaction")?;

        pending_tx
            .watch()
            .await
            .context("unregisterPin confirmation failed")?;

        Ok(())
    }

    async fn submit_verification(
        &self,
        cid: [u8; 32],
        success: bool,
        proof_hash: [u8; 32],
    ) -> Result<()> {
        let provider = build_provider!(self);
        let operator = self.parse_operator_signer()?.address();

        let contract = IPinningRewards::new(self.parse_contract_address()?, &provider);
        let pending_tx = contract
            .submitVerification(operator, cid.into(), success, proof_hash.into())
            .send()
            .await
            .context("Failed to submit verification transaction")?;

        pending_tx
            .watch()
            .await
            .context("Verification submission confirmation failed")?;

        Ok(())
    }

    async fn calculate_rewards(&self) -> Result<u128> {
        let provider = build_provider!(self);
        let operator = self.parse_operator_signer()?.address();

        let contract = IPinningRewards::new(self.parse_contract_address()?, &provider);
        let rewards = contract
            .calculateRewards(operator)
            .call()
            .await
            .context("Failed to calculate pending rewards")?
            ._0;

        u128::try_from(rewards).context("Pending rewards exceed u128")
    }

    async fn claim_rewards(&self) -> Result<u128> {
        let pending_rewards = self.calculate_rewards().await?;
        if pending_rewards == 0 {
            return Ok(0);
        }
        let provider = build_provider!(self);

        let contract = IPinningRewards::new(self.parse_contract_address()?, &provider);
        let pending_tx = contract
            .claimRewards()
            .send()
            .await
            .context("Failed to submit reward claim transaction")?;

        pending_tx
            .watch()
            .await
            .context("Reward claim confirmation failed")?;

        Ok(pending_rewards)
    }

    async fn get_pinner_info(&self, pinner: String) -> Result<ContractPinnerInfo> {
        let provider = build_provider!(self);

        let contract = IPinningRewards::new(self.parse_contract_address()?, &provider);
        let pinner_address = pinner
            .parse::<Address>()
            .with_context(|| format!("Invalid pinner address: {}", pinner))?;
        let info = contract
            .getPinnerInfo(pinner_address)
            .call()
            .await
            .context("Failed to fetch pinner info")?;

        Ok(ContractPinnerInfo {
            is_registered: info.isRegistered,
            staked_amount: u128::try_from(info.stakedAmount)
                .context("Pinner staked amount exceeds u128")?,
            total_pinned_size: u64::try_from(info.totalPinnedSize)
                .context("Pinned size exceeds u64")?,
            successful_verifications: u64::try_from(info.successfulVerifications)
                .context("Successful verification count exceeds u64")?,
            failed_verifications: u64::try_from(info.failedVerifications)
                .context("Failed verification count exceeds u64")?,
            last_reward_claim: u64::try_from(info.lastRewardClaim)
                .context("Last reward claim timestamp exceeds u64")?,
            cumulative_rewards: u128::try_from(info.cumulativeRewards)
                .context("Cumulative rewards exceed u128")?,
        })
    }

    async fn get_pin_info(&self, cid: [u8; 32]) -> Result<ContractPinInfo> {
        let provider = build_provider!(self);

        let contract = IPinningRewards::new(self.parse_contract_address()?, &provider);
        let info = contract
            .getPinInfo(cid.into())
            .call()
            .await
            .context("Failed to fetch pin info")?;

        Ok(ContractPinInfo {
            pinner: info.pinner.to_string(),
            size: u64::try_from(info.size).context("Pin size exceeds u64")?,
            pinned_at: u64::try_from(info.pinnedAt).context("Pinned-at timestamp exceeds u64")?,
            last_verified: {
                let timestamp = u64::try_from(info.lastVerified)
                    .context("Last verified timestamp exceeds u64")?;
                if timestamp == 0 {
                    None
                } else {
                    Some(timestamp)
                }
            },
            access_count: u64::try_from(info.accessCount).context("Access count exceeds u64")?,
            is_active: info.isActive,
        })
    }

    async fn get_pinner_cids(&self) -> Result<Vec<[u8; 32]>> {
        let provider = build_provider!(self);
        let operator = self.parse_operator_signer()?.address();

        let contract = IPinningRewards::new(self.parse_contract_address()?, &provider);
        let cid_hashes = contract
            .getPinnerCids(operator)
            .call()
            .await
            .context("Failed to fetch pinner CID hashes")?
            ._0;

        Ok(cid_hashes.into_iter().map(Into::into).collect())
    }

    async fn get_cid_pinners(&self, cid: [u8; 32]) -> Result<Vec<String>> {
        let provider = build_provider!(self);

        let contract = IPinningRewards::new(self.parse_contract_address()?, &provider);
        let pinners = contract
            .getCidPinners(cid.into())
            .call()
            .await
            .context("Failed to fetch CID pinners")?
            ._0;

        Ok(pinners
            .into_iter()
            .map(|address| address.to_string())
            .collect())
    }

    async fn fund_rewards_pool(&self, amount: u128) -> Result<()> {
        self.approve_creg(amount).await?;
        let provider = build_provider!(self);

        let contract = IPinningRewards::new(self.parse_contract_address()?, &provider);
        let pending_tx = contract
            .fundRewardsPool(U256::from(amount))
            .send()
            .await
            .context("Failed to submit rewards pool funding transaction")?;

        pending_tx
            .watch()
            .await
            .context("Rewards pool funding confirmation failed")?;

        Ok(())
    }

    async fn get_rewards_pool(&self) -> Result<u128> {
        let provider = build_provider!(self);

        let contract = IPinningRewards::new(self.parse_contract_address()?, &provider);
        let rewards_pool = contract
            .rewardsPool()
            .call()
            .await
            .context("Failed to fetch rewards pool balance")?
            ._0;

        u128::try_from(rewards_pool).context("Rewards pool balance exceeds u128")
    }
}
