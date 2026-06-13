use alloy::{primitives::Address, providers::ProviderBuilder, sol};
use common::{PackageStatus, PublishRequest};

use crate::SharedState;

sol!(
    #[sol(rpc)]
    interface IPublisherStakingRead {
        function stakedBalance(address publisher) external view returns (uint256);
    }
);

#[derive(Debug, Clone, Copy)]
pub enum AdmissionSurface {
    Rest,
    Grpc,
}

impl AdmissionSurface {
    pub fn label(self) -> &'static str {
        match self {
            Self::Rest => "REST",
            Self::Grpc => "gRPC",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AdmissionOptions {
    pub surface: AdmissionSurface,
    pub verify_publisher_auth: bool,
}

#[derive(Debug, Clone)]
pub struct AdmissionReceipt {
    pub canonical: String,
    pub pending_count: usize,
}

#[derive(Debug)]
pub enum AdmissionError {
    InvalidPackageId(String),
    InvalidPublisherSignature(String),
    Publisher(PublisherAdmissionError),
    Scanner(crate::admission_scan::AdmissionScanError),
    AlreadyVerified(String),
    Revoked(String),
    AlreadyPending(String),
    Storage(String),
    ShieldedPublishDisabled(String),
}

impl std::fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPackageId(message)
            | Self::InvalidPublisherSignature(message)
            | Self::AlreadyVerified(message)
            | Self::Revoked(message)
            | Self::AlreadyPending(message)
            | Self::Storage(message)
            | Self::ShieldedPublishDisabled(message) => write!(f, "{}", message),
            Self::Publisher(error) => write!(f, "{}", error),
            Self::Scanner(error) => write!(f, "Pre-mempool YARA admission failed: {}", error),
        }
    }
}

impl std::error::Error for AdmissionError {}

#[derive(Debug)]
pub enum PublisherAdmissionError {
    InvalidAddress(String),
    Unstaked(String),
    Unavailable(String),
}

impl std::fmt::Display for PublisherAdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidAddress(msg) | Self::Unstaked(msg) | Self::Unavailable(msg) => {
                write!(f, "{}", msg)
            }
        }
    }
}

impl std::error::Error for PublisherAdmissionError {}

pub async fn admit_publish_request(
    state: &SharedState,
    request: PublishRequest,
    options: AdmissionOptions,
) -> Result<AdmissionReceipt, AdmissionError> {
    validate_package_id(&request)?;
    if request.shielded && !common::shielded_publish_enabled() {
        return Err(AdmissionError::ShieldedPublishDisabled(
            "shielded publish is disabled; set CREG_SHIELDED_PUBLISH_ENABLED=true on the node \
             (experimental — see docs/PHASE3_KICKOFF.md)"
                .to_string(),
        ));
    }
    if options.verify_publisher_auth {
        verify_publish_auth(state, &request).await?;
    }

    let canonical = request.id.canonical();
    let ipfs_url = {
        let state = state.read().await;
        match state.chain.get_package(&canonical) {
            Ok(Some(record)) => {
                if matches!(record.status, PackageStatus::Verified) {
                    return Err(AdmissionError::AlreadyVerified(format!(
                        "{} is already verified on chain",
                        canonical
                    )));
                }
                if matches!(record.status, PackageStatus::Revoked { .. }) {
                    return Err(AdmissionError::Revoked(format!(
                        "{} is revoked and cannot be resubmitted",
                        canonical
                    )));
                }
            }
            Ok(None) => {}
            Err(error) => return Err(AdmissionError::Storage(error.to_string())),
        }
        if let Some(existing) = state.pending_pool.get(&canonical) {
            if existing.request.content_hash == request.content_hash {
                return Err(AdmissionError::AlreadyPending(format!(
                    "{} is already pending with the same content hash",
                    canonical
                )));
            }
        }
        state.config.ipfs_url.clone()
    };

    if let Err(error) = crate::admission_scan::run_pre_mempool_yara_gate(&request, &ipfs_url).await
    {
        tracing::warn!(
            surface = options.surface.label(),
            canonical = %canonical,
            "Pre-mempool YARA gate rejected submission: {}",
            error
        );
        return Err(AdmissionError::Scanner(error));
    }

    let pending_count = {
        let mut state = state.write().await;
        if !state.pending_pool.insert(request) {
            return Err(AdmissionError::AlreadyPending(format!(
                "{} is already pending with the same content hash",
                canonical
            )));
        }
        state.pending_pool.len()
    };

    tracing::info!(
        surface = options.surface.label(),
        canonical = %canonical,
        pending_count,
        "Package admitted into pending pool"
    );

    Ok(AdmissionReceipt {
        canonical,
        pending_count,
    })
}

pub async fn verify_publish_auth(
    state: &SharedState,
    request: &PublishRequest,
) -> Result<(), AdmissionError> {
    validate_package_id(request)?;
    verify_publish_sig(request)
        .map_err(|error| AdmissionError::InvalidPublisherSignature(error.to_string()))?;
    ensure_publisher_staked(state, &request.publisher_address)
        .await
        .map_err(AdmissionError::Publisher)
}

fn validate_package_id(request: &PublishRequest) -> Result<(), AdmissionError> {
    if request.id.ecosystem.trim().is_empty()
        || request.id.name.trim().is_empty()
        || request.id.version.trim().is_empty()
    {
        return Err(AdmissionError::InvalidPackageId(
            "Package ecosystem, name, and version are required".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn verify_publish_sig(req: &PublishRequest) -> anyhow::Result<()> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    if req.publisher_address.trim().is_empty() {
        anyhow::bail!("Publisher EVM address is required for runtime admission");
    }

    let msg = common::publish_signature_message(&req.id, &req.content_hash, &req.publisher_address);

    // Single-signature fallback.
    if req.publisher_pubkeys.is_empty() {
        let pubkey_bytes = hex::decode(&req.publisher_pubkey)?;
        let sig_bytes = hex::decode(&req.signature)?;
        let vk = VerifyingKey::try_from(pubkey_bytes.as_slice())
            .map_err(|_| anyhow::anyhow!("Invalid Ed25519 public key"))?;
        let sig = Signature::try_from(sig_bytes.as_slice())
            .map_err(|_| anyhow::anyhow!("Invalid Ed25519 signature"))?;
        return vk
            .verify(msg.as_bytes(), &sig)
            .map_err(|_| anyhow::anyhow!("Signature verification failed"));
    }

    // Multi-signature: require at least threshold-of-N valid signatures.
    let threshold = if req.threshold == 0 { 2 } else { req.threshold };

    if req.signatures.len() != req.publisher_pubkeys.len() {
        anyhow::bail!(
            "Signature count ({}) does not match pubkey count ({})",
            req.signatures.len(),
            req.publisher_pubkeys.len()
        );
    }

    let mut valid = 0usize;
    for (pubkey_hex, sig_hex) in req.publisher_pubkeys.iter().zip(req.signatures.iter()) {
        let pk_bytes = match hex::decode(pubkey_hex) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let sig_bytes = match hex::decode(sig_hex) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let vk = match VerifyingKey::try_from(pk_bytes.as_slice()) {
            Ok(k) => k,
            Err(_) => continue,
        };
        let sig = match Signature::try_from(sig_bytes.as_slice()) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if vk.verify(msg.as_bytes(), &sig).is_ok() {
            valid += 1;
        }
    }

    if valid >= threshold {
        Ok(())
    } else {
        anyhow::bail!(
            "Multi-sig verification failed: only {}/{} valid signatures (need {})",
            valid,
            req.publisher_pubkeys.len(),
            threshold
        )
    }
}

fn parse_publisher_address(publisher_address: &str) -> Result<Address, PublisherAdmissionError> {
    let normalized = common::canonical_publisher_address(publisher_address);
    if normalized.is_empty() {
        return Err(PublisherAdmissionError::InvalidAddress(
            "Publisher EVM address is required for runtime admission".into(),
        ));
    }

    normalized.parse::<Address>().map_err(|_| {
        PublisherAdmissionError::InvalidAddress(
            "Publisher EVM address must be a valid 0x-prefixed address".into(),
        )
    })
}

pub(crate) async fn ensure_publisher_staked(
    state: &SharedState,
    publisher_address: &str,
) -> Result<(), PublisherAdmissionError> {
    let publisher = parse_publisher_address(publisher_address)?;
    let (rpc_url, staking_addr_s) = {
        let s = state.read().await;
        (s.config.eth_rpc_url.clone(), s.config.staking_addr.clone())
    };

    if rpc_url.trim().is_empty() {
        return Err(PublisherAdmissionError::Unavailable(
            "Publisher stake enforcement unavailable: CREG_ETH_RPC is not configured".into(),
        ));
    }
    if staking_addr_s.trim().is_empty()
        || staking_addr_s.eq_ignore_ascii_case("0x0000000000000000000000000000000000000000")
    {
        return Err(PublisherAdmissionError::Unavailable(
            "Publisher stake enforcement unavailable: CREG_STAKING_ADDR is not configured".into(),
        ));
    }

    let staking_addr = staking_addr_s.parse::<Address>().map_err(|_| {
        PublisherAdmissionError::Unavailable(
            "Publisher stake enforcement unavailable: CREG_STAKING_ADDR is invalid".into(),
        )
    })?;

    let provider = ProviderBuilder::new().on_http(rpc_url.parse().map_err(|_| {
        PublisherAdmissionError::Unavailable(
            "Publisher stake enforcement unavailable: CREG_ETH_RPC is invalid".into(),
        )
    })?);
    let staking = IPublisherStakingRead::new(staking_addr, &provider);
    let staked = staking
        .stakedBalance(publisher)
        .call()
        .await
        .map_err(|error| {
            PublisherAdmissionError::Unavailable(format!(
                "Publisher stake lookup failed: {}",
                error
            ))
        })?
        ._0;

    if staked == alloy::primitives::U256::ZERO {
        return Err(PublisherAdmissionError::Unstaked(format!(
            "Publisher {} has no on-chain stake and cannot publish",
            common::canonical_publisher_address(publisher_address)
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chain_store::ChainStore,
        config::NodeConfig,
        pending_pool::PendingPool,
        publisher_index::PublisherIndex,
        state::{
            BridgeStatus, NodeState, P2PStatus, ValidatorRegistrationStatus, ValidatorSetSyncStatus,
        },
    };
    use axum::{http::StatusCode, routing::post, Json, Router};
    use common::{PackageId, PackageManifest, PublishRequest};
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use serde_json::Value;
    use std::{collections::HashMap, sync::Arc};
    use tempfile::TempDir;
    use tokio::{
        net::TcpListener,
        sync::{Mutex, RwLock},
    };

    static ENV_LOCK: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();

    fn env_lock() -> &'static Mutex<()> {
        ENV_LOCK.get_or_init(|| Mutex::new(()))
    }

    struct EnvRestore {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvRestore {
        fn set(key: &'static str, value: impl AsRef<str>) -> Self {
            let previous = std::env::var(key).ok();
            std::env::set_var(key, value.as_ref());
            Self { key, previous }
        }
    }

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    fn make_keypair() -> (SigningKey, String) {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = hex::encode(sk.verifying_key().as_bytes());
        (sk, pk)
    }

    fn make_tarball(path: &str, content: &str) -> anyhow::Result<Vec<u8>> {
        let mut tar_bytes = Vec::new();
        {
            let encoder =
                flate2::write::GzEncoder::new(&mut tar_bytes, flate2::Compression::default());
            let mut archive = tar::Builder::new(encoder);
            let mut header = tar::Header::new_gnu();
            header.set_size(content.as_bytes().len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive.append_data(&mut header, path, content.as_bytes())?;
            archive.finish()?;
            archive.into_inner()?.finish()?;
        }
        Ok(tar_bytes)
    }

    fn write_rules(dir: &std::path::Path, threat_level: u8) -> anyhow::Result<()> {
        std::fs::create_dir_all(dir)?;
        std::fs::write(
            dir.join("test-malware.yar"),
            format!(
                r#"
rule TestMaliciousPayload {{
    meta:
        threat_level = {threat_level}
        description = "test malicious payload"
        category = "test"
    strings:
        $payload = "MALICIOUS_PAYLOAD"
    condition:
        $payload
}}
"#
            ),
        )?;
        Ok(())
    }

    async fn spawn_mock_staking_rpc(staked_balance: u64) -> String {
        async fn handle_rpc(Json(payload): Json<Value>, staked_result: String) -> Json<Value> {
            Json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": payload.get("id").cloned().unwrap_or_else(|| serde_json::json!(1)),
                "result": staked_result,
            }))
        }

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let staked_result = format!("0x{:064x}", staked_balance);
        let app = Router::new().route(
            "/",
            post({
                let staked_result = staked_result.clone();
                move |payload| handle_rpc(payload, staked_result.clone())
            }),
        );

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        format!("http://{}", addr)
    }

    async fn spawn_mock_ipfs(payload: Vec<u8>, status: StatusCode) -> String {
        async fn handle_ipfs(
            payload: Vec<u8>,
            status: StatusCode,
        ) -> impl axum::response::IntoResponse {
            (status, payload)
        }

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/api/v0/cat",
            post({
                let payload = payload.clone();
                move || handle_ipfs(payload.clone(), status)
            }),
        );

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        format!("http://{}", addr)
    }

    async fn make_test_state(
        staked_balance: u64,
        ipfs_url: String,
    ) -> anyhow::Result<(SharedState, TempDir)> {
        let rpc_url = spawn_mock_staking_rpc(staked_balance).await;
        let tempdir = tempfile::tempdir()?;
        let chain = ChainStore::open(tempdir.path())?;

        let state = Arc::new(RwLock::new(NodeState {
            chain,
            pending_pool: PendingPool::new(),
            publisher_index: PublisherIndex::new(),
            validator_set_bootstrap: common::ValidatorSet::default(),
            validator_set: common::ValidatorSet::default(),
            package_rounds: HashMap::new(),
            config: NodeConfig {
                data_dir: tempdir.path().to_path_buf(),
                eth_rpc_url: rpc_url,
                staking_addr: "0x1000000000000000000000000000000000000001".into(),
                ipfs_url,
                ..Default::default()
            },
            p2p_status: P2PStatus::default(),
            bridge_status: BridgeStatus::default(),
            vrf_proofs: HashMap::new(),
            decryption_shares: HashMap::new(),
            validator_registrations: HashMap::<String, ValidatorRegistrationStatus>::new(),
            validator_set_sync: ValidatorSetSyncStatus::default(),
            view_change_certs: HashMap::new(),
            reorgs: Vec::new(),
            pbft_engine: crate::state::PbftEngine::new(),
        }));

        Ok((state, tempdir))
    }

    fn signed_request(payload: &[u8], content_hash: String, cid: &str) -> PublishRequest {
        let (sk, pk) = make_keypair();
        let mut request = PublishRequest {
            id: PackageId::new("npm", "test", "1.0.0"),
            content_hash,
            ipfs_cid: cid.into(),
            publisher_address: "0x1111111111111111111111111111111111111111".into(),
            publisher_pubkey: pk,
            signature: String::new(),
            manifest: PackageManifest::default(),
            submitted_at: chrono::Utc::now(),
            shielded: false,
            key_bundle: None,
            pgp_signature: None,
            pgp_public_key: None,
            threshold: 0,
            publisher_pubkeys: Vec::new(),
            signatures: Vec::new(),
        };
        let message = common::publish_signature_message(
            &request.id,
            &request.content_hash,
            &request.publisher_address,
        );
        request.signature = hex::encode(sk.sign(message.as_bytes()).to_bytes());
        assert_eq!(request.content_hash, common::sha256_hex(payload));
        request
    }

    async fn admit_for_test(
        state: &SharedState,
        request: PublishRequest,
    ) -> Result<AdmissionReceipt, AdmissionError> {
        admit_publish_request(
            state,
            request,
            AdmissionOptions {
                surface: AdmissionSurface::Rest,
                verify_publisher_auth: true,
            },
        )
        .await
    }

    #[tokio::test]
    async fn admission_rejects_missing_yara_rules() -> anyhow::Result<()> {
        let _guard = env_lock().lock().await;
        let no_rules = tempfile::tempdir()?;
        let _rules = EnvRestore::set("CREG_YARA_RULES_DIR", no_rules.path().display().to_string());
        let payload = make_tarball("index.js", "console.log('safe');")?;
        let ipfs_url = spawn_mock_ipfs(payload.clone(), StatusCode::OK).await;
        let (state, _tempdir) = make_test_state(1, ipfs_url).await?;
        let request = signed_request(&payload, common::sha256_hex(&payload), "bafymissingrules");

        let error = admit_for_test(&state, request).await.unwrap_err();
        assert!(matches!(
            error,
            AdmissionError::Scanner(crate::admission_scan::AdmissionScanError::RulesUnavailable)
        ));
        assert!(!state.read().await.pending_pool.contains("npm:test@1.0.0"));
        Ok(())
    }

    #[tokio::test]
    async fn admission_rejects_ipfs_fetch_failure() -> anyhow::Result<()> {
        let _guard = env_lock().lock().await;
        let rules = tempfile::tempdir()?;
        write_rules(rules.path(), 5)?;
        let _rules = EnvRestore::set("CREG_YARA_RULES_DIR", rules.path().display().to_string());
        let payload = make_tarball("index.js", "console.log('safe');")?;
        let ipfs_url =
            spawn_mock_ipfs(b"missing".to_vec(), StatusCode::INTERNAL_SERVER_ERROR).await;
        let (state, _tempdir) = make_test_state(1, ipfs_url).await?;
        let request = signed_request(&payload, common::sha256_hex(&payload), "bafyipfsfail");

        let error = admit_for_test(&state, request).await.unwrap_err();
        assert!(matches!(
            error,
            AdmissionError::Scanner(crate::admission_scan::AdmissionScanError::IpfsFetch { .. })
        ));
        assert!(!state.read().await.pending_pool.contains("npm:test@1.0.0"));
        Ok(())
    }

    #[tokio::test]
    async fn admission_rejects_content_hash_mismatch() -> anyhow::Result<()> {
        let _guard = env_lock().lock().await;
        let rules = tempfile::tempdir()?;
        write_rules(rules.path(), 5)?;
        let _rules = EnvRestore::set("CREG_YARA_RULES_DIR", rules.path().display().to_string());
        let payload = make_tarball("index.js", "console.log('safe');")?;
        let ipfs_url = spawn_mock_ipfs(payload.clone(), StatusCode::OK).await;
        let (state, _tempdir) = make_test_state(1, ipfs_url).await?;
        let wrong_hash = common::sha256_hex(b"different payload");
        let request = signed_request(b"different payload", wrong_hash, "bafyhashmismatch");

        let error = admit_for_test(&state, request).await.unwrap_err();
        assert!(matches!(
            error,
            AdmissionError::Scanner(
                crate::admission_scan::AdmissionScanError::ContentHashMismatch { .. }
            )
        ));
        assert!(!state.read().await.pending_pool.contains("npm:test@1.0.0"));
        Ok(())
    }

    #[tokio::test]
    async fn admission_rejects_oversized_payload() -> anyhow::Result<()> {
        let _guard = env_lock().lock().await;
        let rules = tempfile::tempdir()?;
        write_rules(rules.path(), 5)?;
        let _rules = EnvRestore::set("CREG_YARA_RULES_DIR", rules.path().display().to_string());
        let _limit = EnvRestore::set("CREG_PRE_MEMPOOL_SCAN_MAX_BYTES", "8");
        let payload = make_tarball("index.js", "console.log('safe');")?;
        let ipfs_url = spawn_mock_ipfs(payload.clone(), StatusCode::OK).await;
        let (state, _tempdir) = make_test_state(1, ipfs_url).await?;
        let request = signed_request(&payload, common::sha256_hex(&payload), "bafytoolarge");

        let error = admit_for_test(&state, request).await.unwrap_err();
        assert!(matches!(
            error,
            AdmissionError::Scanner(
                crate::admission_scan::AdmissionScanError::PayloadTooLarge { .. }
            )
        ));
        assert!(!state.read().await.pending_pool.contains("npm:test@1.0.0"));
        Ok(())
    }

    #[tokio::test]
    async fn admission_rejects_malicious_yara_match() -> anyhow::Result<()> {
        let _guard = env_lock().lock().await;
        let rules = tempfile::tempdir()?;
        write_rules(rules.path(), 5)?;
        let _rules = EnvRestore::set("CREG_YARA_RULES_DIR", rules.path().display().to_string());
        let payload = make_tarball("index.js", "const marker = 'MALICIOUS_PAYLOAD';")?;
        let ipfs_url = spawn_mock_ipfs(payload.clone(), StatusCode::OK).await;
        let (state, _tempdir) = make_test_state(1, ipfs_url).await?;
        let request = signed_request(&payload, common::sha256_hex(&payload), "bafymalicious");

        let error = admit_for_test(&state, request).await.unwrap_err();
        assert!(matches!(
            error,
            AdmissionError::Scanner(crate::admission_scan::AdmissionScanError::Rejected { .. })
        ));
        assert!(!state.read().await.pending_pool.contains("npm:test@1.0.0"));
        Ok(())
    }

    #[tokio::test]
    async fn admission_accepts_benign_package_into_pending_pool() -> anyhow::Result<()> {
        let _guard = env_lock().lock().await;
        let rules = tempfile::tempdir()?;
        write_rules(rules.path(), 5)?;
        let _rules = EnvRestore::set("CREG_YARA_RULES_DIR", rules.path().display().to_string());
        let payload = make_tarball("index.js", "module.exports = () => 'safe';")?;
        let ipfs_url = spawn_mock_ipfs(payload.clone(), StatusCode::OK).await;
        let (state, _tempdir) = make_test_state(1, ipfs_url).await?;
        let request = signed_request(&payload, common::sha256_hex(&payload), "bafybenign");

        let receipt = admit_for_test(&state, request).await?;
        assert_eq!(receipt.canonical, "npm:test@1.0.0");
        assert_eq!(receipt.pending_count, 1);
        assert!(state.read().await.pending_pool.contains("npm:test@1.0.0"));
        Ok(())
    }

    fn shielded_signed_request(
        plaintext: &[u8],
        wire: &[u8],
        bundle: &str,
        cid: &str,
    ) -> PublishRequest {
        let mut request = signed_request(plaintext, common::sha256_hex(plaintext), cid);
        request.shielded = true;
        request.key_bundle = Some(bundle.to_string());
        assert_ne!(wire, plaintext, "IPFS mock must serve encrypted wire bytes");
        request
    }

    #[tokio::test]
    async fn admission_accepts_shielded_when_enabled() -> anyhow::Result<()> {
        let _guard = env_lock().lock().await;
        let _enabled = EnvRestore::set("CREG_SHIELDED_PUBLISH_ENABLED", "true");
        let plaintext = make_tarball("index.js", "module.exports = () => 'shielded-safe';")?;
        let (wire, bundle) = common::encrypt_shielded_package(&plaintext, None)?;
        let ipfs_url = spawn_mock_ipfs(wire.clone(), StatusCode::OK).await;
        let (state, _tempdir) = make_test_state(1, ipfs_url).await?;
        let request = shielded_signed_request(&plaintext, &wire, &bundle, "bafyshieldedenabled");

        let receipt = admit_for_test(&state, request).await?;
        assert_eq!(receipt.canonical, "npm:test@1.0.0");
        assert_eq!(receipt.pending_count, 1);
        assert!(state.read().await.pending_pool.contains("npm:test@1.0.0"));
        Ok(())
    }

    #[tokio::test]
    async fn admission_rejects_shielded_when_disabled() -> anyhow::Result<()> {
        let _guard = env_lock().lock().await;
        let _enabled = EnvRestore::set("CREG_SHIELDED_PUBLISH_ENABLED", "false");
        let (state, _tempdir) = make_test_state(1, "http://127.0.0.1:65535".into()).await?;
        let mut request = signed_request(b"payload", common::sha256_hex(b"payload"), "bafyshield");
        request.shielded = true;

        let error = admit_publish_request(
            &state,
            request,
            AdmissionOptions {
                surface: AdmissionSurface::Rest,
                verify_publisher_auth: false,
            },
        )
        .await
        .unwrap_err();

        assert!(matches!(error, AdmissionError::ShieldedPublishDisabled(_)));
        assert!(!state.read().await.pending_pool.contains("npm:test@1.0.0"));
        Ok(())
    }
}
