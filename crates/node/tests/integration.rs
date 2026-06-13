// crates/node/tests/integration.rs
// End-to-end integration tests for the chain registry node.
// Spins up a real in-process node and drives the full publish → verify lifecycle.

use chrono::Utc;
use common::{PackageId, PackageManifest, PublishRequest, VerdictStatus};

mod helpers {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    /// Generate a throwaway Ed25519 keypair for tests.
    pub fn generate_keypair() -> (SigningKey, String, String) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let pubkey_hex = hex::encode(signing_key.verifying_key().as_bytes());
        (signing_key, pubkey_hex, String::new())
    }

    /// Build a signed PublishRequest for testing.
    pub fn make_publish_request(
        ecosystem: &str,
        name: &str,
        version: &str,
    ) -> (PublishRequest, Vec<u8>) {
        let (signing_key, pubkey_hex, _) = generate_keypair();

        // Create a minimal valid tarball (empty gzip).
        let tarball = create_minimal_tarball(name, version);
        let content_hash = common::sha256_hex(&tarball);

        let id = PackageId::new(ecosystem, name, version);
        let msg = format!("{}{}", id.canonical(), content_hash);
        let sig = signing_key.sign(msg.as_bytes());

        let request = PublishRequest {
            id,
            content_hash,
            ipfs_cid: format!("bafyDev{}", &common::sha256_hex(b"test")[..32]),
            publisher_pubkey: pubkey_hex,
            signature: hex::encode(sig.to_bytes()),
            manifest: PackageManifest::default(),
            submitted_at: Utc::now(),
            ..Default::default()
        };

        (request, tarball)
    }

    pub fn create_minimal_tarball(name: &str, version: &str) -> Vec<u8> {
        use flate2::{write::GzEncoder, Compression};
        use std::io::Write;

        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        let package_json = format!(
            r#"{{"name":"{}","version":"{}","description":"test package"}}"#,
            name, version
        );
        // Write a minimal tar entry (header + content).
        let header_bytes = format!("{:0<100}", "package/package.json");
        gz.write_all(header_bytes.as_bytes()).ok();
        gz.write_all(package_json.as_bytes()).ok();
        gz.finish().unwrap_or_default()
    }
}

#[cfg(test)]
mod chain_store_tests {
    use chrono::Utc;
    use common::{Block, BlockHeader, ChainRecord, PackageId, PackageStatus, Transaction};
    use node::chain_store::ChainStore;
    use tempfile::TempDir;

    fn make_store() -> (ChainStore, TempDir) {
        let dir = TempDir::new().unwrap();
        let store = ChainStore::open(dir.path()).unwrap();
        (store, dir)
    }

    #[test]
    fn genesis_block_is_created_on_open() {
        let (store, _dir) = make_store();
        assert_eq!(store.tip_height().unwrap(), 0);
        let genesis = store.get_block_by_height(0).unwrap();
        assert!(genesis.is_some());
    }

    #[test]
    fn insert_and_retrieve_block() {
        let (store, _dir) = make_store();
        let block = common::Block {
            header: BlockHeader {
                height: 1,
                prev_hash: store.tip_hash().unwrap(),
                merkle_root: "abc".into(),
                proposer_id: "test-node".into(),
                timestamp: Utc::now(),
                validator_set_hash: "dev".into(),
                vrf_output: None,
                vrf_proof: None,
            },
            transactions: vec![],
            pbft_signatures: vec![],
        };
        let hash = block.hash();
        store.insert_block(&block).unwrap();

        assert_eq!(store.tip_height().unwrap(), 1);
        let retrieved = store.get_block_by_hash(&hash).unwrap().unwrap();
        assert_eq!(retrieved.header.height, 1);
    }

    #[test]
    fn package_indexed_from_publish_transaction() {
        let (store, _dir) = make_store();

        let record = ChainRecord {
            id: PackageId::new("npm", "express", "4.18.2"),
            content_hash: "abc123".into(),
            ipfs_cid: "bafytest".into(),
            publisher_pubkey: "pubkey".into(),
            block_hash: "0".repeat(64),
            published_at: Utc::now(),
            validator_signatures: vec![],
            status: PackageStatus::Verified,
            ..Default::default()
        };

        let tx = Transaction::Publish(record);
        let block = common::Block {
            header: BlockHeader {
                height: 1,
                prev_hash: store.tip_hash().unwrap(),
                merkle_root: common::merkle_root(&[tx.clone()]),
                proposer_id: "test".into(),
                timestamp: Utc::now(),
                validator_set_hash: "dev".into(),
                vrf_output: None,
                vrf_proof: None,
            },
            transactions: vec![tx],
            pbft_signatures: vec![],
        };
        store.insert_block(&block).unwrap();

        let found = store.get_package("npm:express@4.18.2").unwrap().unwrap();
        assert_eq!(found.id.name, "express");
        assert!(matches!(found.status, PackageStatus::Verified));
    }

    #[test]
    fn revocation_updates_package_status() {
        let (store, _dir) = make_store();

        // First insert a verified package.
        let record = ChainRecord {
            id: PackageId::new("npm", "malicious", "1.0.0"),
            content_hash: "abc".into(),
            ipfs_cid: "bafytest".into(),
            publisher_pubkey: "pub".into(),
            block_hash: "0".repeat(64),
            published_at: Utc::now(),
            validator_signatures: vec![],
            status: PackageStatus::Verified,
            ..Default::default()
        };

        let pub_tx = Transaction::Publish(record);
        let block1 = common::Block {
            header: BlockHeader {
                height: 1,
                prev_hash: store.tip_hash().unwrap(),
                merkle_root: "a".into(),
                proposer_id: "t".into(),
                timestamp: Utc::now(),
                validator_set_hash: "dev".into(),
                vrf_output: None,
                vrf_proof: None,
            },
            transactions: vec![pub_tx],
            pbft_signatures: vec![],
        };
        store.insert_block(&block1).unwrap();

        // Then revoke it.
        let revoke_tx = Transaction::Revoke {
            package_canonical: "npm:malicious@1.0.0".into(),
            reason: "Contains cryptocurrency miner".into(),
            revoked_by: "governance".into(),
            evidence_hash: "evidence".into(),
        };
        let block2 = common::Block {
            header: BlockHeader {
                height: 2,
                prev_hash: block1.hash(),
                merkle_root: "b".into(),
                proposer_id: "t".into(),
                timestamp: Utc::now(),
                validator_set_hash: "dev".into(),
                vrf_output: None,
                vrf_proof: None,
            },
            transactions: vec![revoke_tx],
            pbft_signatures: vec![],
        };
        store.insert_block(&block2).unwrap();

        let found = store.get_package("npm:malicious@1.0.0").unwrap().unwrap();
        assert!(matches!(found.status, PackageStatus::Revoked { .. }));
    }
}

#[cfg(test)]
mod consensus_tests {
    use chrono::Utc;
    use common::{
        Block, BlockHeader, BlockSignature, Transaction, ValidatorSignature, ValidatorVote,
    };
    use consensus::{validator_set::ValidatorInfo, PbftEngine, ValidatorSet};
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    struct TestValidator {
        id: String,
        signing_key: SigningKey,
        pubkey_hex: String,
    }

    impl TestValidator {
        fn new(id: &str) -> Self {
            let signing_key = SigningKey::generate(&mut OsRng);
            let pubkey_hex = hex::encode(signing_key.verifying_key().as_bytes());
            Self {
                id: id.to_string(),
                signing_key,
                pubkey_hex,
            }
        }

        fn to_validator_info(&self) -> ValidatorInfo {
            ValidatorInfo {
                id: self.id.clone(),
                pubkey: self.pubkey_hex.clone(),
                eth_address: None,
                stake: 1_000_000,
                reputation: 75,
                is_active: true,
            }
        }

        fn to_vrf_validator(&self) -> consensus::vrf::VrfValidator {
            consensus::vrf::VrfValidator {
                id: self.id.clone(),
                pubkey: self.pubkey_hex.clone(),
                vrf_output: None,
                vrf_proof: None,
            }
        }

        fn sign_vote(&self, phase: &str, block_hash: &str) -> BlockSignature {
            let message = consensus::pbft::pbft_signature_message(phase, block_hash);
            let signature = self.signing_key.sign(message.as_bytes());
            BlockSignature {
                validator_id: self.id.clone(),
                pubkey: self.pubkey_hex.clone(),
                signature: hex::encode(signature.to_bytes()),
            }
        }
    }

    fn make_block(height: u64, prev: &str, proposer_id: &str) -> Block {
        Block {
            header: BlockHeader {
                height,
                prev_hash: prev.to_string(),
                merkle_root: "root".into(),
                proposer_id: proposer_id.to_string(),
                timestamp: Utc::now(),
                validator_set_hash: "dev".into(),
                vrf_output: None,
                vrf_proof: None,
            },
            transactions: vec![],
            pbft_signatures: vec![],
        }
    }

    #[test]
    fn pbft_finalises_with_quorum() {
        let mut engine = PbftEngine::new();
        let mut vs = ValidatorSet::new();
        let mut validators = Vec::new();

        for i in 1..=4 {
            let v = TestValidator::new(&format!("val-{}", i));
            vs.add(v.to_validator_info());
            validators.push(v);
        }

        let active: Vec<consensus::vrf::VrfValidator> =
            validators.iter().map(|v| v.to_vrf_validator()).collect();

        let proposer_id = consensus::vrf::select_proposer_deterministic(&active, &"0".repeat(64))
            .expect("selected proposer");

        let block = make_block(1, &"0".repeat(64), &proposer_id);
        let hash = engine.start_round(block, vs).unwrap();

        // Send 3 PREPARE votes.
        for i in 0..3 {
            let sig = validators[i].sign_vote("prepare", &hash);
            let _ = engine.prepare(&hash, &validators[i].id, sig).unwrap();
        }

        // Send 3 COMMIT votes — should finalise.
        let mut finalised = false;
        for i in 0..3 {
            let sig = validators[i].sign_vote("commit", &hash);
            finalised = engine.commit(&hash, &validators[i].id, sig).unwrap();
        }
        assert!(finalised, "Block should be finalised after quorum");
    }

    #[test]
    fn pbft_fails_without_quorum() {
        let mut engine = PbftEngine::new();
        let mut vs = ValidatorSet::new();
        let mut validators = Vec::new();

        for i in 1..=4 {
            let v = TestValidator::new(&format!("val-{}", i));
            vs.add(v.to_validator_info());
            validators.push(v);
        }

        let active: Vec<consensus::vrf::VrfValidator> =
            validators.iter().map(|v| v.to_vrf_validator()).collect();

        let proposer_id = consensus::vrf::select_proposer_deterministic(&active, &"0".repeat(64))
            .expect("selected proposer");

        let block = make_block(1, &"0".repeat(64), &proposer_id);
        let hash = engine.start_round(block, vs).unwrap();

        // Send 3 PREPARE votes.
        for i in 0..3 {
            let sig = validators[i].sign_vote("prepare", &hash);
            let _ = engine.prepare(&hash, &validators[i].id, sig).unwrap();
        }

        // Only 2 COMMIT votes — quorum not met.
        for i in 0..2 {
            let sig = validators[i].sign_vote("commit", &hash);
            let _ = engine.commit(&hash, &validators[i].id, sig).unwrap();
        }

        let sigs = engine.finalised_sigs(&hash);
        assert!(
            sigs.len() < 3,
            "Should not have finalised sigs without quorum"
        );
    }

    #[test]
    fn vrf_selection_is_deterministic_and_collision_free() {
        let validators: Vec<String> = (0..20).map(|i| format!("val_{}", i)).collect();

        let a = consensus::vrf::select_validators(&validators, "npm:lodash@4.0.0", 42, 7, None)
            .unwrap();
        let b = consensus::vrf::select_validators(&validators, "npm:lodash@4.0.0", 42, 7, None)
            .unwrap();
        assert_eq!(a, b, "VRF must be deterministic");

        let unique: std::collections::HashSet<_> = a.iter().collect();
        assert_eq!(unique.len(), 7, "VRF must not select duplicates");
    }
}

#[cfg(test)]
mod resolver_tests {
    use common::{PackageId, VerdictStatus};

    #[tokio::test]
    async fn resolver_returns_unknown_for_unreachable_node() {
        let id = PackageId::new("npm", "nonexistent-pkg-xyz", "1.0.0");
        // Point at a definitely unreachable node.
        let verdict = resolver::resolve_id(&id, Some("http://127.0.0.1:19999"))
            .await
            .unwrap();
        assert_eq!(verdict.status, VerdictStatus::Unknown);
    }

    #[test]
    fn package_id_canonical_format() {
        let id = PackageId::new("npm", "@scope/pkg", "2.0.0");
        assert_eq!(id.canonical(), "npm:@scope/pkg@2.0.0");
    }

    #[test]
    fn verdict_status_helpers() {
        assert!(VerdictStatus::Verified {
            block_hash: "a".into(),
            content_hash: "b".into(),
            ipfs_cid: String::new(),
            findings: vec![]
        }
        .is_safe());
        assert!(VerdictStatus::Revoked {
            reason: "bad".into(),
            findings: vec![]
        }
        .is_blocked());
        assert!(!VerdictStatus::Unverified.is_safe());
        assert!(!VerdictStatus::Unknown.is_safe());
    }
}
