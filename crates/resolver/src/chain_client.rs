// crates/resolver/src/chain_client.rs
// Hybrid client that queries a chain node via gRPC (fast) or REST (fallback).

use anyhow::{Context, Result};
use chrono::Utc;
use common::proto::registry_service_client::RegistryServiceClient;
use common::proto::GetVersionRequest;
use common::{PackageId, TrustVerdict, VerdictSource, VerdictStatus};

/// Resolve a verdict using the best available protocol (gRPC -> REST).
pub async fn fetch_verdict(id: &PackageId, node_url: &str) -> Result<TrustVerdict> {
    // ── 1. Attempt gRPC (Port 50051 - Industrial Speed) ──────────────────────
    // Strip http/https and port from node_url to guess gRPC endpoint
    let base_url = node_url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split(':')
        .next()
        .unwrap_or("localhost");
    let grpc_url = format!("http://{}:50051", base_url);

    // Attempt connection
    let mut client: RegistryServiceClient<tonic::transport::Channel> =
        match RegistryServiceClient::connect(grpc_url).await {
            Ok(c) => c,
            Err(_) => return fetch_verdict_rest(id, node_url).await,
        };

    let request = tonic::Request::new(GetVersionRequest {
        ecosystem: id.ecosystem.clone(),
        name: id.name.clone(),
    });

    // Request version from gRPC registry
    match client.get_latest_version(request).await {
        Ok(response) => {
            let res: common::proto::GetVersionResponse = response.into_inner();
            if res.found {
                return Ok(TrustVerdict {
                    package: id.clone(),
                    status: VerdictStatus::Verified {
                        block_hash: String::new(),
                        content_hash: res.content_hash,
                        ipfs_cid: String::new(), // not in gRPC response; populated via REST fallback
                        findings: vec![],
                    },
                    resolved_at: Utc::now(),
                    source: VerdictSource::Chain {
                        node_url: node_url.to_string(),
                    },
                    deterministic_risk: None,
                });
            }
        }
        Err(_) => {
            // Fallback handled below
        }
    }

    // ── 2. Fallback to REST (Port 8080 - Universal Compatibility) ────────────
    fetch_verdict_rest(id, node_url).await
}

async fn fetch_verdict_rest(id: &PackageId, node_url: &str) -> Result<TrustVerdict> {
    let canonical = id.canonical();
    let encoded_canonical = urlencoding::encode(&canonical).into_owned();
    let grouped_url = format!(
        "{}/v1/public/packages/{}",
        node_url.trim_end_matches('/'),
        encoded_canonical
    );
    let legacy_url = format!(
        "{}/v1/packages/{}",
        node_url.trim_end_matches('/'),
        encoded_canonical
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    let resp = client
        .get(&grouped_url)
        .header("Accept", "application/json")
        .send()
        .await
        .with_context(|| format!("Failed to reach chain node at {}", node_url))?;

    let resp = if matches!(
        resp.status(),
        reqwest::StatusCode::NOT_FOUND
            | reqwest::StatusCode::METHOD_NOT_ALLOWED
            | reqwest::StatusCode::NOT_IMPLEMENTED
    ) {
        client
            .get(&legacy_url)
            .header("Accept", "application/json")
            .send()
            .await
            .with_context(|| format!("Failed to reach legacy package endpoint at {}", node_url))?
    } else {
        resp
    };

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(TrustVerdict {
            package: id.clone(),
            status: VerdictStatus::Unknown,
            resolved_at: Utc::now(),
            source: VerdictSource::Chain {
                node_url: node_url.to_string(),
            },
            deterministic_risk: None,
        });
    }

    // Deserialize as the API's PackageResp shape (not ChainRecord directly).
    #[derive(serde::Deserialize, Default)]
    struct PackageApiResp {
        canonical: String,
        status: String,
        block_hash: Option<String>,
        content_hash: Option<String>,
        ipfs_cid: Option<String>,
        #[allow(dead_code)]
        publisher: Option<String>,
        #[allow(dead_code)]
        published_at: Option<String>,
        revocation_reason: Option<String>,
        deterministic_risk: Option<common::DeterministicRiskSummary>,
    }

    let record: PackageApiResp = resp
        .error_for_status()
        .context("Chain node returned an error")?
        .json()
        .await
        .context("Invalid JSON from chain node (expected package response)")?;

    let status = match record.status.as_str() {
        "verified" => VerdictStatus::Verified {
            block_hash: record.block_hash.unwrap_or_default(),
            content_hash: record.content_hash.unwrap_or_default(),
            ipfs_cid: record.ipfs_cid.unwrap_or_default(),
            findings: vec![], // Findings not included in the lightweight REST response
        },
        "revoked" => VerdictStatus::Revoked {
            reason: record.revocation_reason.unwrap_or_else(|| "Revoked".into()),
            findings: vec![],
        },
        _ => VerdictStatus::Unverified,
    };
    let _ = record.canonical; // suppress unused warning

    Ok(TrustVerdict {
        package: id.clone(),
        status,
        resolved_at: Utc::now(),
        source: VerdictSource::Chain {
            node_url: node_url.to_string(),
        },
        deterministic_risk: record.deterministic_risk,
    })
}
