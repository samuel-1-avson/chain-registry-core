// crates/validator/src/lib.rs
// Mechanical consensus validator — runs all pipeline stages and returns a
// signed vote to the consensus engine.
//
// Pipeline stages (in order):
//   Stage 1 — Static Analysis    (static_analysis.rs)
//   Stage 2 — Behavioral Sandbox (sandbox.rs)
//   Stage 3 — Differential Diff  (diff.rs)
//   Stage 4 — LLM-Assisted Review(llm.rs)  ← deep semantic scan
//   Stage 5 — PGP Verification   (pgp.rs)
//   Stage 6 — Publisher Reputation(reputation.rs)
//   [AAA]   — External AI Auditor (opt-in, post-rejection only)

pub mod bundle;
pub mod diff;
pub mod intelligence;
pub mod llm;
pub mod pgp;
pub mod report;
pub mod reputation;
pub mod risk;
pub mod sandbox;
pub mod static_analysis;
pub mod typosquat;
pub mod wasm_sandbox;

use anyhow::Result;
use common::{Finding, PublishRequest, ValidatorVote};
use report::{AuditProof, ValidationReport};
use reputation::{assess_publisher, FinalDecision};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ValidationResult {
    pub vote: ValidatorVote,
    pub pgp_fingerprint: Option<String>,
    pub findings: Vec<Finding>,
    pub analysis_bundles: bundle::AnalysisBundleSet,
    pub deterministic_risk: risk::RiskSummary,
}

/// Run all validator pipeline stages and produce a signed vote.
///
/// `prev_manifest` — manifest from the previous verified version of this
/// package, used by the diff stage to detect permission escalation.
///
/// `prev_sandbox` — sandbox result from the previous verified version, used
/// by the diff stage to detect runtime behavioral changes (DF005–DF007).
/// Pass `None` for the first publish of a package.
pub async fn validate_package(
    req: &PublishRequest,
    tarball: &[u8],
    _privkey: &str,
    prev_manifest: Option<&common::PackageManifest>,
    prev_sandbox: Option<&sandbox::SandboxResult>,
) -> Result<ValidationResult> {
    let canonical = req.id.canonical();
    tracing::info!("Starting validator pipeline for {}", canonical);

    let node_url =
        std::env::var("CREG_NODE_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".into());

    // Refresh the typosquat dataset from CREG_TYPOSQUAT_URL if configured and
    // the TTL has expired.  Failures are non-fatal; the compile-time baseline
    // is always available as a fallback.
    typosquat::maybe_refresh().await;

    // ── Stage 1 (static) + Stage 6 (reputation) run concurrently ────────────
    let (static_result, rep_result) = tokio::join!(
        static_analysis::run(tarball, &req.manifest),
        assess_publisher(&req.publisher_pubkey, &node_url),
    );

    let mut report = ValidationReport::new(req.id.clone());
    report.apply_static(static_result?);

    // ── Stage 2 — Behavioral Sandbox ─────────────────────────────────────────
    let sandbox_result = sandbox::run(&req.id, tarball, &req.manifest).await?;
    report.apply_sandbox(sandbox_result.clone());

    // Persist result for the next version's diff stage. This covers the common
    // case where the same node processes consecutive versions of a package.
    sandbox::store_result(&canonical, &sandbox_result);

    // ── Stage 3 — Differential Analysis ──────────────────────────────────────
    // prev_sandbox supplies the previous version's runtime observations so that
    // DF005 (new network host), DF006 (new fs write), and DF007 (new process
    // spawn) can fire. Without it these three findings are silently skipped.
    let diff_result = diff::analyze(&req.manifest, &sandbox_result, prev_manifest, prev_sandbox);
    report.apply_diff(diff_result);

    // ── Stage 4 — LLM-Assisted Review ────────────────────────────────────────
    // Performs deep semantic analysis: Shannon entropy scanning across all files,
    // per-file LLM analysis of high-risk and high-entropy content, and a holistic
    // package summary with an overall maliciousness score and risk tier.
    //
    // When CREG_LLM_ENABLED=true the review runs using the configured provider
    // chain (Anthropic → OpenAI → OpenRouter → Ollama). When disabled, the stage
    // returns a degraded result that still carries entropy data.
    //
    // LLM findings are integrated into the report via apply_llm():
    //   - Per-file findings (LLM001, LLM002, …) with severity and description
    //   - A summary finding (LLM000) when score ≥ 60
    //   - Entropy alerts (LLM-ENT) for high-entropy files
    //   - A skip notice (LLM-SKIP) when the stage is disabled
    tracing::info!("[{}] Stage 4 — LLM-assisted review", canonical);
    let llm_review = llm::review_package(
        tarball,
        &req.id,
        &req.manifest,
        &report.findings,
        &req.content_hash,
    )
    .await;
    report.apply_llm(llm_review);

    // ── Stage 5 — Web-of-Trust PGP Verification ──────────────────────────────
    let mut pgp_fingerprint = None;
    if let (Some(sig_hex), Some(pubk_hex)) = (&req.pgp_signature, &req.pgp_public_key) {
        if let (Ok(sig_bytes), Ok(pubk_bytes)) = (hex::decode(sig_hex), hex::decode(pubk_hex)) {
            let pgp_res = pgp::verify_signature(tarball, &sig_bytes, &pubk_bytes);
            pgp_fingerprint = pgp_res.fingerprint.clone();
            report.apply_pgp(pgp_res);
        }
    }

    let rep = rep_result.unwrap_or_else(|_| reputation::ReputationAssessment {
        confidence_delta: 0,
        publisher_pubkey: req.publisher_pubkey.clone(),
        notes: vec!["Reputation check unreachable — neutral".into()],
        revoked_pgp_fps: vec![],
    });

    for note in &rep.notes {
        tracing::debug!("[{}] rep: {}", canonical, note);
    }

    // ── PGP key revocation check ──────────────────────────────────────────────
    // A publisher may have revoked their PGP key after it was compromised.
    // The revocation list is stored on-chain in the publisher's reputation record
    // and checked here after the signature has been cryptographically verified.
    // A revoked-key signature is treated as Critical even if the crypto is valid.
    if let Some(fp) = &pgp_fingerprint {
        if rep
            .revoked_pgp_fps
            .iter()
            .any(|r| r.eq_ignore_ascii_case(fp))
        {
            tracing::warn!(
                "[{}] PGP fingerprint {} is in publisher's revocation list",
                canonical,
                &fp[..fp.len().min(16)]
            );
            report.findings.push(Finding {
                id: "PGP004".into(),
                title: "Revoked PGP key used for signing".into(),
                severity: common::FindingSeverity::Critical,
                description: format!(
                    "Package was signed with PGP key {} which the publisher has declared revoked. \
                     This key may have been compromised. Reject until re-signed with a valid key.",
                    fp
                ),
                file: "pgp".into(),
                line: None,
            });
        }
    }

    // ── Deterministic risk aggregation ───────────────────────────────────────
    let risk_aggregator = risk::RiskAggregator::default();
    let deterministic_risk = risk_aggregator.summarize(
        &req.id,
        &report.findings,
        report.deterministic_score,
        report.advisory_score,
        report.ensemble_score,
        report.llm_review.as_ref(),
        &report.analysis_bundles,
        &rep,
    );
    tracing::info!(
        "[{}] Deterministic risk {} score={} disposition={} digest={}",
        canonical,
        deterministic_risk.band,
        deterministic_risk.score,
        deterministic_risk.disposition,
        &deterministic_risk.evidence_digest[..deterministic_risk.evidence_digest.len().min(12)]
    );
    report.record_deterministic_risk(deterministic_risk.clone());

    let mut decision = risk_aggregator.decide(&deterministic_risk);

    // ── AAA (Automated AI Auditor) Stage ──────────────────────────────────────
    // Only runs when CREG_AAA_ENABLED=true is explicitly set. The AAA auditor
    // is an external service that may not be deployed — calling it unconditionally
    // causes silent failures.
    let aaa_enabled = std::env::var("CREG_AAA_ENABLED")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    if decision.is_reject() && aaa_enabled {
        tracing::info!("[{}] Triggering Automated AI Audit (AAA)...", canonical);
        match aaa_audit(&report, req).await {
            Ok(proof) => {
                // Cryptographically verify the AAA proof before honouring it.
                // Operator must pin the trusted auditor pubkey via CREG_AAA_PUBKEY.
                // The signed message binds canonical || content_hash || verdict
                // so a leaked "cleared" signature cannot be replayed against a
                // different package or version.
                match verify_aaa_proof(&proof, &canonical, &req.content_hash) {
                    Ok(()) if proof.verdict == "cleared" => {
                        report.aaa_verdict = Some(proof);
                        decision = FinalDecision::Approve { confidence: 85 };
                        tracing::info!(
                            "[{}] AAA cleared the package with a signed proof",
                            canonical
                        );
                    }
                    Ok(()) => {
                        tracing::warn!(
                            "[{}] AAA returned verdict='{}' — rejection stands",
                            canonical,
                            proof.verdict
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            "[{}] AAA proof verification failed: {} — rejection stands",
                            canonical,
                            e
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    "[{}] AAA audit failed: {} — original rejection stands",
                    canonical,
                    e
                );
            }
        }
    } else if decision.is_reject() {
        tracing::debug!(
            "[{}] AAA is not enabled (set CREG_AAA_ENABLED=true to activate)",
            canonical
        );
    }

    let vote = if decision.is_reject() {
        let base = decision
            .reject_reason()
            .unwrap_or("Validation failed")
            .to_string();
        let detail = if report.has_critical_findings() {
            format!("{}; {}", base, report.critical_finding_summary())
        } else {
            base
        };
        tracing::warn!("[{}] REJECT — {}", canonical, detail);
        ValidatorVote::Reject { reason: detail }
    } else {
        if let reputation::FinalDecision::ApproveWithWarning { warning, .. } = &decision {
            tracing::warn!("[{}] APPROVE WITH WARNING — {}", canonical, warning);
        } else {
            tracing::info!("[{}] APPROVE", canonical);
        }
        ValidatorVote::Approve
    };

    Ok(ValidationResult {
        vote,
        pgp_fingerprint,
        findings: report.findings,
        analysis_bundles: report.analysis_bundles,
        deterministic_risk,
    })
}

/// Domain tag for the AAA signature format. Bumping this invalidates all
/// previously-issued auditor signatures.
const AAA_MESSAGE_DOMAIN: &str = "creg-aaa-v1";

/// Verify an AAA proof against the pinned auditor public key (env
/// `CREG_AAA_PUBKEY`, hex-encoded Ed25519). Binds the signature to the
/// canonical package id, the content hash, and the verdict so it cannot be
/// replayed across packages or versions.
fn verify_aaa_proof(proof: &AuditProof, canonical: &str, content_hash: &str) -> Result<()> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let pinned_pubkey = std::env::var("CREG_AAA_PUBKEY")
        .map_err(|_| anyhow::anyhow!("CREG_AAA_PUBKEY is not set — cannot verify AAA proof"))?;

    if proof.signature.is_empty() {
        anyhow::bail!("AAA proof has an empty signature");
    }
    if proof.auditor_pubkey.is_empty() {
        anyhow::bail!("AAA proof has an empty auditor_pubkey");
    }
    if !proof
        .auditor_pubkey
        .eq_ignore_ascii_case(pinned_pubkey.trim())
    {
        anyhow::bail!(
            "AAA auditor_pubkey does not match pinned CREG_AAA_PUBKEY (got {}, expected {})",
            proof.auditor_pubkey,
            pinned_pubkey
        );
    }

    let pubkey_bytes = hex::decode(proof.auditor_pubkey.trim())
        .map_err(|e| anyhow::anyhow!("auditor_pubkey is not valid hex: {}", e))?;
    let vk = VerifyingKey::try_from(pubkey_bytes.as_slice())
        .map_err(|e| anyhow::anyhow!("auditor_pubkey is not a valid Ed25519 key: {}", e))?;

    let sig_bytes = hex::decode(&proof.signature)
        .map_err(|e| anyhow::anyhow!("signature is not valid hex: {}", e))?;
    let sig = Signature::try_from(sig_bytes.as_slice())
        .map_err(|e| anyhow::anyhow!("signature is not a valid Ed25519 signature: {}", e))?;

    let msg = format!(
        "{}|{}|{}|{}",
        AAA_MESSAGE_DOMAIN, canonical, content_hash, proof.verdict
    );
    vk.verify(msg.as_bytes(), &sig)
        .map_err(|e| anyhow::anyhow!("AAA signature verification failed: {}", e))?;

    Ok(())
}

/// Deep Audit call to an external AI Auditor provider.
///
/// Sends a structured audit envelope (findings + metadata) rather than the
/// full tarball. This prevents leaking proprietary package contents to a
/// third-party service. If the auditor needs the tarball for re-analysis,
/// it can fetch it directly from IPFS using the provided CID.
async fn aaa_audit(report: &ValidationReport, req: &PublishRequest) -> Result<AuditProof> {
    let auditor_url = std::env::var("AAA_AUDITOR_URL")
        .unwrap_or_else(|_| "http://ai-auditor-central.service.cluster.local/v1/audit".into());

    tracing::info!("Dispatching Deep Audit to {}", auditor_url);

    /// Structured audit envelope — does NOT include the raw tarball.
    /// The auditor may independently fetch the tarball from IPFS via `ipfs_cid`
    /// if it needs to re-run its own analysis.
    #[derive(serde::Serialize)]
    struct AuditReq<'a> {
        package: &'a common::PackageId,
        findings: &'a [Finding],
        /// SHA-256 of the tarball — auditor can verify integrity before fetching.
        content_hash: &'a str,
        /// IPFS CID — auditor fetches the tarball from here if needed.
        ipfs_cid: &'a str,
        /// Summary stats for the auditor to triage without fetching the tarball.
        finding_counts: FindingCounts,
    }

    #[derive(serde::Serialize)]
    struct FindingCounts {
        critical: usize,
        high: usize,
        medium: usize,
        low: usize,
    }

    let counts = FindingCounts {
        critical: report
            .findings
            .iter()
            .filter(|f| matches!(f.severity, common::FindingSeverity::Critical))
            .count(),
        high: report
            .findings
            .iter()
            .filter(|f| matches!(f.severity, common::FindingSeverity::High))
            .count(),
        medium: report
            .findings
            .iter()
            .filter(|f| matches!(f.severity, common::FindingSeverity::Medium))
            .count(),
        low: report
            .findings
            .iter()
            .filter(|f| matches!(f.severity, common::FindingSeverity::Low))
            .count(),
    };

    let audit_req = AuditReq {
        package: &report.package,
        findings: &report.findings,
        content_hash: &req.content_hash,
        ipfs_cid: &req.ipfs_cid,
        finding_counts: counts,
    };

    let resp = reqwest::Client::new()
        .post(&auditor_url)
        .json(&audit_req)
        .send()
        .await?;

    if !resp.status().is_success() {
        anyhow::bail!("AI Auditor returned error: {}", resp.status());
    }

    let proof: AuditProof = resp.json().await?;
    Ok(proof)
}
