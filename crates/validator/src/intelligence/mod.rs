// Lane C — multi-step package intelligence (post-consensus, non-binding).

use std::time::Instant;

use chrono::Utc;
use common::{
    AgentStep, ChainRecord, ConsensusAdvisorySnapshot, Finding, IntelligenceSections,
    IntelligenceStatus, PackageIntelligenceReport, INTELLIGENCE_SCHEMA_V1,
};
use flate2::read::GzDecoder;
use std::io::Read;
use tar::Archive;

use crate::llm::{self, RiskTier};

/// Generate a Lane C intelligence report for a verified package.
///
/// Uses a small agent trace: explore → ingest findings → optional Lane B LLM → synthesize.
pub async fn generate_report(record: &ChainRecord, tarball: &[u8]) -> PackageIntelligenceReport {
    let canonical = record.id.canonical();
    let mut trace = Vec::new();
    let mut step_no = 0u32;

    let explore = trace_step(
        &mut trace,
        &mut step_no,
        "explore_tarball",
        explore_tarball(tarball, record),
    );
    let osv_summary = trace_step(
        &mut trace,
        &mut step_no,
        "osv_advisory_lookup",
        summarize_osv_advisories(record),
    );
    let findings_summary = trace_step(
        &mut trace,
        &mut step_no,
        "ingest_findings",
        summarize_findings(&record.findings),
    );

    let manifest = record.manifest.clone().unwrap_or_default();
    let llm_review = llm::review_package(
        tarball,
        &record.id,
        &manifest,
        &record.findings,
        &record.content_hash,
    )
    .await;

    let advisory = ConsensusAdvisorySnapshot {
        maliciousness_score: llm_review.maliciousness_score,
        risk_tier: llm_review.risk_tier.to_string(),
        package_summary: llm_review.package_summary.clone(),
        model_used: llm_review.model_used.clone(),
        degraded: llm_review.degraded,
    };

    trace_step(
        &mut trace,
        &mut step_no,
        "lane_b_semantic_review",
        if llm_review.degraded {
            format!(
                "Lane B skipped or degraded: {}",
                llm_review.degraded_reason.as_deref().unwrap_or("unknown")
            )
        } else {
            format!(
                "Lane B complete — score {} tier {}",
                llm_review.maliciousness_score, llm_review.risk_tier
            )
        },
    );

    let sections = synthesize_sections(
        &explore,
        &findings_summary,
        &osv_summary,
        record,
        &llm_review,
    );
    trace_step(
        &mut trace,
        &mut step_no,
        "synthesize_report",
        "Structured Lane C sections assembled".into(),
    );

    let status = if llm_review.degraded && record.findings.is_empty() {
        IntelligenceStatus::Degraded
    } else if llm_review.degraded {
        IntelligenceStatus::Degraded
    } else {
        IntelligenceStatus::Ready
    };

    let mut report = PackageIntelligenceReport {
        schema_version: INTELLIGENCE_SCHEMA_V1.to_string(),
        canonical,
        content_hash: record.content_hash.clone(),
        generated_at: Utc::now(),
        status,
        lane: "C".into(),
        consensus_advisory: Some(advisory),
        sections,
        agent_trace: trace,
        report_digest: String::new(),
        error: None,
    };
    report.finalize_digest();
    report
}

fn trace_step(
    trace: &mut Vec<AgentStep>,
    step_no: &mut u32,
    tool: &str,
    summary: String,
) -> String {
    *step_no += 1;
    let started = Instant::now();
    trace.push(AgentStep {
        step: *step_no,
        tool: tool.to_string(),
        summary: summary.clone(),
        duration_ms: started.elapsed().as_millis() as u64,
    });
    summary
}

fn explore_tarball(tarball: &[u8], record: &ChainRecord) -> String {
    let mut decoder = GzDecoder::new(tarball);
    let mut decoded = Vec::new();
    if decoder.read_to_end(&mut decoded).is_err() {
        return format!(
            "Could not decompress tarball for {}; using manifest metadata only",
            record.id.canonical()
        );
    }

    let mut archive = Archive::new(&decoded[..]);
    let mut entries = match archive.entries() {
        Ok(entries) => entries,
        Err(_) => {
            return "Invalid tar archive".into();
        }
    };

    let mut file_count = 0usize;
    let mut total_bytes = 0usize;
    let mut top_dirs = std::collections::BTreeSet::new();

    while let Some(Ok(entry)) = entries.next() {
        if let Ok(path) = entry.path() {
            file_count += 1;
            if let Ok(meta) = entry.header().size() {
                total_bytes = total_bytes.saturating_add(meta as usize);
            }
            if let Some(first) = path.components().next() {
                top_dirs.insert(first.as_os_str().to_string_lossy().to_string());
            }
        }
    }

    format!(
        "{} files (~{} KB), top-level: [{}]",
        file_count,
        total_bytes / 1024,
        top_dirs.into_iter().take(8).collect::<Vec<_>>().join(", ")
    )
}

fn summarize_osv_advisories(record: &ChainRecord) -> String {
    let info = ml_validator::osv_client::PackageInfo {
        name: record.id.name.clone(),
        version: record.id.version.clone(),
        ecosystem: record.id.ecosystem.clone(),
    };

    let result = ml_validator::osv_lookup_advisory(&info);
    if !result.queried {
        return "OSV advisory lookup unavailable (set CREG_OSV_LIVE_FALLBACK or enable pinned snapshot)".into();
    }

    if result.vulnerabilities.is_empty() {
        return format!(
            "No known OSV advisories for {} (live fallback={})",
            record.id.canonical(),
            ml_validator::osv_live_fallback_enabled()
        );
    }

    let ids: Vec<&str> = result
        .vulnerabilities
        .iter()
        .take(6)
        .map(|v| v.id.as_str())
        .collect();
    format!(
        "{} OSV advisories for {}: {}",
        result.vulnerabilities.len(),
        record.id.canonical(),
        ids.join(", ")
    )
}

fn summarize_findings(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return "No consensus findings recorded".into();
    }
    let critical = findings
        .iter()
        .filter(|f| matches!(f.severity, common::FindingSeverity::Critical))
        .count();
    let high = findings
        .iter()
        .filter(|f| matches!(f.severity, common::FindingSeverity::High))
        .count();
    format!(
        "{} findings (critical={}, high={}); ids: {}",
        findings.len(),
        critical,
        high,
        findings
            .iter()
            .take(6)
            .map(|f| f.id.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn synthesize_sections(
    explore: &str,
    findings_summary: &str,
    osv_summary: &str,
    record: &ChainRecord,
    llm_review: &llm::LlmReview,
) -> IntelligenceSections {
    let manifest = record.manifest.as_ref();
    let manifest_note = manifest
        .map(|m| {
            format!(
                "Declared manifest: network_hosts={:?}, fs_writes={:?}, spawns_processes={}.",
                m.allowed_network_hosts, m.allowed_fs_writes, m.spawns_processes
            )
        })
        .unwrap_or_else(|| "No manifest attached.".into());

    let risk = &record.deterministic_risk;
    let deterministic_block = format!(
        "Consensus deterministic risk: band={}, score={}, disposition={}. {}",
        risk.band, risk.score, risk.disposition, findings_summary
    );

    let llm_block = if llm_review.degraded {
        "Lane B semantic review was not available on this node (set CREG_LLM_ENABLED and a provider). Advisory LLM output is omitted.".into()
    } else {
        format!(
            "Lane B advisory (non-binding): tier {}, score {}. {}",
            llm_review.risk_tier, llm_review.maliciousness_score, llm_review.package_summary
        )
    };

    let executive = if !llm_review.package_summary.is_empty() && !llm_review.degraded {
        llm_review.package_summary.clone()
    } else {
        format!(
            "Package {} ({}) was verified by consensus. {}",
            record.id.name, record.id.version, deterministic_block
        )
    };

    let mut residual = Vec::new();
    for f in &record.findings {
        if matches!(
            f.severity,
            common::FindingSeverity::High | common::FindingSeverity::Critical
        ) {
            residual.push(format!("{}: {}", f.id, f.title));
        }
    }
    if llm_review.risk_tier == RiskTier::Suspicious
        || llm_review.risk_tier == RiskTier::LikelyMalicious
    {
        residual.push(
            "Lane B flagged elevated semantic risk — review advisory findings before production use."
                .into(),
        );
    }

    let mut actions =
        vec!["Review consensus findings and sandbox permissions before install.".into()];
    if llm_review.degraded {
        actions.push(
            "Enable CREG_LLM_ENABLED on an intelligence node for full semantic analysis.".into(),
        );
    }

    IntelligenceSections {
        executive_summary: executive,
        what_it_does: if llm_review.package_summary.is_empty() {
            format!(
                "{} package `{}` v{} published by {}.",
                record.id.ecosystem, record.id.name, record.id.version, record.publisher_pubkey
            )
        } else {
            llm_review.package_summary.clone()
        },
        architecture: format!("Archive layout: {}. {}", explore, manifest_note),
        supply_chain: format!(
            "{} Ecosystem {}. IPFS CID {}. Content hash {}. OSV: {}.",
            record.id.ecosystem, record.id.name, record.ipfs_cid, record.content_hash, osv_summary
        ),
        security_assessment: format!("{}\n\n{}", deterministic_block, llm_block),
        residual_risks: residual,
        recommended_actions: actions,
    }
}
