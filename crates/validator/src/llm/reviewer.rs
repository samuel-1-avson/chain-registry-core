use super::context::PackageEvidencePacket;
use super::{FileAnalysis, LlmResult, LlmReview, RiskTier};
use anyhow::Result;
use common::{Finding, FindingSeverity, PackageId, PackageManifest};
use std::time::Instant;

pub(super) struct StructuredReviewer;

impl StructuredReviewer {
    pub(super) async fn review_snippet(code_snippet: &str) -> Result<LlmResult> {
        let encoded = super::sanitize_for_prompt(code_snippet);
        let messages = super::build_messages(&encoded);

        match super::call_llm(&messages, 50).await {
            Ok((resp, _model)) => super::parse_llm_response(&resp),
            Err(error) => Ok(LlmResult::Unavailable(format!(
                "All providers failed: {}",
                error
            ))),
        }
    }

    pub(super) async fn review_package(
        pkg_id: &PackageId,
        manifest: &PackageManifest,
        prior_findings: &[Finding],
        packet: PackageEvidencePacket,
    ) -> LlmReview {
        let t0 = Instant::now();

        let mut file_analyses: Vec<FileAnalysis> = Vec::new();
        let mut all_findings: Vec<Finding> = Vec::new();
        let mut model_used = String::new();
        let mut finding_counter = 0usize;

        for selected in &packet.selected_files {
            let prior_for_file: Vec<&Finding> = prior_findings
                .iter()
                .filter(|finding| finding.file == selected.path)
                .collect();

            let messages = super::build_file_analysis_messages(
                pkg_id,
                &selected.path,
                &selected.content,
                selected.entropy,
                &prior_for_file,
                super::is_high_risk_path(&selected.path),
            );

            match super::call_llm(&messages, 1500).await {
                Ok((resp, model)) => {
                    if model_used.is_empty() {
                        model_used = model.clone();
                    }
                    let analysis =
                        super::parse_file_analysis(&selected.path, &resp, &model, pkg_id);

                    for (title, severity, description) in &analysis.findings {
                        finding_counter += 1;
                        all_findings.push(Finding {
                            id: format!("LLM{:03}", finding_counter),
                            title: title.clone(),
                            severity: severity.clone(),
                            description: description.clone(),
                            file: selected.path.clone(),
                            line: None,
                        });
                    }

                    file_analyses.push(analysis);
                }
                Err(error) => {
                    tracing::warn!(
                        "[{}] LLM file analysis failed for {}: {}",
                        pkg_id.canonical(),
                        selected.path,
                        error
                    );
                    finding_counter += 1;
                    all_findings.push(Finding {
                        id: format!("LLM{:03}", finding_counter),
                        title: "LLM file analysis unavailable".into(),
                        severity: FindingSeverity::Low,
                        description: format!(
                            "LLM analysis of {} could not be completed ({}). \
                             File was flagged by static/entropy analysis but not semantically verified.",
                            selected.path,
                            error
                        ),
                        file: selected.path.clone(),
                        line: None,
                    });
                }
            }
        }

        let top_file_score = file_analyses
            .iter()
            .map(|analysis| analysis.file_score)
            .max()
            .unwrap_or(0);

        let analysed_paths: std::collections::HashSet<&str> = file_analyses
            .iter()
            .map(|analysis| analysis.path.as_str())
            .collect();
        let entropy_alerts = packet
            .entropy_alerts
            .into_iter()
            .map(|mut alert| {
                alert.llm_analysed = analysed_paths.contains(alert.path.as_str());
                alert
            })
            .collect::<Vec<_>>();

        let summary_messages = super::build_summary_messages(
            pkg_id,
            manifest,
            &entropy_alerts,
            &file_analyses,
            prior_findings,
            top_file_score,
        );

        let (maliciousness_score, package_summary, injection_patterns, final_model) =
            match super::call_llm(&summary_messages, 2000).await {
                Ok((resp, model)) => {
                    let active_model = if model_used.is_empty() {
                        model.clone()
                    } else {
                        model_used.clone()
                    };
                    let (score, summary, patterns) = super::parse_summary(&resp, &model, pkg_id);
                    (score, summary, patterns, active_model)
                }
                Err(error) => {
                    tracing::warn!(
                        "[{}] LLM package summary failed: {}",
                        pkg_id.canonical(),
                        error
                    );
                    (
                        top_file_score,
                        format!(
                            "LLM summary unavailable ({}). Per-file scores: max={}. \
                             Manual review recommended.",
                            error, top_file_score
                        ),
                        Vec::new(),
                        model_used,
                    )
                }
            };

        let risk_tier = RiskTier::from_score(maliciousness_score);
        let duration_ms = t0.elapsed().as_millis() as u64;

        tracing::info!(
            "[{}] Stage 4 complete in {}ms — score={} tier={} model={} findings={} entropy_alerts={}",
            pkg_id.canonical(),
            duration_ms,
            maliciousness_score,
            risk_tier,
            final_model,
            all_findings.len(),
            entropy_alerts.len(),
        );

        LlmReview {
            maliciousness_score,
            risk_tier,
            package_summary,
            findings: all_findings,
            high_entropy_files: entropy_alerts,
            injection_patterns,
            model_used: final_model,
            analysis_duration_ms: duration_ms,
            degraded: false,
            degraded_reason: None,
        }
    }
}
