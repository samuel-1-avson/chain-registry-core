// crates/validator/src/reputation.rs
// Stage 3: Reputation-weighted voting.
// Before casting its PBFT vote, a validator checks the publisher's
// on-chain history: prior revocations, stake size, and submission volume.
// This stage cannot alone block a package — it adjusts the confidence
// score that feeds into the final ValidatorVote.

use serde::{Deserialize, Serialize};

/// Confidence adjustment produced by the reputation stage.
/// A very negative adjustment will tip a borderline static/sandbox result
/// into a Reject. A strong positive will not override clear malice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationAssessment {
    /// -100 (deeply untrusted) to +100 (highly trusted publisher).
    pub confidence_delta: i32,
    pub publisher_pubkey: String,
    pub notes: Vec<String>,
    /// PGP key fingerprints (hex) that the publisher has declared revoked.
    /// The PGP stage checks the signing key's fingerprint against this list
    /// and emits a Critical PGP004 finding if the key was revoked.
    #[serde(default)]
    pub revoked_pgp_fps: Vec<String>,
}

/// Query the reputation of a publisher from the chain node.
/// In a full deployment this calls GET /v1/publishers/:pubkey on the node.
pub async fn assess_publisher(
    publisher_pubkey: &str,
    node_url: &str,
) -> anyhow::Result<ReputationAssessment> {
    let url = format!(
        "{}/v1/publishers/{}",
        node_url.trim_end_matches('/'),
        publisher_pubkey
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(4))
        .build()?;

    // Retry up to two times for transient network failures. On HTTP 404 we
    // assume a legitimately unknown publisher; on other errors we default to
    // a *negative* delta so that a brand-new or opaque attacker account does
    // not receive the same treatment as a trusted long-running publisher.
    const MAX_ATTEMPTS: u32 = 3;
    let mut last_error: Option<String> = None;
    for attempt in 1..=MAX_ATTEMPTS {
        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => match resp.json::<PublisherRecord>().await {
                Ok(body) => return Ok(build_assessment(publisher_pubkey, &body)),
                Err(e) => last_error = Some(format!("decode failed: {}", e)),
            },
            Ok(resp) if resp.status() == reqwest::StatusCode::NOT_FOUND => {
                // Publisher has no record yet — treat as first-time with light penalty.
                return Ok(ReputationAssessment {
                    confidence_delta: -10,
                    publisher_pubkey: publisher_pubkey.to_string(),
                    notes: vec!["Publisher not found on chain — first-time publisher (-10)".into()],
                    revoked_pgp_fps: vec![],
                });
            }
            Ok(resp) => {
                last_error = Some(format!("HTTP {}", resp.status()));
            }
            Err(e) => {
                last_error = Some(format!("transport error: {}", e));
            }
        }
        if attempt < MAX_ATTEMPTS {
            tokio::time::sleep(std::time::Duration::from_millis(200 * attempt as u64)).await;
        }
    }

    // All retries exhausted — fail *pessimistically* rather than neutrally so
    // that a brief outage cannot turn unknown attackers into trusted publishers.
    let reason = last_error.unwrap_or_else(|| "unknown".into());
    tracing::warn!(
        "Reputation lookup for {} failed after {} attempts: {}",
        publisher_pubkey,
        MAX_ATTEMPTS,
        reason
    );
    Ok(ReputationAssessment {
        confidence_delta: -25,
        publisher_pubkey: publisher_pubkey.to_string(),
        notes: vec![format!(
            "Reputation service unreachable ({}) — treating as untrusted (-25)",
            reason
        )],
        revoked_pgp_fps: vec![],
    })
}

/// Publisher record as returned by the chain node REST API.
#[derive(Deserialize)]
struct PublisherRecord {
    total_packages: u32,
    verified_count: u32,
    revoked_count: u32,
    stake_wei: u64,
    first_seen_days: u32,
    /// PGP fingerprints (hex) that the publisher has declared revoked.
    /// Absent from older API versions — defaults to empty.
    #[serde(default)]
    revoked_pgp_fps: Vec<String>,
}

fn build_assessment(pubkey: &str, rec: &PublisherRecord) -> ReputationAssessment {
    let mut delta: i32 = 0;
    let mut notes = Vec::new();
    let revoked_pgp_fps = rec.revoked_pgp_fps.clone();

    // ── Revocation penalty ────────────────────────────────────────────────────
    if rec.revoked_count > 0 {
        let penalty = (rec.revoked_count as i32) * -25;
        delta += penalty;
        notes.push(format!(
            "{} prior revocation(s) → -{} confidence",
            rec.revoked_count,
            penalty.abs()
        ));
    }

    // ── Track record bonus ────────────────────────────────────────────────────
    if rec.verified_count >= 10 {
        delta += 20;
        notes.push(format!(
            "{} verified packages on record → +20",
            rec.verified_count
        ));
    } else if rec.verified_count >= 3 {
        delta += 10;
        notes.push(format!(
            "{} verified packages on record → +10",
            rec.verified_count
        ));
    } else if rec.verified_count == 0 && rec.total_packages == 0 {
        delta -= 10;
        notes.push("First-time publisher — no track record → -10".into());
    }

    // ── Stake size bonus (skin in the game) ──────────────────────────────────
    // 1 ETH = 1e18 wei
    let stake_eth = rec.stake_wei / 1_000_000_000_000_000_000;
    if stake_eth >= 5 {
        delta += 15;
        notes.push(format!("{} ETH staked → +15 confidence", stake_eth));
    } else if stake_eth >= 1 {
        delta += 5;
        notes.push(format!("{} ETH staked → +5 confidence", stake_eth));
    }

    // ── Account age bonus ─────────────────────────────────────────────────────
    if rec.first_seen_days >= 365 {
        delta += 10;
        notes.push(format!("Account {} days old → +10", rec.first_seen_days));
    } else if rec.first_seen_days < 7 {
        delta -= 15;
        notes.push(format!(
            "Account only {} days old → -15",
            rec.first_seen_days
        ));
    }

    // Hard floor/ceiling.
    delta = delta.clamp(-100, 100);

    ReputationAssessment {
        confidence_delta: delta,
        publisher_pubkey: pubkey.to_string(),
        notes,
        revoked_pgp_fps,
    }
}

/// Combine static analysis + sandbox findings with the reputation delta
/// to produce a final pass/fail decision with a confidence score.
pub fn final_decision(
    static_critical: bool,
    sandbox_critical: bool,
    reputation_delta: i32,
) -> FinalDecision {
    // Any critical finding is always a hard reject regardless of reputation.
    if static_critical || sandbox_critical {
        return FinalDecision::Reject {
            reason: if static_critical {
                "Critical static analysis finding".into()
            } else {
                "Critical sandbox behavior finding".into()
            },
            confidence: 95,
        };
    }

    // No critical findings — use reputation to decide.
    // Thresholds overridable via env vars so operators can tune trust sensitivity
    // without recompiling. Defaults: reject < -50, warn -50..0, approve >= 0.
    let reject_threshold: i32 = std::env::var("CREG_REP_REJECT_THRESHOLD")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(-50);
    let warn_threshold: i32 = std::env::var("CREG_REP_WARN_THRESHOLD")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    if reputation_delta < reject_threshold {
        FinalDecision::Reject {
            reason: format!(
                "Publisher reputation score {} falls below trust threshold ({})",
                reputation_delta, reject_threshold
            ),
            confidence: 70,
        }
    } else if reputation_delta < warn_threshold {
        FinalDecision::ApproveWithWarning {
            warning: format!(
                "Publisher reputation is low (delta {}). Monitor this package.",
                reputation_delta
            ),
            confidence: (50 + reputation_delta).max(10) as u8,
        }
    } else {
        FinalDecision::Approve {
            confidence: (60 + reputation_delta / 2).min(100) as u8,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FinalDecision {
    Approve { confidence: u8 },
    ApproveWithWarning { warning: String, confidence: u8 },
    Reject { reason: String, confidence: u8 },
}

impl FinalDecision {
    pub fn is_reject(&self) -> bool {
        matches!(self, FinalDecision::Reject { .. })
    }

    pub fn reject_reason(&self) -> Option<&str> {
        match self {
            FinalDecision::Reject { reason, .. } => Some(reason),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critical_finding_always_rejects() {
        let d = final_decision(true, false, 100);
        assert!(d.is_reject());
    }

    #[test]
    fn bad_reputation_rejects_clean_package() {
        let d = final_decision(false, false, -80);
        assert!(d.is_reject());
    }

    #[test]
    fn good_reputation_approves() {
        let d = final_decision(false, false, 50);
        assert!(!d.is_reject());
        assert!(matches!(d, FinalDecision::Approve { confidence } if confidence > 60));
    }

    #[test]
    fn marginal_reputation_warns() {
        let d = final_decision(false, false, -20);
        assert!(matches!(d, FinalDecision::ApproveWithWarning { .. }));
    }

    #[test]
    fn multiple_revocations_tank_score() {
        let rec = PublisherRecord {
            total_packages: 5,
            verified_count: 3,
            revoked_count: 3,
            stake_wei: 0,
            first_seen_days: 30,
            revoked_pgp_fps: vec![],
        };
        let assessment = build_assessment("pubkey", &rec);
        assert!(assessment.confidence_delta < -50);
    }
}
