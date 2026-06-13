use super::{EntropyAlert, LlmReview};

pub(super) struct LlmEscalationGate;

impl LlmEscalationGate {
    pub(super) fn ensure_snippet_enabled() -> Result<(), String> {
        if llm_enabled() {
            Ok(())
        } else {
            Err("LLM analysis disabled (set CREG_LLM_ENABLED=true to enable)".into())
        }
    }

    pub(super) fn reserve_snippet_call() -> Result<(), String> {
        if let Ok(mut limiter) = super::RATE_LIMITER.lock() {
            limiter.check()
        } else {
            Ok(())
        }
    }

    pub(super) fn ensure_package_enabled(
        entropy_alerts: Vec<EntropyAlert>,
    ) -> Result<(), LlmReview> {
        if llm_enabled() {
            Ok(())
        } else {
            Err(LlmReview::degraded(disabled_reason(), entropy_alerts))
        }
    }

    pub(super) fn reserve_package_call(entropy_alerts: Vec<EntropyAlert>) -> Result<(), LlmReview> {
        if let Ok(mut limiter) = super::RATE_LIMITER.lock() {
            if let Err(reason) = limiter.check() {
                return Err(LlmReview::degraded(reason, entropy_alerts));
            }
        }

        Ok(())
    }
}

fn llm_enabled() -> bool {
    std::env::var("CREG_LLM_ENABLED")
        .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
        .unwrap_or(false)
}

fn disabled_reason() -> String {
    "CREG_LLM_ENABLED is not set — LLM stage skipped. Set CREG_LLM_ENABLED=true \
     and configure at least one provider key (ANTHROPIC_API_KEY, OPENAI_API_KEY, \
     OPENROUTER_API_KEY, or CREG_OLLAMA_URL) to enable deep LLM analysis."
        .to_string()
}
