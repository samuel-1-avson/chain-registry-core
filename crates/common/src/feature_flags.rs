//! Runtime feature gates (Phase 3 — SEC-304).

/// Parse a boolean environment variable (`1`, `true`, `yes`, case-insensitive).
pub fn env_bool(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(value) => matches!(
            value.trim(),
            "1" | "true" | "TRUE" | "True" | "yes" | "YES" | "Yes"
        ),
        Err(_) => default,
    }
}

/// Shielded (`creg publish --shield`) is **off** unless explicitly enabled on CLI and node.
pub fn shielded_publish_enabled() -> bool {
    env_bool("CREG_SHIELDED_PUBLISH_ENABLED", false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shielded_defaults_off() {
        std::env::remove_var("CREG_SHIELDED_PUBLISH_ENABLED");
        assert!(!shielded_publish_enabled());
    }

    #[test]
    fn env_bool_parses_truthy() {
        std::env::set_var("CREG_TEST_FLAG", "true");
        assert!(env_bool("CREG_TEST_FLAG", false));
        std::env::remove_var("CREG_TEST_FLAG");
    }
}
