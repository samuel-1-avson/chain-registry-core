// crates/cli/src/retry.rs
// Exponential back-off retry helper for fallible async operations.

use std::time::Duration;
use tracing::warn;

/// Retry `op` up to `max_attempts` times using exponential back-off.
/// The first attempt is immediate.  On failure the delay doubles each time,
/// starting at `base_delay`, capped at 30 seconds.
///
/// Returns the first `Ok` result or the last `Err` if all attempts fail.
pub async fn with_retry<F, Fut, T, E>(
    label: &str,
    max_attempts: u32,
    base_delay: Duration,
    mut op: F,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let mut delay = base_delay;
    let mut last_err = None;

    for attempt in 1..=max_attempts {
        match op().await {
            Ok(v) => return Ok(v),
            Err(e) => {
                if attempt < max_attempts {
                    warn!(
                        "{}: attempt {}/{} failed ({}), retrying in {:?}",
                        label, attempt, max_attempts, e, delay
                    );
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(30));
                }
                last_err = Some(e);
            }
        }
    }

    Err(last_err.expect("at least one attempt must have been made"))
}
