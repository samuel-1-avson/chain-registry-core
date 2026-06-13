// crates/node/src/pidlock.rs
// Single-node-per-data-directory enforcement via PID lock file.
//
// On **mainnet** (`CREG_TESTNET=false`, the default) the node writes
// `creg-node.lock` into its data directory at startup. If the file already
// exists and the recorded process is still alive, the node refuses to start.
// This prevents operators from accidentally running two validators on the
// same machine which would double-sign and get slashed.
//
// On **testnet** (`CREG_TESTNET=true`) the lock is skipped entirely so that
// developers can spin up multiple nodes on one machine for local testing.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

const LOCK_FILE_NAME: &str = "creg-node.lock";

pub struct PidLock {
    path: PathBuf,
}

impl PidLock {
    /// Attempt to acquire the lock.
    ///
    /// * If the lock file does not exist → create it with our PID.
    /// * If the lock file exists and the PID inside is still alive → bail.
    /// * If the lock file exists but the PID is stale → overwrite with our PID.
    pub fn acquire(data_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(data_dir)
            .with_context(|| format!("Failed to create data directory {}", data_dir.display()))?;

        let path = data_dir.join(LOCK_FILE_NAME);
        let our_pid = std::process::id();

        if path.exists() {
            let contents = std::fs::read_to_string(&path)
                .with_context(|| format!("Failed to read lock file {}", path.display()))?;

            if let Ok(existing_pid) = contents.trim().parse::<u32>() {
                if is_process_alive(existing_pid) {
                    bail!(
                        "Another chain-registry node is already running (PID {pid}).\n\
                         Lock file: {lock}\n\n\
                         Mainnet enforces one node per machine. If the previous node \
                         crashed, delete the lock file and retry:\n\
                         \n    rm {lock}\n\n\
                         For multi-node testing, set CREG_TESTNET=true.",
                        pid = existing_pid,
                        lock = path.display(),
                    );
                }
                tracing::warn!(
                    "Stale lock file found (PID {} is not running). Reclaiming.",
                    existing_pid
                );
            }
        }

        std::fs::write(&path, our_pid.to_string())
            .with_context(|| format!("Failed to write lock file {}", path.display()))?;

        tracing::info!("PID lock acquired (PID {}, {})", our_pid, path.display());

        Ok(Self { path })
    }

    /// Release the lock by removing the file.
    pub fn release(&self) {
        if self.path.exists() {
            if let Err(e) = std::fs::remove_file(&self.path) {
                tracing::warn!("Failed to remove lock file {}: {}", self.path.display(), e);
            } else {
                tracing::info!("PID lock released ({})", self.path.display());
            }
        }
    }
}

impl Drop for PidLock {
    fn drop(&mut self) {
        self.release();
    }
}

/// Check whether a process with the given PID is still alive.
#[cfg(unix)]
fn is_process_alive(pid: u32) -> bool {
    // kill(pid, 0) checks existence without sending a signal.
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

#[cfg(windows)]
fn is_process_alive(pid: u32) -> bool {
    use std::process::Command;
    // `tasklist /FI "PID eq <pid>"` returns the process row if alive.
    Command::new("tasklist")
        .args(["/FI", &format!("PID eq {}", pid), "/NH"])
        .output()
        .map(|o| {
            let stdout = String::from_utf8_lossy(&o.stdout);
            // If the PID is found, tasklist prints its name; otherwise
            // it prints "INFO: No tasks are running..."
            !stdout.contains("No tasks are running")
                && !stdout.contains("INFO:")
                && stdout.contains(&pid.to_string())
        })
        .unwrap_or(false)
}

#[cfg(not(any(unix, windows)))]
fn is_process_alive(_pid: u32) -> bool {
    // Conservative: assume alive on unknown platforms.
    true
}
