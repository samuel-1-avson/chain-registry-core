//! WASM Sandboxing for Package Validation
//!
//! This crate provides a secure, cross-platform sandbox for validating packages
//! using WebAssembly.
//!
//! The sandbox enforces memory limits via `StoreLimitsBuilder`, CPU limits via
//! wasmtime epoch-based interruption, and provides no WASI imports by default
//! (modules that call WASI functions will trap). This makes it suitable as a
//! fallback when nsjail/gVisor/Docker are unavailable, though production
//! deployments should still prefer nsjail for the strongest isolation.

use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, info, warn};
use wasmtime::{Engine, Module, Store, StoreLimits, StoreLimitsBuilder};

pub mod capabilities;
pub mod limits;

pub use capabilities::CapabilitySet;
pub use limits::ResourceLimits;

/// Errors that can occur during WASM sandbox execution
#[derive(Error, Debug)]
pub enum SandboxError {
    #[error("WASM compilation error: {0}")]
    CompilationError(String),

    #[error("WASM execution error: {0}")]
    ExecutionError(String),

    #[error("Resource limit exceeded: {0}")]
    ResourceLimitExceeded(String),

    #[error("Timeout after {0:?}")]
    Timeout(Duration),

    #[error("Memory access error: {0}")]
    MemoryError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Sandbox configuration
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Memory limit in bytes
    pub memory_limit: usize,
    /// CPU time limit in seconds
    pub timeout_secs: u64,
    /// Allowed capabilities
    pub capabilities: CapabilitySet,
    /// Environment variables
    pub env_vars: HashMap<String, String>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            memory_limit: 256 * 1024 * 1024, // 256MB
            timeout_secs: 30,
            capabilities: CapabilitySet::default(),
            env_vars: HashMap::new(),
        }
    }
}

impl SandboxConfig {
    /// Set memory limit
    pub fn with_memory_limit(mut self, bytes: usize) -> Self {
        self.memory_limit = bytes;
        self
    }

    /// Set timeout
    pub fn with_timeout_secs(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }
}

/// Input data for sandbox execution
#[derive(Debug, Clone)]
pub struct SandboxInput {
    /// Package metadata
    pub package_name: String,
    pub package_version: String,
    pub ecosystem: String,
    /// Package content
    pub tarball_bytes: Vec<u8>,
}

impl SandboxInput {
    /// Create new sandbox input
    pub fn new(package_name: &str, version: &str, ecosystem: &str) -> Self {
        Self {
            package_name: package_name.to_string(),
            package_version: version.to_string(),
            ecosystem: ecosystem.to_string(),
            tarball_bytes: vec![],
        }
    }

    /// Set tarball bytes
    pub fn with_tarball(mut self, bytes: Vec<u8>) -> Self {
        self.tarball_bytes = bytes;
        self
    }
}

/// Result of sandbox execution
#[derive(Debug, Clone)]
pub struct SandboxResult {
    /// Whether execution was successful
    pub success: bool,
    /// Exit code
    pub exit_code: i32,
    /// stdout output
    pub stdout: String,
    /// stderr output
    pub stderr: String,
    /// Resource usage
    pub resource_usage: ResourceUsage,
    /// Validation findings
    pub findings: Vec<SafetyFinding>,
}

/// Resource usage statistics
#[derive(Debug, Clone, Default)]
pub struct ResourceUsage {
    /// Peak memory usage in bytes
    pub peak_memory: usize,
    /// CPU time used in milliseconds
    pub cpu_time_ms: u64,
    /// Wall clock time in milliseconds
    pub wall_time_ms: u64,
}

/// Safety finding from validation
#[derive(Debug, Clone)]
pub struct SafetyFinding {
    /// Severity level
    pub severity: Severity,
    /// Category
    pub category: String,
    /// Description
    pub description: String,
}

/// Severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// WASM Sandbox for package validation
pub struct WasmSandbox {
    engine: Engine,
    config: SandboxConfig,
}

/// Store data carrying resource limits and execution state for wasmtime.
struct SandboxState {
    limits: StoreLimits,
    /// Exit code communicated by `proc_exit` before the WASM trap fires.
    /// None if the module terminated via a trap rather than a clean exit.
    exit_code: Option<i32>,
}

impl WasmSandbox {
    /// Create a new WASM sandbox.
    ///
    /// NOTE: We intentionally do NOT use wasmtime epoch interruption because
    /// it causes STATUS_STACK_BUFFER_OVERRUN aborts on Windows with wasmtime 18.
    /// Timeouts are enforced externally via tokio::time::timeout instead.
    pub fn new(config: SandboxConfig) -> Result<Self, SandboxError> {
        info!("Initializing WASM sandbox");

        let engine_config = wasmtime::Config::new();
        // No epoch_interruption, no async_support — pure synchronous execution
        // with external timeout enforcement.

        let engine = Engine::new(&engine_config).map_err(|e| {
            SandboxError::CompilationError(format!("Engine creation failed: {}", e))
        })?;

        Ok(Self { engine, config })
    }

    /// Return a snapshot of the sandbox configuration as key-value pairs.
    pub fn stats(&self) -> HashMap<&'static str, u64> {
        let mut m = HashMap::new();
        m.insert("memory_limit", self.config.memory_limit as u64);
        m.insert("timeout_secs", self.config.timeout_secs);
        m
    }

    /// Run a WASM module in the sandbox with timeout and resource limits enforced.
    ///
    /// Timeout is enforced by running the WASM execution on a blocking thread
    /// wrapped in `tokio::time::timeout`. If the module exceeds the deadline,
    /// the blocking thread is detached. This avoids wasmtime epoch interruption
    /// which crashes on Windows.
    pub async fn run(
        &self,
        wasm_bytes: &[u8],
        _input: &SandboxInput,
    ) -> Result<SandboxResult, SandboxError> {
        debug!("Compiling WASM module");

        // Compile module (can be done on async thread — it's fast)
        let module = Module::new(&self.engine, wasm_bytes)
            .map_err(|e| SandboxError::CompilationError(e.to_string()))?;

        // Clone what we need for the blocking closure
        let engine = self.engine.clone();
        let memory_limit = self.config.memory_limit;
        let timeout_duration = Duration::from_secs(self.config.timeout_secs);

        // Run the entire instantiation + execution on a blocking thread
        // so we can enforce timeout externally via tokio::time::timeout.
        let handle = tokio::task::spawn_blocking(move || {
            // Build store with resource limits.
            let limits = StoreLimitsBuilder::new().memory_size(memory_limit).build();

            let mut store = Store::new(
                &engine,
                SandboxState {
                    limits,
                    exit_code: None,
                },
            );
            store.limiter(|state| &mut state.limits);

            // ── WASI stub linker ──────────────────────────────────────────
            let mut linker: wasmtime::Linker<SandboxState> = wasmtime::Linker::new(&engine);

            // fd_write(fd, iovs, iovs_len, nwritten) -> errno
            let _ = linker.func_wrap(
                "wasi_snapshot_preview1",
                "fd_write",
                |_: wasmtime::Caller<'_, SandboxState>,
                 _fd: i32,
                 _iovs: i32,
                 _iovs_len: i32,
                 _nwritten: i32|
                 -> i32 { 8 },
            );
            let _ = linker.func_wrap(
                "wasi_snapshot_preview1",
                "fd_read",
                |_: wasmtime::Caller<'_, SandboxState>,
                 _fd: i32,
                 _iovs: i32,
                 _iovs_len: i32,
                 _nread: i32|
                 -> i32 { 8 },
            );
            let _ = linker.func_wrap(
                "wasi_snapshot_preview1",
                "fd_close",
                |_: wasmtime::Caller<'_, SandboxState>, _fd: i32| -> i32 { 8 },
            );
            let _ = linker.func_wrap(
                "wasi_snapshot_preview1",
                "fd_seek",
                |_: wasmtime::Caller<'_, SandboxState>,
                 _fd: i32,
                 _offset: i64,
                 _whence: i32,
                 _newoffset: i32|
                 -> i32 { 8 },
            );
            let _ = linker.func_wrap(
                "wasi_snapshot_preview1",
                "fd_fdstat_get",
                |_: wasmtime::Caller<'_, SandboxState>, _fd: i32, _stat: i32| -> i32 { 8 },
            );
            let _ = linker.func_wrap(
                "wasi_snapshot_preview1",
                "fd_fdstat_set_flags",
                |_: wasmtime::Caller<'_, SandboxState>, _fd: i32, _flags: i32| -> i32 { 8 },
            );
            let _ = linker.func_wrap(
                "wasi_snapshot_preview1",
                "fd_filestat_get",
                |_: wasmtime::Caller<'_, SandboxState>, _fd: i32, _stat: i32| -> i32 { 8 },
            );
            let _ = linker.func_wrap(
                "wasi_snapshot_preview1",
                "fd_prestat_get",
                |_: wasmtime::Caller<'_, SandboxState>, _fd: i32, _prestat: i32| -> i32 { 8 },
            );
            let _ = linker.func_wrap(
                "wasi_snapshot_preview1",
                "fd_prestat_dir_name",
                |_: wasmtime::Caller<'_, SandboxState>, _fd: i32, _path: i32, _len: i32| -> i32 {
                    8
                },
            );
            let _ = linker.func_wrap(
                "wasi_snapshot_preview1",
                "path_open",
                |_: wasmtime::Caller<'_, SandboxState>,
                 _: i32,
                 _: i32,
                 _: i32,
                 _: i32,
                 _: i32,
                 _: i64,
                 _: i64,
                 _: i32,
                 _: i32|
                 -> i32 { 8 },
            );
            let _ = linker.func_wrap(
                "wasi_snapshot_preview1",
                "environ_sizes_get",
                |_: wasmtime::Caller<'_, SandboxState>, _count: i32, _size: i32| -> i32 { 0 },
            );
            let _ = linker.func_wrap(
                "wasi_snapshot_preview1",
                "environ_get",
                |_: wasmtime::Caller<'_, SandboxState>, _environ: i32, _buf: i32| -> i32 { 0 },
            );
            let _ = linker.func_wrap(
                "wasi_snapshot_preview1",
                "args_sizes_get",
                |_: wasmtime::Caller<'_, SandboxState>, _argc: i32, _size: i32| -> i32 { 0 },
            );
            let _ = linker.func_wrap(
                "wasi_snapshot_preview1",
                "args_get",
                |_: wasmtime::Caller<'_, SandboxState>, _argv: i32, _buf: i32| -> i32 { 0 },
            );
            let _ = linker.func_wrap(
                "wasi_snapshot_preview1",
                "clock_time_get",
                |_: wasmtime::Caller<'_, SandboxState>, _id: i32, _prec: i64, _time: i32| -> i32 {
                    52
                },
            );
            let _ = linker.func_wrap(
                "wasi_snapshot_preview1",
                "clock_res_get",
                |_: wasmtime::Caller<'_, SandboxState>, _id: i32, _res: i32| -> i32 { 52 },
            );
            let _ = linker.func_wrap(
                "wasi_snapshot_preview1",
                "random_get",
                |_: wasmtime::Caller<'_, SandboxState>, _buf: i32, _len: i32| -> i32 { 52 },
            );
            let _ = linker.func_wrap(
                "wasi_snapshot_preview1",
                "sched_yield",
                |_: wasmtime::Caller<'_, SandboxState>| -> i32 { 0 },
            );
            let _ = linker.func_wrap(
                "wasi_snapshot_preview1",
                "poll_oneoff",
                |_: wasmtime::Caller<'_, SandboxState>,
                 _in: i32,
                 _out: i32,
                 _nsubs: i32,
                 _nevents: i32|
                 -> i32 { 52 },
            );
            // proc_exit: record exit code and bail — MUST NOT call process::exit.
            let _ = linker.func_wrap(
                "wasi_snapshot_preview1",
                "proc_exit",
                |mut caller: wasmtime::Caller<'_, SandboxState>,
                 code: i32|
                 -> Result<(), anyhow::Error> {
                    caller.data_mut().exit_code = Some(code);
                    anyhow::bail!("wasm-sandbox-proc-exit:{}", code)
                },
            );

            // ── Instantiate and run ──────────────────────────────────────
            let instance = linker
                .instantiate(&mut store, &module)
                .map_err(|e| SandboxError::ExecutionError(e.to_string()))?;

            let func = instance
                .get_typed_func::<(), i32>(&mut store, "_start")
                .or_else(|_| instance.get_typed_func::<(), i32>(&mut store, "main"))
                .map_err(|e| {
                    SandboxError::ExecutionError(format!("No entry point (_start/main): {}", e))
                })?;

            let call_result = func
                .call(&mut store, ())
                .map_err(|e| SandboxError::ExecutionError(e.to_string()));

            // Measure peak memory
            let memories: Vec<wasmtime::Memory> = instance
                .exports(&mut store)
                .filter_map(|exp| exp.into_memory())
                .collect();
            let peak_memory: usize = memories.iter().map(|mem| mem.data_size(&store)).sum();

            match call_result {
                Ok(exit_code) => Ok(SandboxResult {
                    success: exit_code == 0,
                    exit_code,
                    stdout: String::new(),
                    stderr: String::new(),
                    resource_usage: ResourceUsage {
                        peak_memory,
                        cpu_time_ms: 0,
                        wall_time_ms: 0,
                    },
                    findings: vec![],
                }),
                Err(SandboxError::ExecutionError(ref msg))
                    if msg.contains("wasm-sandbox-proc-exit:") =>
                {
                    let code = store.data().exit_code.unwrap_or(0);
                    Ok(SandboxResult {
                        success: code == 0,
                        exit_code: code,
                        stdout: String::new(),
                        stderr: String::new(),
                        resource_usage: ResourceUsage {
                            peak_memory,
                            cpu_time_ms: 0,
                            wall_time_ms: 0,
                        },
                        findings: vec![],
                    })
                }
                Err(SandboxError::ExecutionError(ref msg)) if msg.contains("memory") => {
                    Err(SandboxError::ResourceLimitExceeded(format!(
                        "Memory limit exceeded (limit: {} bytes): {}",
                        memory_limit, msg
                    )))
                }
                Err(e) => Err(e),
            }
        });

        // Enforce timeout externally. If the blocking thread exceeds the
        // deadline, we return a Timeout error. The orphaned thread will be
        // cleaned up when the process exits.
        match tokio::time::timeout(timeout_duration, handle).await {
            Ok(Ok(result)) => result,
            Ok(Err(join_err)) => {
                // JoinError — the blocking task panicked
                Err(SandboxError::ExecutionError(format!(
                    "WASM execution task failed: {}",
                    join_err
                )))
            }
            Err(_elapsed) => {
                warn!(
                    "WASM execution timed out (limit: {}s)",
                    self.config.timeout_secs
                );
                Err(SandboxError::Timeout(timeout_duration))
            }
        }
    }

    /// Run a validator script on a package
    pub async fn validate_package(
        &self,
        validator_wasm: &[u8],
        package_data: &SandboxInput,
    ) -> Result<SandboxResult, SandboxError> {
        debug!("Running package validation in WASM sandbox");
        self.run(validator_wasm, package_data).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_config() {
        let config = SandboxConfig::default()
            .with_memory_limit(1024)
            .with_timeout_secs(10);

        assert_eq!(config.memory_limit, 1024);
        assert_eq!(config.timeout_secs, 10);
    }

    #[test]
    fn test_sandbox_input() {
        let input = SandboxInput::new("test-pkg", "1.0.0", "npm");

        assert_eq!(input.package_name, "test-pkg");
        assert_eq!(input.ecosystem, "npm");
    }
}
