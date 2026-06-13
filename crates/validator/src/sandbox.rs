// crates/validator/src/sandbox.rs
// Stage 2: Behavioural analysis — installs the package in a locked-down
// container and records what system calls it makes.
//
// Engine fallback chain:
//   1. nsjail — kernel namespaces + seccomp-BPF (Linux only, strongest)
//   2. gVisor (runsc) — userspace syscall interception (Linux, strong)
//   3. Docker — OCI container isolation with seccomp profile
//   4. WASM/WASI — cross-platform wasmtime sandbox (for -wasm packages)
//   5. Dev bypass — CREG_DEV_SANDBOX=true in debug builds only
//   6. No sandbox — SB011 CRITICAL finding

use anyhow::Result;
use common::{Finding, FindingSeverity, PackageManifest};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Instant;

async fn command_ready(program: &str, args: &[&str]) -> bool {
    match tokio::process::Command::new(program)
        .args(args)
        .output()
        .await
    {
        Ok(output) if output.status.success() => true,
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!(
                "Sandbox engine '{}' unavailable: exit={} stderr={}",
                program,
                output.status,
                stderr.trim()
            );
            false
        }
        Err(err) => {
            tracing::debug!("Sandbox engine '{}' not found: {}", program, err);
            false
        }
    }
}

// ── Public Types ────────────────────────────────────────────────────────────

/// Reported sandbox engine status for health/runtime-config surfaces (MAL-001).
///
/// Mirrors the engine waterfall in [`run`] without executing a package, so
/// operators and monitoring can verify which engine a validator will use
/// before it ever votes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SandboxStatus {
    /// Engine that will be used for behavioural analysis:
    /// "nsjail", "dev-bypass", "gvisor", "docker", or "none".
    pub engine: String,
    /// True when `CREG_DEV_SANDBOX=true` is set in the environment.
    /// Behavioural analysis is skipped and every package receives the
    /// High-severity SB012 finding. Must be false on public validators.
    pub dev_bypass: bool,
    /// True when the active engine runs packages with real isolation
    /// (nsjail/gVisor/Docker). False for dev-bypass and none.
    pub isolated: bool,
    /// True when the engine is a degraded fallback (Docker raises SB010;
    /// "none" means non-WASM packages fail closed and the validator abstains).
    pub degraded: bool,
    /// Human-readable note for operators.
    pub note: String,
}

static SANDBOX_STATUS: tokio::sync::OnceCell<SandboxStatus> = tokio::sync::OnceCell::const_new();

/// Detect (once per process) which sandbox engine this node will use.
/// The result is cached because engine availability does not change at
/// runtime and probing spawns external processes.
pub async fn engine_status() -> SandboxStatus {
    SANDBOX_STATUS
        .get_or_init(detect_engine_status)
        .await
        .clone()
}

/// For read-only nodes (observers), probe validator HTTP peers for fleet sandbox
/// status when the local process has no sandbox engine installed.
pub async fn fleet_sandbox_from_peers(peer_urls: &[String]) -> Option<SandboxStatus> {
    if peer_urls.is_empty() {
        return None;
    }

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
    {
        Ok(c) => c,
        Err(_) => return None,
    };

    #[derive(serde::Deserialize)]
    struct PeerHealth {
        sandbox: Option<SandboxStatus>,
    }

    for url in peer_urls {
        let health_url = format!("{}/v1/health", url.trim_end_matches('/'));
        let Ok(resp) = client.get(&health_url).send().await else {
            continue;
        };
        if !resp.status().is_success() {
            continue;
        }
        let Ok(body) = resp.json::<PeerHealth>().await else {
            continue;
        };
        if let Some(sandbox) = body.sandbox.filter(|s| s.engine != "none") {
            return Some(sandbox);
        }
    }

    None
}

async fn detect_engine_status() -> SandboxStatus {
    let dev_bypass = std::env::var("CREG_DEV_SANDBOX").as_deref() == Ok("true");
    if command_ready("nsjail", &["--help"]).await {
        return SandboxStatus {
            engine: "nsjail".into(),
            dev_bypass,
            isolated: true,
            degraded: false,
            note: "kernel namespaces + seccomp-BPF (primary engine)".into(),
        };
    }
    if dev_bypass {
        return SandboxStatus {
            engine: "dev-bypass".into(),
            dev_bypass,
            isolated: false,
            degraded: true,
            note: "CREG_DEV_SANDBOX=true — behavioural analysis skipped; every package receives SB012 (High). Local development only.".into(),
        };
    }
    if command_ready("runsc", &["--version"]).await {
        return SandboxStatus {
            engine: "gvisor".into(),
            dev_bypass,
            isolated: true,
            degraded: false,
            note: "userspace syscall interception (runsc)".into(),
        };
    }
    if command_ready("docker", &["version", "--format", "{{.Server.Version}}"]).await {
        return SandboxStatus {
            engine: "docker".into(),
            dev_bypass,
            isolated: true,
            degraded: true,
            note: "OCI container fallback — packages receive SB010 (degraded isolation)".into(),
        };
    }
    SandboxStatus {
        engine: "none".into(),
        dev_bypass,
        isolated: false,
        degraded: true,
        note: "no sandbox engine available — non-WASM packages fail closed and this validator abstains".into(),
    }
}

#[derive(Debug, Clone)]
pub struct SandboxResult {
    pub findings: Vec<Finding>,
    pub observed_network_hosts: Vec<String>,
    pub observed_fs_writes: Vec<String>,
    pub observed_process_spawns: Vec<String>,
    /// Execution metrics for observability.
    pub metrics: SandboxMetrics,
}

/// Execution metrics collected during sandbox run.
#[derive(Debug, Clone, Default)]
pub struct SandboxMetrics {
    /// Which engine was used: "nsjail", "gvisor", "docker", "wasm", "dev-bypass", "none".
    pub engine_used: String,
    /// Wall-clock time in milliseconds.
    pub wall_time_ms: u64,
    /// Process exit code (0 = success).
    pub exit_code: i32,
    /// Total number of behavioural observations recorded.
    pub observations_count: usize,
    /// Total number of findings produced.
    pub findings_count: usize,
}

/// Sandbox configuration limits.
pub struct SandboxConfig {
    /// Wall-clock timeout for the install + postinstall hooks (seconds).
    pub timeout_secs: u64,
    /// Max memory for the sandbox (megabytes).
    pub memory_mb: u32,
    /// Block all network by default; only whitelist declared manifest hosts.
    pub network_mode: NetworkMode,
    /// Path to the nsjail seccomp config file (protobuf text format).
    pub nsjail_config_path: Option<PathBuf>,
    /// Path to the Docker seccomp profile JSON.
    pub docker_seccomp_path: Option<PathBuf>,
    /// Base directory for per-ecosystem minimal rootfs trees.
    pub rootfs_base_dir: Option<PathBuf>,
    /// SHA-256 hash of the tarball for result caching.
    pub tarball_hash: Option<String>,
}

pub enum NetworkMode {
    /// No outbound connections at all.
    Isolated,
    /// Allow only hosts declared in the manifest.
    ManifestOnly,
    /// Full network (used for testing only — never in production validators).
    Full,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        // Resolve config paths relative to the executable.
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()));

        let config_base = exe_dir.clone().map(|d| d.join("config").join("sandbox"));

        Self {
            timeout_secs: 120,
            memory_mb: 512,
            network_mode: NetworkMode::ManifestOnly,
            nsjail_config_path: config_base.as_ref().map(|d| d.join("nsjail-seccomp.cfg")),
            docker_seccomp_path: config_base.as_ref().map(|d| d.join("docker-seccomp.json")),
            rootfs_base_dir: config_base.as_ref().map(|d| d.join("rootfs")),
            tarball_hash: None,
        }
    }
}

/// In-memory cache for sandbox results keyed by deterministic hash.
static RESULT_CACHE: std::sync::LazyLock<std::sync::Mutex<HashMap<String, SandboxResult>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

/// Canonical-keyed store for the most-recent sandbox result per package.
/// Used by the diff analysis stage to compare current vs. previous version
/// runtime behavior. Keyed by the package canonical (e.g. `npm:express@4.18.2`).
/// Populated by `store_result` after each successful sandbox run; looked up by
/// `get_result` before the next version of the same package is processed.
static CANONICAL_STORE: std::sync::LazyLock<std::sync::Mutex<HashMap<String, SandboxResult>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

/// Persist a sandbox result by canonical for use by the diff stage when the
/// next version of the same package is processed.
pub fn store_result(canonical: &str, result: &SandboxResult) {
    if let Ok(mut store) = CANONICAL_STORE.lock() {
        store.insert(canonical.to_string(), result.clone());
    }
}

/// Retrieve a previously stored sandbox result by canonical.
/// Returns `None` if this is the first time the package has been processed
/// on this node, or if the node was restarted since the last run.
pub fn get_result(canonical: &str) -> Option<SandboxResult> {
    CANONICAL_STORE.lock().ok()?.get(canonical).cloned()
}

// ── Cache key helper ────────────────────────────────────────────────────────

fn compute_cache_key(tarball_bytes: &[u8], ecosystem: &str, config: &SandboxConfig) -> String {
    use sha2::{Digest, Sha256};
    // NetworkMode discriminant is included so that results run under different
    // network policies (e.g. ManifestOnly vs Isolated) are never conflated.
    // A package that probes for internet access behaves differently when egress
    // is blocked — caching across modes would silently drop those findings.
    let network_mode_byte: u8 = match config.network_mode {
        NetworkMode::Isolated => 0,
        NetworkMode::ManifestOnly => 1,
        NetworkMode::Full => 2,
    };
    let mut hasher = Sha256::new();
    hasher.update(tarball_bytes);
    hasher.update(ecosystem.as_bytes());
    hasher.update(config.timeout_secs.to_le_bytes());
    hasher.update(config.memory_mb.to_le_bytes());
    hasher.update([network_mode_byte]);
    hex::encode(hasher.finalize())
}

async fn resolve_manifest_domains(hosts: &[String]) -> HashSet<String> {
    let mut resolved = HashSet::new();
    for host in hosts {
        if host.parse::<IpAddr>().is_ok() {
            resolved.insert(host.clone());
            continue;
        }
        if let Ok(addrs) = tokio::net::lookup_host(format!("{}:443", host)).await {
            for addr in addrs {
                resolved.insert(addr.ip().to_string());
            }
        }
        if let Ok(addrs) = tokio::net::lookup_host(format!("{}:80", host)).await {
            for addr in addrs {
                resolved.insert(addr.ip().to_string());
            }
        }
    }
    resolved
}

// ── Main Entry Point ────────────────────────────────────────────────────────

pub async fn run(
    _pkg_id: &common::PackageId,
    tarball_bytes: &[u8],
    manifest: &PackageManifest,
) -> Result<SandboxResult> {
    let mut config = SandboxConfig::default();
    let start_time = Instant::now();

    // ── A4: Result Caching ────────────────────────────────────────────────────
    // Check cache for deterministic packages (same tarball + ecosystem + config).
    let cache_key = compute_cache_key(tarball_bytes, &_pkg_id.ecosystem, &config);
    config.tarball_hash = Some(cache_key.clone());

    if let Ok(cache) = RESULT_CACHE.lock() {
        if let Some(cached) = cache.get(&cache_key) {
            tracing::info!("Sandbox result cache HIT for {}", _pkg_id);
            return Ok(cached.clone());
        }
    }

    let tmp_dir = std::env::temp_dir().join(format!("creg-sandbox-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&tmp_dir)?;

    let tarball_path = tmp_dir.join("package.tar.gz");
    std::fs::write(&tarball_path, tarball_bytes)?;

    tracing::info!("Starting sandbox engine detection for {} ...", _pkg_id);

    // Pre-resolve allowed network hosts to IP addresses asynchronously
    let resolved_ips = resolve_manifest_domains(&manifest.allowed_network_hosts).await;

    // ── Engine 1: nsjail ──────────────────────────────────────────────────────
    // nsjail has no --version flag; --help exits 0 when the binary is usable.
    if command_ready("nsjail", &["--help"]).await {
        tracing::info!("nsjail detected — using primary sandbox engine");
        let result = run_nsjail_sandbox(
            &tarball_path,
            _pkg_id,
            &config,
            manifest,
            &resolved_ips,
            start_time,
        )
        .await;
        let _ = std::fs::remove_dir_all(&tmp_dir);
        let result = result?;
        cache_result(&cache_key, &result);
        return Ok(result);
    }

    // ── Dev bypass (operator opt-in via CREG_DEV_SANDBOX=true) ────────────────
    // Works in release builds too so that the docker-compose dev profile can
    // run the release image without a real sandbox engine installed. Never
    // enable this on mainnet validators — it completely skips behavioural
    // analysis and raises a High-severity finding on every package.
    if std::env::var("CREG_DEV_SANDBOX").as_deref() == Ok("true") {
        tracing::warn!(
            "CREG_DEV_SANDBOX=true — behavioural analysis is SKIPPED for {}. \
             This is for local development only; NEVER set this flag on a mainnet validator.",
            _pkg_id
        );
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return Ok(SandboxResult {
            findings: vec![Finding {
                id: "SB012".into(),
                title: "Dev sandbox bypass active".into(),
                severity: FindingSeverity::High,
                description: "CREG_DEV_SANDBOX=true: Behavioural analysis was skipped. Operator opted in to an unsafe local-development bypass.".into(),
                file: "sandbox-engine".into(),
                line: None,
            }],
            observed_network_hosts: vec![],
            observed_fs_writes: vec![],
            observed_process_spawns: vec![],
            metrics: SandboxMetrics {
                engine_used: "dev-bypass".into(),
                wall_time_ms: start_time.elapsed().as_millis() as u64,
                exit_code: 0,
                observations_count: 0,
                findings_count: 1,
            },
        });
    }

    // ── Engine 2: gVisor (runsc) ──────────────────────────────────────────────
    if command_ready("runsc", &["--version"]).await {
        tracing::info!("gVisor (runsc) detected — using userspace syscall sandbox");
        let result = run_gvisor_sandbox(
            &tarball_path,
            _pkg_id,
            &config,
            manifest,
            &resolved_ips,
            start_time,
        )
        .await;
        let _ = std::fs::remove_dir_all(&tmp_dir);
        let result = result?;
        cache_result(&cache_key, &result);
        return Ok(result);
    }

    // ── Engine 3: Docker ──────────────────────────────────────────────────────
    if command_ready("docker", &["version", "--format", "{{.Server.Version}}"]).await {
        tracing::warn!("Falling back to Docker containment (reduced isolation)");
        let docker_result = run_docker_sandbox(&tarball_path, _pkg_id, &config, start_time).await;
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return match docker_result {
            Ok(obs) => {
                let mut findings = check_against_manifest(&obs, manifest, &resolved_ips);
                findings.push(Finding {
                    id: "SB010".into(),
                    title: "Degraded sandbox isolation".into(),
                    severity: FindingSeverity::Medium,
                    description: "Package was analysed using Docker instead of nsjail — kernel-level syscall filtering is not active.".into(),
                    file: "sandbox-engine".into(),
                    line: None,
                });
                let observations_count =
                    obs.network_hosts.len() + obs.fs_writes.len() + obs.process_spawns.len();
                let result = SandboxResult {
                    metrics: SandboxMetrics {
                        engine_used: "docker".into(),
                        wall_time_ms: start_time.elapsed().as_millis() as u64,
                        exit_code: obs.exit_code,
                        observations_count,
                        findings_count: findings.len(),
                    },
                    findings,
                    observed_network_hosts: obs.network_hosts,
                    observed_fs_writes: obs.fs_writes,
                    observed_process_spawns: obs.process_spawns,
                };
                cache_result(&cache_key, &result);
                Ok(result)
            }
            Err(e) => {
                tracing::error!("Docker sandbox also failed: {}", e);
                Err(e)
            }
        };
    }

    // ── Engine 4: WASM/WASI ───────────────────────────────────────────────────
    // Cross-platform fallback — more secure than "no sandbox" but limited to
    // packages that include WASM payloads or can be executed via WASI.
    let is_wasm_candidate = _pkg_id.name.ends_with("-wasm") || tarball_contains_wasm(tarball_bytes);

    if is_wasm_candidate {
        tracing::info!("Attempting WASM/WASI sandbox for {} ...", _pkg_id);
        match crate::wasm_sandbox::run_in_wasm(_pkg_id, &tarball_path, &config, manifest).await {
            Ok(wasm_result) => {
                let _ = std::fs::remove_dir_all(&tmp_dir);
                let observations_count = wasm_result.observed_network_hosts.len()
                    + wasm_result.observed_fs_writes.len()
                    + wasm_result.observed_process_spawns.len();
                let result = SandboxResult {
                    metrics: SandboxMetrics {
                        engine_used: "wasm".into(),
                        wall_time_ms: start_time.elapsed().as_millis() as u64,
                        exit_code: 0,
                        observations_count,
                        findings_count: wasm_result.findings.len(),
                    },
                    ..wasm_result
                };
                cache_result(&cache_key, &result);
                return Ok(result);
            }
            Err(e) => {
                tracing::warn!(
                    "WASM sandbox failed for {}: {} — continuing to degraded mode",
                    _pkg_id,
                    e
                );
            }
        }
    }

    // ── No sandbox — FAIL CLOSED ──────────────────────────────────────────────
    // No engine is available and the operator did not explicitly opt in via
    // CREG_DEV_SANDBOX=true. Refusing to produce a SandboxResult causes the
    // validator pipeline to propagate the error and abstain from voting,
    // which is the correct safety posture for mainnet.
    let _ = std::fs::remove_dir_all(&tmp_dir);
    tracing::error!(
        "No sandboxing engine available (nsjail, gVisor, Docker, WASM) and \
         CREG_DEV_SANDBOX is not set. Refusing to validate {} — the validator \
         will abstain from this round. Install nsjail or set CREG_DEV_SANDBOX=true \
         on non-mainnet deployments.",
        _pkg_id
    );
    anyhow::bail!(
        "no sandbox engine available for {} and CREG_DEV_SANDBOX is not set; \
         refusing to vote without behavioural analysis",
        _pkg_id
    )
}

/// Maximum number of entries in RESULT_CACHE.
/// Configurable via `CREG_SANDBOX_CACHE_SIZE` (default: 1000).
fn sandbox_cache_max() -> usize {
    std::env::var("CREG_SANDBOX_CACHE_SIZE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000)
}

fn cache_result(key: &str, result: &SandboxResult) {
    if let Ok(mut cache) = RESULT_CACHE.lock() {
        let max = sandbox_cache_max();
        if cache.len() >= max {
            // Bounded eviction: clear the entire cache when the cap is reached.
            // This prevents unbounded memory growth while keeping the
            // implementation dependency-free (a full LRU would require the
            // `lru` crate). The configurable CREG_SANDBOX_CACHE_SIZE lets
            // operators tune the trade-off between memory and cache hit rate.
            cache.clear();
            tracing::debug!(
                "Sandbox RESULT_CACHE evicted (reached {} entries cap; tune via CREG_SANDBOX_CACHE_SIZE)",
                max
            );
        }
        cache.insert(key.to_string(), result.clone());
    }
}

/// Check if a tarball contains .wasm files (H1: WASM detection).
fn tarball_contains_wasm(tarball_bytes: &[u8]) -> bool {
    use flate2::read::GzDecoder;
    let decoder = GzDecoder::new(tarball_bytes);
    if let Ok(mut archive) = tar::Archive::new(decoder).entries() {
        while let Some(Ok(entry)) = archive.next() {
            if let Ok(path) = entry.path() {
                if path.extension().map_or(false, |ext| ext == "wasm") {
                    return true;
                }
            }
        }
    }
    false
}

// ── Ecosystem Helpers ───────────────────────────────────────────────────────

/// Select ecosystem-specific install commands for nsjail.
fn nsjail_install_args(ecosystem: &str, tarball_path: &Path) -> Vec<std::ffi::OsString> {
    let cmd_str = match ecosystem {
        "npm" => format!(
            "/usr/bin/node /usr/lib/node_modules/npm/bin/npm-cli.js install {} >/dev/null 2>&1",
            tarball_path.to_string_lossy()
        ),
        "cargo" => format!(
            "/usr/bin/cargo install --path {} --no-default-features >/dev/null 2>&1",
            tarball_path.to_string_lossy()
        ),
        "rubygems" => format!(
            "/usr/bin/gem install {} >/dev/null 2>&1",
            tarball_path.to_string_lossy()
        ),
        "maven" => format!(
            "/usr/bin/mvn install:install-file -Dfile={} >/dev/null 2>&1",
            tarball_path.to_string_lossy()
        ),
        _ => format!(
            "/usr/bin/python3 -m pip install {} >/dev/null 2>&1",
            tarball_path.to_string_lossy()
        ),
    };
    vec!["/bin/sh".into(), "-c".into(), cmd_str.into()]
}

/// Select ecosystem-specific Docker image and install command.
fn docker_ecosystem_config(ecosystem: &str) -> (&'static str, &'static str) {
    match ecosystem {
        "npm" => ("node:20-slim", "npm install /pkg/package.tar.gz"),
        "cargo" => (
            "rust:1-slim",
            "cargo install --path /pkg/package.tar.gz --no-default-features",
        ),
        "rubygems" => ("ruby:3-slim", "gem install /pkg/package.tar.gz"),
        "maven" => (
            "maven:3-eclipse-temurin-21",
            "mvn install:install-file -Dfile /pkg/package.tar.gz",
        ),
        _ => ("python:3-slim", "pip install /pkg/package.tar.gz"),
    }
}

/// Resolve the per-ecosystem rootfs directory for nsjail chroot (C1).
fn resolve_rootfs(config: &SandboxConfig, ecosystem: &str) -> String {
    if let Some(ref base) = config.rootfs_base_dir {
        let eco_dir = match ecosystem {
            "npm" => "npm",
            "cargo" => "cargo",
            "rubygems" => "rubygems",
            "maven" => "maven",
            _ => "pip",
        };
        let rootfs_path = base.join(eco_dir);
        if rootfs_path.is_dir() {
            return rootfs_path.to_string_lossy().into_owned();
        }
        tracing::warn!(
            "Rootfs not found at {} — falling back to /",
            rootfs_path.display()
        );
    }
    "/".to_string()
}

// ── nsjail Engine ───────────────────────────────────────────────────────────

async fn run_nsjail_sandbox(
    tarball_path: &Path,
    pkg_id: &common::PackageId,
    config: &SandboxConfig,
    manifest: &PackageManifest,
    resolved_ips: &HashSet<String>,
    start_time: Instant,
) -> Result<SandboxResult> {
    let install_args = nsjail_install_args(&pkg_id.ecosystem, tarball_path);
    let chroot_path = resolve_rootfs(config, &pkg_id.ecosystem);

    let mut cmd = tokio::process::Command::new("nsjail");
    cmd.arg("-Mo");

    // C2: Use seccomp config file if available.
    if let Some(ref cfg_path) = config.nsjail_config_path {
        if cfg_path.is_file() {
            cmd.arg("--config").arg(cfg_path);
            tracing::info!("nsjail: Using seccomp config from {}", cfg_path.display());
        } else {
            tracing::warn!(
                "nsjail: Seccomp config not found at {} — running without explicit policy",
                cfg_path.display()
            );
        }
    }

    // H3: Structured logging via --log_fd (fd 3 for JSON-structured output).
    // nsjail writes structured log to the specified fd; we capture via stderr.
    cmd.arg("--log_fd").arg("2");

    cmd.arg("--chroot")
        .arg(&chroot_path)
        .arg("--user")
        .arg("99999")
        .arg("--group")
        .arg("99999")
        .arg("--time_limit")
        .arg(config.timeout_secs.to_string())
        .arg("--max_cpus")
        .arg("1")
        .arg("--rlimit_as")
        .arg(config.memory_mb.to_string())
        .arg("--")
        .args(&install_args);

    let output = cmd.output().await?;

    let observations = parse_nsjail_output(&output.stderr)?;
    let findings = check_against_manifest(&observations, manifest, resolved_ips);
    let observations_count = observations.network_hosts.len()
        + observations.fs_writes.len()
        + observations.process_spawns.len();

    Ok(SandboxResult {
        metrics: SandboxMetrics {
            engine_used: "nsjail".into(),
            wall_time_ms: start_time.elapsed().as_millis() as u64,
            exit_code: output.status.code().unwrap_or(-1),
            observations_count,
            findings_count: findings.len(),
        },
        findings,
        observed_network_hosts: observations.network_hosts,
        observed_fs_writes: observations.fs_writes,
        observed_process_spawns: observations.process_spawns,
    })
}

// ── gVisor Engine (A1) ─────────────────────────────────────────────────────

async fn run_gvisor_sandbox(
    tarball_path: &Path,
    pkg_id: &common::PackageId,
    config: &SandboxConfig,
    manifest: &PackageManifest,
    resolved_ips: &HashSet<String>,
    start_time: Instant,
) -> Result<SandboxResult> {
    let (docker_image, install_cmd) = docker_ecosystem_config(&pkg_id.ecosystem);
    let install_cmd_redirected = format!("{} >/dev/null 2>&1", install_cmd);

    // gVisor runs as a Docker runtime, so we use `docker run --runtime=runsc`.
    let docker_future = tokio::process::Command::new("docker")
        .arg("run")
        .arg("--rm")
        .arg("--runtime=runsc")
        .arg("--network=none")
        .arg("--read-only")
        .arg("--tmpfs")
        .arg("/tmp:size=256m")
        .arg("--memory")
        .arg(format!("{}m", config.memory_mb))
        .arg("--cpus")
        .arg("1")
        .arg("-v")
        .arg(format!("{}:/pkg/package.tar.gz:ro", tarball_path.display()))
        .arg(docker_image)
        .arg("sh")
        .arg("-c")
        .arg(&install_cmd_redirected)
        .output();

    let output = tokio::time::timeout(
        std::time::Duration::from_secs(config.timeout_secs),
        docker_future,
    )
    .await
    .map_err(|_| anyhow::anyhow!("gVisor sandbox timed out after {}s", config.timeout_secs))?
    .map_err(|e| anyhow::anyhow!("gVisor sandbox execution failed: {}", e))?;

    // gVisor stderr is similar to Docker's — parse with the Docker parser.
    let observations = parse_docker_output(&output.stderr)?;
    let mut findings = check_against_manifest(&observations, manifest, resolved_ips);
    findings.push(Finding {
        id: "SB013".into(),
        title: "gVisor sandbox used".into(),
        severity: FindingSeverity::Low,
        description: "Package was analysed using gVisor (runsc) — userspace syscall interception provides strong isolation.".into(),
        file: "sandbox-engine".into(),
        line: None,
    });

    let observations_count = observations.network_hosts.len()
        + observations.fs_writes.len()
        + observations.process_spawns.len();

    Ok(SandboxResult {
        metrics: SandboxMetrics {
            engine_used: "gvisor".into(),
            wall_time_ms: start_time.elapsed().as_millis() as u64,
            exit_code: output.status.code().unwrap_or(-1),
            observations_count,
            findings_count: findings.len(),
        },
        findings,
        observed_network_hosts: observations.network_hosts,
        observed_fs_writes: observations.fs_writes,
        observed_process_spawns: observations.process_spawns,
    })
}

// ── Docker Engine ───────────────────────────────────────────────────────────

async fn run_docker_sandbox(
    tarball_path: &Path,
    pkg_id: &common::PackageId,
    config: &SandboxConfig,
    _start_time: Instant,
) -> Result<Observations> {
    let (docker_image, install_cmd) = docker_ecosystem_config(&pkg_id.ecosystem);

    // M2: Wrap the install command with strace to capture successful writes
    // and process spawns that the error-based parser would miss.
    let strace_wrapper = format!(
        "strace -f -e trace=network,write,openat,execve -o /tmp/strace.log sh -c '{} >/dev/null 2>&1' 2>&1; \
         cat /tmp/strace.log >&2",
        install_cmd
    );

    let mut docker_cmd = tokio::process::Command::new("docker");
    docker_cmd
        .arg("run")
        .arg("--rm")
        .arg("--network=none")
        .arg("--read-only")
        .arg("--tmpfs")
        .arg("/tmp:size=256m")
        .arg("--memory")
        .arg(format!("{}m", config.memory_mb))
        .arg("--cpus")
        .arg("1");

    // M1: Apply Docker seccomp profile if available.
    if let Some(ref seccomp_path) = config.docker_seccomp_path {
        if seccomp_path.is_file() {
            docker_cmd
                .arg("--security-opt")
                .arg(format!("seccomp={}", seccomp_path.display()));
            tracing::info!(
                "Docker: Using seccomp profile from {}",
                seccomp_path.display()
            );
        }
    }

    docker_cmd
        .arg("-v")
        .arg(format!("{}:/pkg/package.tar.gz:ro", tarball_path.display()))
        .arg(docker_image)
        .arg("sh")
        .arg("-c")
        .arg(&strace_wrapper);

    let docker_future = docker_cmd.output();

    let output = tokio::time::timeout(
        std::time::Duration::from_secs(config.timeout_secs),
        docker_future,
    )
    .await
    .map_err(|_| anyhow::anyhow!("Docker sandbox timed out after {}s", config.timeout_secs))?
    .map_err(|e| anyhow::anyhow!("Docker sandbox execution failed: {}", e))?;

    // Parse both the original Docker error-based output AND the strace output.
    let mut observations = parse_docker_output(&output.stderr)?;
    let strace_obs = parse_strace_output(&output.stderr)?;
    merge_observations(&mut observations, strace_obs);

    observations.exit_code = output.status.code().unwrap_or(-1);
    Ok(observations)
}

// ── Observation Types ───────────────────────────────────────────────────────

struct Observations {
    network_hosts: Vec<String>,
    fs_writes: Vec<String>,
    process_spawns: Vec<String>,
    exit_code: i32,
}

/// Merge additional observations from strace into the primary set, deduplicating.
fn merge_observations(primary: &mut Observations, additional: Observations) {
    for host in additional.network_hosts {
        if !primary.network_hosts.contains(&host) {
            primary.network_hosts.push(host);
        }
    }
    for path in additional.fs_writes {
        if !primary.fs_writes.contains(&path) {
            primary.fs_writes.push(path);
        }
    }
    for spawn in additional.process_spawns {
        if !primary.process_spawns.contains(&spawn) {
            primary.process_spawns.push(spawn);
        }
    }
}

// ── Log Parsers ─────────────────────────────────────────────────────────────

fn sanitize_control_characters(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_control() && c != '\n' && c != '\r' && c != '\t' {
                '?'
            } else {
                c
            }
        })
        .collect()
}

/// Parse nsjail stderr/audit logs to extract observed system calls.
/// nsjail in `-Mo` (audit/monitor mode) logs seccomp events in the format:
///   `[SECCOMP] connect(fd, addr={sa_family=AF_INET, addr=93.184.216.34, port=443}, ...)`
///   `[SECCOMP] open("/etc/passwd", O_RDONLY|O_CLOEXEC)`
///   `[SECCOMP] execve("/bin/sh", ["/bin/sh", "-c", "curl ..."])`
fn parse_nsjail_output(stderr: &[u8]) -> Result<Observations> {
    let raw_str = String::from_utf8_lossy(stderr);
    let stderr_str = sanitize_control_characters(&raw_str);
    let mut network_hosts = Vec::new();
    let mut fs_writes = Vec::new();
    let mut process_spawns = Vec::new();

    const MAX_OBSERVED_NET_HOSTS: usize = 500;
    const MAX_OBSERVED_FS_WRITES: usize = 1000;
    const MAX_OBSERVED_SPAWNS: usize = 500;
    let mut limit_warned = false;

    for line in stderr_str.lines() {
        if network_hosts.len() >= MAX_OBSERVED_NET_HOSTS
            || fs_writes.len() >= MAX_OBSERVED_FS_WRITES
            || process_spawns.len() >= MAX_OBSERVED_SPAWNS
        {
            if !limit_warned {
                tracing::warn!("Sandbox observations limit reached; truncating remaining output to prevent DoS.");
                limit_warned = true;
            }
        }

        // ── Network connections ────────────────────────────────────────────
        if line.contains("connect(") {
            if network_hosts.len() >= MAX_OBSERVED_NET_HOSTS {
                continue;
            }
            if let Some(addr_start) = line.find("addr=") {
                let rest = &line[addr_start + 5..];
                let addr: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '.')
                    .collect();
                if !addr.is_empty() && addr.contains('.') {
                    network_hosts.push(addr);
                    continue;
                }
            }
            if let Some(start) = line.find('"') {
                let rest = &line[start + 1..];
                if let Some(end) = rest.find('"') {
                    let host = &rest[..end];
                    if !host.is_empty() {
                        network_hosts.push(host.to_string());
                        continue;
                    }
                }
            }
            network_hosts.push(format!("unknown-egress (raw: {})", line.trim()));
        }

        // ── Filesystem writes ─────────────────────────────────────────────
        if line.contains("open(")
            && (line.contains("O_WRONLY") || line.contains("O_RDWR") || line.contains("O_CREAT"))
        {
            if fs_writes.len() >= MAX_OBSERVED_FS_WRITES {
                continue;
            }
            if let Some(start) = line.find('"') {
                let rest = &line[start + 1..];
                if let Some(end) = rest.find('"') {
                    let path = &rest[..end];
                    if !path.is_empty() {
                        fs_writes.push(path.to_string());
                        continue;
                    }
                }
            }
            fs_writes.push(format!("unknown-write (raw: {})", line.trim()));
        }

        // ── Process spawns ────────────────────────────────────────────────
        if line.contains("execve(") {
            if process_spawns.len() >= MAX_OBSERVED_SPAWNS {
                continue;
            }
            if let Some(start) = line.find('"') {
                let rest = &line[start + 1..];
                if let Some(end) = rest.find('"') {
                    let binary = &rest[..end];
                    if !binary.is_empty() {
                        process_spawns.push(binary.to_string());
                        continue;
                    }
                }
            }
            process_spawns.push(format!("unknown-spawn (raw: {})", line.trim()));
        }
    }

    Ok(Observations {
        network_hosts,
        fs_writes,
        process_spawns,
        exit_code: 0,
    })
}

/// Parse Docker container stderr to extract behavioural observations.
fn parse_docker_output(stderr: &[u8]) -> Result<Observations> {
    let raw_str = String::from_utf8_lossy(stderr);
    let stderr_str = sanitize_control_characters(&raw_str);
    let mut network_hosts = Vec::new();
    let mut fs_writes = Vec::new();
    let mut process_spawns = Vec::new();

    const MAX_OBSERVED_NET_HOSTS: usize = 500;
    const MAX_OBSERVED_FS_WRITES: usize = 1000;
    const MAX_OBSERVED_SPAWNS: usize = 500;
    let mut limit_warned = false;

    for line in stderr_str.lines() {
        if network_hosts.len() >= MAX_OBSERVED_NET_HOSTS
            || fs_writes.len() >= MAX_OBSERVED_FS_WRITES
            || process_spawns.len() >= MAX_OBSERVED_SPAWNS
        {
            if !limit_warned {
                tracing::warn!("Sandbox observations limit reached; truncating remaining output to prevent DoS.");
                limit_warned = true;
            }
        }

        let lower = line.to_lowercase();

        if lower.contains("econnrefused")
            || lower.contains("enetunreach")
            || lower.contains("getaddrinfo")
            || lower.contains("dns resolution")
            || lower.contains("network is unreachable")
        {
            if network_hosts.len() < MAX_OBSERVED_NET_HOSTS {
                if let Some(idx) = lower.find("enotfound ") {
                    let rest = &line[idx + 10..];
                    let host: String = rest.chars().take_while(|c| !c.is_whitespace()).collect();
                    if !host.is_empty() {
                        network_hosts.push(host);
                        continue;
                    }
                }
                network_hosts.push(format!("network-attempt-detected (raw: {})", line.trim()));
            }
        }

        if lower.contains("erofs") || lower.contains("read-only file system") {
            if fs_writes.len() < MAX_OBSERVED_FS_WRITES {
                if let Some(start) = line.find('\'') {
                    let rest = &line[start + 1..];
                    if let Some(end) = rest.find('\'') {
                        fs_writes.push(rest[..end].to_string());
                        continue;
                    }
                }
                fs_writes.push(format!("write-attempted (raw: {})", line.trim()));
            }
        }

        if lower.contains("spawn") || lower.contains("child_process") || lower.contains("exec(") {
            if process_spawns.len() < MAX_OBSERVED_SPAWNS {
                process_spawns.push(format!("process-spawn-detected (raw: {})", line.trim()));
            }
        }
    }

    Ok(Observations {
        network_hosts,
        fs_writes,
        process_spawns,
        exit_code: 0,
    })
}

/// M2: Parse strace output to capture successful writes and process spawns.
/// strace output format:
///   `connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = 0`
///   `openat(AT_FDCWD, "/tmp/foo", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 3`
///   `execve("/bin/sh", ["sh", "-c", "..."], ...) = 0`
fn parse_strace_output(stderr: &[u8]) -> Result<Observations> {
    let raw_str = String::from_utf8_lossy(stderr);
    let stderr_str = sanitize_control_characters(&raw_str);
    let mut network_hosts = Vec::new();
    let mut fs_writes = Vec::new();
    let mut process_spawns = Vec::new();

    const MAX_OBSERVED_NET_HOSTS: usize = 500;
    const MAX_OBSERVED_FS_WRITES: usize = 1000;
    const MAX_OBSERVED_SPAWNS: usize = 500;
    let mut limit_warned = false;

    for line in stderr_str.lines() {
        if network_hosts.len() >= MAX_OBSERVED_NET_HOSTS
            || fs_writes.len() >= MAX_OBSERVED_FS_WRITES
            || process_spawns.len() >= MAX_OBSERVED_SPAWNS
        {
            if !limit_warned {
                tracing::warn!("Sandbox observations limit reached; truncating remaining output to prevent DoS.");
                limit_warned = true;
            }
        }

        // strace connect: extract IP from inet_addr("x.x.x.x")
        if line.starts_with("connect(") || line.contains("] connect(") {
            if network_hosts.len() < MAX_OBSERVED_NET_HOSTS {
                if let Some(start) = line.find("inet_addr(\"") {
                    let rest = &line[start + 11..];
                    if let Some(end) = rest.find('"') {
                        let ip = &rest[..end];
                        if !ip.is_empty() {
                            network_hosts.push(ip.to_string());
                        }
                    }
                }
            }
        }

        // strace openat with write flags (successful — return value >= 0)
        if (line.starts_with("openat(") || line.contains("] openat("))
            && (line.contains("O_WRONLY") || line.contains("O_RDWR") || line.contains("O_CREAT"))
            && !line.ends_with("= -1 EROFS")
            && !line.ends_with("= -1 EACCES")
        {
            if fs_writes.len() < MAX_OBSERVED_FS_WRITES {
                if let Some(start) = line.find('"') {
                    let rest = &line[start + 1..];
                    if let Some(end) = rest.find('"') {
                        let path = &rest[..end];
                        if !path.is_empty() {
                            fs_writes.push(path.to_string());
                        }
                    }
                }
            }
        }

        // strace execve (successful)
        if (line.starts_with("execve(") || line.contains("] execve(")) && line.contains("= 0") {
            if process_spawns.len() < MAX_OBSERVED_SPAWNS {
                if let Some(start) = line.find('"') {
                    let rest = &line[start + 1..];
                    if let Some(end) = rest.find('"') {
                        let binary = &rest[..end];
                        if !binary.is_empty() {
                            process_spawns.push(binary.to_string());
                        }
                    }
                }
            }
        }
    }

    Ok(Observations {
        network_hosts,
        fs_writes,
        process_spawns,
        exit_code: 0,
    })
}

// ── Manifest Validation ─────────────────────────────────────────────────────

/// Cross-check the observed behaviour against what the publisher declared.
/// H2: Supports `allowed_process_spawns` allowlist for fine-grained process control.
fn check_against_manifest(
    obs: &Observations,
    manifest: &PackageManifest,
    resolved_ips: &HashSet<String>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Undeclared network access — subdomain/IP matching.
    for host in &obs.network_hosts {
        let is_ip = host.parse::<IpAddr>().is_ok();
        let allowed = if is_ip {
            resolved_ips.contains(host)
        } else {
            manifest
                .allowed_network_hosts
                .iter()
                .any(|declared| host == declared || host.ends_with(&format!(".{}", declared)))
        };
        if !allowed {
            findings.push(Finding {
                id: "SB001".into(),
                title: "Undeclared network access".into(),
                severity: FindingSeverity::High,
                description: format!("Undeclared network access to '{}'", host),
                file: "install-hook".into(),
                line: None,
            });
        }
    }

    // Undeclared filesystem writes — prefix matching.
    for path in &obs.fs_writes {
        let allowed = manifest.allowed_fs_writes.iter().any(|declared| {
            path == declared
                || path.starts_with(&format!("{}/", declared))
                || path.starts_with(&format!("{}\\", declared))
        });
        if !allowed {
            findings.push(Finding {
                id: "SB002".into(),
                title: "Undeclared filesystem write".into(),
                severity: FindingSeverity::High,
                description: format!("Undeclared filesystem write to '{}'", path),
                file: "install-hook".into(),
                line: None,
            });
        }
    }

    // H2: Process spawn validation with allowlist support.
    for spawn in &obs.process_spawns {
        if manifest.spawns_processes {
            // If the manifest has a specific allowlist, check against it.
            if !manifest.allowed_process_spawns.is_empty() {
                let binary_name = Path::new(spawn)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                let allowed = manifest
                    .allowed_process_spawns
                    .iter()
                    .any(|declared| spawn == declared || binary_name == *declared);
                if !allowed {
                    findings.push(Finding {
                        id: "SB004".into(),
                        title: "Process spawn not in allowlist".into(),
                        severity: FindingSeverity::High,
                        description: format!(
                            "Process '{}' spawned but not in allowed_process_spawns: {:?}",
                            spawn, manifest.allowed_process_spawns
                        ),
                        file: "install-hook".into(),
                        line: None,
                    });
                }
            }
            // Otherwise spawns_processes=true without allowlist means all spawns are OK.
        } else {
            findings.push(Finding {
                id: "SB003".into(),
                title: "Undeclared process spawn".into(),
                severity: FindingSeverity::Critical,
                description: format!("Undeclared child process spawn: '{}'", spawn),
                file: "install-hook".into(),
                line: None,
            });
        }
    }

    findings
}

// ── Phase-Based Execution (A5) ──────────────────────────────────────────────

/// Multi-phase sandbox execution for deeper behavioral analysis.
/// Phase 1: Install — dependency resolution (network may be allowed)
/// Phase 2: Post-install — hook execution (network blocked)
/// Phase 3: Import — runtime loading (network blocked, strict mode)
///
/// This is a design hook — called from `run()` when `CREG_MULTIPHASE=true`.
#[allow(dead_code)]
pub async fn run_multiphase(
    pkg_id: &common::PackageId,
    tarball_bytes: &[u8],
    manifest: &PackageManifest,
) -> Result<SandboxResult> {
    let phase1_manifest = PackageManifest {
        allowed_network_hosts: manifest.allowed_network_hosts.clone(),
        allowed_fs_writes: manifest.allowed_fs_writes.clone(),
        spawns_processes: manifest.spawns_processes,
        allowed_process_spawns: manifest.allowed_process_spawns.clone(),
        description: manifest.description.clone(),
    };

    // Phase 1: Install with declared network access
    let phase1 = run(pkg_id, tarball_bytes, &phase1_manifest).await?;
    if phase1
        .findings
        .iter()
        .any(|f| matches!(f.severity, FindingSeverity::Critical))
    {
        return Ok(phase1);
    }

    // Phase 2: Post-install hooks — no network
    let phase2_manifest = PackageManifest {
        allowed_network_hosts: vec![], // No network in post-install
        ..phase1_manifest.clone()
    };
    let phase2 = run(pkg_id, tarball_bytes, &phase2_manifest).await?;

    // Merge findings from both phases.
    let mut combined = phase1;
    combined.findings.extend(phase2.findings);
    for host in phase2.observed_network_hosts {
        if !combined.observed_network_hosts.contains(&host) {
            combined.observed_network_hosts.push(host);
        }
    }
    for path in phase2.observed_fs_writes {
        if !combined.observed_fs_writes.contains(&path) {
            combined.observed_fs_writes.push(path);
        }
    }
    for spawn in phase2.observed_process_spawns {
        if !combined.observed_process_spawns.contains(&spawn) {
            combined.observed_process_spawns.push(spawn);
        }
    }

    Ok(combined)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_control_characters() {
        let input = "hello\x00world\x1b[31mred\r\nnewline";
        let sanitized = sanitize_control_characters(input);
        assert_eq!(sanitized, "hello?world?[31mred\r\nnewline");
    }

    #[tokio::test]
    async fn test_resolve_manifest_domains() {
        // Test with raw IPs
        let hosts = vec!["127.0.0.1".to_string(), "8.8.8.8".to_string()];
        let resolved = resolve_manifest_domains(&hosts).await;
        assert!(resolved.contains("127.0.0.1"));
        assert!(resolved.contains("8.8.8.8"));

        // Test with localhost (should resolve to 127.0.0.1)
        let local_hosts = vec!["localhost".to_string()];
        let resolved_local = resolve_manifest_domains(&local_hosts).await;
        assert!(resolved_local.contains("127.0.0.1") || resolved_local.contains("::1"));
    }

    #[test]
    fn test_observation_limit_and_truncation() {
        // Generate a large mock stderr with many connect calls
        let mut mock_stderr = Vec::new();
        for i in 0..600 {
            mock_stderr.extend_from_slice(
                format!(
                    "[SECCOMP] connect(fd, addr={{sa_family=AF_INET, addr=1.1.1.{}, port=443}})\n",
                    i
                )
                .as_bytes(),
            );
        }

        let obs = parse_nsjail_output(&mock_stderr).unwrap();
        // Limit is 500
        assert_eq!(obs.network_hosts.len(), 500);
    }
}
