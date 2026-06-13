// crates/cli/src/intercept.rs
// Manages the PATH shims that transparently intercept package manager calls.
//
// On Unix:  copies the creg binary into ~/.local/bin as `npm`, `pip`, etc.
// On Windows: writes `.cmd` batch wrappers + prints PowerShell PATH guidance.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

const SHIM_TARGETS: &[(&str, &str)] = &[
    ("npm", "npm"),
    ("pip", "pip"),
    ("pip3", "pip"),
    ("cargo", "cargo-shim"),
    ("gem", "gem"),
    ("mvn", "mvn"),
];

/// Install shim binaries into `shim_dir` (defaults to ~/.local/bin on Unix,
/// %LOCALAPPDATA%\creg\bin on Windows).
pub fn setup_shims(shim_dir: Option<&Path>) -> Result<()> {
    let dir = shim_dir.map(PathBuf::from).unwrap_or_else(default_shim_dir);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("Cannot create shim dir: {}", dir.display()))?;

    let current_exe = std::env::current_exe()?;

    #[cfg(windows)]
    install_windows_shims(&current_exe, &dir)?;

    #[cfg(not(windows))]
    install_unix_shims(&current_exe, &dir)?;

    println!("\n  Shim directory: {}", dir.display());
    print_path_instructions(&dir);
    Ok(())
}

/// Remove shims by deleting the named files from the shim directory.
pub fn remove_shims() -> Result<()> {
    let dir = default_shim_dir();
    for (shim_name, _) in SHIM_TARGETS {
        // On Windows shims are .cmd files; on Unix they are plain binaries.
        #[cfg(windows)]
        let path = dir.join(format!("{}.cmd", shim_name));
        #[cfg(not(windows))]
        let path = dir.join(shim_name);

        if path.exists() {
            std::fs::remove_file(&path)?;
            println!("  ✓ Removed shim: {}", path.display());
        }
    }
    Ok(())
}

// ── Unix ─────────────────────────────────────────────────────────────────────

#[cfg(not(windows))]
fn install_unix_shims(current_exe: &Path, dir: &Path) -> Result<()> {
    let exe_dir = current_exe.parent().unwrap_or(Path::new("."));

    for (shim_name, bin_name) in SHIM_TARGETS {
        let shim_binary = exe_dir.join(bin_name);
        let source = if shim_binary.exists() {
            &shim_binary
        } else {
            current_exe
        };
        let dest = dir.join(shim_name);
        std::fs::copy(source, &dest)
            .with_context(|| format!("Failed to copy shim to {}", dest.display()))?;

        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&dest)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&dest, perms)?;

        println!("  ✓ Installed shim: {}", dest.display());
    }
    Ok(())
}

// ── Windows ──────────────────────────────────────────────────────────────────

#[cfg(windows)]
fn install_windows_shims(current_exe: &Path, dir: &Path) -> Result<()> {
    // Quote the exe path in case it contains spaces.
    let creg_path = current_exe.display().to_string();

    for (shim_name, _bin_name) in SHIM_TARGETS {
        // Write a .cmd batch wrapper that delegates to creg, forwarding all args.
        // The shim dispatches on argv[0] (the script name without extension).
        let cmd_content = format!(
            "@echo off\r\n\
             \"{creg_path}\" {shim_name} %*\r\n",
            creg_path = creg_path,
            shim_name = shim_name,
        );
        let dest = dir.join(format!("{}.cmd", shim_name));
        std::fs::write(&dest, cmd_content)
            .with_context(|| format!("Failed to write shim to {}", dest.display()))?;

        // Also write a PowerShell wrapper so `pwsh -c npm install foo` works.
        let ps1_content = format!(
            "& \"{creg_path}\" {shim_name} @args\r\n",
            creg_path = creg_path,
            shim_name = shim_name,
        );
        let ps1_dest = dir.join(format!("{}.ps1", shim_name));
        std::fs::write(&ps1_dest, ps1_content)
            .with_context(|| format!("Failed to write PS1 shim to {}", ps1_dest.display()))?;

        println!("  ✓ Installed shim: {}", dest.display());
    }

    // Offer to update the user PATH in the Windows Registry.
    try_register_windows_path(dir);
    Ok(())
}

/// Attempt to prepend `dir` to the user-level PATH via PowerShell.
/// This is a best-effort helper — failure is non-fatal.
#[cfg(windows)]
fn try_register_windows_path(dir: &Path) {
    let dir_str = dir.display().to_string();

    // Build the PowerShell snippet that prepends the shim dir to User PATH.
    let ps_script = format!(
        r#"$target = [System.EnvironmentVariableTarget]::User; \
$current = [Environment]::GetEnvironmentVariable('PATH', $target); \
if ($current -notlike '*{dir}*') {{ \
    [Environment]::SetEnvironmentVariable('PATH', '{dir};' + $current, $target); \
    Write-Host 'PATH updated successfully.' \
}} else {{ \
    Write-Host 'PATH already contains shim directory.' \
}}"#,
        dir = dir_str
    );

    let status = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &ps_script])
        .status();

    match status {
        Ok(s) if s.success() => println!("  ✓ Added shim directory to user PATH via registry."),
        _ => {
            eprintln!(
                "  ⚠ Could not update PATH automatically. Run this in PowerShell:\n\
                 $p=[System.EnvironmentVariableTarget]::User;\
                 [Environment]::SetEnvironmentVariable('PATH','{};'+[Environment]::GetEnvironmentVariable('PATH',$p),$p)",
                dir_str
            );
        }
    }
}

// ── Shared ───────────────────────────────────────────────────────────────────

fn print_path_instructions(dir: &Path) {
    #[cfg(windows)]
    let _ = dir;

    #[cfg(windows)]
    println!("  Restart your terminal (or open a new one) for PATH changes to take effect.");

    #[cfg(not(windows))]
    {
        println!("  Add to your shell profile to persist:");
        println!("    export PATH=\"{}:$PATH\"", dir.display());
    }
}

fn default_shim_dir() -> PathBuf {
    #[cfg(windows)]
    {
        // %LOCALAPPDATA%\creg\bin  (e.g. C:\Users\Alice\AppData\Local\creg\bin)
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("C:\\creg"))
            .join("creg")
            .join("bin")
    }
    #[cfg(not(windows))]
    {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join(".local")
            .join("bin")
    }
}
