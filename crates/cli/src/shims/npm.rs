// crates/cli/src/shims/npm.rs
// This binary is placed in ~/.local/bin/npm.
// When the developer types `npm install express`, this runs first.
// It reads the arguments, routes through chain-registry verification,
// then calls the real npm.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // The shim rewrites argv[0] as "npm" and delegates to creg's install logic.
    // Sub-commands other than install/ci/add pass through unmodified.
    let passthrough = should_passthrough(&args);

    let exit_code = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime")
        .block_on(async {
            if passthrough {
                // Not an install-type command — run real npm directly.
                run_real_pm("npm", &args[1..]).await
            } else {
                // Extract the package(s) from `npm install pkg1 pkg2 ...`
                run_verified_install("npm", &args).await
            }
        });

    std::process::exit(exit_code);
}

fn should_passthrough(args: &[String]) -> bool {
    // If no sub-command, or sub-command is not install/ci/add — pass through.
    let sub = args.get(1).map(String::as_str).unwrap_or("");
    !matches!(sub, "install" | "i" | "ci" | "add")
}

async fn run_verified_install(ecosystem: &str, args: &[String]) -> i32 {
    // Collect package names (skip flags starting with -)
    let packages: Vec<&str> = args[2..]
        .iter()
        .filter(|a| !a.starts_with('-') && !a.starts_with("--"))
        .map(String::as_str)
        .collect();

    if packages.is_empty() {
        // `npm install` with no args — just sync node_modules, pass through.
        return run_real_pm(ecosystem, &args[1..]).await;
    }

    // Verify each package against the chain before installing.
    for pkg in &packages {
        match resolver::resolve(pkg, Some(ecosystem), None).await {
            Ok(verdict) if verdict.status.is_blocked() => {
                eprintln!(
                    "\x1b[31m✗ BLOCKED\x1b[0m  {} — chain registry: REVOKED",
                    pkg
                );
                return 1;
            }
            Ok(verdict) if !verdict.status.is_safe() => {
                eprintln!(
                    "\x1b[33m⚠ WARNING\x1b[0m  {} — not chain-verified. Proceed with caution.",
                    pkg
                );
            }
            Ok(_) => {
                eprintln!("\x1b[32m✓ VERIFIED\x1b[0m {}", pkg);
            }
            Err(e) => {
                eprintln!(
                    "\x1b[33m⚠ CHAIN UNREACHABLE\x1b[0m ({}). Proceeding with original registry.",
                    e
                );
            }
        }
    }

    run_real_pm(ecosystem, &args[1..]).await
}

async fn run_real_pm(pm: &str, args: &[String]) -> i32 {
    // Find the real npm — skip the first match (our shim).
    let real = match which::which_all(pm)
        .map(|mut it| {
            it.next();
            it.next()
        })
        .ok()
        .flatten()
    {
        Some(p) => p,
        None => {
            eprintln!("chain-registry: could not find real {}", pm);
            return 127;
        }
    };

    std::process::Command::new(real)
        .args(args)
        .status()
        .map(|s| s.code().unwrap_or(1))
        .unwrap_or(1)
}
