// crates/cli/src/shims/pip.rs
// PATH shim for `pip install` — identical logic to the npm shim
// but targets the PyPI ecosystem.

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let exit_code = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime")
        .block_on(async {
            let sub = args.get(1).map(String::as_str).unwrap_or("");
            if !matches!(sub, "install" | "download") {
                return run_real("pip", &args[1..]).await;
            }
            run_verified_install("pypi", &args).await
        });

    std::process::exit(exit_code);
}

async fn run_verified_install(ecosystem: &str, args: &[String]) -> i32 {
    // pip install pkg1 pkg2 --flag  →  extract package names
    let packages: Vec<&str> = args[2..]
        .iter()
        .filter(|a| !a.starts_with('-') && !a.ends_with(".txt") && !a.ends_with(".cfg"))
        .map(String::as_str)
        .collect();

    for pkg in &packages {
        match resolver::resolve(pkg, Some(ecosystem), None).await {
            Ok(v) if v.status.is_blocked() => {
                eprintln!(
                    "\x1b[31m✗ BLOCKED\x1b[0m  {} — chain registry: REVOKED",
                    pkg
                );
                return 1;
            }
            Ok(v) if !v.status.is_safe() => {
                eprintln!("\x1b[33m⚠ WARNING\x1b[0m  {} — not chain-verified.", pkg);
            }
            Ok(_) => eprintln!("\x1b[32m✓ VERIFIED\x1b[0m {}", pkg),
            Err(e) => eprintln!("\x1b[33m⚠ CHAIN UNREACHABLE\x1b[0m ({}). Continuing.", e),
        }
    }

    run_real("pip", &args[1..]).await
}

async fn run_real(pm: &str, args: &[String]) -> i32 {
    let args_str: Vec<&str> = args.iter().map(String::as_str).collect();
    let real = match which::which_all(pm).ok().and_then(|mut it| {
        it.next();
        it.next()
    }) {
        Some(p) => p,
        None => {
            eprintln!("chain-registry: real {} not found", pm);
            return 127;
        }
    };

    std::process::Command::new(real)
        .args(&args_str)
        .status()
        .map(|s| s.code().unwrap_or(1))
        .unwrap_or(1)
}
