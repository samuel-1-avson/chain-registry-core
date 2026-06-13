// crates/cli/src/shims/mvn.rs
// PATH shim for Maven (`mvn`) — intercepts dependency downloads for the Java ecosystem.
// Specifically hooks `mvn install`, `mvn dependency:resolve`, and `mvn package`
// to verify any newly introduced dependencies against the chain registry.

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let exit_code = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime")
        .block_on(async {
            let sub = args.get(1).map(String::as_str).unwrap_or("");
            // Only intercept lifecycle phases that pull dependencies.
            if !matches!(
                sub,
                "install"
                    | "package"
                    | "verify"
                    | "compile"
                    | "dependency:resolve"
                    | "dependency:get"
            ) {
                return run_real(&args[1..]).await;
            }
            run_verified_build("maven", &args).await
        });

    std::process::exit(exit_code);
}

async fn run_verified_build(ecosystem: &str, args: &[String]) -> i32 {
    // For Maven we can't easily extract package names from the CLI args alone —
    // they're declared in pom.xml. Parse the pom.xml instead.
    let packages = read_pom_dependencies();

    if packages.is_empty() {
        // No pom.xml or no dependencies — just pass through.
        return run_real(&args[1..]).await;
    }

    println!(
        "[chain-registry] Checking {} Maven dependencies...",
        packages.len()
    );

    let mut blocked = false;
    for (group_id, artifact_id, version) in &packages {
        let canonical = format!("{}:{}", group_id, artifact_id);
        match resolver::resolve(&canonical, Some(ecosystem), None).await {
            Ok(v) if v.status.is_blocked() => {
                eprintln!(
                    "\x1b[31m✗ BLOCKED\x1b[0m  {}:{} — chain registry: REVOKED",
                    group_id, artifact_id
                );
                blocked = true;
            }
            Ok(v) if !v.status.is_safe() => {
                eprintln!(
                    "\x1b[33m⚠ WARNING\x1b[0m  {}:{} {} — not chain-verified.",
                    group_id, artifact_id, version
                );
            }
            Ok(_) => eprintln!("\x1b[32m✓\x1b[0m {}:{}", group_id, artifact_id),
            Err(e) => eprintln!("[chain-registry] chain unreachable ({}). Continuing.", e),
        }
    }

    if blocked {
        eprintln!("[chain-registry] Build blocked due to revoked dependency.");
        return 1;
    }

    run_real(&args[1..]).await
}

/// Parse `pom.xml` in the current directory for dependency entries.
fn read_pom_dependencies() -> Vec<(String, String, String)> {
    let content = match std::fs::read_to_string("pom.xml") {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let mut deps = Vec::new();
    let mut group = String::new();
    let mut artifact = String::new();
    let mut version = String::new();
    let mut in_dep = false;

    for line in content.lines() {
        let line = line.trim();
        if line == "<dependency>" {
            in_dep = true;
            group.clear();
            artifact.clear();
            version.clear();
        } else if line == "</dependency>" && in_dep {
            if !group.is_empty() && !artifact.is_empty() {
                deps.push((
                    group.clone(),
                    artifact.clone(),
                    if version.is_empty() {
                        "RELEASE".into()
                    } else {
                        version.clone()
                    },
                ));
            }
            in_dep = false;
        } else if in_dep {
            if let Some(v) = extract_xml_value(line, "groupId") {
                group = v;
            }
            if let Some(v) = extract_xml_value(line, "artifactId") {
                artifact = v;
            }
            if let Some(v) = extract_xml_value(line, "version") {
                version = v;
            }
        }
    }
    deps
}

fn extract_xml_value(line: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let start = line.find(&open)? + open.len();
    let end = line.find(&close)?;
    Some(line[start..end].to_string())
}

async fn run_real(args: &[String]) -> i32 {
    let args_str: Vec<&str> = args.iter().map(String::as_str).collect();
    let real = match which::which_all("mvn").ok().and_then(|mut it| {
        it.next();
        it.next()
    }) {
        Some(p) => p,
        None => {
            eprintln!("chain-registry: real mvn not found");
            return 127;
        }
    };
    std::process::Command::new(real)
        .args(&args_str)
        .status()
        .map(|s| s.code().unwrap_or(1))
        .unwrap_or(1)
}
