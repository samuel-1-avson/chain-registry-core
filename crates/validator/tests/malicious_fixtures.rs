//! MAL-002 — static-analysis coverage for malicious package fixtures.

use common::PackageManifest;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use tar::Builder;
use validator::static_analysis;

#[derive(Debug, Deserialize)]
struct FixtureMeta {
    id: String,
    category: String,
    #[allow(dead_code)]
    description: String,
    expected_findings: Vec<String>,
}

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testnet/malicious-fixtures")
}

fn tar_package(package_dir: &Path) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut archive = Builder::new(&mut encoder);
        archive
            .append_dir_all("package", package_dir)
            .expect("tar package dir");
        archive.finish().expect("finish tar");
    }
    encoder.finish().expect("finish gzip")
}

fn load_fixtures() -> Vec<(FixtureMeta, Vec<u8>)> {
    let root = fixtures_root();
    assert!(root.is_dir(), "missing fixture root at {}", root.display());

    let mut out = Vec::new();
    for entry in fs::read_dir(&root).expect("read fixtures dir") {
        let entry = entry.expect("fixture entry");
        if !entry.file_type().expect("file type").is_dir() {
            continue;
        }
        let dir = entry.path();
        let meta_path = dir.join("meta.json");
        if !meta_path.is_file() {
            continue;
        }
        let meta: FixtureMeta =
            serde_json::from_str(&fs::read_to_string(&meta_path).expect("read meta.json"))
                .expect("parse meta.json");
        let package_dir = dir.join("package");
        assert!(
            package_dir.is_dir(),
            "{} missing package/ directory",
            meta.id
        );
        let tarball = tar_package(&package_dir);
        out.push((meta, tarball));
    }
    out.sort_by(|a, b| a.0.id.cmp(&b.0.id));
    assert!(
        out.len() >= 7,
        "expected at least 7 malicious fixtures, found {}",
        out.len()
    );
    out
}

#[tokio::test]
async fn malicious_fixture_suite_static_analysis() {
    for (meta, tarball) in load_fixtures() {
        let manifest = PackageManifest::default();
        let result = static_analysis::run(&tarball, &manifest)
            .await
            .unwrap_or_else(|e| panic!("{} static analysis failed: {e}", meta.id));

        let finding_ids: Vec<String> = result.findings.iter().map(|f| f.id.clone()).collect();

        let matched = meta
            .expected_findings
            .iter()
            .any(|expected| finding_ids.iter().any(|id| id == expected));

        assert!(
            matched,
            "{} ({}) expected one of {:?}, got findings {:?}",
            meta.id, meta.category, meta.expected_findings, finding_ids
        );
    }
}
