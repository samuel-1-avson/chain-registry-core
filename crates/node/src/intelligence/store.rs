use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use common::{IntelligenceStatus, PackageIntelligenceReport, PackageIntelligenceResponse};

#[derive(Debug, Clone)]
pub struct IntelligenceStore {
    dir: PathBuf,
}

impl IntelligenceStore {
    pub fn new(data_dir: &Path) -> Self {
        let dir = data_dir.join("intelligence");
        let _ = std::fs::create_dir_all(&dir);
        Self { dir }
    }

    fn path_for(&self, content_hash: &str) -> PathBuf {
        let key = content_hash.trim_start_matches("0x").to_ascii_lowercase();
        self.dir.join(format!("{key}.json"))
    }

    pub fn get_by_content_hash(&self, content_hash: &str) -> Option<PackageIntelligenceReport> {
        let path = self.path_for(content_hash);
        let raw = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&raw).ok()
    }

    pub fn put(&self, report: &PackageIntelligenceReport) -> Result<()> {
        let path = self.path_for(&report.content_hash);
        let json = serde_json::to_string_pretty(report).context("serialize intelligence report")?;
        std::fs::write(path, json).context("write intelligence report")
    }

    pub fn response_for_package(
        &self,
        canonical: &str,
        content_hash: Option<&str>,
    ) -> PackageIntelligenceResponse {
        if let Some(hash) = content_hash {
            if let Some(report) = self.get_by_content_hash(hash) {
                return PackageIntelligenceResponse {
                    canonical: canonical.to_string(),
                    content_hash: Some(hash.to_string()),
                    status: report.status.clone(),
                    message: None,
                    report: Some(report),
                };
            }
        }

        PackageIntelligenceResponse {
            canonical: canonical.to_string(),
            content_hash: content_hash.map(str::to_string),
            status: IntelligenceStatus::Pending,
            message: Some(
                "Intelligence report not generated yet. Enable CREG_INTELLIGENCE_ENABLED on a node with IPFS access.".into(),
            ),
            report: None,
        }
    }
}
