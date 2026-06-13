use common::Finding;

#[derive(Debug, Clone)]
pub(super) struct SelectedFile {
    pub path: String,
    pub content: String,
    pub entropy: f64,
}

#[derive(Debug, Clone)]
pub(super) struct PackageEvidencePacket {
    pub file_count: usize,
    pub entropy_alerts: Vec<super::EntropyAlert>,
    pub selected_files: Vec<SelectedFile>,
}

pub(super) struct EvidencePacketBuilder;

impl EvidencePacketBuilder {
    pub(super) fn build(tarball: &[u8], prior_findings: &[Finding]) -> PackageEvidencePacket {
        let files = super::extract_tarball(tarball);
        let entropy_alerts = super::scan_entropy(&files);
        let selected_files =
            super::select_files_for_analysis(&files, prior_findings, super::max_files_to_analyse())
                .into_iter()
                .filter_map(|(path, data, entropy)| {
                    let content = std::str::from_utf8(&data).ok()?;
                    let content = super::sanitize_content(content, super::max_file_chars());
                    if content.trim().is_empty() {
                        None
                    } else {
                        Some(SelectedFile {
                            path,
                            content,
                            entropy,
                        })
                    }
                })
                .collect();

        PackageEvidencePacket {
            file_count: files.len(),
            entropy_alerts,
            selected_files,
        }
    }
}
