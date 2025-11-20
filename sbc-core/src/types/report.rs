use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use super::{Finding, Severity};

/// Metadata about when and where the snapshot was taken
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMetadata {
    pub version: String,
    pub timestamp: DateTime<Utc>,
    pub hostname: String,
    pub run_as_root: bool,
}

/// System identification and hardware info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub kernel_version: Option<String>,
    pub architecture: Option<String>,
    pub board_model: Option<String>,
    pub cpu_info: Option<String>,
    pub memory_total_kb: Option<u64>,
}

/// Report from the accounts & authentication module
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountsReport {
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<serde_json::Value>,
}

/// Report from the network exposure module
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkReport {
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<serde_json::Value>,
}

/// Report from the services module
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServicesReport {
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<serde_json::Value>,
}

/// Report from the filesystem module
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemReport {
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<serde_json::Value>,
}

/// Report from the packages module
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackagesReport {
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<serde_json::Value>,
}

/// Overall security score and risk assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityScore {
    /// Total score (sum of all finding severities)
    pub total_score: u32,

    /// Risk level based on score
    pub risk_level: String,

    /// Count of findings by severity
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
}

impl SecurityScore {
    /// Calculate security score from all findings
    pub fn calculate(all_findings: &[&Finding]) -> Self {
        let total_score: u32 = all_findings.iter()
            .map(|f| f.severity.score())
            .sum();

        let critical_count = all_findings.iter().filter(|f| f.severity == Severity::Critical).count();
        let high_count = all_findings.iter().filter(|f| f.severity == Severity::High).count();
        let medium_count = all_findings.iter().filter(|f| f.severity == Severity::Medium).count();
        let low_count = all_findings.iter().filter(|f| f.severity == Severity::Low).count();
        let info_count = all_findings.iter().filter(|f| f.severity == Severity::Info).count();

        let risk_level = if critical_count > 0 {
            "Critical"
        } else if high_count > 3 {
            "High"
        } else if high_count > 0 || medium_count > 5 {
            "Medium-High"
        } else if medium_count > 0 {
            "Medium"
        } else if low_count > 0 {
            "Low"
        } else {
            "Minimal"
        }.to_string();

        Self {
            total_score,
            risk_level,
            critical_count,
            high_count,
            medium_count,
            low_count,
            info_count,
        }
    }
}

/// Complete snapshot of system security and configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub metadata: SnapshotMetadata,
    pub system: SystemInfo,
    pub accounts: AccountsReport,
    pub network: NetworkReport,
    pub services: ServicesReport,
    pub filesystem: FilesystemReport,
    pub packages: PackagesReport,
    pub security_score: SecurityScore,
}

impl Snapshot {
    /// Get all findings from all modules
    pub fn all_findings(&self) -> Vec<&Finding> {
        let mut findings = Vec::new();
        findings.extend(&self.accounts.findings);
        findings.extend(&self.network.findings);
        findings.extend(&self.services.findings);
        findings.extend(&self.filesystem.findings);
        findings.extend(&self.packages.findings);
        findings
    }
}
