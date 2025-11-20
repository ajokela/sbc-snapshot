pub mod modules;
pub mod types;

use anyhow::Result;
use chrono::Utc;
use types::*;

/// Main orchestrator for running all analyzers and generating a snapshot
pub struct SnapshotRunner {
    include_raw_data: bool,
}

impl SnapshotRunner {
    pub fn new() -> Self {
        Self {
            include_raw_data: false,
        }
    }

    pub fn with_raw_data(mut self, include: bool) -> Self {
        self.include_raw_data = include;
        self
    }

    /// Check if running as root
    fn is_root() -> bool {
        nix::unistd::Uid::effective().is_root()
    }

    /// Get hostname
    fn get_hostname() -> String {
        nix::unistd::gethostname()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "unknown".to_string())
    }

    /// Run all analyzers and generate a complete snapshot
    pub fn run(&self) -> Result<Snapshot> {
        // Collect metadata
        let metadata = SnapshotMetadata {
            version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: Utc::now(),
            hostname: Self::get_hostname(),
            run_as_root: Self::is_root(),
        };

        // Collect system info
        let system = modules::system_info::SystemInfoCollector::new().collect()?;

        // Run accounts analyzer
        let accounts_findings = modules::accounts::AccountsAnalyzer::new().analyze()?;
        let accounts = AccountsReport {
            findings: accounts_findings,
            raw: None,
        };

        // Run SSH analyzer
        let ssh_findings = modules::ssh::SshAnalyzer::new().analyze()?;

        // Run network analyzer
        let network_findings = modules::network::NetworkAnalyzer::new().analyze()?;

        // Run firewall analyzer
        let firewall_findings = modules::firewall::FirewallAnalyzer::new().analyze()?;

        // Combine SSH, network, and firewall findings into network report
        let mut all_network_findings = ssh_findings;
        all_network_findings.extend(network_findings);
        all_network_findings.extend(firewall_findings);

        let network = NetworkReport {
            findings: all_network_findings,
            raw: None,
        };

        // Run services analyzer
        let services_findings = modules::services::ServicesAnalyzer::new().analyze()?;
        let services = ServicesReport {
            findings: services_findings,
            raw: None,
        };

        // Run filesystem analyzer
        let mut filesystem_findings = modules::filesystem::FilesystemAnalyzer::new().analyze()?;

        // Run sudoers analyzer and add to filesystem findings
        let sudoers_findings = modules::sudoers::SudoersAnalyzer::new().analyze()?;
        filesystem_findings.extend(sudoers_findings);

        let filesystem = FilesystemReport {
            findings: filesystem_findings,
            raw: None,
        };

        // Run packages analyzer
        let packages_findings = modules::packages::PackagesAnalyzer::new().analyze()?;
        let packages = PackagesReport {
            findings: packages_findings,
            raw: None,
        };

        // Calculate security score
        let snapshot_temp = Snapshot {
            metadata: metadata.clone(),
            system: system.clone(),
            accounts: accounts.clone(),
            network: network.clone(),
            services: services.clone(),
            filesystem: filesystem.clone(),
            packages: packages.clone(),
            security_score: SecurityScore {
                total_score: 0,
                risk_level: "Unknown".to_string(),
                critical_count: 0,
                high_count: 0,
                medium_count: 0,
                low_count: 0,
                info_count: 0,
            },
        };

        let all_findings = snapshot_temp.all_findings();
        let security_score = SecurityScore::calculate(&all_findings);

        // Build final snapshot
        Ok(Snapshot {
            metadata,
            system,
            accounts,
            network,
            services,
            filesystem,
            packages,
            security_score,
        })
    }
}

impl Default for SnapshotRunner {
    fn default() -> Self {
        Self::new()
    }
}
