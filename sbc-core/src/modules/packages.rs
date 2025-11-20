use crate::types::{Finding, Severity};
use anyhow::Result;
use std::fs;
use std::path::Path;
use std::process::Command;

/// Package Manager and Updates Analyzer
///
/// Checks for pending updates and repository configuration
pub struct PackagesAnalyzer;

impl PackagesAnalyzer {
    pub fn new() -> Self {
        Self
    }

    /// Detect which package manager is available
    fn detect_package_manager(&self) -> Option<PackageManager> {
        if Path::new("/usr/bin/apt").exists() || Path::new("/usr/bin/apt-get").exists() {
            Some(PackageManager::Apt)
        } else if Path::new("/usr/bin/dnf").exists() {
            Some(PackageManager::Dnf)
        } else if Path::new("/usr/bin/yum").exists() {
            Some(PackageManager::Yum)
        } else if Path::new("/usr/bin/pacman").exists() {
            Some(PackageManager::Pacman)
        } else {
            None
        }
    }

    /// Check for available updates (APT)
    fn check_apt_updates(&self) -> Result<UpdateInfo> {
        // Try to read apt update status without running apt update
        // This reads the cache that apt-get update creates
        let output = Command::new("apt")
            .args(&["list", "--upgradable"])
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Count upgradable packages
        let mut total = 0;
        let mut security = 0;

        for line in stdout.lines() {
            if line.contains("/") && !line.starts_with("Listing") {
                total += 1;
                // Try to detect security updates (APT doesn't always mark them clearly)
                if line.contains("security") || line.contains("-security") {
                    security += 1;
                }
            }
        }

        Ok(UpdateInfo {
            total_updates: total,
            security_updates: security,
        })
    }

    /// Check for available updates (DNF/Yum)
    fn check_dnf_updates(&self) -> Result<UpdateInfo> {
        let cmd = if Path::new("/usr/bin/dnf").exists() { "dnf" } else { "yum" };

        let output = Command::new(cmd)
            .args(&["check-update", "-q"])
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        let total = stdout.lines()
            .filter(|line| !line.trim().is_empty() && line.contains('.'))
            .count();

        // DNF/Yum doesn't easily distinguish security updates without plugin
        Ok(UpdateInfo {
            total_updates: total,
            security_updates: 0, // Would need dnf updateinfo for this
        })
    }

    /// Check APT repository configuration
    fn check_apt_sources(&self) -> Result<Vec<RepoIssue>> {
        let mut issues = Vec::new();

        // Check /etc/apt/sources.list
        if let Ok(content) = fs::read_to_string("/etc/apt/sources.list") {
            issues.extend(self.analyze_apt_sources(&content, "/etc/apt/sources.list"));
        }

        // Check /etc/apt/sources.list.d/
        if let Ok(entries) = fs::read_dir("/etc/apt/sources.list.d") {
            for entry in entries.flatten() {
                if entry.path().extension().and_then(|s| s.to_str()) == Some("list") {
                    if let Ok(content) = fs::read_to_string(entry.path()) {
                        let filename = entry.file_name().to_string_lossy().to_string();
                        issues.extend(self.analyze_apt_sources(&content, &format!("/etc/apt/sources.list.d/{}", filename)));
                    }
                }
            }
        }

        Ok(issues)
    }

    fn analyze_apt_sources(&self, content: &str, source: &str) -> Vec<RepoIssue> {
        let mut issues = Vec::new();

        for line in content.lines() {
            let trimmed = line.trim();

            // Skip comments and empty lines
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Check for HTTP (not HTTPS)
            if trimmed.contains("http://") && !trimmed.contains("https://") {
                issues.push(RepoIssue {
                    source: source.to_string(),
                    issue: "Uses HTTP instead of HTTPS".to_string(),
                    severity: Severity::Medium,
                    line: trimmed.to_string(),
                });
            }

            // Check for [trusted=yes] or similar that disables GPG verification
            if trimmed.contains("[trusted=yes]") || trimmed.contains("trusted=yes") {
                issues.push(RepoIssue {
                    source: source.to_string(),
                    issue: "GPG verification disabled (trusted=yes)".to_string(),
                    severity: Severity::High,
                    line: trimmed.to_string(),
                });
            }

            // Check for unusual/third-party repositories (basic heuristic)
            if !trimmed.contains("debian.org")
                && !trimmed.contains("ubuntu.com")
                && !trimmed.contains("raspberrypi.org")
                && !trimmed.contains("armbian.com")
                && trimmed.starts_with("deb") {
                // This is a third-party repo
                issues.push(RepoIssue {
                    source: source.to_string(),
                    issue: "Third-party repository".to_string(),
                    severity: Severity::Info,
                    line: trimmed.to_string(),
                });
            }
        }

        issues
    }

    pub fn analyze(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Detect package manager
        let pm = match self.detect_package_manager() {
            Some(pm) => pm,
            None => {
                findings.push(
                    Finding::new(
                        "packages-001",
                        "packages",
                        Severity::Low,
                        "Could not detect package manager"
                    )
                    .with_details("No apt, dnf, yum, or pacman found")
                );
                return Ok(findings);
            }
        };

        // Check for updates based on package manager
        let update_info = match pm {
            PackageManager::Apt => self.check_apt_updates(),
            PackageManager::Dnf | PackageManager::Yum => self.check_dnf_updates(),
            PackageManager::Pacman => {
                findings.push(
                    Finding::new(
                        "packages-002",
                        "packages",
                        Severity::Info,
                        "Pacman detected but update checking not yet implemented"
                    )
                );
                return Ok(findings);
            }
        };

        match update_info {
            Ok(info) => {
                if info.total_updates > 0 {
                    let severity = if info.security_updates > 0 {
                        Severity::High
                    } else if info.total_updates > 20 {
                        Severity::Medium
                    } else {
                        Severity::Low
                    };

                    let mut finding = Finding::new(
                        "packages-100",
                        "packages",
                        severity,
                        format!("{} package update(s) available", info.total_updates)
                    );

                    if info.security_updates > 0 {
                        finding = finding.with_details(format!(
                            "Includes {} security update(s)",
                            info.security_updates
                        ));
                    }

                    finding = finding.with_remediation(match pm {
                        PackageManager::Apt => "Run: sudo apt update && sudo apt upgrade",
                        PackageManager::Dnf => "Run: sudo dnf upgrade",
                        PackageManager::Yum => "Run: sudo yum update",
                        PackageManager::Pacman => "Run: sudo pacman -Syu",
                    });

                    findings.push(finding);
                } else {
                    findings.push(
                        Finding::new(
                            "packages-101",
                            "packages",
                            Severity::Info,
                            "All packages are up to date"
                        )
                    );
                }
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "packages-102",
                        "packages",
                        Severity::Low,
                        "Could not check for package updates"
                    )
                    .with_details(format!("Error: {}. You may need to run 'apt update' first.", e))
                );
            }
        }

        // Check repository configuration (APT only for now)
        if pm == PackageManager::Apt {
            if let Ok(repo_issues) = self.check_apt_sources() {
                for issue in repo_issues {
                    findings.push(
                        Finding::new(
                            format!("packages-200-{}", findings.len()),
                            "packages",
                            issue.severity,
                            issue.issue.clone()
                        )
                        .with_details(format!("In {}: {}", issue.source, issue.line))
                    );
                }
            }
        }

        // Check for unattended-upgrades (Debian/Ubuntu)
        if pm == PackageManager::Apt {
            let unattended_enabled = Path::new("/etc/apt/apt.conf.d/50unattended-upgrades").exists()
                || Path::new("/etc/apt/apt.conf.d/20auto-upgrades").exists();

            if unattended_enabled {
                findings.push(
                    Finding::new(
                        "packages-300",
                        "packages",
                        Severity::Info,
                        "Unattended upgrades configured"
                    )
                    .with_details("Automatic security updates are enabled")
                );
            } else {
                findings.push(
                    Finding::new(
                        "packages-301",
                        "packages",
                        Severity::Medium,
                        "Unattended upgrades not configured"
                    )
                    .with_details("Automatic security updates are not enabled")
                    .with_remediation("Install unattended-upgrades: sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades")
                );
            }
        }

        Ok(findings)
    }
}

impl Default for PackagesAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl super::Analyzer for PackagesAnalyzer {
    fn analyze(&self) -> Result<Vec<Finding>> {
        self.analyze()
    }

    fn category(&self) -> &'static str {
        "packages"
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum PackageManager {
    Apt,
    Dnf,
    Yum,
    Pacman,
}

#[derive(Debug)]
struct UpdateInfo {
    total_updates: usize,
    security_updates: usize,
}

#[derive(Debug)]
struct RepoIssue {
    source: String,
    issue: String,
    severity: Severity,
    line: String,
}
