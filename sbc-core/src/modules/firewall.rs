use crate::types::{Finding, Severity};
use anyhow::Result;
use std::process::Command;
use std::path::Path;

/// Firewall Configuration Analyzer
///
/// Checks iptables, nftables, ufw, and firewalld status
pub struct FirewallAnalyzer;

impl FirewallAnalyzer {
    pub fn new() -> Self {
        Self
    }

    /// Check if ufw is installed and active
    fn check_ufw(&self) -> Option<FirewallStatus> {
        if !Path::new("/usr/sbin/ufw").exists() {
            return None;
        }

        let output = Command::new("ufw")
            .arg("status")
            .output()
            .ok()?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        if stdout.contains("Status: active") {
            Some(FirewallStatus::Active("ufw".to_string()))
        } else if stdout.contains("Status: inactive") {
            Some(FirewallStatus::Inactive("ufw".to_string()))
        } else {
            Some(FirewallStatus::Unknown("ufw".to_string()))
        }
    }

    /// Check if firewalld is installed and active
    fn check_firewalld(&self) -> Option<FirewallStatus> {
        let output = Command::new("firewall-cmd")
            .arg("--state")
            .output()
            .ok()?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        if stdout.trim() == "running" {
            Some(FirewallStatus::Active("firewalld".to_string()))
        } else if stdout.contains("not running") {
            Some(FirewallStatus::Inactive("firewalld".to_string()))
        } else {
            None
        }
    }

    /// Check nftables
    fn check_nftables(&self) -> Option<FirewallStatus> {
        let output = Command::new("nft")
            .args(&["list", "ruleset"])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Check if there are any actual rules (not just empty tables)
        let has_rules = stdout.lines()
            .any(|line| {
                let trimmed = line.trim();
                // Look for actual rule directives
                trimmed.starts_with("accept") ||
                trimmed.starts_with("drop") ||
                trimmed.starts_with("reject") ||
                trimmed.starts_with("counter")
            });

        if has_rules {
            Some(FirewallStatus::Active("nftables".to_string()))
        } else if !stdout.trim().is_empty() {
            Some(FirewallStatus::Inactive("nftables".to_string()))
        } else {
            None
        }
    }

    /// Check iptables (legacy)
    fn check_iptables(&self) -> Option<IptablesStatus> {
        let output = Command::new("iptables")
            .args(&["-L", "-n"])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Check for default policies
        let mut input_policy = None;
        let mut forward_policy = None;
        let mut output_policy = None;

        for line in stdout.lines() {
            if line.starts_with("Chain INPUT") {
                input_policy = self.extract_policy(line);
            } else if line.starts_with("Chain FORWARD") {
                forward_policy = self.extract_policy(line);
            } else if line.starts_with("Chain OUTPUT") {
                output_policy = self.extract_policy(line);
            }
        }

        // Count actual rules (not just the header lines)
        let rule_count = stdout.lines()
            .filter(|line| {
                let trimmed = line.trim();
                !trimmed.is_empty() &&
                !trimmed.starts_with("Chain") &&
                !trimmed.starts_with("target") &&
                !trimmed.starts_with("pkts")
            })
            .count();

        Some(IptablesStatus {
            input_policy,
            forward_policy,
            output_policy,
            rule_count,
        })
    }

    fn extract_policy(&self, line: &str) -> Option<String> {
        // Format: "Chain INPUT (policy ACCEPT)"
        if let Some(start) = line.find("policy ") {
            let policy_str = &line[start + 7..];
            if let Some(end) = policy_str.find(')') {
                return Some(policy_str[..end].to_string());
            }
        }
        None
    }

    pub fn analyze(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check high-level firewall tools first
        let ufw_status = self.check_ufw();
        let firewalld_status = self.check_firewalld();
        let nftables_status = self.check_nftables();
        let iptables_status = self.check_iptables();

        // Determine overall firewall state
        let has_active_firewall = matches!(ufw_status, Some(FirewallStatus::Active(_)))
            || matches!(firewalld_status, Some(FirewallStatus::Active(_)))
            || matches!(nftables_status, Some(FirewallStatus::Active(_)));

        // UFW findings
        match ufw_status {
            Some(FirewallStatus::Active(_)) => {
                findings.push(
                    Finding::new(
                        "firewall-100",
                        "firewall",
                        Severity::Info,
                        "UFW (Uncomplicated Firewall) is active"
                    )
                );
            }
            Some(FirewallStatus::Inactive(_)) => {
                findings.push(
                    Finding::new(
                        "firewall-101",
                        "firewall",
                        Severity::High,
                        "UFW is installed but not active"
                    )
                    .with_remediation("Enable UFW with: sudo ufw enable")
                );
            }
            _ => {}
        }

        // firewalld findings
        match firewalld_status {
            Some(FirewallStatus::Active(_)) => {
                findings.push(
                    Finding::new(
                        "firewall-110",
                        "firewall",
                        Severity::Info,
                        "firewalld is active"
                    )
                );
            }
            Some(FirewallStatus::Inactive(_)) => {
                findings.push(
                    Finding::new(
                        "firewall-111",
                        "firewall",
                        Severity::High,
                        "firewalld is installed but not running"
                    )
                    .with_remediation("Start firewalld with: sudo systemctl start firewalld && sudo systemctl enable firewalld")
                );
            }
            _ => {}
        }

        // nftables findings
        match nftables_status {
            Some(FirewallStatus::Active(_)) => {
                findings.push(
                    Finding::new(
                        "firewall-120",
                        "firewall",
                        Severity::Info,
                        "nftables has active rules"
                    )
                );
            }
            Some(FirewallStatus::Inactive(_)) => {
                if !has_active_firewall {
                    findings.push(
                        Finding::new(
                            "firewall-121",
                            "firewall",
                            Severity::Medium,
                            "nftables is available but has no active rules"
                        )
                    );
                }
            }
            _ => {}
        }

        // iptables findings
        if let Some(ipt_status) = iptables_status {
            let all_accept = ipt_status.input_policy.as_deref() == Some("ACCEPT")
                && ipt_status.forward_policy.as_deref() == Some("ACCEPT");

            if !has_active_firewall {
                if all_accept && ipt_status.rule_count == 0 {
                    findings.push(
                        Finding::new(
                            "firewall-200",
                            "firewall",
                            Severity::High,
                            "No firewall detected - iptables has default ACCEPT policy with no rules"
                        )
                        .with_details("All incoming connections are allowed")
                        .with_remediation("Install and configure a firewall (ufw, firewalld, or nftables)")
                    );
                } else if all_accept && ipt_status.rule_count < 5 {
                    findings.push(
                        Finding::new(
                            "firewall-201",
                            "firewall",
                            Severity::Medium,
                            format!("Minimal firewall protection - only {} iptables rule(s)", ipt_status.rule_count)
                        )
                        .with_details("Default policy is ACCEPT with very few rules")
                        .with_remediation("Review and strengthen firewall rules")
                    );
                } else if ipt_status.rule_count > 0 {
                    findings.push(
                        Finding::new(
                            "firewall-202",
                            "firewall",
                            Severity::Info,
                            format!("iptables has {} rule(s) configured", ipt_status.rule_count)
                        )
                        .with_details(format!(
                            "Policies: INPUT={}, FORWARD={}, OUTPUT={}",
                            ipt_status.input_policy.as_deref().unwrap_or("unknown"),
                            ipt_status.forward_policy.as_deref().unwrap_or("unknown"),
                            ipt_status.output_policy.as_deref().unwrap_or("unknown")
                        ))
                    );
                }
            }
        } else if !has_active_firewall {
            findings.push(
                Finding::new(
                    "firewall-300",
                    "firewall",
                    Severity::High,
                    "Unable to determine firewall status"
                )
                .with_details("Could not check ufw, firewalld, nftables, or iptables (may need root)")
                .with_remediation("Run with sudo to check firewall status")
            );
        }

        // Summary finding if no firewall at all
        if !has_active_firewall && findings.is_empty() {
            findings.push(
                Finding::new(
                    "firewall-999",
                    "firewall",
                    Severity::Critical,
                    "No firewall appears to be configured or active"
                )
                .with_remediation("Install and configure a firewall immediately (ufw is recommended for simplicity)")
            );
        }

        Ok(findings)
    }
}

impl Default for FirewallAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl super::Analyzer for FirewallAnalyzer {
    fn analyze(&self) -> Result<Vec<Finding>> {
        self.analyze()
    }

    fn category(&self) -> &'static str {
        "firewall"
    }
}

#[derive(Debug)]
#[allow(dead_code)]
enum FirewallStatus {
    Active(String),
    Inactive(String),
    Unknown(String),
}

#[derive(Debug)]
struct IptablesStatus {
    input_policy: Option<String>,
    forward_policy: Option<String>,
    output_policy: Option<String>,
    rule_count: usize,
}
