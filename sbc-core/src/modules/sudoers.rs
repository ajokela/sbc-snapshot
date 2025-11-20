use crate::types::{Finding, Severity};
use anyhow::Result;
use std::fs;
use std::path::Path;

/// Sudoers Configuration Analyzer
///
/// Examines /etc/sudoers and /etc/sudoers.d/* for security issues
pub struct SudoersAnalyzer;

impl SudoersAnalyzer {
    pub fn new() -> Self {
        Self
    }

    /// Parse sudoers files and extract relevant rules
    fn parse_sudoers(&self) -> Result<Vec<SudoRule>> {
        let mut rules = Vec::new();

        // Read main sudoers file
        if let Ok(content) = fs::read_to_string("/etc/sudoers") {
            rules.extend(self.extract_rules(&content, "/etc/sudoers"));
        }

        // Read sudoers.d directory
        if let Ok(entries) = fs::read_dir("/etc/sudoers.d") {
            for entry in entries.flatten() {
                if let Ok(content) = fs::read_to_string(entry.path()) {
                    let filename = entry.file_name().to_string_lossy().to_string();
                    rules.extend(self.extract_rules(&content, &format!("/etc/sudoers.d/{}", filename)));
                }
            }
        }

        Ok(rules)
    }

    fn extract_rules(&self, content: &str, source: &str) -> Vec<SudoRule> {
        let mut rules = Vec::new();

        for line in content.lines() {
            let trimmed = line.trim();

            // Skip comments and empty lines
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Skip Defaults, User_Alias, etc.
            if trimmed.starts_with("Defaults")
                || trimmed.starts_with("User_Alias")
                || trimmed.starts_with("Runas_Alias")
                || trimmed.starts_with("Host_Alias")
                || trimmed.starts_with("Cmnd_Alias") {
                continue;
            }

            // Parse user privilege specification
            // Format: user HOST=(RUNAS) COMMANDS
            // Examples:
            //   pi ALL=(ALL:ALL) NOPASSWD: ALL
            //   %sudo ALL=(ALL:ALL) ALL
            //   alex ALL=(ALL) NOPASSWD: /usr/bin/reboot

            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 3 {
                let user_or_group = parts[0].to_string();
                let has_nopasswd = trimmed.contains("NOPASSWD:");
                let has_all_commands = trimmed.ends_with("ALL") || trimmed.contains("ALL") && !trimmed.contains(':');
                let has_passwd = trimmed.contains("PASSWD:") || (!has_nopasswd && !trimmed.contains("NOPASSWD"));

                rules.push(SudoRule {
                    user_or_group,
                    source: source.to_string(),
                    has_nopasswd,
                    has_all_commands,
                    has_passwd,
                    raw_line: trimmed.to_string(),
                });
            }
        }

        rules
    }

    pub fn analyze(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check if we can read sudoers
        if !Path::new("/etc/sudoers").exists() {
            findings.push(
                Finding::new(
                    "sudoers-001",
                    "sudoers",
                    Severity::Low,
                    "Cannot access /etc/sudoers"
                )
                .with_details("File doesn't exist or cannot be read (may need root)")
            );
            return Ok(findings);
        }

        let rules = match self.parse_sudoers() {
            Ok(r) => r,
            Err(e) => {
                findings.push(
                    Finding::new(
                        "sudoers-002",
                        "sudoers",
                        Severity::Medium,
                        "Failed to parse sudoers configuration"
                    )
                    .with_details(format!("Error: {}. May need root permissions.", e))
                );
                return Ok(findings);
            }
        };

        // Check for NOPASSWD with ALL commands (very dangerous)
        let nopasswd_all: Vec<_> = rules.iter()
            .filter(|r| r.has_nopasswd && r.has_all_commands)
            .collect();

        for rule in &nopasswd_all {
            let severity = if rule.user_or_group.starts_with('%') {
                // Group rule
                Severity::High
            } else {
                // Individual user
                Severity::Critical
            };

            findings.push(
                Finding::new(
                    format!("sudoers-100-{}", rule.user_or_group.trim_start_matches('%')),
                    "sudoers",
                    severity,
                    format!("'{}' has passwordless sudo for ALL commands", rule.user_or_group)
                )
                .with_details(format!("Rule: {} (from {})", rule.raw_line, rule.source))
                .with_remediation(format!(
                    "Remove NOPASSWD: or restrict to specific commands only. Edit {}",
                    rule.source
                ))
            );
        }

        // Check for common vendor defaults that are dangerous
        let vendor_defaults = [
            ("pi", "Raspberry Pi OS default"),
            ("orangepi", "Orange Pi default"),
            ("rock", "Radxa default"),
            ("odroid", "Odroid default"),
            ("ubuntu", "Ubuntu default user"),
            ("debian", "Debian default user"),
        ];

        for (username, description) in &vendor_defaults {
            if let Some(rule) = rules.iter().find(|r| r.user_or_group == *username) {
                if rule.has_nopasswd {
                    findings.push(
                        Finding::new(
                            format!("sudoers-200-{}", username),
                            "sudoers",
                            Severity::High,
                            format!("Default vendor user '{}' has NOPASSWD sudo access", username)
                        )
                        .with_details(format!("{} - Rule: {}", description, rule.raw_line))
                        .with_remediation(format!(
                            "Remove or restrict NOPASSWD for '{}' user, or remove the user entirely",
                            username
                        ))
                    );
                }
            }
        }

        // Check for ALL=(ALL) or ALL=(ALL:ALL) - full privileges
        let full_privs: Vec<_> = rules.iter()
            .filter(|r| r.has_all_commands)
            .collect();

        if !full_privs.is_empty() {
            let users: Vec<String> = full_privs.iter()
                .map(|r| r.user_or_group.clone())
                .collect();

            findings.push(
                Finding::new(
                    "sudoers-300",
                    "sudoers",
                    Severity::Info,
                    format!("{} user(s)/group(s) can run any command via sudo", full_privs.len())
                )
                .with_details(format!("Users/Groups: {}", users.join(", ")))
            );
        }

        // Check for %sudo or %wheel group
        let admin_groups = rules.iter()
            .filter(|r| r.user_or_group == "%sudo" || r.user_or_group == "%wheel" || r.user_or_group == "%admin")
            .collect::<Vec<_>>();

        if admin_groups.is_empty() {
            findings.push(
                Finding::new(
                    "sudoers-400",
                    "sudoers",
                    Severity::Low,
                    "No standard admin group (%sudo, %wheel, %admin) found in sudoers"
                )
                .with_details("This might indicate a non-standard configuration")
            );
        } else {
            for group_rule in admin_groups {
                if group_rule.has_nopasswd {
                    findings.push(
                        Finding::new(
                            format!("sudoers-401-{}", group_rule.user_or_group.trim_start_matches('%')),
                            "sudoers",
                            Severity::High,
                            format!("Admin group '{}' has NOPASSWD access", group_rule.user_or_group)
                        )
                        .with_details("All members of this group can sudo without password")
                        .with_remediation("Consider requiring passwords for sudo operations")
                    );
                } else {
                    findings.push(
                        Finding::new(
                            format!("sudoers-402-{}", group_rule.user_or_group.trim_start_matches('%')),
                            "sudoers",
                            Severity::Info,
                            format!("Admin group '{}' configured (password required)", group_rule.user_or_group)
                        )
                    );
                }
            }
        }

        // Summary
        findings.push(
            Finding::new(
                "sudoers-900",
                "sudoers",
                Severity::Info,
                format!("{} sudo rule(s) configured", rules.len())
            )
        );

        Ok(findings)
    }
}

impl Default for SudoersAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl super::Analyzer for SudoersAnalyzer {
    fn analyze(&self) -> Result<Vec<Finding>> {
        self.analyze()
    }

    fn category(&self) -> &'static str {
        "sudoers"
    }
}

#[derive(Debug, Clone)]
struct SudoRule {
    user_or_group: String,
    source: String,
    has_nopasswd: bool,
    has_all_commands: bool,
    #[allow(dead_code)]
    has_passwd: bool,
    raw_line: String,
}
